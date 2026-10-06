//! Typed packet admission for embedded servers.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use hickory_server::proto::rr::{Name, RecordSet, RecordType};
use iroh_base::PublicKey;
use iroh_dns::pkarr::SignedPacket;
use n0_error::{Result, StdResultExt, bail_any};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    store::ZoneStore,
    util::{
        PublicKeyBytes, signed_packet_to_hickory_message, signed_packet_to_hickory_records_with_ttl,
    },
};

/// Host-owned admission of native signed packets, consulted for every request.
///
/// `None` means unavailable, never authoritative absence. The host must validate
/// its authority and namespace policy before returning a coherent accepted view.
/// Work is directly awaited and must be cancellation-safe; do not detach it.
#[async_trait]
pub trait PacketLookup: Send + Sync + 'static {
    /// Admit a packet for this key, or report unavailable evidence.
    async fn lookup(&self, key: PublicKey) -> Result<Option<PacketLease>>;
}

/// A native signed packet and conservative process-local timing budgets.
///
/// This is trusted host input, not a serialized proof. Age comes from the
/// original signed timestamp under host policy; refresh, restart or finality
/// outages must not reset it. Future skew cannot extend original record TTLs.
#[derive(Debug, Clone)]
pub struct PacketLease {
    packet: SignedPacket,
    observed_at: Instant,
    age_at_observation: Duration,
    remaining_validity: Duration,
}

impl PacketLease {
    /// Construct an admission snapshot. Invalid or expired timing fails closed
    /// when used. Observe no later than the instant represented by the budgets.
    pub fn new(
        packet: SignedPacket,
        observed_at: Instant,
        age_at_observation: Duration,
        remaining_validity: Duration,
    ) -> Self {
        Self {
            packet,
            observed_at,
            age_at_observation,
            remaining_validity,
        }
    }
    /// The original packet; its signed bytes are never rewritten.
    pub fn packet(&self) -> &SignedPacket {
        &self.packet
    }
    /// Process-local observation instant; never persist this value.
    pub fn observed_at(&self) -> Instant {
        self.observed_at
    }
    /// Signed age at observation, including conservative host clock policy.
    pub fn age_at_observation(&self) -> Duration {
        self.age_at_observation
    }
    /// Remaining freshness and explicit authorization budget at observation.
    pub fn remaining_validity(&self) -> Duration {
        self.remaining_validity
    }

    fn timing_at(&self, now: Instant) -> Option<(Duration, Duration)> {
        let elapsed = now.checked_duration_since(self.observed_at)?;
        let age = self.age_at_observation.checked_add(elapsed)?;
        let remaining = self.remaining_validity.checked_sub(elapsed)?;
        (remaining.as_secs() > 0).then_some((age, remaining))
    }
    fn ttl_left(ttl: u32, timing: (Duration, Duration)) -> Option<u32> {
        let left = Duration::from_secs(u64::from(ttl))
            .checked_sub(timing.0)?
            .min(timing.1)
            .as_secs();
        (left > 0).then_some(left as u32)
    }
    fn pkarr_usable_at(&self, now: impl FnOnce() -> Instant) -> Result<bool> {
        let message = signed_packet_to_hickory_message(&self.packet).anyerr()?;
        let Some(timing) = self.timing_at(now()) else {
            return Ok(false);
        };
        let mut count = 0;
        for record in message
            .answers
            .iter()
            .chain(&message.authorities)
            .chain(&message.additionals)
        {
            if record.record_type() == RecordType::OPT {
                continue;
            }
            count += 1;
            if Self::ttl_left(record.ttl, timing).is_none() {
                return Ok(false);
            }
        }
        Ok(count > 0)
    }
}

#[derive(Clone, derive_more::Debug)]
pub(crate) enum Backend {
    Store(ZoneStore),
    Injected(Arc<InjectedLookup>),
}

impl From<ZoneStore> for Backend {
    fn from(store: ZoneStore) -> Self {
        Self::Store(store)
    }
}

#[derive(derive_more::Debug)]
pub(crate) struct InjectedLookup {
    #[debug("PacketLookup")]
    lookup: Arc<dyn PacketLookup>,
    cancel: CancellationToken,
    entered: RwLock<()>,
}

impl Backend {
    pub(crate) fn injected(lookup: Arc<dyn PacketLookup>) -> Self {
        Self::Injected(Arc::new(InjectedLookup {
            lookup,
            cancel: CancellationToken::new(),
            entered: RwLock::new(()),
        }))
    }
    pub(crate) fn is_injected(&self) -> bool {
        matches!(self, Self::Injected(_))
    }
    pub(crate) fn store(&self) -> Option<&ZoneStore> {
        match self {
            Self::Store(store) => Some(store),
            Self::Injected(_) => None,
        }
    }
    pub(crate) fn cancel(&self) {
        if let Self::Injected(backend) = self {
            backend.cancel.cancel();
        }
    }
    pub(crate) async fn drain(&self) {
        if let Self::Injected(backend) = self {
            backend.cancel.cancel();
            // The host future is destroyed before its read guard is released.
            let _exclusive = backend.entered.write().await;
        }
    }
    async fn admitted(&self, key: &PublicKeyBytes) -> Result<Option<PacketLease>> {
        let Self::Injected(backend) = self else {
            bail_any!("not an injected backend")
        };
        let guard = tokio::select! { biased;
            _ = backend.cancel.cancelled() => return Ok(None),
            guard = backend.entered.read() => guard,
        };
        if backend.cancel.is_cancelled() {
            return Ok(None);
        }
        let key = PublicKey::from_bytes(key.as_bytes()).anyerr()?;
        let result = tokio::select! { biased;
            _ = backend.cancel.cancelled() => Ok(None),
            result = backend.lookup.lookup(key) => result,
        };
        // Select has dropped the directly awaited host future before this guard.
        drop(guard);
        let Some(mut lease) = result? else {
            return Ok(None);
        };
        // Native constructors can be unchecked. Revalidate native bytes here.
        let packet = SignedPacket::from_bytes(lease.packet.as_bytes()).anyerr()?;
        if packet.public_key() != key {
            bail_any!("lookup packet signer differs from requested key");
        }
        lease.packet = packet;
        Ok(Some(lease))
    }
    pub(crate) async fn resolve(
        &self,
        key: &PublicKeyBytes,
        name: &Name,
        kind: RecordType,
    ) -> Result<Option<Arc<RecordSet>>> {
        if let Self::Store(store) = self {
            return store.resolve(key, name, kind).await;
        }
        let Some(lease) = self.admitted(key).await? else {
            return Ok(None);
        };
        let (_, mut sets) = signed_packet_to_hickory_records_with_ttl(&lease.packet, |record| {
            lease
                .timing_at(Instant::now())
                .and_then(|timing| PacketLease::ttl_left(record.ttl, timing))
        })
        .anyerr()?;
        Ok(sets.remove(&hickory_server::proto::rr::RrKey::new(
            name.clone().into(),
            kind,
        )))
    }
    pub(crate) async fn packet(&self, key: &PublicKeyBytes) -> Result<Option<SignedPacket>> {
        if let Self::Store(store) = self {
            return store.get_signed_packet(key).await;
        }
        let Some(lease) = self.admitted(key).await? else {
            return Ok(None);
        };
        if lease.pkarr_usable_at(Instant::now)? {
            Ok(Some(lease.packet))
        } else {
            Ok(None)
        }
    }
    pub(crate) fn report_unavailable(error: &n0_error::AnyError) {
        debug!(%error, "injected packet lookup unavailable");
    }
}

#[cfg(test)]
mod tests;
