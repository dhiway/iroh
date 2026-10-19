use std::{
    io,
    num::NonZeroU16,
    task::{Context, Poll},
};

use bytes::Bytes;
use iroh_base::{EndpointId, RelayUrl};
use iroh_relay::protos::relay::Datagrams;
use n0_future::{
    ready,
    task::{self, AbortOnDropHandle},
};
use n0_watcher::Watcher as _;
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, PollSender};
use tracing::{Instrument, error, info_span, warn};

use super::{RecvInfo, Transmit};
use crate::endpoint::RelayStatus;

mod actor;

pub(crate) use self::actor::{
    Config as RelayActorConfig, HomeRelayWatch, RelayConnectionFailure, RelayConnectionState,
};
use self::actor::{RelayActor, RelayActorMessage, RelayRecvDatagram, RelaySendItem};

type RelayAddrWatcher =
    n0_watcher::Map<n0_watcher::Direct<Option<RelayStatus>>, Option<(RelayUrl, EndpointId)>>;

#[derive(Debug)]
pub(crate) struct RelayTransport {
    /// Queue to receive datagrams from relays for [`noq::AsyncUdpSocket::poll_recv`].
    relay_datagram_recv_queue: mpsc::Receiver<RelayRecvDatagram>,
    /// Channel on which to send datagrams via a relay server.
    relay_datagram_send_channel: mpsc::Sender<RelaySendItem>,
    /// A datagram from the last poll_recv that didn't quite fit our buffers.
    pending_item: Option<RelayRecvDatagram>,
    actor_sender: mpsc::Sender<RelayActorMessage>,
    _actor_handle: AbortOnDropHandle<()>,
    my_relay: HomeRelayWatch,
    my_endpoint_id: EndpointId,
    relay_allowlist: crate::endpoint::RelayAllowlist,
}

impl std::fmt::Display for RelayTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RelayTransport")
    }
}

impl RelayTransport {
    pub(crate) fn new(config: RelayActorConfig, cancel_token: CancellationToken) -> Self {
        let (relay_datagram_send_tx, relay_datagram_send_rx) = mpsc::channel(256);

        let (relay_datagram_recv_tx, relay_datagram_recv_rx) = mpsc::channel(512);

        let (actor_sender, actor_receiver) = mpsc::channel(256);

        let relay_allowlist = config.relay_allowlist.clone();
        let my_endpoint_id = config.secret_key.public();
        let my_relay = config.my_relay.clone();

        let relay_actor = RelayActor::new(config, relay_datagram_recv_tx, cancel_token);

        let actor_handle = AbortOnDropHandle::new(task::spawn(
            async move {
                relay_actor
                    .run(actor_receiver, relay_datagram_send_rx)
                    .await;
            }
            .instrument(info_span!("relay-actor")),
        ));

        Self {
            relay_datagram_recv_queue: relay_datagram_recv_rx,
            relay_datagram_send_channel: relay_datagram_send_tx,
            pending_item: None,
            actor_sender,
            _actor_handle: actor_handle,
            my_relay,
            my_endpoint_id,
            relay_allowlist,
        }
    }

    pub(crate) fn create_sender(&self) -> RelaySender {
        RelaySender {
            sender: PollSender::new(self.relay_datagram_send_channel.clone()),
            relay_allowlist: self.relay_allowlist.clone(),
        }
    }

    pub(super) fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");
        assert_eq!(
            bufs.len(),
            recv_infos.len(),
            "non matching bufs & recv_infos"
        );
        let relay_allowlist = self.relay_allowlist.clone();
        let mut num_msgs = 0;
        let mut consumed = false;
        // Bound work by the caller's batch capacity, but compact accepted datagrams:
        // a rejected/oversized input must never leave an unwritten returned slot.
        for _ in 0..bufs.len() {
            let i = num_msgs;
            let buf_out = &mut bufs[i];
            let meta_out = &mut metas[i];
            let recv_info = &mut recv_infos[i];
            let dm = match self.poll_recv_queue(cx) {
                Poll::Ready(Some(recv)) => recv,
                Poll::Ready(None) => {
                    error!("relay_recv_channel closed");
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "connection closed",
                    )));
                }
                Poll::Pending => {
                    break;
                }
            };

            consumed = true;
            if !relay_allowlist.allows(&dm.url) {
                self.pending_item = None;
                continue;
            }
            // This *tries* to make the datagrams fit into our buffer by re-batching them.
            let num_segments = dm
                .datagrams
                .segment_size
                .map_or(1, |ss| buf_out.len() / u16::from(ss) as usize);
            let datagrams = dm.datagrams.take_segments(num_segments);
            let empty_now = datagrams.contents.is_empty();
            let empty_after = dm.datagrams.contents.is_empty();

            let dm = RelayRecvDatagram {
                datagrams,
                src: dm.src,
                url: dm.url.clone(),
            };

            // If `take_segments` processed the whole contents (empty_after) or none at all
            // (empty_now) we shouldn't process what's left in `self.pending_item`.
            // In the first case the remaining `pending_item` is empty and can be dropped.
            // In the second case a single segment could not fit into the buffer, future
            // calls to `poll_recv` would not change this so drop the `pending_item` with
            // the oversized segment size.
            if empty_after || empty_now {
                self.pending_item = None;
            }
            if empty_now {
                warn!(
                    noq_buf_len = buf_out.len(),
                    segment_size = ?dm.datagrams.segment_size,
                    "dropping received datagram: segment_size too large");
                continue;
            }

            if buf_out.len() < dm.datagrams.contents.len() {
                // Our receive buffer isn't big enough to process this datagram.
                // Continuing would cause a panic.
                warn!(
                    noq_buf_len = buf_out.len(),
                    datagram_len = dm.datagrams.contents.len(),
                    segment_size = ?dm.datagrams.segment_size,
                    "dropping received datagram: noq buffer too small"
                );
                break;
                // In theory we could put some logic in here to fragment the datagram in case
                // we still have enough room in our `buf_out` left to fit a couple of
                // `dm.datagrams.segment_size`es, but we *should* have cut those datagrams
                // to appropriate sizes earlier in the pipeline (just before we put them
                // into the `relay_datagram_recv_queue` in the `ActiveRelayActor`).
                // So the only case in which this happens is we receive a datagram via the relay
                // that's essentially bigger than our configured `max_udp_payload_size`.
                // In that case we drop it and let MTU discovery take over.
            }

            buf_out[..dm.datagrams.contents.len()].copy_from_slice(&dm.datagrams.contents);
            meta_out.len = dm.datagrams.contents.len();
            meta_out.stride = dm
                .datagrams
                .segment_size
                .map_or(dm.datagrams.contents.len(), |s| u16::from(s) as usize);
            meta_out.ecn = None;
            meta_out.dst_ip = None;

            *recv_info = RecvInfo::from_addr((dm.url, dm.src).into());
            num_msgs += 1;
        }

        // If we have any msgs to report, they are in the first `num_msgs_total` slots
        if num_msgs > 0 {
            assert!(num_msgs <= metas.len());
            Poll::Ready(Ok(num_msgs))
        } else {
            // A batch of discarded inputs can exhaust our work budget without
            // polling an empty receiver (and hence without registering a waker).
            // Give queued valid input another bounded poll without a new send.
            if consumed {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }

    pub(super) fn local_addr_watch(&self) -> RelayAddrWatcher {
        let my_endpoint_id = self.my_endpoint_id;
        self.my_relay
            .watch()
            .map(move |status| status.map(|status| (status.url().clone(), my_endpoint_id)))
    }

    pub(super) fn my_relay_status(&self) -> n0_watcher::Direct<Option<RelayStatus>> {
        self.my_relay.watch()
    }

    pub(super) fn create_network_change_sender(&self) -> RelayNetworkChangeSender {
        RelayNetworkChangeSender {
            sender: self.actor_sender.clone(),
        }
    }

    /// Makes sure we have a pending item stored, if not, it'll poll a new one from the queue.
    ///
    /// Returns a mutable reference to the stored pending item.
    #[inline]
    fn poll_recv_queue<'a>(
        &'a mut self,
        cx: &mut Context,
    ) -> Poll<Option<&'a mut RelayRecvDatagram>> {
        // Borrow checker doesn't quite understand an if let Some(_)... here
        if self.pending_item.is_some() {
            return Poll::Ready(self.pending_item.as_mut());
        }

        let item = match self.relay_datagram_recv_queue.poll_recv(cx) {
            Poll::Ready(Some(item)) => item,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => return Poll::Pending,
        };

        Poll::Ready(Some(self.pending_item.insert(item)))
    }
}

#[derive(Debug)]
pub(super) struct RelayNetworkChangeSender {
    sender: mpsc::Sender<RelayActorMessage>,
}

impl RelayNetworkChangeSender {
    pub(super) fn on_network_change(&self, report: &crate::socket::Report) {
        self.send_relay_actor(RelayActorMessage::NetworkChange {
            report: report.clone(),
        });
    }

    /// Triggers an immediate health check on relay connections after a network change.
    pub(super) fn check_connection_after_network_change(&self) {
        self.send_relay_actor(RelayActorMessage::CheckConnectionAfterNetworkChange);
    }

    pub(super) fn rebind(&self) -> io::Result<()> {
        self.send_relay_actor(RelayActorMessage::MaybeCloseRelaysOnRebind);

        Ok(())
    }

    fn send_relay_actor(&self, msg: RelayActorMessage) {
        match self.sender.try_send(msg) {
            Ok(_) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("unable to send to relay actor, already closed");
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("dropping message for relay actor, channel is full");
            }
        }
    }
}

/// Sender to send datagrams to the [`RelayActor`].
///
/// This includes the waker coordination required to support [`noq::UdpSender::poll_send`].
#[derive(Debug, Clone)]
pub(crate) struct RelaySender {
    sender: PollSender<RelaySendItem>,
    relay_allowlist: crate::endpoint::RelayAllowlist,
}

impl RelaySender {
    pub(super) fn is_valid_send_addr(&self, url: &RelayUrl, _endpoint_id: &EndpointId) -> bool {
        self.relay_allowlist.allows(url)
    }

    pub(super) fn poll_send(
        &mut self,
        cx: &mut Context,
        dest_url: RelayUrl,
        dest_endpoint: EndpointId,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.relay_allowlist.allows(&dest_url) {
            return Poll::Ready(Ok(()));
        }
        match ready!(self.sender.poll_reserve(cx)) {
            Ok(()) => {
                let contents = datagrams_from_transmit(transmit);
                let item = RelaySendItem {
                    remote_endpoint: dest_endpoint,
                    url: dest_url.clone(),
                    datagrams: contents,
                };
                match self.sender.send_item(item) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(_err) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "channel to actor is closed",
                    ))),
                }
            }
            Err(_err) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "channel to actor is closed",
            ))),
        }
    }
}

/// Translate a UDP transmit to the `Datagrams` type for sending over the relay.
fn datagrams_from_transmit(transmit: &Transmit<'_>) -> Datagrams {
    Datagrams {
        ecn: transmit.ecn.map(|ecn| match ecn {
            noq_udp::EcnCodepoint::Ect0 => noq_proto::EcnCodepoint::Ect0,
            noq_udp::EcnCodepoint::Ect1 => noq_proto::EcnCodepoint::Ect1,
            noq_udp::EcnCodepoint::Ce => noq_proto::EcnCodepoint::Ce,
        }),
        segment_size: transmit
            .segment_size
            .map(|ss| ss as u16)
            .and_then(NonZeroU16::new),
        contents: Bytes::copy_from_slice(transmit.contents),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        num::NonZeroU16,
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use iroh_base::{EndpointId, SecretKey};
    use iroh_relay::{
        RelayMap,
        tls::{CaTlsConfig, default_provider},
    };
    use tokio::task::JoinSet;
    use tracing::debug;

    use super::*;
    use crate::{defaults::staging, dns::DnsResolver};

    impl RelaySender {
        pub(in crate::socket::transports) fn bounded_for_test(
            capacity: usize,
        ) -> (RelaySender, mpsc::Receiver<RelaySendItem>) {
            let (sender, receiver) = mpsc::channel(capacity);
            (
                RelaySender {
                    sender: PollSender::new(sender),
                    relay_allowlist: Default::default(),
                },
                receiver,
            )
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_relay_datagram_queue() {
        let capacity = 16;
        let (sender, mut receiver) = mpsc::channel(capacity);
        let url = staging::default_na_east_relay().url;

        let mut tasks = JoinSet::new();

        tasks.spawn({
            async move {
                let mut expected_msgs: BTreeSet<usize> = (0..capacity).collect();
                while !expected_msgs.is_empty() {
                    let datagram: RelayRecvDatagram = receiver.recv().await.unwrap();
                    let msg_num = usize::from_le_bytes(datagram.datagrams.contents.as_ref().try_into().unwrap());
                    debug!("Received {msg_num}");

                    if !expected_msgs.remove(&msg_num) {
                        panic!("Received message number {msg_num} twice or more, but expected it only exactly once.");
                    }
                }
            }
        });

        for i in 0..capacity {
            tasks.spawn({
                let sender = sender.clone();
                let url = url.clone();
                async move {
                    debug!("Sending {i}");
                    sender
                        .try_send(RelayRecvDatagram {
                            url,
                            src: EndpointId::from_bytes(&[0u8; 32]).unwrap(),
                            datagrams: Datagrams::from(&i.to_le_bytes()),
                        })
                        .unwrap();
                }
            });
        }

        // We expect all of this work to be done in 10 seconds max.
        if tokio::time::timeout(Duration::from_secs(10), tasks.join_all())
            .await
            .is_err()
        {
            panic!("Timeout - not all messages between 0 and {capacity} received.");
        }
    }

    /// Builds a [`RelayTransport`] that never actually dials a relay (its home
    /// relay watcher is left unset), just so we get a real `poll_recv` to exercise.
    fn test_relay_transport() -> RelayTransport {
        let config = RelayActorConfig {
            my_relay: HomeRelayWatch::default(),
            secret_key: SecretKey::from_bytes(&[7u8; 32]),
            dns_resolver: DnsResolver::new(),
            proxy_url: None,
            ipv6_reported: Arc::new(AtomicBool::new(false)),
            tls_config: CaTlsConfig::insecure_skip_verify()
                .client_config(default_provider())
                .expect("infallible"),
            metrics: Default::default(),
            relay_map: RelayMap::empty(),
            relay_allowlist: Default::default(),
        };
        RelayTransport::new(config, CancellationToken::new())
    }

    fn strict_recv_item(
        url: RelayUrl,
        peer: EndpointId,
        bytes: &'static [u8],
    ) -> RelayRecvDatagram {
        RelayRecvDatagram {
            url,
            src: peer,
            datagrams: Datagrams {
                contents: Bytes::from_static(bytes),
                segment_size: None,
                ecn: None,
            },
        }
    }

    #[tokio::test]
    async fn strict_relays_receive_compacts_denied_then_valid_batch() {
        let mut transport = test_relay_transport();
        let allowed: RelayUrl = "https://allowed.invalid/".parse().unwrap();
        let denied: RelayUrl = "https://denied.invalid/".parse().unwrap();
        transport.relay_allowlist.restrict([allowed.clone()]);
        let peer = SecretKey::generate().public();
        let (tx, rx) = mpsc::channel(8);
        transport.relay_datagram_recv_queue = rx;
        tx.try_send(strict_recv_item(denied, peer, b"denied"))
            .unwrap();
        tx.try_send(strict_recv_item(allowed.clone(), peer, b"valid"))
            .unwrap();
        let mut a = [0xaau8; 64];
        let mut b = [0xbbu8; 64];
        let mut bufs = [io::IoSliceMut::new(&mut a), io::IoSliceMut::new(&mut b)];
        let mut metas = [noq_udp::RecvMeta::default(); 2];
        let mut infos = [RecvInfo::default(), RecvInfo::default()];
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            transport.poll_recv(&mut cx, &mut bufs, &mut metas, &mut infos),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(&a[..metas[0].len], b"valid");
        assert_eq!(metas[0].stride, 5);
        assert!(
            matches!(infos[0].remote(), super::super::Addr::Relay(url,id) if url == &allowed && id == &peer)
        );
        assert_eq!(b, [0xbb; 64]);
    }

    #[derive(Default)]
    struct StrictWakeCounter(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for StrictWakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn strict_relays_receive_denied_budget_wakes_queued_valid_without_new_send() {
        let mut transport = test_relay_transport();
        let allowed: RelayUrl = "https://allowed.invalid/".parse().unwrap();
        let denied: RelayUrl = "https://denied.invalid/".parse().unwrap();
        transport.relay_allowlist.restrict([allowed.clone()]);
        let peer = SecretKey::generate().public();
        let (tx, rx) = mpsc::channel(8);
        transport.relay_datagram_recv_queue = rx;
        for _ in 0..2 {
            tx.try_send(strict_recv_item(denied.clone(), peer, b"denied"))
                .unwrap();
        }
        tx.try_send(strict_recv_item(allowed.clone(), peer, b"valid"))
            .unwrap();
        let counter = Arc::new(StrictWakeCounter::default());
        let waker = std::task::Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let mut a = [0xaau8; 64];
        let mut b = [0xbbu8; 64];
        let mut bufs = [io::IoSliceMut::new(&mut a), io::IoSliceMut::new(&mut b)];
        let mut metas = [noq_udp::RecvMeta::default(); 2];
        let mut infos = [RecvInfo::default(), RecvInfo::default()];
        assert!(
            transport
                .poll_recv(&mut cx, &mut bufs, &mut metas, &mut infos)
                .is_pending()
        );
        assert_eq!(counter.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        // No producer activity between polls: only the receive self-wake permits progress.
        assert!(matches!(
            transport.poll_recv(&mut cx, &mut bufs, &mut metas, &mut infos),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(&a[..metas[0].len], b"valid");
        assert!(
            matches!(infos[0].remote(), super::super::Addr::Relay(url,id) if url == &allowed && id == &peer)
        );
    }

    #[tokio::test]
    async fn strict_relays_sender_and_receive_reject_unapproved_metadata() {
        let mut transport = test_relay_transport();
        transport.relay_allowlist.restrict([]);
        let url: RelayUrl = "https://forbidden.invalid/".parse().unwrap();
        let peer = SecretKey::generate().public();
        let mut sender = transport.create_sender();
        assert!(!sender.is_valid_send_addr(&url, &peer));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            sender
                .poll_send(
                    &mut cx,
                    url.clone(),
                    peer,
                    &Transmit {
                        ecn: None,
                        contents: b"denied",
                        segment_size: None,
                    }
                )
                .is_ready()
        );
        transport.pending_item = Some(RelayRecvDatagram {
            url,
            src: peer,
            datagrams: Datagrams {
                contents: Bytes::from_static(b"denied"),
                segment_size: None,
                ecn: None,
            },
        });
        let mut data = [0u8; 128];
        let mut bufs = [io::IoSliceMut::new(&mut data)];
        let mut metas = [noq_udp::RecvMeta::default()];
        let mut infos = [RecvInfo::from_addr(
            ("https://unused.invalid/".parse::<RelayUrl>().unwrap(), peer).into(),
        )];
        assert!(
            transport
                .poll_recv(&mut cx, &mut bufs, &mut metas, &mut infos)
                .is_pending()
        );
        assert!(transport.pending_item.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn progress_is_made_for_large_segment_size_datagram_batch() {
        let mut transport = test_relay_transport();

        let url = staging::default_na_east_relay().url;
        let src = EndpointId::from_bytes(&[3u8; 32]).unwrap();

        // Fat datagram batch with segment size larger than the buffer
        let datagrams = Datagrams {
            ecn: None,
            segment_size: NonZeroU16::new(2000),
            contents: Bytes::from(vec![0u8; 4000]),
        };

        transport.pending_item = Some(RelayRecvDatagram {
            url,
            src,
            datagrams,
        });

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);

        // Deliberately smaller than the 2000-byte segment size above
        let mut storage = [0u8; 1500];
        let mut metas = [noq_udp::RecvMeta::default()];
        let mut recv_infos = [RecvInfo::default()];

        let mut progressed = false;
        // progress does not need to be immediate but within a reasonable number of iterations
        for _ in 0..10 {
            let mut bufs = [io::IoSliceMut::new(&mut storage)];
            match transport.poll_recv(&mut cx, &mut bufs, &mut metas, &mut recv_infos) {
                Poll::Ready(Ok(_)) | Poll::Pending => {}
                Poll::Ready(Err(err)) => panic!("poll_recv failed: {err}"),
            }
            if transport.pending_item.is_none() {
                progressed = true;
                break;
            }
        }

        assert!(progressed, "poll_recv made no progress on batch too large");
    }
}
