//! Presets allow configuring an endpoint quickly with a chosen set of defaults.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(with_crypto_provider)]
//! # {
//! # async fn wrapper() -> n0_error::Result {
//! use iroh::{Endpoint, RelayMode, Watcher, endpoint::presets};
//!
//! let endpoint = Endpoint::builder(presets::N0).bind().await?;
//! # let _ = endpoint;
//! # Ok(())
//! # }
//! # }
//! ```

use crate::endpoint::Builder;

/// A reusable bundle of endpoint [`Builder`] configuration.
pub trait Preset {
    /// Applies the configuration to the passed in [`Builder`].
    fn apply(self, builder: Builder) -> Builder;
}

/// An empty preset that doesn't set anything on the builder.
///
/// This doesn't set mandatory builder options, so using this in
/// `Endpoint::bind(presets::Empty)` will always fail.
///
/// However, it can be useful, if you want control over all mandatory options
/// yourself, by using `Endpoint::builder(presets::Empty)`.
///
/// If you prefer a minimal version that is guaranteed to work, see the
/// [`Minimal`] preset.
#[derive(Debug, Copy, Clone, Default)]
pub struct Empty;

impl Preset for Empty {
    fn apply(self, builder: Builder) -> Builder {
        builder
    }
}

/// A preset that is almost empty, besides setting mandatory options.
///
/// At the moment the only mandatory option to set on the endpoint builder is
/// [`Builder::crypto_provider`]. This preset makes a choice for that based on
/// the current set of enabled features in iroh, which is why it's only available
/// with the `tls-ring` or `tls-aws-lc-rs` feature flag.
///
/// It uses either [ring] or [aws-lc-rs], depending on which feature is enabled
/// on iroh (preferring ring if both are enabled).
///
/// [ring]: rustls::crypto::ring::default_provider
/// [aws-lc-rs]: rustls::crypto::aws_lc_rs::default_provider
#[cfg(with_crypto_provider)]
#[derive(Debug, Copy, Clone, Default)]
pub struct Minimal;

#[cfg(with_crypto_provider)]
impl Preset for Minimal {
    fn apply(self, mut builder: Builder) -> Builder {
        use std::sync::Arc;

        #[cfg(feature = "tls-ring")]
        {
            builder = builder.crypto_provider(Arc::new(rustls::crypto::ring::default_provider()));
        }

        #[cfg(all(feature = "tls-aws-lc-rs", not(feature = "tls-ring")))]
        {
            builder =
                builder.crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        }

        builder
    }
}

/// Configures a Commons endpoint for caller-supplied discovery and relays.
///
/// This selects the same crypto provider as [`Minimal`] and removes all previously
/// configured address lookups and relay transports, including those from [`N0`].
/// Explicit identity, ALPNs, IP binds and other builder options are preserved.
/// Apply this preset **before** adding custom lookups, relays or a crypto provider;
/// applying it afterward removes or replaces those settings too.
///
/// No discovery service, hosted relay address, chain client or signer is installed.
/// The caller supplies Commons-aware lookup services and relay configuration using
/// the native builder methods. Until then, connections need addressing information
/// supplied by the caller. Endpoint binding does not wait for chain readiness.
///
/// Available with the `tls-ring` or `tls-aws-lc-rs` feature, like [`Minimal`].
///
/// ```
/// use iroh::{Endpoint, address_lookup::memory::MemoryLookup, endpoint::presets};
///
/// let _builder = Endpoint::builder(presets::dw()).address_lookup(MemoryLookup::new());
/// ```
#[cfg(with_crypto_provider)]
pub fn dw() -> impl Preset {
    Dw
}

#[cfg(with_crypto_provider)]
#[derive(Debug, Copy, Clone)]
struct Dw;

#[cfg(with_crypto_provider)]
impl Preset for Dw {
    fn apply(self, builder: Builder) -> Builder {
        Minimal
            .apply(builder)
            .clear_address_lookup()
            .relay_mode(crate::RelayMode::Disabled)
    }
}

/// Configures the endpoint to use the n0 defaults
///
/// Currently this consists of
/// - the DNS Address Lookup service.
/// - the default relay servers provided by Number 0.
/// - setting the [`rustls::crypto::CryptoProvider`] to [ring] or [aws-lc-rs], depending
///   on which feature is enabled in iroh (preferring ring if both are enabled).
///
/// Due to the last point, this preset is only available with the `tls-ring` or
/// `tls-aws-lc-rs` feature enabled.
/// If you want to set your own crypto provider, we recommend copying the
/// implementation of this preset into your own and setting the appropriate crypto
/// provider there.
///
/// The default address lookup service publishes to and resolves from the
/// n0.computer dns server `iroh.link`.
///
/// This is equivalent to adding a [`crate::address_lookup::PkarrPublisher`],
/// a [`crate::address_lookup::PkarrResolver`], and (outside browsers) a
/// [`crate::address_lookup::DnsAddressLookup`], all configured to use the
/// n0.computer dns server.
///
/// This will by default use [`N0_DNS_PKARR_RELAY_PROD`].
/// When in tests, or when the `test-utils` feature is enabled, this will use the
/// [`N0_DNS_PKARR_RELAY_STAGING`].
///
/// [ring]: rustls::crypto::ring::default_provider
/// [aws-lc-rs]: rustls::crypto::aws_lc_rs::default_provider
/// [`N0_DNS_PKARR_RELAY_PROD`]: crate::address_lookup::N0_DNS_PKARR_RELAY_PROD
/// [`N0_DNS_PKARR_RELAY_STAGING`]: crate::address_lookup::N0_DNS_PKARR_RELAY_STAGING
#[cfg(with_crypto_provider)]
#[derive(Debug, Copy, Clone, Default)]
pub struct N0;

#[cfg(with_crypto_provider)]
impl Preset for N0 {
    fn apply(self, mut builder: Builder) -> Builder {
        use crate::{
            address_lookup::{PkarrPublisher, PkarrResolver},
            endpoint::default_relay_mode,
        };

        builder = Minimal.apply(builder);

        builder = builder.address_lookup(PkarrPublisher::n0_dns());

        // Resolve using HTTPS requests to our DNS server's /pkarr path.
        builder = builder.address_lookup(PkarrResolver::n0_dns());

        // Additionally resolve using DNS queries outside browsers.
        #[cfg(not(wasm_browser))]
        {
            builder = builder.address_lookup(crate::address_lookup::DnsAddressLookup::n0_dns());
        }

        builder = builder.relay_mode(default_relay_mode());

        builder
    }
}

/// Configures the endpoint to use the n0 defaults, but with relay mode disabled.
///
/// Currently this consists of
/// - setting `RelayMode::Disabled`
/// - the DNS Address Lookup service, that publishes IP addresses rather than
///   relay urls.
/// - setting the [`rustls::crypto::CryptoProvider`] to [ring] or [aws-lc-rs], depending
///   on which feature is enabled in iroh (preferring ring if both are enabled).
///
/// Due to the last point, this preset is only available with the `tls-ring` or
/// `tls-aws-lc-rs` feature enabled.
/// If you want to set your own crypto provider, we recommend copying the
/// implementation of this preset into your own and setting the appropriate crypto
/// provider there.
///
/// The default address lookup service publishes to and resolves from the
/// n0.computer dns server `iroh.link`.
///
/// This is equivalent to adding a [`crate::address_lookup::PkarrPublisher`],
/// a [`crate::address_lookup::PkarrResolver`], and (outside browsers) a
/// [`crate::address_lookup::DnsAddressLookup`], all configured to use the
/// n0.computer dns server.
///
/// This will by default use [`N0_DNS_PKARR_RELAY_PROD`].
/// When in tests, or when the `test-utils` feature is enabled, this will use the
/// [`N0_DNS_PKARR_RELAY_STAGING`].
///
/// [ring]: rustls::crypto::ring::default_provider
/// [aws-lc-rs]: rustls::crypto::aws_lc_rs::default_provider
/// [`N0_DNS_PKARR_RELAY_PROD`]: crate::address_lookup::N0_DNS_PKARR_RELAY_PROD
/// [`N0_DNS_PKARR_RELAY_STAGING`]: crate::address_lookup::N0_DNS_PKARR_RELAY_STAGING
#[cfg(with_crypto_provider)]
#[derive(Debug, Copy, Clone, Default)]
pub struct N0DisableRelay;

#[cfg(with_crypto_provider)]
impl Preset for N0DisableRelay {
    fn apply(self, builder: Builder) -> Builder {
        use crate::RelayMode;

        N0.apply(builder).relay_mode(RelayMode::Disabled)
    }
}

#[cfg(all(test, with_crypto_provider))]
mod commons_tests {
    use super::*;
    use crate::{
        RelayMap, RelayMode, RelayUrl, SecretKey, address_lookup::memory::MemoryLookup,
        socket::transports::TransportConfig,
    };

    #[test]
    fn fresh_dw_has_crypto_without_lookup_or_relay_defaults() {
        let builder = Builder::new(dw());
        assert!(builder.crypto_provider.is_some());
        assert!(builder.address_lookup.is_empty());
        assert!(
            builder
                .transports
                .iter()
                .all(|transport| !matches!(transport, TransportConfig::Relay { .. }))
        );
        #[cfg(not(wasm_browser))]
        assert_eq!(ip_configs(&builder), ip_configs(&Builder::empty()));
    }

    #[cfg(not(wasm_browser))]
    fn ip_configs(builder: &Builder) -> Vec<(crate::socket::transports::IpConfig, bool)> {
        builder
            .transports
            .iter()
            .filter_map(|transport| match transport {
                TransportConfig::Ip {
                    config,
                    is_user_defined,
                } => Some((*config, *is_user_defined)),
                _ => None,
            })
            .collect()
    }

    #[cfg(not(wasm_browser))]
    #[test]
    fn dw_clears_n0_but_preserves_identity_alpns_and_ip_binds() {
        let key = SecretKey::from_bytes(&[27; 32]);
        let identity = key.public();
        let alpns = vec![b"commons/test/2".to_vec(), b"commons/test/1".to_vec()];
        let builder = Builder::new(N0)
            .secret_key(key)
            .alpns(alpns.clone())
            .clear_ip_transports()
            .bind_addr("127.0.0.1:34567")
            .unwrap()
            .bind_addr("[::1]:34568")
            .unwrap();
        let original_ip_configs = ip_configs(&builder);
        assert!(!builder.address_lookup.is_empty());
        assert!(
            builder
                .transports
                .iter()
                .any(|transport| matches!(transport, TransportConfig::Relay { .. }))
        );

        let builder = builder.preset(dw());
        assert!(builder.address_lookup.is_empty());
        assert!(
            builder
                .transports
                .iter()
                .all(|transport| !matches!(transport, TransportConfig::Relay { .. }))
        );
        assert_eq!(
            builder.secret_key.as_ref().map(SecretKey::public),
            Some(identity)
        );
        assert_eq!(builder.alpn_protocols, alpns);
        assert_eq!(ip_configs(&builder), original_ip_configs);
    }

    #[test]
    fn dw_resets_custom_services_and_allows_later_overrides() {
        let url: RelayUrl = "https://relay.example.invalid".parse().unwrap();
        let relays: RelayMap = [url.clone()].into_iter().collect();
        let builder = Builder::new(Minimal)
            .address_lookup(MemoryLookup::new())
            .relay_mode(RelayMode::Custom(relays.clone()))
            .preset(dw());
        assert!(builder.address_lookup.is_empty());
        assert!(
            builder
                .transports
                .iter()
                .all(|transport| !matches!(transport, TransportConfig::Relay { .. }))
        );

        let builder = builder
            .address_lookup(MemoryLookup::new())
            .relay_mode(RelayMode::Custom(relays));
        assert_eq!(builder.address_lookup.len(), 1);
        let maps: Vec<_> = builder
            .transports
            .iter()
            .filter_map(|transport| match transport {
                TransportConfig::Relay { relay_map, .. } => Some(relay_map),
                _ => None,
            })
            .collect();
        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0].urls::<Vec<_>>(), vec![url]);
    }
}
