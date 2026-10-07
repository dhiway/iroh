//! DNS endpoint discovery for iroh

use iroh_base::EndpointId;
use iroh_dns::dns::DnsResolver;
pub use iroh_dns::dns::{N0_DNS_ENDPOINT_ORIGIN_PROD, N0_DNS_ENDPOINT_ORIGIN_STAGING};
use n0_future::boxed::BoxStream;
use tracing::{Instrument, debug, debug_span, trace};

use crate::{
    Endpoint,
    address_lookup::{
        AddressLookup, AddressLookupBuilder, AddressLookupBuilderError,
        Error as AddressLookupError, Item as AddressLookupItem,
    },
    endpoint::force_staging_infra,
};

/// Delays after which additional DNS lookup calls are issued.
///
/// Each query has its own timeout of 3s. This means that a lookup will finally
/// abort after 6 seconds.
pub(crate) const DNS_STAGGERING_MS: &[u64] = &[200, 300, 600, 1000, 2000, 3000];

/// DNS endpoint discovery
///
/// When asked to resolve a [`EndpointId`], this service performs a lookup in the Domain Name System (DNS).
///
/// By default, it uses the [`Endpoint`]'s DNS resolver to query for `TXT` records under the domain
/// `_iroh.<z32-endpoint-id>.<origin-domain>`:
///
/// * `_iroh`: is the record name
/// * `<z32-endpoint-id>` is the [`EndpointId`] encoded in [`z-base-32`] format
/// * `<origin-domain>` is the endpoint origin domain as set in [`DnsAddressLookup::builder`].
///
/// [`Self::cmns_builder`] explicitly selects `_cmns` instead, without fallback.
///
/// Each TXT record returned from the query is expected to contain a string in the format `<name>=<value>`.
/// If a TXT record contains multiple character strings, they are concatenated first.
/// The supported attributes are:
/// * `relay=<url>`: The URL of the home relay server of the endpoint
///
/// The DNS resolver defaults to using the nameservers configured on the host system, but can be changed
/// with [`crate::endpoint::Builder::dns_resolver`].
///
/// [`z-base-32`]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
/// [`Endpoint`]: crate::Endpoint
#[derive(Debug)]
pub struct DnsAddressLookup {
    origin_domain: String,
    dns_resolver: DnsResolver,
    commons: bool,
}

/// Builder for [`DnsAddressLookup`].
///
/// See [`DnsAddressLookup::builder`].
#[derive(Debug)]
pub struct DnsAddressLookupBuilder {
    origin_domain: String,
    dns_resolver: Option<DnsResolver>,
    commons: bool,
}

impl DnsAddressLookupBuilder {
    /// Sets the DNS resolver to use.
    pub fn dns_resolver(mut self, dns_resolver: DnsResolver) -> Self {
        self.dns_resolver = Some(dns_resolver);
        self
    }

    /// Builds a [`DnsAddressLookup`] with the passed [`DnsResolver`].
    pub fn build(self) -> DnsAddressLookup {
        DnsAddressLookup {
            dns_resolver: self.dns_resolver.unwrap_or_default(),
            origin_domain: self.origin_domain,
            commons: self.commons,
        }
    }
}

impl DnsAddressLookup {
    /// Creates a [`DnsAddressLookupBuilder`] that implements [`AddressLookupBuilder`].
    pub fn builder(origin_domain: String) -> DnsAddressLookupBuilder {
        DnsAddressLookupBuilder {
            origin_domain,
            dns_resolver: None,
            commons: false,
        }
    }

    /// Creates a builder that resolves only Commons `_cmns` records at this origin.
    ///
    /// Uses the native resolver and staggering, with no `_iroh` fallback. Results
    /// supply addresses, not chain authority, freshness or access rights.
    pub fn cmns_builder(origin_domain: String) -> DnsAddressLookupBuilder {
        DnsAddressLookupBuilder {
            commons: true,
            ..Self::builder(origin_domain)
        }
    }

    /// Creates a new DNS address lookup using the `iroh.link` domain.
    ///
    /// This uses the [`N0_DNS_ENDPOINT_ORIGIN_PROD`] domain.
    ///
    /// When running with the environment variable `IROH_FORCE_STAGING_RELAYS`
    /// set to any non empty value the [`N0_DNS_ENDPOINT_ORIGIN_STAGING`] domain
    /// is used instead.
    pub fn n0_dns() -> DnsAddressLookupBuilder {
        if force_staging_infra() {
            Self::builder(N0_DNS_ENDPOINT_ORIGIN_STAGING.to_string())
        } else {
            Self::builder(N0_DNS_ENDPOINT_ORIGIN_PROD.to_string())
        }
    }
}

impl AddressLookupBuilder for DnsAddressLookupBuilder {
    fn into_address_lookup(
        mut self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        if self.dns_resolver.is_none() {
            self.dns_resolver = Some(endpoint.dns_resolver()?.clone());
        }
        Ok(self.build())
    }
}

impl AddressLookup for DnsAddressLookup {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<AddressLookupItem, AddressLookupError>>> {
        let resolver = self.dns_resolver.clone();
        let origin_domain = self.origin_domain.clone();
        let commons = self.commons;
        let span =
            debug_span!("DnsAddressLookup", lookup_id=%endpoint_id.fmt_short(), %origin_domain);
        let fut = async move {
            trace!("starting DNS lookup");
            let endpoint_info = if commons {
                resolver
                    .lookup_cmns_endpoint_by_id_staggered(
                        &endpoint_id,
                        &origin_domain,
                        DNS_STAGGERING_MS,
                    )
                    .await
            } else {
                resolver
                    .lookup_endpoint_by_id_staggered(
                        &endpoint_id,
                        &origin_domain,
                        DNS_STAGGERING_MS,
                    )
                    .await
            }
            .inspect_err(|err| debug!("DNS lookup failed: {err:#}"))
            .map_err(|e| AddressLookupError::from_err_any("dns", e))?;
            debug!(info=?endpoint_info, "DNS lookup success");
            Ok(AddressLookupItem::new(endpoint_info, "dns", None))
        }
        .instrument(span);
        let stream = n0_future::stream::once_future(fut);
        Some(Box::pin(stream))
    }
}

#[cfg(all(test, with_crypto_provider))]
mod cmns_lookup_tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use iroh_dns::dns::{BoxIter, DnsError, Resolver, TxtRecordData};
    use n0_future::{StreamExt, boxed::BoxFuture};

    use super::*;

    #[derive(Clone, Debug)]
    struct TestResolver {
        queries: Arc<Mutex<Vec<String>>>,
        active: Arc<AtomicUsize>,
    }
    impl TestResolver {
        fn new() -> Self {
            Self {
                queries: Arc::default(),
                active: Arc::default(),
            }
        }
    }
    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    impl Resolver for TestResolver {
        fn lookup_ipv4(&self, _: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
            Box::pin(async { panic!("unexpected IPv4 lookup") })
        }
        fn lookup_ipv6(&self, _: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
            Box::pin(async { panic!("unexpected IPv6 lookup") })
        }
        fn lookup_txt(&self, host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
            self.queries.lock().unwrap().push(host.clone());
            self.active.fetch_add(1, Ordering::SeqCst);
            let active = Active(self.active.clone());
            Box::pin(async move {
                let _active = active;
                if host.ends_with("pending.example") {
                    std::future::pending::<()>().await;
                }
                if host.ends_with("error.example") {
                    return Err(n0_error::e!(DnsError::NoResponse));
                }
                let value = if host.ends_with("empty.example") {
                    None
                } else if host.ends_with("invalid.example") {
                    Some("addr=invalid")
                } else if host.ends_with("malformed.example") {
                    Some("unknown=value")
                } else if host.starts_with("_cmns.") {
                    Some("addr=127.0.0.1:2002")
                } else {
                    Some("addr=127.0.0.1:1001")
                };
                let records: Vec<TxtRecordData> = value
                    .into_iter()
                    .map(|v| {
                        [v.as_bytes().to_vec().into_boxed_slice()]
                            .into_iter()
                            .collect()
                    })
                    .collect();
                Ok(Box::new(records.into_iter()) as BoxIter<TxtRecordData>)
            })
        }
        fn clear_cache(&self) {}
        fn reset(&self) -> Box<dyn Resolver> {
            Box::new(self.clone())
        }
    }

    #[tokio::test]
    async fn cmns_dns_resolve_selects_namespace_and_preserves_native_results() {
        let resolver = TestResolver::new();
        let id = crate::SecretKey::from_bytes(&[7; 32]).public();
        for (commons, port) in [(false, 1001), (true, 2002)] {
            let builder = if commons {
                DnsAddressLookup::cmns_builder("records.example".into())
            } else {
                DnsAddressLookup::builder("records.example".into())
            };
            let lookup = builder
                .dns_resolver(DnsResolver::custom(resolver.clone()))
                .build();
            let mut stream = lookup.resolve(id).unwrap();
            let item = stream.next().await.unwrap().unwrap();
            assert_eq!(item.endpoint_id(), id);
            assert_eq!(
                item.endpoint_info().addrs().cloned().collect::<Vec<_>>(),
                vec![iroh_base::TransportAddr::Ip(
                    format!("127.0.0.1:{port}").parse().unwrap()
                )]
            );
            assert_eq!(item.provenance(), "dns");
            assert!(stream.next().await.is_none());
        }
        assert_eq!(
            *resolver.queries.lock().unwrap(),
            vec![
                format!("_iroh.{}.records.example", id.to_z32()),
                format!("_cmns.{}.records.example", id.to_z32())
            ]
        );
        for (origin, succeeds) in [
            ("empty.example", true),
            ("invalid.example", true),
            ("malformed.example", false),
            ("error.example", false),
        ] {
            let lookup = DnsAddressLookup::cmns_builder(origin.into())
                .dns_resolver(DnsResolver::custom(resolver.clone()))
                .build();
            let mut stream = lookup.resolve(id).unwrap();
            let result = stream.next().await.unwrap();
            assert_eq!(result.is_ok(), succeeds, "{origin}: {result:?}");
            if let Ok(item) = result {
                assert_eq!(item.endpoint_info().addrs().count(), 0);
            }
            assert!(stream.next().await.is_none());
        }
        assert_eq!(resolver.active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cmns_dns_inherits_resolver_unless_explicit_and_drop_cancels_staggering() {
        let inherited = TestResolver::new();
        let explicit = TestResolver::new();
        let endpoint = Endpoint::builder(crate::endpoint::presets::dw())
            .dns_resolver(DnsResolver::custom(inherited.clone()))
            .portmapper_config(crate::endpoint::PortmapperConfig::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let test_endpoint = endpoint.clone();
        let test_inherited = inherited.clone();
        let test_explicit = explicit.clone();
        let result = tokio::spawn(async move {
            let id = crate::SecretKey::from_bytes(&[8; 32]).public();
            let lookup = DnsAddressLookup::cmns_builder("records.example".into())
                .into_address_lookup(&test_endpoint)
                .unwrap();
            assert!(lookup.resolve(id).unwrap().next().await.unwrap().is_ok());
            let lookup = DnsAddressLookup::cmns_builder("records.example".into())
                .dns_resolver(DnsResolver::custom(test_explicit.clone()))
                .into_address_lookup(&test_endpoint)
                .unwrap();
            assert!(lookup.resolve(id).unwrap().next().await.unwrap().is_ok());
            assert_eq!(test_inherited.queries.lock().unwrap().len(), 1);
            assert_eq!(test_explicit.queries.lock().unwrap().len(), 1);
            let pending = DnsAddressLookup::cmns_builder("pending.example".into())
                .dns_resolver(DnsResolver::custom(test_explicit.clone()))
                .build();
            let mut stream = pending.resolve(id).unwrap();
            // Keep the lookup pending long enough for native staggered calls to begin.
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(450), stream.next())
                    .await
                    .is_err()
            );
            assert!(test_explicit.active.load(Ordering::SeqCst) >= 2);
            let query_count = test_explicit.queries.lock().unwrap().len();
            drop(stream);
            assert_eq!(test_explicit.active.load(Ordering::SeqCst), 0);
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            assert_eq!(test_explicit.queries.lock().unwrap().len(), query_count);
        })
        .await;
        endpoint.close().await;
        result.unwrap();
    }
}
