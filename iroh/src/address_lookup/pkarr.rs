//! An address lookup service which publishes and resolves endpoint information using a [pkarr] relay.
//!
//! Public-Key Addressable Resource Records, [pkarr], is a system which allows publishing
//! [DNS Resource Records] owned by a particular [`SecretKey`] under a name derived from its
//! corresponding [`PublicKey`], also known as the [`EndpointId`].  Additionally this pkarr
//! Resource Record is signed using the same [`SecretKey`], ensuring authenticity of the
//! record.
//!
//! Pkarr normally stores these records on the [Mainline DHT], but also provides two bridges
//! that do not require clients to directly interact with the DHT:
//!
//! - Resolvers are servers which expose the pkarr Resource Record under a domain name,
//!   e.g. `o3dks..6uyy.dns.iroh.link`.  This allows looking up the pkarr Resource Records
//!   using normal DNS clients.  These resolvers would normally perform lookups on the
//!   Mainline DHT augmented with a local cache to improve performance.
//!
//! - Relays are servers which allow both publishing and looking up of the pkarr Resource
//!   Records using HTTP PUT and GET requests.  They will usually perform the publishing to
//!   the Mainline DHT on behalf on the client as well as cache lookups performed on the DHT
//!   to improve performance.
//!
//! [`PkarrPublisher`] filters published addresses: only relay addresses are published by default.
//! To change this behavior, use [`PkarrPublisherBuilder::addr_filter`] and set it to e.g. [`AddrFilter::unfiltered`].
//! This can be useful to enable publishing IP addresses if the iroh endpoint is reachable via public
//! IP addresses.
//!
//! For address lookup in iroh the pkarr Resource Records contain the addressing information,
//! providing endpoints which retrieve the pkarr Resource Record with enough detail
//! to contact the iroh endpoint.
//!
//! There are several Address Lookup's built on top of pkarr, which can be composed
//! to the application's needs:
//!
//! - [`PkarrPublisher`], which publishes to a pkarr relay server using HTTP.
//!
//! - [`PkarrResolver`], which resolves from a pkarr relay server using HTTP.
//!
//! - [`address_lookup::DnsAddressLookup`], which resolves from a DNS server.
//!
//! Mainline-DHT-based pkarr publishing/lookup lives in the
//! [`iroh-mainline-address-lookup`] crate.
//!
//! [`iroh-mainline-address-lookup`]: https://docs.rs/iroh-mainline-address-lookup
//! [pkarr]: https://pkarr.org
//! [DNS Resource Records]: https://en.wikipedia.org/wiki/Domain_Name_System#Resource_records
//! [Mainline DHT]: https://en.wikipedia.org/wiki/Mainline_DHT
//! [`SecretKey`]: crate::SecretKey
//! [`PublicKey`]: crate::PublicKey
//! [`EndpointId`]: crate::EndpointId
//! [`address_lookup::DnsAddressLookup`]: crate::address_lookup::DnsAddressLookup
//! [`N0` preset]: crate::endpoint::presets::N0
//! [`AddrFilter`]: crate::address_lookup::AddrFilter
//! [`AddrFilter::relay_only`]: crate::address_lookup::AddrFilter::relay_only
//! [`AddrFilter::unfiltered`]: crate::address_lookup::AddrFilter::unfiltered
//! [`PkarrPublisherBuilder::addr_filter`]: PkarrPublisherBuilder::addr_filter

use std::sync::Arc;

use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_dns::{
    EncodingError,
    endpoint_info::{AddrFilter, EndpointInfo},
    pkarr::{SignedPacket, SignedPacketVerifyError},
};
use n0_error::{AnyError, anyerr, e, stack_error};
use n0_future::{
    boxed::BoxStream,
    task::{self, AbortOnDropHandle},
    time::{self, Duration, Instant},
};
use n0_watcher::{Disconnected, Watchable, Watcher as _};
use tracing::{Instrument, debug, info_span, trace, warn};
use url::Url;

#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
use crate::{
    Endpoint,
    address_lookup::{
        AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, EndpointData,
        Error as AddressLookupError, Item as AddressLookupItem,
    },
    endpoint::force_staging_infra,
    util::reqwest_client_builder,
};

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum PkarrError {
    #[error("Invalid public key")]
    PublicKey {
        #[error(std_err)]
        source: iroh_base::KeyParsingError,
    },
    #[error("Packet failed to verify")]
    Verify {
        #[error(std_err)]
        source: SignedPacketVerifyError,
    },
    #[error("Invalid relay URL")]
    InvalidRelayUrl { url: RelayUrl },
    #[error("Error sending http request")]
    HttpSend { source: AnyError },
    #[error("Error resolving http request")]
    HttpRequest { status: http::StatusCode },
    #[error("Http payload error")]
    HttpPayload { source: AnyError },
    #[error("EncodingError")]
    Encoding { source: EncodingError },
}

impl From<PkarrError> for AddressLookupError {
    fn from(err: PkarrError) -> Self {
        AddressLookupError::from_err_any("pkarr", err)
    }
}

/// The production pkarr relay run by [number 0].
///
/// This server is both a pkarr relay server as well as a DNS resolver, see the [module
/// documentation].  However it does not interact with the Mainline DHT, so is a more
/// central service.  It is a reliable service to use for address lookup.
///
/// [number 0]: https://n0.computer
/// [module documentation]: crate::address_lookup::pkarr
pub const N0_DNS_PKARR_RELAY_PROD: &str = "https://dns.iroh.link/pkarr";
/// The testing pkarr relay run by [number 0].
///
/// This server operates similarly to [`N0_DNS_PKARR_RELAY_PROD`] but is not as reliable.
/// It is meant for more experimental use and testing purposes.
///
/// [number 0]: https://n0.computer
pub const N0_DNS_PKARR_RELAY_STAGING: &str = "https://staging-dns.iroh.link/pkarr";

/// Default TTL for the records in the pkarr signed packet.
///
/// The Time To Live (TTL) tells DNS caches how long to store a record. It is ignored by the
/// `iroh-dns-server`, e.g. as running on [`N0_DNS_PKARR_RELAY_PROD`], as the home server
/// keeps the records for the domain. When using the pkarr relay no DNS is involved and the
/// setting is ignored.
// TODO(flub): huh?
pub const DEFAULT_PKARR_TTL: u32 = 30;

/// Interval in which to republish the endpoint info even if unchanged: 5 minutes.
pub const DEFAULT_REPUBLISH_INTERVAL: Duration = Duration::from_secs(60 * 5);

/// Builder for [`PkarrPublisher`].
///
/// See [`PkarrPublisher::builder`].
#[derive(Debug)]
pub struct PkarrPublisherBuilder {
    pkarr_relay: Url,
    ttl: u32,
    republish_interval: Duration,
    filter: AddrFilter,
    #[cfg(not(wasm_browser))]
    dns_resolver: Option<DnsResolver>,
    /// Taken from the endpoint in `into_address_lookup`.
    #[cfg(not(wasm_browser))]
    proxy_url: Option<Url>,
}

impl PkarrPublisherBuilder {
    /// See [`PkarrPublisher::builder`].
    fn new(pkarr_relay: Url) -> Self {
        Self {
            pkarr_relay,
            ttl: DEFAULT_PKARR_TTL,
            republish_interval: DEFAULT_REPUBLISH_INTERVAL,
            filter: AddrFilter::relay_only(),
            #[cfg(not(wasm_browser))]
            dns_resolver: None,
            #[cfg(not(wasm_browser))]
            proxy_url: None,
        }
    }

    /// See [`PkarrPublisher::n0_dns`].
    fn n0_dns() -> Self {
        let pkarr_relay = match force_staging_infra() {
            true => N0_DNS_PKARR_RELAY_STAGING,
            false => N0_DNS_PKARR_RELAY_PROD,
        };

        let pkarr_relay: Url = pkarr_relay.parse().expect("url is valid");
        Self::new(pkarr_relay)
    }

    /// Sets the TTL (time-to-live) for published packets.
    ///
    /// Default is [`DEFAULT_PKARR_TTL`].
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    /// Sets the interval after which packets are republished even if our endpoint info did not change.
    ///
    /// Default is [`DEFAULT_REPUBLISH_INTERVAL`].
    pub fn republish_interval(mut self, republish_interval: Duration) -> Self {
        self.republish_interval = republish_interval;
        self
    }

    /// Sets the DNS resolver to use for resolving the pkarr relay URL.
    #[cfg(not(wasm_browser))]
    pub fn dns_resolver(mut self, dns_resolver: DnsResolver) -> Self {
        self.dns_resolver = Some(dns_resolver);
        self
    }

    /// Sets the address filter to control which addresses are published to the pkarr server.
    ///
    /// By default [`AddrFilter::relay_only`] is used. This avoids leaking IP addresses to the
    /// public pkarr server.
    ///
    /// However, enabling IP address publishing can be useful, e.g. when iroh runs on a machine
    /// connected to the internet via public IP addresses without a firewall.
    /// In such cases, publishing them can make dialing such endpoints via DNS or Pkarr lookup
    /// faster, potentially skipping a relay connection altogether.
    pub fn addr_filter(mut self, filter: AddrFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Builds the [`PkarrPublisher`] with the passed secret key for signing packets.
    ///
    /// This publisher will be able to publish [pkarr](https://pkarr.org) records for [`SecretKey`].
    pub fn build(self, secret_key: SecretKey, tls_config: rustls::ClientConfig) -> PkarrPublisher {
        #[cfg(wasm_browser)]
        let pkarr_client = PkarrRelayClient::new(self.pkarr_relay);

        #[cfg(not(wasm_browser))]
        let pkarr_client = PkarrRelayClient::with_proxy(
            self.pkarr_relay,
            tls_config,
            self.dns_resolver.unwrap_or_default(),
            self.proxy_url,
        );

        PkarrPublisher::new(
            secret_key,
            pkarr_client,
            self.ttl,
            self.republish_interval,
            self.filter,
        )
    }
}

impl AddressLookupBuilder for PkarrPublisherBuilder {
    fn into_address_lookup(
        mut self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        #[cfg(not(wasm_browser))]
        if self.dns_resolver.is_none() {
            self.dns_resolver = Some(endpoint.dns_resolver()?.clone());
        }
        #[cfg(not(wasm_browser))]
        {
            self.proxy_url = endpoint.proxy_url().cloned();
        }
        let tls_config = endpoint.tls_config().clone();
        Ok(self.build(endpoint.secret_key().clone(), tls_config))
    }
}

/// Publisher of address lookup information to a [pkarr] relay.
///
/// This publisher uses HTTP to publish address lookup information to a pkarr relay
/// server, see the [module docs] for details.
///
/// This implements the [`AddressLookup`] trait to be used as an address lookup service.  Note
/// that it only publishes address lookup information, for the corresponding resolver use
/// the [`PkarrResolver`] together with [`AddressLookupServices`].
///
/// By default this publisher only publishes the [`RelayUrl`], to avoid leaking IP addresses to
/// the public pkarr server.  Which addresses are published is controlled by the [`AddrFilter`]
/// set via [`PkarrPublisherBuilder::addr_filter`].
///
/// [pkarr]: https://pkarr.org
/// [module docs]: crate::address_lookup::pkarr
/// [`RelayUrl`]: crate::RelayUrl
/// [`AddressLookupServices`]: super::AddressLookupServices
#[derive(derive_more::Debug, Clone)]
pub struct PkarrPublisher {
    endpoint_id: EndpointId,
    watchable: Watchable<Option<EndpointInfo>>,
    addr_filter: AddrFilter,
    _drop_guard: Arc<AbortOnDropHandle<()>>,
}

impl PkarrPublisher {
    /// Returns a [`PkarrPublisherBuilder`] that publishes endpoint info to a [pkarr] relay at `pkarr_relay`.
    ///
    /// If no further options are set, the pkarr publisher will use [`DEFAULT_PKARR_TTL`] as the
    /// time-to-live value for the published packets, and it will republish Address Lookup information
    /// every [`DEFAULT_REPUBLISH_INTERVAL`], even if the information is unchanged.
    ///
    /// [`PkarrPublisherBuilder`] implements [`AddressLookupBuilder`], so it can be passed to [`address_lookup`].
    /// It will then use the endpoint's secret key to sign published packets.
    ///
    /// [`address_lookup`]:  crate::endpoint::Builder::address_lookup
    /// [pkarr]: https://pkarr.org
    pub fn builder(pkarr_relay: Url) -> PkarrPublisherBuilder {
        PkarrPublisherBuilder::new(pkarr_relay)
    }

    /// Creates a new [`PkarrPublisher`] with a custom TTL and republish intervals.
    ///
    /// This allows creating the publisher with custom time-to-live values of the
    /// [`SignedPacket`]s as well as a custom republish interval.
    fn new(
        secret_key: SecretKey,
        pkarr_client: PkarrRelayClient,
        ttl: u32,
        republish_interval: Duration,
        addr_filter: AddrFilter,
    ) -> Self {
        debug!(
            "creating pkarr publisher that publishes to {}",
            pkarr_client.pkarr_relay_url
        );
        let endpoint_id = secret_key.public();

        let watchable = Watchable::default();
        let service = PublisherService {
            ttl,
            watcher: watchable.watch(),
            secret_key,
            pkarr_client,
            republish_interval,
        };
        let join_handle = task::spawn(service.run().instrument(info_span!("pkarr_publish")));
        Self {
            watchable,
            endpoint_id,
            addr_filter,
            _drop_guard: Arc::new(AbortOnDropHandle::new(join_handle)),
        }
    }

    /// Creates a pkarr publisher which uses the [number 0] pkarr relay server.
    ///
    /// This uses the pkarr relay server operated by [number 0], at
    /// [`N0_DNS_PKARR_RELAY_PROD`].
    ///
    /// When running with the environment variable
    /// `IROH_FORCE_STAGING_RELAYS` set to any non empty value [`N0_DNS_PKARR_RELAY_STAGING`]
    /// server is used instead.
    ///
    /// [number 0]: https://n0.computer
    pub fn n0_dns() -> PkarrPublisherBuilder {
        PkarrPublisherBuilder::n0_dns()
    }

    /// Publishes the addressing information about this endpoint to a pkarr relay.
    ///
    /// This is a nonblocking function, the actual update is performed in the background.
    pub fn update_endpoint_data(&self, data: &EndpointData) {
        let data = data.apply_filter(&self.addr_filter).into_owned();
        let info = EndpointInfo::from_parts(self.endpoint_id, data);
        self.watchable.set(Some(info)).ok();
    }
}

impl AddressLookup for PkarrPublisher {
    fn publish(&self, data: &EndpointData) {
        self.update_endpoint_data(data);
    }
}

/// Publish endpoint info to a pkarr relay.
#[derive(derive_more::Debug, Clone)]
struct PublisherService {
    #[debug("SecretKey")]
    secret_key: SecretKey,
    #[debug("PkarrClient")]
    pkarr_client: PkarrRelayClient,
    watcher: n0_watcher::Direct<Option<EndpointInfo>>,
    ttl: u32,
    republish_interval: Duration,
}

impl PublisherService {
    async fn run(mut self) {
        let mut failed_attempts = 0;
        let republish = time::sleep(Duration::MAX);
        tokio::pin!(republish);
        loop {
            if !self.watcher.is_connected() {
                break;
            }
            if let Some(info) = self.watcher.get() {
                match self.publish_current(info).await {
                    Err(err) => {
                        failed_attempts += 1;
                        // Retry after increasing timeout
                        let retry_after = Duration::from_secs(failed_attempts);
                        republish.as_mut().reset(Instant::now() + retry_after);
                        warn!(
                            err = %format!("{err:#}"),
                            url = %self.pkarr_client.pkarr_relay_url ,
                            ?retry_after,
                            %failed_attempts,
                            "Failed to publish to pkarr",
                        );
                    }
                    Ok(()) => {
                        failed_attempts = 0;
                        // Republish after fixed interval
                        republish
                            .as_mut()
                            .reset(Instant::now() + self.republish_interval);
                    }
                }
            }
            // Wait until either the retry/republish timeout is reached, or the endpoint info changed.
            tokio::select! {
                res = self.watcher.updated() => match res {
                    Ok(_) => debug!("Publish endpoint info to pkarr (info changed)"),
                    Err(Disconnected { .. }) => break,
                },
                _ = &mut republish => debug!("Publish endpoint info to pkarr (interval elapsed)"),
            }
        }
    }

    async fn publish_current(&self, info: EndpointInfo) -> Result<(), PkarrError> {
        debug!(
            data = ?info.data,
            pkarr_relay = %self.pkarr_client.pkarr_relay_url,
            "Publishing endpoint info to pkarr"
        );
        let signed_packet = info
            .to_pkarr_signed_packet(&self.secret_key, self.ttl)
            .map_err(|err| e!(PkarrError::Encoding, err))?;
        self.pkarr_client.publish(&signed_packet).await?;
        trace!(
            data = ?info.data,
            pkarr_relay = %self.pkarr_client.pkarr_relay_url,
            "Published endpoint info to pkarr"
        );
        Ok(())
    }
}

/// Builder for [`PkarrResolver`].
///
/// See [`PkarrResolver::builder`].
#[derive(Debug)]
pub struct PkarrResolverBuilder {
    pkarr_relay: Url,
    commons: bool,
    #[cfg(not(wasm_browser))]
    dns_resolver: Option<DnsResolver>,
    /// Taken from the endpoint in `into_address_lookup`.
    #[cfg(not(wasm_browser))]
    proxy_url: Option<Url>,
}

impl PkarrResolverBuilder {
    /// Sets the DNS resolver to use for resolving the pkarr relay URL.
    #[cfg(not(wasm_browser))]
    pub fn dns_resolver(mut self, dns_resolver: DnsResolver) -> Self {
        self.dns_resolver = Some(dns_resolver);
        self
    }

    /// Creates a [`PkarrResolver`] from this builder.
    pub fn build(self, tls_config: rustls::ClientConfig) -> PkarrResolver {
        #[cfg(wasm_browser)]
        let pkarr_client = PkarrRelayClient::new(self.pkarr_relay);

        #[cfg(not(wasm_browser))]
        let pkarr_client = if self.commons {
            PkarrRelayClient::new_direct(
                self.pkarr_relay,
                tls_config,
                self.dns_resolver.unwrap_or_default(),
            )
        } else {
            PkarrRelayClient::with_proxy(
                self.pkarr_relay,
                tls_config,
                self.dns_resolver.unwrap_or_default(),
                self.proxy_url,
            )
        };

        PkarrResolver {
            pkarr_client,
            commons: self.commons,
        }
    }
}

impl AddressLookupBuilder for PkarrResolverBuilder {
    fn into_address_lookup(
        mut self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        #[cfg(not(wasm_browser))]
        if self.dns_resolver.is_none() {
            self.dns_resolver = Some(endpoint.dns_resolver()?.clone());
        }
        #[cfg(not(wasm_browser))]
        {
            self.proxy_url = endpoint.proxy_url().cloned();
        }
        let tls_config = endpoint.tls_config().clone();
        Ok(self.build(tls_config))
    }
}

/// Resolver of address lookup information from a [pkarr] relay.
///
/// The resolver uses HTTP to query address lookup information from a pkarr relay server,
/// see the [module docs] for details.
///
/// This implements the [`AddressLookup`] trait to be used as an address lookup service.  Note
/// that it only resolves address lookup information, for the corresponding publisher use
/// the [`PkarrPublisher`] together with [`AddressLookupServices`].
///
/// [pkarr]: https://pkarr.org
/// [module docs]: crate::address_lookup::pkarr
/// [`AddressLookupServices`]: super::AddressLookupServices
#[derive(derive_more::Debug, Clone)]
pub struct PkarrResolver {
    pkarr_client: PkarrRelayClient,
    commons: bool,
}

impl PkarrResolver {
    /// Creates a new resolver builder using the pkarr relay server at the URL.
    ///
    /// The builder implements [`AddressLookupBuilder`].
    pub fn builder(pkarr_relay: Url) -> PkarrResolverBuilder {
        PkarrResolverBuilder {
            pkarr_relay,
            commons: false,
            #[cfg(not(wasm_browser))]
            dns_resolver: None,
            #[cfg(not(wasm_browser))]
            proxy_url: None,
        }
    }

    /// Creates a builder that reads only Commons `_cmns` records from this relay.
    ///
    /// Native HTTP, TLS and requested-key signature verification are unchanged.
    /// There is no `_iroh` fallback or additional chain authority/freshness check.
    pub fn cmns_builder(pkarr_relay: Url) -> PkarrResolverBuilder {
        PkarrResolverBuilder {
            commons: true,
            ..Self::builder(pkarr_relay)
        }
    }

    /// Creates a pkarr resolver builder which uses the [number 0] pkarr relay server.
    ///
    /// This uses the pkarr relay server operated by [number 0] at
    /// [`N0_DNS_PKARR_RELAY_PROD`].
    ///
    /// When running with the environment variable `IROH_FORCE_STAGING_RELAYS`
    /// set to any non empty value [`N0_DNS_PKARR_RELAY_STAGING`]
    /// server is used instead.
    ///
    /// [number 0]: https://n0.computer
    pub fn n0_dns() -> PkarrResolverBuilder {
        let pkarr_relay = match force_staging_infra() {
            true => N0_DNS_PKARR_RELAY_STAGING,
            false => N0_DNS_PKARR_RELAY_PROD,
        };

        let pkarr_relay: Url = pkarr_relay.parse().expect("url is valid");
        Self::builder(pkarr_relay)
    }
}

impl AddressLookup for PkarrResolver {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<AddressLookupItem, AddressLookupError>>> {
        let pkarr_client = self.pkarr_client.clone();
        let commons = self.commons;
        let fut = async move {
            let signed_packet = pkarr_client.resolve(endpoint_id).await?;
            let info = if commons {
                EndpointInfo::from_cmns_pkarr_signed_packet(&signed_packet)
            } else {
                EndpointInfo::from_pkarr_signed_packet(&signed_packet)
            }
            .map_err(|err| AddressLookupError::from_err_any("pkarr", err))?;
            let item = AddressLookupItem::new(info, "pkarr", None);
            Ok(item)
        };
        let stream = n0_future::stream::once_future(fut);
        Some(Box::pin(stream))
    }
}

/// A [pkarr](https://pkarr.org) client to publish [`SignedPacket`]s to a pkarr relay.
///
/// [pkarr]: https://pkarr.org
#[derive(Debug, Clone)]
pub struct PkarrRelayClient {
    http_client: reqwest::Client,
    pkarr_relay_url: Url,
    direct: bool,
}

/// A builder for the [`PkarrRelayClient`]
#[derive(Debug, Clone)]
pub struct PkarrRelayClientBuilder {
    pkarr_relay_url: Url,
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,
    #[cfg(not(wasm_browser))]
    tls_config: rustls::ClientConfig,
}

impl PkarrRelayClientBuilder {
    /// Build a [`PkarrRelayClient`].
    pub fn build(self) -> PkarrRelayClient {
        #[cfg(not(wasm_browser))]
        let builder = reqwest_client_builder(self.tls_config, self.dns_resolver);

        #[cfg(wasm_browser)]
        let builder = reqwest_client_builder();

        let http_client = builder.build().expect("failed to create reqwest client");
        PkarrRelayClient {
            http_client,
            pkarr_relay_url: self.pkarr_relay_url,
            direct: false,
        }
    }
}

impl PkarrRelayClient {
    /// Creates a [`PkarrRelayClient`].
    #[cfg(not(wasm_browser))]
    pub fn new(
        pkarr_relay_url: Url,
        tls_config: rustls::ClientConfig,
        dns_resolver: DnsResolver,
    ) -> Self {
        Self::with_proxy(pkarr_relay_url, tls_config, dns_resolver, None)
    }

    /// Creates a [`PkarrRelayClient`] that sends its requests through `proxy_url`, if set.
    #[cfg(not(wasm_browser))]
    pub(crate) fn with_proxy(
        pkarr_relay_url: Url,
        tls_config: rustls::ClientConfig,
        dns_resolver: DnsResolver,
        proxy_url: Option<Url>,
    ) -> Self {
        let mut builder = reqwest_client_builder(tls_config, dns_resolver);
        if let Some(proxy_url) = proxy_url {
            match reqwest::Proxy::all(proxy_url.clone()) {
                Ok(proxy) => builder = builder.proxy(proxy),
                // reqwest only rejects unsupported schemes. The relay client
                // and net_report fail on such a proxy too, at connect time.
                Err(err) => warn!(%proxy_url, "ignoring invalid proxy url for pkarr: {err:#}"),
            }
        }
        let http_client = builder.build().expect("failed to create reqwest client");
        Self {
            http_client,
            pkarr_relay_url,
            direct: false,
        }
    }

    /// Creates a [`PkarrRelayClient`].
    #[cfg(wasm_browser)]
    pub fn new(pkarr_relay_url: Url) -> Self {
        let http_client = reqwest_client_builder()
            .build()
            .expect("failed to create reqwest client");
        Self {
            http_client,
            pkarr_relay_url,
            direct: false,
        }
    }

    /// Creates a native direct HTTP client for an explicitly configured service.
    ///
    /// GET and PUT never follow redirects or use ambient HTTP proxies. Native TLS,
    /// requested-key signature verification and packet decoding are unchanged.
    /// Unlike ordinary constructors, a trailing slash on the base URL is normalized
    /// before appending the endpoint key. Browser redirect/proxy enforcement is not
    /// provided; this constructor is native-only.
    #[cfg(not(wasm_browser))]
    pub fn new_direct(
        pkarr_relay_url: Url,
        tls_config: rustls::ClientConfig,
        dns_resolver: DnsResolver,
    ) -> Self {
        let http_client = reqwest_client_builder(tls_config, dns_resolver)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("failed to create reqwest client");
        Self {
            http_client,
            pkarr_relay_url,
            direct: true,
        }
    }

    fn request_url(&self, endpoint_id: &EndpointId) -> Result<Url, PkarrError> {
        let mut url = self.pkarr_relay_url.clone();
        let mut segments = url.path_segments_mut().map_err(|_| {
            e!(PkarrError::InvalidRelayUrl {
                url: self.pkarr_relay_url.clone().into()
            })
        })?;
        if self.direct {
            segments.pop_if_empty();
        }
        segments.push(&endpoint_id.to_z32());
        drop(segments);
        Ok(url)
    }

    /// Resolves a [`SignedPacket`] for the given [`EndpointId`].
    pub async fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<SignedPacket, AddressLookupError> {
        let url = self.request_url(&endpoint_id)?;

        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|err| e!(PkarrError::HttpSend, anyerr!(err)))?;

        if !response.status().is_success() {
            return Err(e!(PkarrError::HttpRequest {
                status: response.status()
            })
            .into());
        }

        let payload = response
            .bytes()
            .await
            .map_err(|err| e!(PkarrError::HttpPayload, anyerr!(err)))?;
        let packet = SignedPacket::from_relay_payload(&endpoint_id, &payload)
            .map_err(|err| e!(PkarrError::Verify, err))?;
        Ok(packet)
    }

    /// Publishes a [`SignedPacket`].
    pub async fn publish(&self, signed_packet: &SignedPacket) -> Result<(), PkarrError> {
        let url = self.request_url(&signed_packet.public_key())?;

        let response = self
            .http_client
            .put(url)
            .body(signed_packet.to_relay_payload())
            .send()
            .await
            .map_err(|err| e!(PkarrError::HttpSend, anyerr!(err)))?;

        if !response.status().is_success() {
            return Err(e!(PkarrError::HttpRequest {
                status: response.status()
            }));
        }

        Ok(())
    }
}

#[cfg(all(test, not(wasm_browser)))]
mod tests {
    use std::net::Ipv4Addr;

    use n0_error::{Result, StdResultExt};
    use n0_future::{StreamExt, task, time};
    use tokio::{io::AsyncReadExt, sync::oneshot};

    use super::*;
    use crate::endpoint::presets;

    /// Spawns a fake HTTP proxy which captures the request line of the first connection
    /// it receives and then hangs up.
    async fn capturing_proxy() -> Result<(Url, oneshot::Receiver<String>)> {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .anyerr()?;
        let url: Url = format!("http://{}", listener.local_addr().anyerr()?)
            .parse()
            .anyerr()?;
        let (tx, rx) = oneshot::channel();
        task::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while let Ok(1) = stream.read(&mut byte).await {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
            }
            tx.send(String::from_utf8_lossy(&line).trim().to_string())
                .ok();
        });
        Ok((url, rx))
    }

    /// The pkarr resolver sends its requests through the endpoint's proxy.
    #[tokio::test]
    async fn resolver_uses_endpoint_proxy() -> Result {
        let (proxy_url, request_line) = capturing_proxy().await?;
        let endpoint = Endpoint::builder(presets::Minimal)
            .proxy_url(proxy_url)
            .address_lookup(PkarrResolver::builder(
                "https://pkarr.test/pkarr".parse().anyerr()?,
            ))
            .bind()
            .await?;

        // The fake proxy never completes the tunnel, so the lookup fails. What
        // matters is that it was attempted through the proxy.
        let id = SecretKey::generate().public();
        let mut lookup = endpoint.address_lookup()?.resolve(id);
        let _ = time::timeout(Duration::from_secs(10), lookup.next()).await;

        let request_line = time::timeout(Duration::from_secs(10), request_line)
            .await
            .expect("proxy did not receive a request, the lookup bypassed it")
            .anyerr()?;
        assert!(
            request_line.starts_with("CONNECT pkarr.test:443 "),
            "proxy received: {request_line}"
        );
        endpoint.close().await;
        Ok(())
    }
}

#[cfg(all(test, not(wasm_browser), with_crypto_provider))]
mod cmns_lookup_tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use axum::{Router, routing::get};
    use iroh_dns::dns::{BoxIter, DnsError, Resolver, TxtRecordData};
    use n0_future::{StreamExt, boxed::BoxFuture};
    use simple_dns::{CLASS, Name, Packet, ResourceRecord, rdata::RData};

    use super::*;

    #[derive(Clone, Debug, Default)]
    struct LoopbackResolver(Arc<AtomicUsize>);
    impl Resolver for LoopbackResolver {
        fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
            assert!(matches!(host.as_str(), "localhost" | "profile.test"));
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(Box::new([Ipv4Addr::LOCALHOST].into_iter()) as BoxIter<Ipv4Addr>) })
        }
        fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
            assert!(matches!(host.as_str(), "localhost" | "profile.test"));
            Box::pin(async { Ok(Box::new(std::iter::empty()) as BoxIter<Ipv6Addr>) })
        }
        fn lookup_txt(&self, _: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
            Box::pin(async { panic!("unexpected TXT lookup") })
        }
        fn clear_cache(&self) {}
        fn reset(&self) -> Box<dyn Resolver> {
            Box::new(self.clone())
        }
    }

    fn signed_packet(key: &SecretKey, records: &[(&str, &str)]) -> SignedPacket {
        let mut packet = Packet::new_reply(0);
        for (label, value) in records {
            packet.answers.push(ResourceRecord::new(
                Name::new(&format!("{label}.{}", key.public().to_z32()))
                    .unwrap()
                    .into_owned(),
                CLASS::IN,
                30,
                RData::TXT((*value).try_into().unwrap()),
            ));
        }
        let encoded = packet.build_bytes_vec_compressed().unwrap();
        let timestamp = iroh_dns::pkarr::Timestamp::from_micros(1_720_000_000_000_000);
        let mut signable =
            format!("3:seqi{}e1:v{}:", timestamp.as_micros(), encoded.len()).into_bytes();
        signable.extend_from_slice(&encoded);
        let packet = SignedPacket::from_parts_unchecked(
            key.public().as_bytes(),
            &key.sign(&signable).to_bytes(),
            timestamp,
            &encoded,
        )
        .unwrap();
        SignedPacket::from_bytes(packet.as_bytes()).unwrap()
    }

    #[tokio::test]
    async fn cmns_pkarr_resolve_preserves_authentication_and_namespace_results() {
        let key = SecretKey::from_bytes(&[9; 32]);
        let mixed = signed_packet(
            &key,
            &[
                ("_iroh", "addr=127.0.0.1:1001"),
                ("_cmns", "addr=127.0.0.1:2002"),
            ],
        );
        let old_only = signed_packet(&key, &[("_iroh", "addr=127.0.0.1:1001")]);
        let bad_old = signed_packet(
            &key,
            &[("_iroh", "unknown=value"), ("_cmns", "addr=127.0.0.1:2002")],
        );
        let bad_cmns = signed_packet(
            &key,
            &[("_iroh", "addr=127.0.0.1:1001"), ("_cmns", "unknown=value")],
        );
        let invalid = signed_packet(&key, &[("_cmns", "addr=invalid")]);
        let mut tampered = mixed.to_relay_payload().to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        let mut app = Router::new();
        for (name, payload) in [
            ("mixed", mixed.to_relay_payload().to_vec()),
            ("old-only", old_only.to_relay_payload().to_vec()),
            ("bad-old", bad_old.to_relay_payload().to_vec()),
            ("bad-cmns", bad_cmns.to_relay_payload().to_vec()),
            ("invalid", invalid.to_relay_payload().to_vec()),
            ("tampered", tampered),
        ] {
            // Serve the original native payload; the real client must verify it.
            app = app.route(
                &format!("/{name}/{{key}}"),
                get(move || {
                    let payload = payload.clone();
                    async move { payload }
                }),
            );
        }
        app = app.route(
            "/failure/{key}",
            get(|| async { http::StatusCode::SERVICE_UNAVAILABLE }),
        );
        let inherited = LoopbackResolver::default();
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let mut server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
        });
        let mut body = tokio::spawn(async move {
            #[cfg(feature = "tls-ring")]
            let provider = rustls::crypto::ring::default_provider();
            #[cfg(all(feature = "tls-aws-lc-rs", not(feature = "tls-ring")))]
            let provider = rustls::crypto::aws_lc_rs::default_provider();
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            for (route, commons, expected) in [
                ("mixed", false, Some(Some(1001))),
                ("mixed", true, Some(Some(2002))),
                ("old-only", true, Some(None)),
                ("bad-old", true, Some(Some(2002))),
                ("bad-cmns", false, Some(Some(1001))),
                ("bad-cmns", true, None),
                ("invalid", true, Some(None)),
                ("tampered", true, None),
                ("failure", true, None),
            ] {
                let url = format!("http://{addr}/{route}").parse().unwrap();
                let builder = if commons {
                    PkarrResolver::cmns_builder(url)
                } else {
                    PkarrResolver::builder(url)
                };
                let lookup = builder.build(tls.clone());
                let mut stream = lookup.resolve(key.public()).unwrap();
                let item = stream.next().await.unwrap();
                match expected {
                    Some(port) => {
                        let item = item.unwrap();
                        assert_eq!(item.endpoint_id(), key.public());
                        let expected: Vec<_> = port
                            .into_iter()
                            .map(|port| {
                                iroh_base::TransportAddr::Ip(
                                    format!("127.0.0.1:{port}").parse().unwrap(),
                                )
                            })
                            .collect();
                        assert_eq!(
                            item.endpoint_info().addrs().cloned().collect::<Vec<_>>(),
                            expected
                        );
                        assert_eq!(item.provenance(), "pkarr");
                    }
                    None => assert!(item.is_err(), "{route}"),
                }
                assert!(stream.next().await.is_none());
            }
            let local_url: Url = format!("http://localhost:{}/mixed", addr.port())
                .parse()
                .unwrap();
            let lookup = PkarrResolver::cmns_builder(local_url.clone())
                .into_address_lookup(&test_endpoint)
                .unwrap();
            assert!(
                lookup
                    .resolve(key.public())
                    .unwrap()
                    .next()
                    .await
                    .unwrap()
                    .is_ok()
            );
            let inherited_count = inherited.0.load(Ordering::SeqCst);
            assert!(inherited_count > 0);
            let explicit = LoopbackResolver::default();
            let lookup = PkarrResolver::cmns_builder(local_url)
                .dns_resolver(DnsResolver::custom(explicit.clone()))
                .into_address_lookup(&test_endpoint)
                .unwrap();
            assert!(
                lookup
                    .resolve(key.public())
                    .unwrap()
                    .next()
                    .await
                    .unwrap()
                    .is_ok()
            );
            assert!(explicit.0.load(Ordering::SeqCst) > 0);
            assert_eq!(inherited.0.load(Ordering::SeqCst), inherited_count);
            let lookup =
                PkarrResolver::cmns_builder(format!("http://{addr}/mixed").parse().unwrap())
                    .build(tls);
            let wrong_id = SecretKey::from_bytes(&[10; 32]).public();
            let mut stream = lookup.resolve(wrong_id).unwrap();
            assert!(stream.next().await.unwrap().is_err());
            assert!(stream.next().await.is_none());
        });
        let result = tokio::time::timeout(Duration::from_secs(10), &mut body).await;
        if result.is_err() {
            body.abort();
            let _ = body.await;
        }
        let _ = stop.send(());
        // Always stop and join owned tasks before propagating a panic or timeout.
        let server_result = tokio::time::timeout(Duration::from_secs(5), &mut server).await;
        if server_result.is_err() {
            server.abort();
            let _ = server.await;
        }
        endpoint.close().await;
        server_result.unwrap().unwrap().unwrap();
        result.unwrap().unwrap();
    }
    #[tokio::test]
    async fn strict_pkarr_redirects_and_exact_paths() {
        use std::{sync::Mutex, time::Duration};

        use axum::{response::Redirect, routing::any};
        let hits = Arc::new(AtomicUsize::new(0));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_url = format!("http://{}/forbidden", target.local_addr().unwrap());
        let target_task = tokio::spawn(
            axum::serve(
                target,
                Router::new().fallback(any({
                    let hits = hits.clone();
                    move || {
                        let hits = hits.clone();
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
                            http::StatusCode::BAD_GATEWAY
                        }
                    }
                })),
            )
            .into_future(),
        );
        let source = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base: Url = format!("http://{}/pkarr/", source.local_addr().unwrap())
            .parse()
            .unwrap();
        let source_task = tokio::spawn(
            axum::serve(
                source,
                Router::new().fallback(any({
                    let paths = paths.clone();
                    move |uri: http::Uri| {
                        let paths = paths.clone();
                        let target_url = target_url.clone();
                        async move {
                            paths.lock().unwrap().push(uri.path().to_owned());
                            Redirect::temporary(&target_url)
                        }
                    }
                })),
            )
            .into_future(),
        );
        let tls = || {
            iroh_relay::tls::CaTlsConfig::default()
                .client_config(iroh_relay::tls::default_provider())
                .unwrap()
        };
        let key = SecretKey::from_bytes(&[12; 32]);
        let packet = signed_packet(&key, &[("_cmns", "addr=127.0.0.1:1234")]);
        let direct = PkarrRelayClient::new_direct(base.clone(), tls(), DnsResolver::new());
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            assert!(direct.resolve(key.public()).await.is_err());
            assert!(direct.publish(&packet).await.is_err());
            let resolver = PkarrResolver::cmns_builder(base.clone()).build(tls());
            assert!(
                resolver
                    .resolve(key.public())
                    .unwrap()
                    .next()
                    .await
                    .unwrap()
                    .is_err()
            );
            assert_eq!(hits.load(Ordering::SeqCst), 0);
            assert_eq!(
                *paths.lock().unwrap(),
                vec![format!("/pkarr/{}", key.public().to_z32()); 3]
            );
            // Positive trap control: ordinary clients retain their redirect behavior.
            let ordinary =
                PkarrRelayClient::new(base.join("../pkarr").unwrap(), tls(), DnsResolver::new());
            assert!(ordinary.resolve(key.public()).await.is_err());
            assert_eq!(hits.load(Ordering::SeqCst), 1);
        })
        .await;
        source_task.abort();
        target_task.abort();
        let _ = source_task.await;
        let _ = target_task.await;
        result.unwrap();
    }

    #[tokio::test]
    async fn strict_pkarr_proxy_environment() {
        use std::time::Duration;

        use axum::routing::any;
        const CHILD: &str = "T268_200_PROXY_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let hits = Arc::new(AtomicUsize::new(0));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = format!("http://{}/", listener.local_addr().unwrap());
            let task = tokio::spawn(
                axum::serve(
                    listener,
                    Router::new().fallback(any({
                        let hits = hits.clone();
                        move || {
                            let hits = hits.clone();
                            async move {
                                hits.fetch_add(1, Ordering::SeqCst);
                                http::StatusCode::BAD_GATEWAY
                            }
                        }
                    })),
                )
                .into_future(),
            );
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "address_lookup::pkarr::cmns_lookup_tests::strict_pkarr_proxy_environment",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("NO_PROXY", "")
                .env("no_proxy", "");
            for name in [
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "http_proxy",
                "https_proxy",
                "all_proxy",
            ] {
                command.env(name, &proxy);
            }
            let mut child = command
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let finished = tokio::time::timeout(Duration::from_secs(15), async {
                while child.try_wait().unwrap().is_none() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            if finished.is_err() {
                let _ = child.kill();
            }
            let output = child.wait_with_output().unwrap();
            task.abort();
            let _ = task.await;
            assert!(finished.is_ok(), "proxy child exceeded its deadline");
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                hits.load(Ordering::SeqCst),
                1,
                "only the ordinary-client positive control reaches the proxy"
            );
            return;
        }
        let key = SecretKey::from_bytes(&[13; 32]);
        let packet = signed_packet(&key, &[("_cmns", "addr=127.0.0.1:1234")]);
        let hits = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base: Url = format!(
            "http://profile.test:{}/pkarr/",
            listener.local_addr().unwrap().port()
        )
        .parse()
        .unwrap();
        let expected = format!("/pkarr/{}", key.public().to_z32());
        let task = tokio::spawn(
            axum::serve(
                listener,
                Router::new().fallback(any({
                    let hits = hits.clone();
                    move |method: http::Method, uri: http::Uri| {
                        let hits = hits.clone();
                        let expected = expected.clone();
                        let packet = packet.clone();
                        async move {
                            assert_eq!(uri.path(), expected);
                            hits.fetch_add(1, Ordering::SeqCst);
                            if method == http::Method::PUT {
                                (http::StatusCode::NO_CONTENT, Vec::new())
                            } else {
                                (http::StatusCode::OK, packet.to_relay_payload().to_vec())
                            }
                        }
                    }
                })),
            )
            .into_future(),
        );
        let tls = || {
            iroh_relay::tls::CaTlsConfig::default()
                .client_config(iroh_relay::tls::default_provider())
                .unwrap()
        };
        let dns = || DnsResolver::custom(LoopbackResolver::default());
        let result = tokio::time::timeout(Duration::from_secs(8), async {
            let ordinary = PkarrRelayClient::new(base.clone(), tls(), dns());
            assert!(ordinary.resolve(key.public()).await.is_err());
            let direct = PkarrRelayClient::new_direct(base.clone(), tls(), dns());
            assert_eq!(
                direct.resolve(key.public()).await.unwrap().public_key(),
                key.public()
            );
            let packet = signed_packet(&key, &[("_cmns", "addr=127.0.0.1:1234")]);
            direct.publish(&packet).await.unwrap();
            let resolver = PkarrResolver::cmns_builder(base)
                .dns_resolver(dns())
                .build(tls());
            assert!(
                resolver
                    .resolve(key.public())
                    .unwrap()
                    .next()
                    .await
                    .unwrap()
                    .is_ok()
            );
            assert_eq!(hits.load(Ordering::SeqCst), 3);
        })
        .await;
        task.abort();
        let _ = task.await;
        result.unwrap();
    }
}
