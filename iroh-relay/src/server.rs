//! A fully-fledged iroh-relay server over HTTP or HTTPS.
//!
//! This module provides an API to run a full fledged iroh-relay server.  It is primarily
//! used by the `iroh-relay` binary in this crate.  It can be used to run a relay server in
//! other locations however.
//!
//! Retain and await startup and shutdown futures to finish owned native cleanup. Dropping
//! an owner requests cancellation; it does not itself await task destruction. Supervisor
//! completion drains HTTP and captive connections; metrics cleanup remains separately
//! owned by [`Server::shutdown`]. QAD uses its existing native shutdown primitive.
//!
//! The relay server hosts the following services:
//!
//! - HTTPS `/relay`: The main URL endpoint to which clients connect and sends traffic over.
//! - HTTPS `/ping`: Used for net_report probes.
//! - HTTPS `/generate_204`: Used for net_report probes.

use std::{
    borrow::Cow,
    future::Future,
    net::SocketAddr,
    num::NonZeroU32,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use derive_more::Debug;
use http::{
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode,
    header::{AUTHORIZATION, InvalidHeaderValue},
    response::Builder as ResponseBuilder,
};
use http_body_util::Full;
use hyper::body::Incoming;
use iroh_base::EndpointId;
#[cfg(feature = "test-utils")]
use iroh_base::RelayUrl;
use n0_error::{e, stack_error};
use n0_future::{StreamExt, task::AbortOnDropHandle};
use rustls::server::WantsServerCert;
use serde::Serialize;
use tokio::{
    net::TcpListener,
    task::{JoinError, JoinSet},
};
use tokio_rustls_acme::{
    acme::{LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY},
    caches::DirCache,
};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, info_span, instrument};

use self::http_server::{BytesBody, HyperError, HyperResult};
use crate::{
    defaults::DEFAULT_KEY_CACHE_CAPACITY,
    http::{AUTH_TOKEN_URL_QUERY_PARAM, ProtocolVersion, RELAY_PROBE_PATH},
    quic::server::{QuicServer, QuicSpawnError, ServerHandle as QuicServerHandle},
    tls::CaTlsConfig,
};

pub mod client;
pub mod clients;
pub mod http_server;
mod metrics;
pub(crate) mod resolver;
pub mod streams;
#[cfg(feature = "test-utils")]
pub mod testing;

pub use self::{
    http_server::{Handlers, RelayService},
    metrics::{Metrics, RelayMetrics},
    resolver::{DEFAULT_CERT_RELOAD_INTERVAL, reloading_resolver},
};

const NO_CONTENT_CHALLENGE_HEADER: &str = "X-Iroh-Challenge";
const NO_CONTENT_RESPONSE_HEADER: &str = "X-Iroh-Response";
const NOTFOUND: &[u8] = b"Not Found";
const ROBOTS_TXT: &[u8] = b"User-agent: *\nDisallow: /\n";
const INDEX: &[u8] = br#"<html><body>
<h1>Iroh Relay</h1>
<p>
  This is an <a href="https://iroh.computer/">Iroh</a> Relay server.
</p>
"#;
const TLS_HEADERS: [(&str, &str); 2] = [
    (
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains",
    ),
    (
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'self'; block-all-mixed-content; plugin-types 'none'",
    ),
];

/// Creates a new [`BytesBody`] with no content.
fn body_empty() -> BytesBody {
    Box::new(http_body_util::Full::new(hyper::body::Bytes::new()))
}

/// Configuration for the full Relay.
///
/// Be aware the generic parameters are for when using the Let's Encrypt TLS configuration.
/// If not used dummy ones need to be provided, e.g. `ServerConfig::<(), ()>::default()`.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ServerConfig {
    /// Configuration for the Relay server, disabled if `None`.
    pub relay: Option<RelayConfig>,
    /// Configuration for the QUIC server, disabled if `None`.
    pub quic: Option<QuicConfig>,
    /// Socket to serve metrics on.
    #[cfg(feature = "metrics")]
    pub metrics_addr: Option<SocketAddr>,
}

/// Configuration for the Relay HTTP and HTTPS server.
///
/// This includes the HTTP services hosted by the Relay server, the Relay `/relay` HTTP
/// endpoint is only one of the services served.
#[derive(Debug)]
#[non_exhaustive]
pub struct RelayConfig {
    /// The socket address on which the Relay HTTP server should bind.
    ///
    /// Normally you'd choose port `80`.  The bind address for the HTTPS server is
    /// configured in [`RelayConfig::tls`].
    ///
    /// If [`RelayConfig::tls`] is `None` then this serves all the HTTP services without
    /// TLS.
    pub http_bind_addr: SocketAddr,
    /// TLS configuration for the HTTPS server.
    ///
    /// If *None* all the HTTP services that would be served here are served from
    /// [`RelayConfig::http_bind_addr`].
    pub tls: Option<TlsConfig>,
    /// Rate limits.
    pub limits: Limits,
    /// Key cache capacity.
    pub key_cache_capacity: Option<usize>,
    /// Access control for incoming connections.
    pub access: Arc<dyn DynAccessControl>,
}

impl RelayConfig {
    /// Creates a new [`RelayConfig`] bound to `http_bind_addr` with default settings.
    ///
    /// TLS is disabled, default [`Limits`] are used, the key cache capacity is unset, and
    /// access defaults to [`AllowAll`]. Adjust any of these by assigning to the
    /// corresponding fields after construction.
    pub fn new(http_bind_addr: impl Into<SocketAddr>) -> Self {
        Self {
            http_bind_addr: http_bind_addr.into(),
            tls: None,
            limits: Limits::default(),
            key_cache_capacity: None,
            access: Arc::new(AllowAll),
        }
    }
}

/// A process-unique identifier for a single relay client connection.
///
/// A new id is assigned to every incoming connection when its [`ClientRequest`]
/// is created, before the access check runs. The same id is passed to
/// [`AccessControl::on_connect`] and [`AccessControl::on_disconnect`], so an
/// implementation can match the two callbacks even when one endpoint holds
/// several concurrent connections.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, derive_more::Display)]
#[display("{_0}")]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Returns a fresh, process-unique connection id.
    fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// Details about an incoming relay client connection.
///
/// Passed to [`AccessControl::on_connect`] to decide whether to admit the connection.
#[derive(Debug, Clone)]
pub struct ClientRequest {
    connection_id: ConnectionId,
    endpoint_id: EndpointId,
    protocol_version: ProtocolVersion,
    request: http::request::Parts,
}

impl ClientRequest {
    /// Creates a new [`ClientRequest`] from an [`EndpointId`] and HTTP request parts.
    ///
    /// The [`EndpointId`] must be proven by the relay handshake. The request parts
    /// come from the client's WebSocket request. A fresh [`ConnectionId`] is assigned.
    pub fn new(
        endpoint_id: EndpointId,
        protocol_version: ProtocolVersion,
        request: http::request::Parts,
    ) -> Self {
        Self {
            connection_id: ConnectionId::next(),
            endpoint_id,
            protocol_version,
            request,
        }
    }

    /// Returns the [`ConnectionId`] assigned to this connection.
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Returns the [`ProtocolVersion`] negotiated for this connection.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the [`EndpointId`] of the client.
    ///
    /// The relay handshake authenticates this id before the access hook
    /// is invoked. The client proves possession of the secret key for
    /// this public key by either signing keying material exported from
    /// the TLS session or a challenge issued by the server.
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// Returns the URI of the HTTP request with which the client connected.
    pub fn uri(&self) -> &http::Uri {
        &self.request.uri
    }

    /// Returns an iterator over the query parameters set in the URI of the HTTP request.
    ///
    /// Each item is a `(name, value)` pair. Both names and values are percent-decoded.
    /// The query string is parsed in order, and the same name may appear more than once.
    pub fn query_pairs(&self) -> impl Iterator<Item = (Cow<'_, str>, Cow<'_, str>)> {
        url::form_urlencoded::parse(self.request.uri.query().unwrap_or("").as_bytes())
    }

    /// Returns the headers of the HTTP request with which the client connected.
    pub fn headers(&self) -> &http::HeaderMap {
        &self.request.headers
    }

    /// Returns the authorization token from the client's HTTP request, if any.
    ///
    /// Walks the `Authorization` headers in order and returns the value of
    /// the first one whose scheme is `Bearer` (matched case-insensitively).
    /// Headers with a different scheme are skipped.
    ///
    /// If none of the `Authorization` headers carries a `Bearer` scheme,
    /// returns the value of the `token` URL query parameter, or `None` if
    /// the URL has no `token` parameter.
    ///
    /// If an `Authorization` header value is not valid UTF-8 the function returns
    /// `None` immediately, without checking later headers or the URL query.
    pub fn auth_token(&self) -> Option<String> {
        for value in self.request.headers.get_all(AUTHORIZATION) {
            let value = value.to_str().ok()?;
            if let Some((scheme, token)) = value.split_once(' ')
                && scheme.eq_ignore_ascii_case("Bearer")
            {
                return Some(token.to_string());
            }
        }
        self.query_pairs()
            .find(|(name, _)| name == AUTH_TOKEN_URL_QUERY_PARAM)
            .map(|(_, value)| value.into_owned())
    }
}

/// Controls which endpoints may use the relay and observes their lifecycle.
///
/// Implement this trait to gate access to a relay server.
///
/// Both callbacks carry the connection's [`ConnectionId`], so an implementation
/// can index connections precisely even when one endpoint holds several.
pub trait AccessControl: std::fmt::Debug + Send + Sync + 'static {
    /// Decides whether a connecting client is admitted.
    ///
    /// Called once per incoming connection, before the connection is
    /// registered. Returns [`Access::Allow`] to admit it or [`Access::Deny`]
    /// to reject it.
    ///
    /// Can be implemented as `async fn on_connect(&self, request: &ClientRequest) -> Access`.
    fn on_connect(&self, request: &ClientRequest) -> impl Future<Output = Access> + Send;

    /// Notifies that a connection has ended.
    ///
    /// Called once for every connection that [`Self::on_connect`] admitted,
    /// identified by the same [`ConnectionId`].
    ///
    /// Note that this is a sync method being called in an async context. Make sure that your
    /// implementation does not block the runtime.
    fn on_disconnect(&self, endpoint_id: EndpointId, connection_id: ConnectionId) {
        let _ = (endpoint_id, connection_id);
    }
}

/// A dyn-compatible version of [`AccessControl`] that returns boxed futures.
///
/// Any type that implements [`AccessControl`] automatically implements
/// `DynAccessControl`. Wrap it in an `Arc` to store it as an
/// `Arc<dyn DynAccessControl>`, for example in [`RelayConfig::access`].
pub trait DynAccessControl: std::fmt::Debug + Send + Sync + 'static {
    /// See [`AccessControl::on_connect`].
    fn on_connect<'a>(
        &'a self,
        request: &'a ClientRequest,
    ) -> Pin<Box<dyn Future<Output = Access> + Send + 'a>>;

    /// See [`AccessControl::on_disconnect`].
    fn on_disconnect(&self, endpoint_id: EndpointId, connection_id: ConnectionId);
}

impl<T: AccessControl> DynAccessControl for T {
    fn on_connect<'a>(
        &'a self,
        request: &'a ClientRequest,
    ) -> Pin<Box<dyn Future<Output = Access> + Send + 'a>> {
        Box::pin(<Self as AccessControl>::on_connect(self, request))
    }

    fn on_disconnect(&self, endpoint_id: EndpointId, connection_id: ConnectionId) {
        <Self as AccessControl>::on_disconnect(self, endpoint_id, connection_id)
    }
}

/// An [`AccessControl`] that admits every endpoint.
///
/// This is the default used by [`RelayConfig::new`].
#[derive(Debug, Clone, Copy)]
pub struct AllowAll;

impl AccessControl for AllowAll {
    async fn on_connect(&self, _request: &ClientRequest) -> Access {
        Access::Allow
    }
}

/// Access restriction for an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// Access is allowed.
    Allow,
    /// Access is denied.
    Deny {
        /// Optional reason for denial to send back to the client.
        reason: Option<String>,
    },
}

/// Reports a connection's disconnect to [`AccessControl`] when dropped.
///
/// A guard is created the moment [`AccessControl::on_connect`] admits a
/// connection, and is then held for the connection's entire lifetime. Dropping
/// it - whether the connection closed cleanly, hit an error, or setup returned
/// early - calls [`AccessControl::on_disconnect`] exactly once.
///
/// Threading the guard through connection setup and into the connection actor
/// makes it impossible to admit a connection without eventually reporting its
/// disconnect, even as the surrounding code changes.
///
/// Embedders that register connections through [`Clients::register`] construct
/// the guard themselves; see that method for the expected lifecycle.
///
/// [`Clients::register`]: crate::server::clients::Clients::register
#[derive(Debug)]
pub struct OnDisconnectGuard {
    access: Option<Arc<dyn DynAccessControl>>,
    endpoint_id: EndpointId,
    connection_id: ConnectionId,
}

impl OnDisconnectGuard {
    /// Creates a guard for the connection described by `request`.
    ///
    /// Dropping the guard calls [`AccessControl::on_disconnect`] on `access`
    /// with the request's [`EndpointId`] and [`ConnectionId`]. Create it only
    /// once [`AccessControl::on_connect`] has admitted the connection.
    pub fn for_access_control(access: Arc<dyn DynAccessControl>, request: &ClientRequest) -> Self {
        Self {
            access: Some(access),
            endpoint_id: request.endpoint_id(),
            connection_id: request.connection_id(),
        }
    }

    /// Creates a no-op guard for `endpoint_id`.
    ///
    /// The guard carries `endpoint_id` and a fresh [`ConnectionId`] but has no
    /// access control attached, so dropping it does nothing.
    pub fn empty(endpoint_id: EndpointId) -> Self {
        Self {
            access: None,
            endpoint_id,
            connection_id: ConnectionId::next(),
        }
    }

    /// Returns the [`EndpointId`] of the guarded connection.
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// Returns the [`ConnectionId`] of the guarded connection.
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }
}

impl Drop for OnDisconnectGuard {
    fn drop(&mut self) {
        if let Some(access) = self.access.as_ref() {
            access.on_disconnect(self.endpoint_id, self.connection_id);
        }
    }
}

/// Configuration for the QUIC server.
#[derive(Debug)]
#[non_exhaustive]
pub struct QuicConfig {
    /// The socket address on which the QUIC server should bind.
    ///
    /// Normally you'd chose port `7842`, see [`crate::defaults::DEFAULT_RELAY_QUIC_PORT`].
    pub bind_addr: SocketAddr,
    /// The TLS server configuration for the QUIC server.
    ///
    /// If this [`rustls::ServerConfig`] does not support TLS 1.3, the QUIC server will fail
    /// to spawn.
    ///
    /// Will use the TLS config from [`RelayConfig::tls`] if unset. If neither is set the QUIC
    /// server will fail to spawn.
    pub server_config: Option<rustls::ServerConfig>,
}

impl QuicConfig {
    /// Creates a new [`QuicConfig`] bound to `bind_addr`.
    ///
    /// The TLS server config is left unset and inherited from [`RelayConfig::tls`].
    pub fn new(bind_addr: impl Into<SocketAddr>) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            server_config: None,
        }
    }
}

/// TLS configuration for Relay server.
///
/// Normally the Relay server accepts connections on both HTTPS and HTTP.
#[derive(Debug)]
#[non_exhaustive]
pub struct TlsConfig {
    /// The socket address on which to serve the HTTPS server.
    ///
    /// Since the captive portal probe has to run over plain text HTTP and TLS is used for
    /// the main relay server this has to be on a different port.  When TLS is not enabled
    /// this is served on the [`RelayConfig::http_bind_addr`] socket address.
    ///
    /// Normally you'd choose port `443`.
    pub https_bind_addr: SocketAddr,
    /// Mode for getting a cert.
    pub cert: CertConfig,
}

impl TlsConfig {
    /// Creates a new [`TlsConfig`] with the given bind address and certificate configuration.
    pub fn new(https_bind_addr: impl Into<SocketAddr>, cert: CertConfig) -> Self {
        Self {
            https_bind_addr: https_bind_addr.into(),
            cert,
        }
    }
}

/// Rate limits.
// TODO: accept_conn_limit and accept_conn_burst are not currently implemented.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Limits {
    /// Rate limits for incoming traffic from a client connection.
    pub client_rx: Option<ClientRateLimit>,
    /// Rate limit for accepting new connections. Unlimited if not set.
    ///
    /// Not currently implemented, setting this has no effect.
    pub accept_conn_limit: Option<f64>,
    /// Burst limit for accepting new connections. Unlimited if not set.
    ///
    /// Not currently implemented, setting this has no effect.
    pub accept_conn_burst: Option<usize>,
}

/// Per-client rate limit configuration.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClientRateLimit {
    /// Max number of bytes per second to read from the client connection.
    pub bytes_per_second: NonZeroU32,
    /// Max number of bytes to read in a single burst.
    pub max_burst_bytes: Option<NonZeroU32>,
}

impl ClientRateLimit {
    /// Creates a new [`ClientRateLimit`] with the given byte rate.
    ///
    /// `max_burst_bytes` is left unset; assign it after construction to allow bursting.
    pub fn new(bytes_per_second: NonZeroU32) -> Self {
        Self {
            bytes_per_second,
            max_burst_bytes: None,
        }
    }
}

/// TLS certificate configuration.
#[derive(Debug)]
#[non_exhaustive]
pub enum CertConfig {
    /// Use Let's Encrypt.
    LetsEncrypt {
        /// Configuration for the ACME client.
        acme_config: AcmeConfig,
        /// Builder for the [`rustls::ServerConfig`].
        ///
        /// The ACME resolver will be injected when starting the server.
        server_config_builder: rustls::ConfigBuilder<rustls::ServerConfig, WantsServerCert>,
    },
    /// Use a TLS key and certificate chain that can be reloaded.
    Manual {
        /// The [`rustls::ServerConfig`] to use.
        ///
        /// This needs to have the certificates or a certificate loader, it will be used by the server as-is.
        server_config: rustls::ServerConfig,
    },
}

/// Configuration for the ACME client.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub(crate) directory_url: String,
    pub(crate) domains: Vec<String>,
    pub(crate) contact: Vec<String>,
    pub(crate) cache_path: Option<PathBuf>,
    pub(crate) tls_config: CaTlsConfig,
}

impl AcmeConfig {
    /// Creates a new [`AcmeConfig`] with a ACME directory URL.
    pub fn new(directory_url: String) -> Self {
        Self {
            directory_url,
            domains: Vec::new(),
            contact: Vec::new(),
            cache_path: None,
            tls_config: CaTlsConfig::default(),
        }
    }

    /// Creates a new [`AcmeConfig`] with the Let's Encrypt directory URL.
    pub fn letsencrypt(production: bool) -> Self {
        let url = if production {
            LETS_ENCRYPT_PRODUCTION_DIRECTORY
        } else {
            LETS_ENCRYPT_STAGING_DIRECTORY
        };
        Self::new(url.to_string())
    }

    /// Provides the list of domains for which certificates should be obtained.
    pub fn domains(mut self, domains: Vec<String>) -> Self {
        self.domains = domains;
        self
    }

    /// Provides a list of contacts for the account.
    ///
    /// Note that email addresses must include a `mailto:` prefix.
    pub fn contact(mut self, contact: Vec<String>) -> Self {
        self.contact = contact;
        self
    }

    /// Sets the directory where to cache certificates.
    ///
    /// If not called certificates will not be cached.
    pub fn cache_path(mut self, path: PathBuf) -> Self {
        self.cache_path = Some(path);
        self
    }

    /// Sets the [`CaTlsConfig`] used to verify the ACME server's TLS certificate.
    ///
    /// Defaults to [`CaTlsConfig::embedded`]. Set a config with extra roots when targeting
    /// an ACME server whose certificate is not signed by a publicly trusted CA, such as a
    /// local test server.
    pub fn tls_config(mut self, tls_config: CaTlsConfig) -> Self {
        self.tls_config = tls_config;
        self
    }
}

/// A running Relay + QAD server.
///
/// This is a full Relay server, including QAD, Relay and various associated HTTP services.
///
/// Dropping this will stop the server.
#[derive(Debug)]
pub struct Server {
    /// The address of the HTTP server, if configured.
    http_addr: Option<SocketAddr>,
    /// The address of the HTTPS server, if the relay server is using TLS.
    ///
    /// If the Relay server is not using TLS then it is served from the
    /// [`Server::http_addr`].
    https_addr: Option<SocketAddr>,
    /// The address of the QUIC server, if configured.
    quic_addr: Option<SocketAddr>,
    /// Handle to the relay server.
    relay_handle: Option<http_server::ServerHandle>,
    /// Handle to the relay service for runtime control.
    relay_service: Option<http_server::RelayService>,
    /// Handle to the quic server.
    quic_handle: Option<QuicServerHandle>,
    /// The main task running the server.
    supervisor: Option<AbortOnDropHandle<Result<(), SupervisorError>>>,
    metrics: RelayMetrics,
    metrics_server: Option<iroh_metrics::service::MetricsServer>,
}

/// Server spawn errors
#[allow(missing_docs)]
#[stack_error(derive, add_meta, std_sources)]
#[non_exhaustive]
pub enum SpawnError {
    #[error("Unable to get local address")]
    LocalAddr { source: std::io::Error },
    #[error("Failed to bind QAD listener")]
    QuicSpawn { source: QuicSpawnError },
    #[error("Failed to parse TLS header")]
    TlsHeaderParse { source: InvalidHeaderValue },
    #[error("Failed to bind TcpListener")]
    BindTlsListener { source: std::io::Error },
    #[error("Failed to build ACME client TLS config")]
    AcmeClientTlsConfig {
        #[error(std_err)]
        source: std::io::Error,
    },
    #[error("No local address")]
    NoLocalAddr { source: std::io::Error },
    #[error("Failed to bind server socket to {addr}")]
    BindTcpListener {
        source: std::io::Error,
        addr: SocketAddr,
    },
    #[error("Error starting metrics server")]
    Metrics {
        #[error(std_err)]
        source: std::io::Error,
    },
}

/// Server task errors
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum SupervisorError {
    #[error("Acme event stream finished")]
    AcmeEventStreamFinished {},
    #[error(transparent)]
    JoinError {
        #[error(from, std_err)]
        source: JoinError,
    },
    #[error("No relay services are enabled")]
    NoRelayServicesEnabled {},
    #[error("Task cancelled")]
    TaskCancelled {},
}

impl Server {
    /// Starts the server.
    pub async fn spawn(config: ServerConfig) -> Result<Self, SpawnError> {
        let mut tasks = JoinSet::new();

        let metrics = RelayMetrics::default();

        #[cfg(not(feature = "metrics"))]
        let metrics_server = None;

        #[cfg(feature = "metrics")]
        let metrics_server = if let Some(addr) = config.metrics_addr {
            debug!("Starting metrics server");
            let mut registry = iroh_metrics::Registry::default();
            registry.register_all(&metrics);
            let server = iroh_metrics::service::MetricsServer::spawn(addr, Arc::new(registry))
                .await
                .map_err(|err| e!(SpawnError::Metrics, err))?;
            Some(server)
        } else {
            None
        };

        let mut relay_server = None;
        let mut captive = None;
        let startup = async {
            let (http_addr, tls_config) = match config.relay {
                Some(relay_config) => {
                    debug!("Starting Relay server");
                    let mut headers = HeaderMap::new();
                    for (name, value) in TLS_HEADERS.iter() {
                        headers.insert(
                            *name,
                            value
                                .parse()
                                .map_err(|err| e!(SpawnError::TlsHeaderParse, err))?,
                        );
                    }
                    let relay_bind_addr = match relay_config.tls {
                        Some(ref tls) => tls.https_bind_addr,
                        None => relay_config.http_bind_addr,
                    };
                    let key_cache_capacity = relay_config
                        .key_cache_capacity
                        .unwrap_or(DEFAULT_KEY_CACHE_CAPACITY);
                    let mut builder = http_server::ServerBuilder::new(relay_bind_addr)
                        .metrics(metrics.server.clone())
                        .headers(headers)
                        .key_cache_capacity(key_cache_capacity)
                        .access(relay_config.access)
                        .request_handler(Method::GET, "/", Box::new(root_handler))
                        .request_handler(Method::GET, "/index.html", Box::new(root_handler))
                        .request_handler(Method::GET, RELAY_PROBE_PATH, Box::new(probe_handler))
                        .request_handler(Method::GET, "/robots.txt", Box::new(robots_handler))
                        .request_handler(Method::GET, "/healthz", Box::new(healthz_handler));
                    if let Some(cfg) = relay_config.limits.client_rx {
                        builder = builder.client_rx_ratelimit(cfg);
                    }
                    let (http_addr, tls_config) = match relay_config.tls {
                        Some(tls_config) => {
                            let server_tls_config = match tls_config.cert {
                                CertConfig::LetsEncrypt {
                                    acme_config,
                                    server_config_builder,
                                } => {
                                    let cache = acme_config.cache_path.map(DirCache::new);
                                    let crypto_provider =
                                        server_config_builder.crypto_provider().clone();
                                    let client_tls_config = acme_config
                                        .tls_config
                                        .client_config(crypto_provider)
                                        .map_err(|err| e!(SpawnError::AcmeClientTlsConfig, err))?;
                                    let config =
                                        tokio_rustls_acme::AcmeConfig::new_with_client_tls_config(
                                            acme_config.domains,
                                            Arc::new(client_tls_config),
                                        )
                                        .contact(acme_config.contact)
                                        .directory(acme_config.directory_url)
                                        .cache_option(cache);
                                    let mut state = config.state();
                                    let resolver = state.resolver().clone();
                                    let server_config =
                                        server_config_builder.with_cert_resolver(resolver);
                                    let acceptor =
                                        http_server::TlsAcceptor::LetsEncrypt(state.acceptor());
                                    tasks.spawn(
                                        async move {
                                            while let Some(event) = state.next().await {
                                                match event {
                                                    Ok(ok) => debug!("acme event: {ok:?}"),
                                                    Err(err) => error!("error: {err:?}"),
                                                }
                                            }
                                            Err(e!(SupervisorError::AcmeEventStreamFinished))
                                        }
                                        .instrument(info_span!("acme")),
                                    );
                                    http_server::TlsConfig {
                                        config: Arc::new(server_config),
                                        acceptor,
                                    }
                                }
                                CertConfig::Manual { server_config } => {
                                    let server_config = Arc::new(server_config);
                                    let acceptor =
                                        tokio_rustls::TlsAcceptor::from(server_config.clone());
                                    let acceptor = http_server::TlsAcceptor::Manual(acceptor);
                                    http_server::TlsConfig {
                                        config: server_config,
                                        acceptor,
                                    }
                                }
                            };
                            builder = builder.tls_config(Some(server_tls_config.clone()));

                            // Some services always need to be served over HTTP without TLS.  Run
                            // these standalone.
                            let http_listener = TcpListener::bind(&relay_config.http_bind_addr)
                                .await
                                .map_err(|err| e!(SpawnError::BindTlsListener, err))?;
                            let http_addr = http_listener
                                .local_addr()
                                .map_err(|err| e!(SpawnError::NoLocalAddr, err))?;
                            let cancel = CancellationToken::new();
                            let stop = cancel.clone();
                            let id = tasks
                                .spawn(
                                    async move {
                                        run_captive_portal_service(
                                            http_listener,
                                            stop,
                                            #[cfg(test)]
                                            None,
                                        )
                                        .await;
                                        Ok(())
                                    }
                                    .instrument(info_span!("http-service", addr = %http_addr)),
                                )
                                .id();
                            captive = Some((id, cancel));
                            (Some(http_addr), Some(server_tls_config))
                        }
                        None => {
                            // If running Relay without TLS add the plain HTTP server directly
                            // to the Relay server.
                            builder = builder.request_handler(
                                Method::GET,
                                "/generate_204",
                                Box::new(serve_no_content_handler),
                            );
                            (None, None)
                        }
                    };
                    relay_server = Some(builder.spawn().await?);
                    (http_addr, tls_config)
                }
                None => (None, None),
            };
            let quic_server = match config.quic {
                Some(quic_config) => {
                    debug!("Starting QUIC server {}", quic_config.bind_addr);
                    let server_config = quic_config
                        .server_config
                        .or(tls_config.map(|config| (*config.config).clone()))
                        .ok_or_else(|| {
                            e!(SpawnError::QuicSpawn, e!(QuicSpawnError::TlsNotConfigured))
                        })?;
                    Some(
                        QuicServer::spawn(
                            quic_config.bind_addr,
                            server_config,
                            metrics.server.clone(),
                        )
                        .map_err(|err| e!(SpawnError::QuicSpawn, err))?,
                    )
                }
                None => None,
            };
            Ok::<_, SpawnError>((http_addr, quic_server))
        }
        .await;
        let (http_addr, quic_server) = match startup {
            Ok(started) => started,
            Err(error) => {
                if let Some(server) = relay_server.as_mut() {
                    server.shutdown();
                    let _ = server.task_handle().await;
                }
                let _ = drain_captive(&mut tasks, captive.take()).await;
                tasks.shutdown().await;
                if let Some(server) = metrics_server {
                    server.shutdown().await;
                }
                return Err(error);
            }
        };
        // If http_addr is Some then relay_server is serving HTTPS.  If http_addr is None
        // relay_server is serving HTTP, including the /generate_204 service.
        let relay_addr = relay_server.as_ref().map(|srv| srv.addr());
        let relay_handle = relay_server.as_ref().map(|srv| srv.handle());
        let relay_service = relay_server.as_ref().map(|srv| srv.service().clone());

        let quic_addr = quic_server.as_ref().map(|srv| srv.bind_addr());
        let quic_handle = quic_server.as_ref().map(|srv| srv.handle());

        let task = tokio::spawn(relay_supervisor(tasks, relay_server, quic_server, captive));

        Ok(Self {
            http_addr: http_addr.or(relay_addr),
            https_addr: http_addr.and(relay_addr),
            quic_addr,
            relay_handle,
            relay_service,
            quic_handle,
            supervisor: Some(AbortOnDropHandle::new(task)),
            metrics,
            metrics_server,
        })
    }

    /// Requests graceful shutdown.
    ///
    /// Returns once all server tasks have stopped. If [`Self::join`] already delivered
    /// the supervisor result, this only finishes remaining cleanup; the caller retains
    /// responsibility for that result. Otherwise this returns the unconsumed result,
    /// including a task that finished before shutdown was requested.
    ///
    /// Retain and await one consuming shutdown future to completion. Dropping it, for
    /// example after a timeout, does not certify that cleanup finished.
    pub async fn shutdown(self) -> Result<(), SupervisorError> {
        // Only the Relay server and QUIC server need shutting down, the supervisor will abort the tasks in
        // the JoinSet when the server terminates.
        if let Some(handle) = self.relay_handle {
            handle.shutdown();
        }
        if let Some(handle) = self.quic_handle {
            handle.shutdown();
        }
        if let Some(server) = self.metrics_server {
            server.shutdown().await;
        }
        match self.supervisor {
            Some(supervisor) => supervisor.await?,
            None => Ok(()),
        }
    }

    /// Waits for the server's supervisor task to finish.
    ///
    /// Returns the exit result of the supervisor task. Unlike [`Self::shutdown`], this does
    /// *not* request shutdown, it only waits for the server to terminate on its own (for
    /// example, after an internal error or because the supervisor was aborted from
    /// elsewhere). The outer [`JoinError`] is only produced if the supervisor task itself
    /// panics or is aborted.
    ///
    /// Cancelling a pending wait leaves the task owned by the server, so the wait can
    /// be retried or followed by [`Self::shutdown`]. Any terminal result consumes the
    /// task output. Retain that result, finish shutdown, then propagate the result;
    /// successful cleanup does not replace a previously observed supervisor error.
    ///
    /// # Panics
    ///
    /// Panics if called again after a preceding call returned a terminal result.
    pub async fn join(&mut self) -> Result<Result<(), SupervisorError>, JoinError> {
        let result = self
            .supervisor
            .as_mut()
            .expect("supervisor result already consumed")
            .await;
        // Clear ownership before returning either the inner result or outer JoinError.
        self.supervisor.take();
        result
    }

    /// The socket address the HTTPS server is listening on.
    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.https_addr
    }

    /// The socket address the HTTP server is listening on.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// The socket address the QUIC server is listening on.
    pub fn quic_addr(&self) -> Option<SocketAddr> {
        self.quic_addr
    }

    /// Get the server's https [`RelayUrl`].
    ///
    /// This uses [`Self::https_addr`] so it's mostly useful for local development.
    #[cfg(feature = "test-utils")]
    pub fn https_url(&self) -> Option<RelayUrl> {
        self.https_addr.map(|addr| {
            url::Url::parse(&format!("https://{addr}"))
                .expect("valid url")
                .into()
        })
    }

    /// Get the server's http [`RelayUrl`].
    ///
    /// This uses [`Self::http_addr`] so it's mostly useful for local development.
    #[cfg(feature = "test-utils")]
    pub fn http_url(&self) -> Option<RelayUrl> {
        self.http_addr.map(|addr| {
            url::Url::parse(&format!("http://{addr}"))
                .expect("valid url")
                .into()
        })
    }

    /// Returns the metrics collected in the relay server.
    pub fn metrics(&self) -> &RelayMetrics {
        &self.metrics
    }

    /// Returns a handle to the embedded [`RelayService`] for runtime control.
    pub fn relay_service(&self) -> Option<&RelayService> {
        self.relay_service.as_ref()
    }
}

// Captive owns connection descendants: signal it and observe its own result before
// aborting the unrelated auxiliary tasks. A selected result has already consumed it.
async fn drain_captive(
    tasks: &mut JoinSet<Result<(), SupervisorError>>,
    captive: Option<(tokio::task::Id, CancellationToken)>,
) -> Option<Result<Result<(), SupervisorError>, JoinError>> {
    let (id, cancel) = captive?;
    cancel.cancel();
    while let Some(result) = tasks.join_next_with_id().await {
        match result {
            Ok((finished, output)) if finished == id => return Some(Ok(output)),
            Err(error) if error.id() == id => return Some(Err(error)),
            _ => (),
        }
    }
    None
}

/// Supervisor for the relay server tasks.
///
/// As soon as one of the tasks exits, all other tasks are stopped and the server stops.
/// The supervisor finishes once all tasks are finished.
#[instrument(skip_all)]
async fn relay_supervisor(
    mut tasks: JoinSet<Result<(), SupervisorError>>,
    mut relay_http_server: Option<http_server::Server>,
    quic_server: Option<QuicServer>,
    mut captive: Option<(tokio::task::Id, CancellationToken)>,
) -> Result<(), SupervisorError> {
    let mut quic_server = quic_server;
    let quic_enabled = quic_server.is_some();
    let mut quic_fut = match quic_server {
        Some(ref mut server) => n0_future::Either::Left(server.task_handle()),
        None => n0_future::Either::Right(n0_future::future::pending()),
    };
    let relay_enabled = relay_http_server.is_some();
    let mut relay_fut = match relay_http_server {
        Some(ref mut server) => n0_future::Either::Left(server.task_handle()),
        None => n0_future::Either::Right(n0_future::future::pending()),
    };
    let mut http_consumed = false;
    let mut res = tokio::select! {
        biased;
        Some(ret) = tasks.join_next_with_id() => {
            let id = match &ret { Ok((id, _)) => *id, Err(err) => err.id() };
            if captive.as_ref().is_some_and(|(captive_id, _)| *captive_id == id) { captive = None; }
            ret.map(|(_, output)| output)
        },
        ret = &mut quic_fut, if quic_enabled => ret.map(Ok),
        ret = &mut relay_fut, if relay_enabled => { http_consumed = true; ret.map(Ok) },
        else => Ok(Err(e!(SupervisorError::NoRelayServicesEnabled))),
    };

    if let Some(server) = relay_http_server.as_mut() {
        server.shutdown();
        if !http_consumed {
            let cleanup = server.task_handle().await.map(Ok);
            if matches!(res, Ok(Ok(()))) {
                res = cleanup;
            }
        }
    }
    if let Some(server) = quic_server {
        server.shutdown().await;
    }
    if let Some(cleanup) = drain_captive(&mut tasks, captive).await
        && matches!(res, Ok(Ok(())))
    {
        res = cleanup;
    }
    tasks.shutdown().await;

    match res {
        Ok(Ok(())) => {
            debug!("Task exited");
            Ok(())
        }
        Ok(Err(err)) => {
            error!(%err, "Task failed");
            Err(err)
        }
        Err(err) => {
            if let Ok(panic) = err.try_into_panic() {
                error!("Task panicked");
                std::panic::resume_unwind(panic);
            }
            debug!("Task cancelled");
            Err(e!(SupervisorError::TaskCancelled))
        }
    }
}

fn root_handler(
    _r: Request<Incoming>,
    response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    let body: BytesBody = Box::new(Full::from(INDEX));
    response
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(body)
        .map_err(|err| Box::new(err) as HyperError)
}

/// HTTP latency queries
fn probe_handler(
    _r: Request<Incoming>,
    response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    response
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .body(body_empty())
        .map_err(|err| Box::new(err) as HyperError)
}

fn robots_handler(
    _r: Request<Incoming>,
    response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    let body: BytesBody = Box::new(Full::from(ROBOTS_TXT));
    response
        .status(StatusCode::OK)
        .body(body)
        .map_err(|err| Box::new(err) as HyperError)
}

/// For captive portal detection.
fn serve_no_content_handler<B: hyper::body::Body>(
    r: Request<B>,
    mut response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    let check = |c: &HeaderValue| {
        !c.is_empty() && c.len() < 64 && c.as_bytes().iter().all(|c| is_challenge_char(*c as char))
    };

    if let Some(challenge) = r.headers().get(NO_CONTENT_CHALLENGE_HEADER)
        && check(challenge)
    {
        response = response.header(
            NO_CONTENT_RESPONSE_HEADER,
            format!("response {}", challenge.to_str()?),
        );
    }

    response
        .status(StatusCode::NO_CONTENT)
        .body(body_empty())
        .map_err(|err| Box::new(err) as HyperError)
}

fn is_challenge_char(c: char) -> bool {
    // Semi-randomly chosen as a limited set of valid characters
    c.is_ascii_lowercase()
        || c.is_ascii_uppercase()
        || c.is_ascii_digit()
        || c == '.'
        || c == '-'
        || c == '_'
}

/// Health check response
#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    git_hash: &'static str,
}

fn healthz_handler(
    _r: Request<Incoming>,
    response: ResponseBuilder,
) -> HyperResult<Response<BytesBody>> {
    let health = Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        git_hash: "unknown",
    };
    let body = serde_json::to_string(&health).unwrap_or_else(|_| r#"{"status":"error"}"#.into());
    let body: BytesBody = Box::new(Full::from(body));
    response
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|err| Box::new(err) as HyperError)
}

#[cfg(test)]
struct CaptiveConnectionDrop(Option<Arc<std::sync::atomic::AtomicBool>>);
#[cfg(test)]
impl Drop for CaptiveConnectionDrop {
    fn drop(&mut self) {
        if let Some(flag) = &self.0 {
            flag.store(true, Ordering::SeqCst);
        }
    }
}

/// Stops accepting on cancellation and awaits its native connection group.
async fn run_captive_portal_service(
    http_listener: TcpListener,
    cancel: CancellationToken,
    #[cfg(test)] connection_dropped: Option<Arc<std::sync::atomic::AtomicBool>>,
) {
    info!("serving");

    // Retain this future through cooperative cancellation to await descendants.
    let mut tasks = JoinSet::new();
    let mut child_panic = None;

    loop {
        tokio::select! {
            biased;

            _ = cancel.cancelled() => break,
            Some(res) = tasks.join_next() => {
                if let Err(err) = res
                    && err.is_panic()
                {
                    child_panic = Some(err);
                    break;
                }
            }

            res = http_listener.accept() => {
                match res {
                    Ok((stream, peer_addr)) => {
                        debug!(%peer_addr, "Connection opened",);
                        let handler = CaptivePortalService;

                        let stream = crate::server::streams::MaybeTlsStream::Plain(stream);
                        let stream = hyper_util::rt::TokioIo::new(stream);
                        let connection = hyper::server::conn::http1::Builder::new()
                            .keep_alive(false)
                            .serve_connection(stream, handler);
                        #[cfg(test)]
                        let connection_dropped = connection_dropped.clone();
                        tasks.spawn(async move {
                            #[cfg(test)]
                            let _drop_witness = CaptiveConnectionDrop(connection_dropped);
                            match tokio::time::timeout(Duration::from_secs(30), connection).await {
                                Ok(Ok(())) => {}
                                Ok(Err(err)) => error!("Failed to serve connection: {err:?}"),
                                Err(_) => debug!(%peer_addr, "Captive portal connection timed out"),
                            }
                        });
                    }
                    Err(err) => {
                        error!(
                            "[CaptivePortalService] failed to accept connection: {:#?}",
                            err
                        );
                    }
                }
            }
        }
    }
    tasks.shutdown().await;
    if let Some(err) = child_panic {
        panic!("task panicked: {err:#?}");
    }
}

#[derive(Clone)]
struct CaptivePortalService;

impl hyper::service::Service<Request<Incoming>> for CaptivePortalService {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        match (req.method(), req.uri().path()) {
            // Captive Portal checker
            (&Method::GET, "/generate_204") => {
                Box::pin(async move { serve_no_content_handler(req, Response::builder()) })
            }
            _ => {
                // Return 404 not found response.
                let body: BytesBody = Box::new(Full::from(NOTFOUND));
                let r = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(body)
                    .map_err(|err| Box::new(err) as HyperError);
                Box::pin(async move { r })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    use http::StatusCode;
    use iroh_base::{EndpointId, RelayUrl, SecretKey};
    use iroh_dns::dns::DnsResolver;
    use n0_error::{Result, StackResultExt, StdResultExt};
    use n0_future::{SinkExt, StreamExt};
    use n0_tracing_test::traced_test;
    use rand::{RngExt, SeedableRng};
    use tracing::{info, instrument};
    use url::Url;

    use super::{
        Access, AccessControl, ClientRequest, NO_CONTENT_CHALLENGE_HEADER,
        NO_CONTENT_RESPONSE_HEADER, RelayConfig, Server, ServerConfig, SpawnError,
    };
    use crate::{
        client::{ClientBuilder, ConnectError},
        protos::{
            handshake,
            relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
        },
        test_utils::static_resolver,
        tls::{self, CaTlsConfig, default_provider},
    };

    /// An [`AccessControl`] backed by a closure, for tests.
    #[derive(derive_more::Debug)]
    struct TestAccess(#[debug("access fn")] Box<dyn Fn(&ClientRequest) -> Access + Send + Sync>);

    impl AccessControl for TestAccess {
        async fn on_connect(&self, request: &ClientRequest) -> Access {
            (self.0)(request)
        }
    }

    async fn spawn_local_relay() -> std::result::Result<Server, SpawnError> {
        let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.key_cache_capacity = Some(1024);
        Server::spawn(ServerConfig {
            relay: Some(relay),
            quic: None,
            metrics_addr: None,
        })
        .await
    }

    #[instrument]
    async fn try_send_recv(
        client_a: &mut crate::client::Client,
        client_b: &mut crate::client::Client,
        b_key: EndpointId,
        msg: Datagrams,
    ) -> Result<RelayToClientMsg> {
        // try resend 10 times
        for _ in 0..10 {
            client_a
                .send(ClientToRelayMsg::Datagrams {
                    dst_endpoint_id: b_key,
                    datagrams: msg.clone(),
                })
                .await?;
            let Ok(res) = tokio::time::timeout(Duration::from_millis(500), client_b.next()).await
            else {
                continue;
            };
            let res = res.expect("stream finished")?;
            return Ok(res);
        }
        panic!("failed to send and recv message");
    }

    fn dns_resolver() -> DnsResolver {
        DnsResolver::new()
    }

    fn ring_config() -> rustls::ClientConfig {
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth()
    }

    #[tokio::test]
    #[traced_test]
    async fn test_no_services() {
        let mut server = Server::spawn(ServerConfig::default()).await.unwrap();
        let res = tokio::time::timeout(Duration::from_secs(5), server.join())
            .await
            .expect("timeout, server not finished")
            .expect("server task JoinError");
        assert!(res.is_err());
    }

    #[tokio::test]
    #[traced_test]
    async fn test_conflicting_bind() {
        let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 1234));
        relay.key_cache_capacity = Some(1024);
        let res = Server::spawn(ServerConfig {
            relay: Some(relay),
            quic: None,
            metrics_addr: Some((Ipv4Addr::LOCALHOST, 1234).into()),
        })
        .await;
        assert!(res.is_err()); // AddrInUse
    }

    #[tokio::test]
    #[traced_test]
    async fn test_root_handler() {
        let server = spawn_local_relay().await.unwrap();
        let url = format!("http://{}", server.http_addr().unwrap());

        let client = reqwest::Client::builder()
            .use_preconfigured_tls(ring_config())
            .build()
            .unwrap();
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();
        assert!(body.contains("iroh.computer"));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_captive_portal_service() {
        let server = spawn_local_relay().await.unwrap();
        let url = format!("http://{}/generate_204", server.http_addr().unwrap());
        let challenge = "123az__.";

        let client = reqwest::Client::builder()
            .use_preconfigured_tls(ring_config())
            .build()
            .unwrap();
        let response = client
            .get(&url)
            .header(NO_CONTENT_CHALLENGE_HEADER, challenge)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let header = response.headers().get(NO_CONTENT_RESPONSE_HEADER).unwrap();
        assert_eq!(header.to_str().unwrap(), format!("response {challenge}"));
        let body = response.text().await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    #[traced_test]
    async fn test_relay_clients() -> Result<()> {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let server = spawn_local_relay().await?;

        let relay_url = format!("http://{}", server.http_addr().unwrap());
        let relay_url: RelayUrl = relay_url.parse()?;

        let client_config = CaTlsConfig::default()
            .client_config(default_provider())
            .unwrap();

        // set up client a
        let a_secret_key = SecretKey::from_bytes(&rng.random());
        let a_key = a_secret_key.public();
        let resolver = dns_resolver();
        info!("client a build & connect");
        let mut client_a = ClientBuilder::new(relay_url.clone(), a_secret_key, resolver.clone())
            .tls_client_config(client_config.clone())
            .connect()
            .await?;

        // set up client b
        let b_secret_key = SecretKey::from_bytes(&rng.random());
        let b_key = b_secret_key.public();
        info!("client b build & connect");
        let mut client_b = ClientBuilder::new(relay_url.clone(), b_secret_key, resolver.clone())
            .tls_client_config(client_config)
            .connect()
            .await?;

        info!("sending a -> b");

        // send message from a to b
        let msg = Datagrams::from("hello, b");
        let res = try_send_recv(&mut client_a, &mut client_b, b_key, msg.clone()).await?;
        let RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } = res
        else {
            panic!("client_b received unexpected message {res:?}");
        };

        assert_eq!(a_key, remote_endpoint_id);
        assert_eq!(msg, datagrams);

        info!("sending b -> a");
        // send message from b to a
        let msg = Datagrams::from("howdy, a");
        let res = try_send_recv(&mut client_b, &mut client_a, a_key, msg.clone()).await?;

        let RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } = res
        else {
            panic!("client_a received unexpected message {res:?}");
        };

        assert_eq!(b_key, remote_endpoint_id);
        assert_eq!(msg, datagrams);

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_relay_access_control() -> Result<()> {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let current_span = tracing::info_span!("this is a test");
        let _guard = current_span.enter();

        let client_config = CaTlsConfig::default()
            .client_config(default_provider())
            .unwrap();

        let a_secret_key = SecretKey::from_bytes(&rng.random());
        let a_key = a_secret_key.public();

        let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.key_cache_capacity = Some(1024);
        relay.access = Arc::new(TestAccess(Box::new(move |request| {
            let endpoint_id = request.endpoint_id();
            info!("checking {}", endpoint_id);
            // reject endpoint a
            if endpoint_id == a_key {
                Access::Deny { reason: None }
            } else {
                Access::Allow
            }
        })));
        let server = Server::spawn(ServerConfig {
            relay: Some(relay),
            quic: None,
            metrics_addr: None,
        })
        .await?;

        let relay_url = format!("http://{}", server.http_addr().unwrap());
        let relay_url: RelayUrl = relay_url.parse()?;

        // set up client a
        let resolver = dns_resolver();
        let result = ClientBuilder::new(relay_url.clone(), a_secret_key, resolver)
            .tls_client_config(client_config.clone())
            .connect()
            .await;

        assert!(
            matches!(result, Err(ConnectError::Handshake { source: handshake::Error::ServerDeniedAuth { reason, .. }, .. }) if reason == "not authorized")
        );

        // test that another client has access

        // set up client b
        let b_secret_key = SecretKey::from_bytes(&rng.random());
        let b_key = b_secret_key.public();

        let resolver = dns_resolver();
        let mut client_b = ClientBuilder::new(relay_url.clone(), b_secret_key, resolver)
            .tls_client_config(client_config.clone())
            .connect()
            .await?;

        // set up client c
        let c_secret_key = SecretKey::from_bytes(&rng.random());
        let c_key = c_secret_key.public();

        let resolver = dns_resolver();
        let mut client_c = ClientBuilder::new(relay_url.clone(), c_secret_key, resolver)
            .tls_client_config(client_config)
            .connect()
            .await?;

        // send message from b to c
        let msg = Datagrams::from("hello, c");
        let res = try_send_recv(&mut client_b, &mut client_c, c_key, msg.clone()).await?;

        if let RelayToClientMsg::Datagrams {
            remote_endpoint_id,
            datagrams,
        } = res
        {
            assert_eq!(b_key, remote_endpoint_id);
            assert_eq!(msg, datagrams);
        } else {
            panic!("client_c received unexpected message {res:?}");
        }

        Ok(())
    }

    /// Verifies that [`ClientBuilder::auth_token`] forwards a token to the
    /// relay so the [`AccessControl::on_connect`] hook can read it via
    /// [`ClientRequest::auth_token`].
    #[tokio::test]
    #[traced_test]
    async fn test_relay_client_auth_token_forwarded() -> Result<()> {
        const TOKEN: &str = "secret-token";

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let client_config = CaTlsConfig::default()
            .client_config(default_provider())
            .unwrap();

        let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.key_cache_capacity = Some(1024);
        relay.access = Arc::new(TestAccess(Box::new(move |request| {
            if request.auth_token().as_deref() == Some(TOKEN) {
                Access::Allow
            } else {
                Access::Deny { reason: None }
            }
        })));
        let server = Server::spawn(ServerConfig {
            relay: Some(relay),
            quic: None,
            metrics_addr: None,
        })
        .await?;

        let relay_url = format!("http://{}", server.http_addr().unwrap());
        let relay_url: RelayUrl = relay_url.parse()?;

        // No query param: denied.
        let secret_key = SecretKey::from_bytes(&rng.random());
        let result = ClientBuilder::new(relay_url.clone(), secret_key, dns_resolver())
            .tls_client_config(client_config.clone())
            .connect()
            .await;
        assert!(matches!(
            result,
            Err(ConnectError::Handshake { source: handshake::Error::ServerDeniedAuth { reason, .. }, .. })
                if reason == "not authorized"
        ));

        // Wrong token: denied.
        let secret_key = SecretKey::from_bytes(&rng.random());
        let result = ClientBuilder::new(relay_url.clone(), secret_key, dns_resolver())
            .tls_client_config(client_config.clone())
            .auth_token("wrong-token")
            .connect()
            .await;
        assert!(matches!(
            result,
            Err(ConnectError::Handshake { source: handshake::Error::ServerDeniedAuth { reason, .. }, .. })
                if reason == "not authorized"
        ));

        // Correct token: connection succeeds.
        let secret_key = SecretKey::from_bytes(&rng.random());
        let _client = ClientBuilder::new(relay_url, secret_key, dns_resolver())
            .tls_client_config(client_config)
            .auth_token(TOKEN)
            .connect()
            .await?;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_relay_clients_full() -> Result<()> {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let server = spawn_local_relay().await.unwrap();
        let relay_url = format!("http://{}", server.http_addr().unwrap());
        let relay_url: RelayUrl = relay_url.parse().unwrap();

        let client_config = CaTlsConfig::default()
            .client_config(default_provider())
            .unwrap();

        // set up client a
        let a_secret_key = SecretKey::from_bytes(&rng.random());
        let resolver = dns_resolver();
        let mut client_a = ClientBuilder::new(relay_url.clone(), a_secret_key, resolver.clone())
            .tls_client_config(client_config.clone())
            .connect()
            .await?;

        // set up client b
        let b_secret_key = SecretKey::from_bytes(&rng.random());
        let b_key = b_secret_key.public();
        let _client_b = ClientBuilder::new(relay_url.clone(), b_secret_key, resolver.clone())
            .tls_client_config(client_config)
            .connect()
            .await?;

        // send messages from a to b, without b receiving anything.
        // we should still keep succeeding to send, even if the packet won't be forwarded
        // by the relay server because the server's send queue for b fills up.
        let msg = Datagrams::from("hello, b");
        for _i in 0..1000 {
            client_a
                .send(ClientToRelayMsg::Datagrams {
                    dst_endpoint_id: b_key,
                    datagrams: msg.clone(),
                })
                .await?;
        }
        Ok(())
    }

    /// Regression test: A relay client that prefers IPv6 falls back to IPv4
    /// when the advertised IPv6 address is unreachable.
    #[tokio::test]
    #[traced_test]
    async fn test_relay_client_falls_back_to_ipv4() -> Result {
        // A relay reachable only over IPv4.
        let config = ServerConfig {
            relay: Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0))),
            ..Default::default()
        };
        let server = Server::spawn(config).await?;
        let addr = server.http_addr().expect("http relay address");

        // Resolves to both the real IPv4 address and an unreachable IPv6 address.
        let resolver = static_resolver(
            vec![Ipv4Addr::LOCALHOST],
            vec!["2001:db8::dead".parse().expect("valid IPv6")],
        );
        let url: Url = format!("http://relay.test:{}", addr.port())
            .parse()
            .expect("valid relay url");

        let client = ClientBuilder::new(url, SecretKey::generate(), resolver)
            .tls_client_config(tls::make_dangerous_client_config())
            // Force IPv6 preference
            .address_family_selector(|| true);

        tokio::time::timeout(Duration::from_secs(10), client.connect())
            .await
            .with_std_context(|_| "relay connect timed out")?
            .context("relay connect")?;

        server.shutdown().await.context("relay server shutdown")?;
        Ok(())
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use std::{
        future::{Future, poll_fn},
        net::{Ipv4Addr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::Poll,
        time::Duration,
    };

    use n0_future::task::AbortOnDropHandle;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::{RelayConfig, Server, ServerConfig, SupervisorError};

    async fn bounded(future: impl Future<Output = ()>) {
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .expect("whole scenario timeout");
    }

    async fn metrics_server(relay: bool) -> (Server, SocketAddr) {
        let server = Server::spawn(ServerConfig {
            relay: relay.then(|| RelayConfig::new((Ipv4Addr::LOCALHOST, 0))),
            metrics_addr: Some((Ipv4Addr::LOCALHOST, 0).into()),
            ..Default::default()
        })
        .await
        .unwrap();
        let addr = server.metrics_server.as_ref().unwrap().local_addr();
        (server, addr)
    }

    async fn assert_serving(addr: SocketAddr) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(String::from_utf8_lossy(&response).contains("iroh.computer"));
    }

    async fn assert_metrics_live(addr: SocketAddr) {
        // Drop this connection before shutdown so it cannot hold graceful HTTP drain open.
        drop(
            TcpStream::connect(addr)
                .await
                .expect("metrics still listens"),
        );
    }

    async fn assert_metrics_released(addr: SocketAddr) {
        let listener = TcpListener::bind(addr)
            .await
            .expect("metrics listener released");
        drop(listener);
    }

    async fn poll_then_cancel_join(server: &mut Server) {
        let mut wait = Box::pin(server.join());
        poll_fn(|cx| {
            assert!(
                wait.as_mut().poll(cx).is_pending(),
                "native supervisor still running"
            );
            Poll::Ready(())
        })
        .await;
        drop(wait);
        assert!(
            server
                .supervisor
                .as_ref()
                .is_some_and(|task| !task.is_finished())
        );
    }

    async fn wait_finished(server: &Server) {
        // Observe completion without taking the supervisor output.
        while !server.supervisor.as_ref().unwrap().is_finished() {
            tokio::task::yield_now().await;
        }
    }

    struct Destroyed(Arc<AtomicBool>);
    impl Drop for Destroyed {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    async fn inject_outer_failure(server: &mut Server, panic: bool) -> Arc<AtomicBool> {
        // Only outer JoinError fixtures replace the private task. Real native no-services
        // completion, relay serving and metrics ownership are exercised separately.
        wait_finished(server).await;
        drop(server.supervisor.take());
        let destroyed = Arc::new(AtomicBool::new(false));
        let witness = destroyed.clone();
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        server.supervisor = Some(AbortOnDropHandle::new(tokio::spawn(async move {
            let _guard = Destroyed(witness);
            entered.send(()).unwrap();
            if panic {
                panic!("injected supervisor panic");
            }
            std::future::pending::<Result<(), SupervisorError>>().await
        })));
        entered_rx.await.unwrap();
        if !panic {
            server.supervisor.as_ref().unwrap().abort();
        }
        wait_finished(server).await;
        assert!(
            destroyed.load(Ordering::SeqCst),
            "entered task future destroyed"
        );
        destroyed
    }

    #[tokio::test]
    async fn no_services_join_then_shutdown() {
        bounded(async {
            let mut server = Server::spawn(ServerConfig::default()).await.unwrap();
            let result = server.join().await.expect("native supervisor completed");
            assert!(matches!(
                result,
                Err(SupervisorError::NoRelayServicesEnabled { .. })
            ));
            server
                .shutdown()
                .await
                .expect("consumed result must not be polled again");
        })
        .await;
    }

    #[tokio::test]
    async fn pending_join_cancel_then_native_success() {
        bounded(async {
            let (mut server, metrics) = metrics_server(true).await;
            let addr = server.http_addr().unwrap();
            assert_serving(addr).await;
            poll_then_cancel_join(&mut server).await;
            assert_serving(addr).await;
            server.relay_handle.as_ref().unwrap().shutdown();
            server.join().await.unwrap().unwrap();
            assert!(server.supervisor.is_none());
            assert_metrics_live(metrics).await;
            server.shutdown().await.unwrap();
            assert_metrics_released(metrics).await;
        })
        .await;
    }

    #[tokio::test]
    async fn pending_join_cancel_then_direct_shutdown() {
        bounded(async {
            let (mut server, metrics) = metrics_server(true).await;
            let addr = server.http_addr().unwrap();
            poll_then_cancel_join(&mut server).await;
            assert_serving(addr).await;
            server.shutdown().await.unwrap();
            assert_metrics_released(metrics).await;
        })
        .await;
    }

    #[tokio::test]
    async fn native_inner_error_join_then_metrics_cleanup() {
        bounded(async {
            let (mut server, metrics) = metrics_server(false).await;
            assert!(matches!(
                server.join().await.unwrap(),
                Err(SupervisorError::NoRelayServicesEnabled { .. })
            ));
            assert!(server.supervisor.is_none());
            assert_metrics_live(metrics).await;
            server.shutdown().await.unwrap();
            assert_metrics_released(metrics).await;
        })
        .await;
    }

    #[tokio::test]
    async fn unobserved_native_inner_error_direct_shutdown() {
        bounded(async {
            let (server, metrics) = metrics_server(false).await;
            wait_finished(&server).await;
            assert_metrics_live(metrics).await;
            assert!(matches!(
                server.shutdown().await,
                Err(SupervisorError::NoRelayServicesEnabled { .. })
            ));
            assert_metrics_released(metrics).await;
        })
        .await;
    }

    async fn outer_error_join_then_cleanup(panic: bool) {
        let (mut server, metrics) = metrics_server(false).await;
        let destroyed = inject_outer_failure(&mut server, panic).await;
        let error = server
            .join()
            .await
            .expect_err("outer task failure delivered");
        assert_eq!(error.is_panic(), panic);
        assert_eq!(error.is_cancelled(), !panic);
        assert!(server.supervisor.is_none());
        assert_metrics_live(metrics).await;
        server.shutdown().await.unwrap();
        assert_metrics_released(metrics).await;
        assert!(destroyed.load(Ordering::SeqCst));
    }

    async fn unobserved_outer_error_direct_shutdown(panic: bool) {
        let (mut server, metrics) = metrics_server(false).await;
        let destroyed = inject_outer_failure(&mut server, panic).await;
        assert_metrics_live(metrics).await;
        match server.shutdown().await {
            Err(SupervisorError::JoinError { source, .. }) => {
                assert_eq!(source.is_panic(), panic);
                assert_eq!(source.is_cancelled(), !panic);
            }
            other => panic!("expected converted outer JoinError, got {other:?}"),
        }
        assert_metrics_released(metrics).await;
        assert!(destroyed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn outer_cancellation_join_then_cleanup() {
        bounded(outer_error_join_then_cleanup(false)).await;
    }

    #[tokio::test]
    async fn outer_panic_join_then_cleanup() {
        bounded(outer_error_join_then_cleanup(true)).await;
    }

    #[tokio::test]
    async fn unobserved_outer_cancellation_direct_shutdown() {
        bounded(unobserved_outer_error_direct_shutdown(false)).await;
    }

    #[tokio::test]
    async fn unobserved_outer_panic_direct_shutdown() {
        bounded(unobserved_outer_error_direct_shutdown(true)).await;
    }
}

#[cfg(test)]
mod cleanup_tests {
    use std::{
        convert::Infallible,
        future::Future,
        net::Ipv4Addr,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use bytes::Bytes;
    use tokio::{
        io::AsyncWriteExt,
        net::TcpStream,
        sync::{Notify, oneshot},
        task::JoinSet,
    };

    use super::*;

    async fn bounded(f: impl Future<Output = ()>) {
        tokio::time::timeout(Duration::from_secs(10), f)
            .await
            .expect("whole cleanup scenario");
    }

    struct PendingBody {
        entered: Arc<Notify>,
        dropped: Arc<AtomicBool>,
        root: Arc<std::sync::Mutex<Option<tokio::task::AbortHandle>>>,
        root_finished: Arc<AtomicBool>,
    }
    impl hyper::body::Body for PendingBody {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
            self.entered.notify_one();
            Poll::Pending
        }
    }
    impl Drop for PendingBody {
        fn drop(&mut self) {
            self.root_finished.store(
                self.root.lock().unwrap().as_ref().unwrap().is_finished(),
                Ordering::SeqCst,
            );
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    async fn pending_http() -> (
        http_server::Server,
        TcpStream,
        Arc<AtomicBool>,
        Arc<AtomicBool>,
    ) {
        let entered = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let root = Arc::new(std::sync::Mutex::new(None));
        let root_finished = Arc::new(AtomicBool::new(false));
        let (r, f) = (root.clone(), root_finished.clone());
        let (e, d) = (entered.clone(), dropped.clone());
        let mut server = http_server::ServerBuilder::new((Ipv4Addr::LOCALHOST, 0).into())
            .request_handler(
                Method::GET,
                "/pending",
                Box::new(move |_, response| {
                    Ok(response
                        .body(Box::new(PendingBody {
                            entered: e.clone(),
                            dropped: d.clone(),
                            root: r.clone(),
                            root_finished: f.clone(),
                        }) as BytesBody)
                        .unwrap())
                }),
            )
            .request_handler(
                Method::GET,
                "/panic",
                Box::new(|_, _| panic!("native connection panic")),
            )
            .spawn()
            .await
            .unwrap();
        *root.lock().unwrap() = Some(server.task_handle().abort_handle());
        let mut stream = TcpStream::connect(server.addr()).await.unwrap();
        stream
            .write_all(b"GET /pending HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        entered.notified().await;
        (server, stream, dropped, root_finished)
    }

    struct CompletionWitness {
        dropped: Arc<AtomicBool>,
        observed: Arc<AtomicBool>,
    }
    impl Drop for CompletionWitness {
        fn drop(&mut self) {
            self.observed
                .store(self.dropped.load(Ordering::SeqCst), Ordering::SeqCst);
        }
    }
    async fn supervisor_drains(mode: u8) {
        bounded(async {
            let (server, stream, dropped, _) = pending_http().await;
            let mut tasks = JoinSet::new();
            let (tx, rx) = oneshot::channel();
            tasks.spawn(async move {
                rx.await.unwrap();
                match mode {
                    0 => Ok(()),
                    1 => Err(e!(SupervisorError::AcmeEventStreamFinished)),
                    _ => panic!("primary auxiliary panic"),
                }
            });
            let observed = Arc::new(AtomicBool::new(false));
            let witness = CompletionWitness {
                dropped: dropped.clone(),
                observed: observed.clone(),
            };
            let supervisor = tokio::spawn(async move {
                let _witness = witness;
                relay_supervisor(tasks, Some(server), None, None).await
            });
            tx.send(()).unwrap();
            let outcome = supervisor.await;
            let drained_at_completion = observed.load(Ordering::SeqCst);
            // Old abort-on-drop ownership must also finish before the baseline assertion.
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
            drop(stream);
            match mode {
                0 => assert!(outcome.unwrap().is_ok()),
                1 => assert!(outcome.unwrap().is_err()),
                _ => assert!(outcome.unwrap_err().is_panic()),
            }
            assert!(
                drained_at_completion,
                "native HTTP body still alive when supervisor completed"
            );
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn supervisor_success_drains_http() {
        supervisor_drains(0).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn supervisor_error_drains_http() {
        supervisor_drains(1).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn supervisor_panic_drains_http() {
        supervisor_drains(2).await;
    }

    async fn failed_start(later_bind: bool) {
        bounded(async {
            let reserve = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let addr = reserve.local_addr().unwrap();
            drop(reserve);
            let metrics_reserve = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let metrics_addr = metrics_reserve.local_addr().unwrap();
            drop(metrics_reserve);
            let occupied = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let mut quic = QuicConfig::new(occupied.local_addr().unwrap());
            if later_bind {
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                quic.server_config = Some(rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions().unwrap().with_no_client_auth()
                    .with_single_cert(vec![cert.cert.der().clone()], rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap());
            }
            let result = Server::spawn(ServerConfig { relay: Some(RelayConfig::new(addr)), quic: Some(quic), metrics_addr: Some(metrics_addr), ..Default::default() }).await;
            match result.unwrap_err() {
                SpawnError::QuicSpawn { source, .. } => {
                    if later_bind { assert!(matches!(source, QuicSpawnError::EndpointServer { .. })); }
                    else { assert!(matches!(source, QuicSpawnError::TlsNotConfigured { .. })); }
                }
                error => panic!("unexpected startup error: {error:#}"),
            }
            let relay_released = std::net::TcpListener::bind(addr).is_ok();
            let metrics_released = std::net::TcpListener::bind(metrics_addr).is_ok();
            // Finish scheduled aborts before asserting the captured failure witness.
            loop {
                if let (Ok(a), Ok(b)) = (std::net::TcpListener::bind(addr), std::net::TcpListener::bind(metrics_addr)) { drop((a,b)); break; }
                tokio::task::yield_now().await;
            }
            assert!(relay_released && metrics_released, "failed start returned before created listeners were released: relay={relay_released} metrics={metrics_released}");
        }).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn failed_start_missing_qad_tls_drains() {
        failed_start(false).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn failed_start_qad_bind_drains() {
        failed_start(true).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn http_child_panic_drains_other_connection() {
        bounded(async {
            let (mut server, live, dropped, root_finished) = pending_http().await;
            let mut trigger = TcpStream::connect(server.addr()).await.unwrap();
            trigger
                .write_all(b"GET /panic HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            let error = server.task_handle().await.unwrap_err();
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
            drop((live, trigger));
            assert!(error.is_panic());
            assert!(
                !root_finished.load(Ordering::SeqCst),
                "HTTP root finished before live connection destruction"
            );
        })
        .await;
    }

    struct CaptiveCompletion {
        descendant_dropped: Arc<AtomicBool>,
        closed: Arc<AtomicBool>,
    }
    impl Drop for CaptiveCompletion {
        fn drop(&mut self) {
            self.closed.store(
                self.descendant_dropped.load(Ordering::SeqCst),
                Ordering::SeqCst,
            );
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn captive_completion_drains_live_connection() {
        bounded(async {
            use tokio::io::AsyncReadExt;
            let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();
            let descendant_dropped = Arc::new(AtomicBool::new(false));
            let connection_dropped = descendant_dropped.clone();
            let closed = Arc::new(AtomicBool::new(false));
            let witness = CaptiveCompletion {
                descendant_dropped,
                closed: closed.clone(),
            };
            let cancel = CancellationToken::new();
            let stop = cancel.clone();
            let task = tokio::spawn(async move {
                let _witness = witness;
                run_captive_portal_service(listener, stop, Some(connection_dropped)).await;
            });
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(b"GET /generate_204 HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            let mut response = [0; 1024];
            let n = stream.read(&mut response).await.unwrap();
            assert!(response[..n].starts_with(b"HTTP/1.1 204"));
            stream
                .write_all(b"GET /generate_204 HTTP/1.1\r\nHost:")
                .await
                .unwrap();
            let stream = Arc::new(stream);
            cancel.cancel();
            task.await.unwrap();
            let closed_at_completion = closed.load(Ordering::SeqCst);
            loop {
                match stream.try_read(&mut [0; 1024]) {
                    Ok(0) => break,
                    Ok(_) => (),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
                    // Windows reports a peer close after unread data as WSAECONNABORTED.
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => break,
                    Err(e) => panic!("captive fixture read: {e}"),
                }
            }
            assert!(
                closed_at_completion,
                "captive parent completed before accepted connection future destruction"
            );
        })
        .await;
    }

    async fn completed_http_result(primary_error: bool, auxiliary: bool) {
        bounded(async {
            let (mut server, live, dropped, _) = pending_http().await;
            let mut trigger = TcpStream::connect(server.addr()).await.unwrap();
            trigger
                .write_all(b"GET /panic HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            while !server.task_handle().is_finished() {
                tokio::task::yield_now().await;
            }
            let mut tasks = JoinSet::new();
            if auxiliary {
                let task = tasks.spawn(async move {
                    if primary_error {
                        Err(e!(SupervisorError::AcmeEventStreamFinished))
                    } else {
                        Ok(())
                    }
                });
                while !task.is_finished() {
                    tokio::task::yield_now().await;
                }
            }
            let result = tokio::spawn(relay_supervisor(tasks, Some(server), None, None)).await;
            assert!(dropped.load(Ordering::SeqCst));
            drop((live, trigger));
            if primary_error {
                assert!(matches!(
                    result.unwrap(),
                    Err(SupervisorError::AcmeEventStreamFinished { .. })
                ));
            } else {
                let panic = result.unwrap_err().into_panic();
                let message = panic
                    .downcast_ref::<String>()
                    .expect("formatted native child panic");
                assert!(
                    message.contains("task panicked:")
                        && message.contains("native connection panic")
                );
            }
        })
        .await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn selected_http_result_is_consumed_once() {
        completed_http_result(false, false).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn successful_auxiliary_preserves_http_cleanup_panic() {
        completed_http_result(false, true).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn primary_error_precedes_http_cleanup_panic() {
        completed_http_result(true, true).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn supervisor_drains_actual_captive_before_auxiliary_abort() {
        bounded(async {
            use tokio::io::AsyncReadExt;
            let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();
            let dropped = Arc::new(AtomicBool::new(false));
            let flag = dropped.clone();
            let cancel = CancellationToken::new();
            let stop = cancel.clone();
            let mut tasks = JoinSet::new();
            let id = tasks
                .spawn(async move {
                    run_captive_portal_service(listener, stop, Some(flag)).await;
                    Ok(())
                })
                .id();
            let mut peer = TcpStream::connect(addr).await.unwrap();
            peer.write_all(b"GET /generate_204 HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            let mut response = [0; 1024];
            assert!(peer.read(&mut response).await.unwrap() > 0);
            let (server, live, http_dropped, _) = pending_http().await;
            tasks.spawn(async { Err(e!(SupervisorError::AcmeEventStreamFinished)) });
            let result = relay_supervisor(tasks, Some(server), None, Some((id, cancel))).await;
            assert!(matches!(
                result,
                Err(SupervisorError::AcmeEventStreamFinished { .. })
            ));
            assert!(dropped.load(Ordering::SeqCst));
            assert!(http_dropped.load(Ordering::SeqCst));
            drop((peer, live));
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_start_https_bind_drains_captive_and_metrics() {
        bounded(async {
            let reserve = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let http = reserve.local_addr().unwrap();
            drop(reserve);
            let reserve = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let metrics = reserve.local_addr().unwrap();
            drop(reserve);
            let occupied = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let https = occupied.local_addr().unwrap();
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
            let mut relay = RelayConfig::new(http);
            relay.tls = Some(TlsConfig::new(https, CertConfig::Manual { server_config }));
            let error = Server::spawn(ServerConfig {
                relay: Some(relay),
                metrics_addr: Some(metrics),
                ..Default::default()
            })
            .await
            .unwrap_err();
            assert!(matches!(error, SpawnError::BindTcpListener { addr, .. } if addr == https));
            // Native captive and metrics listeners must already be gone before yielding.
            let plain =
                std::net::TcpListener::bind(http).expect("captive startup listener drained");
            let metrics =
                std::net::TcpListener::bind(metrics).expect("metrics startup listener drained");
            drop((plain, metrics, occupied));
        })
        .await;
    }
}
