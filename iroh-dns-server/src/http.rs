//! HTTP server part of iroh-dns-server

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Request, State},
    handler::Handler,
    http::Method,
    middleware::{self, Next},
    response::IntoResponse,
    routing::get,
};
use n0_error::{Result, StdResultExt, anyerr, bail_any};
use n0_future::{FutureExt, future::Boxed as BoxFuture};
use serde::{Deserialize, Serialize};
use socket2::{SockRef, TcpKeepalive};
use tokio::{net::TcpListener, task::JoinSet};
use tower_http::{
    cors::{self, CorsLayer},
    trace::TraceLayer,
};
use tracing::{Level, info, span, warn};

mod doh;
mod error;
mod pkarr;
mod rate_limiting;
mod tls;

pub use self::{rate_limiting::RateLimitConfig, tls::CertMode};
use crate::state::AppState;

/// How long a connection may be idle before keepalive probing starts.
const TCP_KEEPALIVE_TIME: Duration = Duration::from_mins(1);

/// Interval between keepalive probes once probing starts.
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Enable TCP keepalive on `listener`, which accepted connections inherit.
///
/// Without it, connections whose peer vanished without closing are never
/// reaped: they accumulate for the lifetime of the process until it is
/// OOM-killed.
fn set_keepalive(listener: &std::net::TcpListener) -> std::io::Result<()> {
    let keepalive = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_TIME)
        .with_interval(TCP_KEEPALIVE_INTERVAL);
    SockRef::from(listener).set_tcp_keepalive(&keepalive)
}

/// Configuration for the HTTP listener.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct HttpConfig {
    /// Port to bind the HTTP listener to.
    pub port: u16,
    /// Address to bind the HTTP listener to (defaults to `::`, i.e. IPv6 wildcard which also covers IPv4).
    pub bind_addr: Option<IpAddr>,
}

/// Configuration for the HTTPS listener.
///
/// Certificates are obtained according to [`Self::cert_mode`].
#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct HttpsConfig {
    /// Port to bind the HTTPS listener to.
    pub port: u16,
    /// Address to bind the HTTPS listener to (defaults to `::`, i.e. IPv6 wildcard which also covers IPv4).
    pub bind_addr: Option<IpAddr>,
    /// Domains for which TLS certificates are issued or loaded.
    pub domains: Vec<String>,
    /// Strategy used to obtain TLS certificates.
    pub cert_mode: CertMode,
    /// Contact email address passed to Let's Encrypt.
    ///
    /// Required when [`Self::cert_mode`] is [`CertMode::LetsEncrypt`]; ignored
    /// otherwise.
    pub letsencrypt_contact: Option<String>,
    /// Whether to use the Let's Encrypt production endpoint instead of staging.
    ///
    /// Only applies when [`Self::cert_mode`] is [`CertMode::LetsEncrypt`]. When
    /// unset, the ACME staging endpoint is used.
    pub letsencrypt_prod: Option<bool>,
}

/// The HTTP(S) server part of iroh-dns-server
#[derive(Debug)]
pub(crate) struct HttpServer {
    tasks: JoinSet<std::io::Result<()>>,
    handles: Vec<axum_server::Handle<SocketAddr>>,
    http_addr: Option<SocketAddr>,
    https_addr: Option<SocketAddr>,
}

/// Owns unstarted native futures. Dropping staged setup destroys these futures
/// and their sockets without admitting requests or starting certificate work.
pub(crate) struct PreparedHttpServer {
    tasks: Vec<BoxFuture<std::io::Result<()>>>,
    handles: Vec<axum_server::Handle<SocketAddr>>,
    http_addr: Option<SocketAddr>,
    https_addr: Option<SocketAddr>,
}

impl PreparedHttpServer {
    fn new() -> Self {
        Self {
            tasks: Vec::new(),
            handles: Vec::new(),
            http_addr: None,
            https_addr: None,
        }
    }

    fn stage_task(&mut self, task: BoxFuture<std::io::Result<()>>) {
        self.tasks.push(task);
    }

    pub(crate) fn start(self) -> HttpServer {
        let mut tasks = JoinSet::new();
        for task in self.tasks {
            tasks.spawn(task);
        }
        HttpServer {
            tasks,
            handles: self.handles,
            http_addr: self.http_addr,
            https_addr: self.https_addr,
        }
    }
}

impl HttpServer {
    /// Bind and prepare native work without starting serving or ACME tasks.
    pub(crate) async fn prepare(
        http_config: Option<HttpConfig>,
        https_config: Option<HttpsConfig>,
        rate_limit_config: RateLimitConfig,
        state: AppState,
        cert_cache_dir: PathBuf,
    ) -> Result<PreparedHttpServer> {
        if http_config.is_none() && https_config.is_none() {
            bail_any!("Either http or https config is required");
        }

        let app = create_app(state, &rate_limit_config);

        let mut prepared = PreparedHttpServer::new();
        // prepare HTTP
        let http_addr = if let Some(config) = http_config {
            let bind_addr = SocketAddr::new(
                config.bind_addr.unwrap_or(Ipv6Addr::UNSPECIFIED.into()),
                config.port,
            );
            let app = app.clone();
            let listener = TcpListener::bind(bind_addr)
                .await
                .anyerr()?
                .into_std()
                .anyerr()?;
            let bound_addr = listener.local_addr().anyerr()?;
            set_keepalive(&listener).anyerr()?;
            let handle = axum_server::Handle::new();
            prepared.handles.push(handle.clone());
            let fut = axum_server::from_tcp(listener)?
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());
            info!("HTTP server bound at {bind_addr}");
            prepared.stage_task(fut.boxed());
            Some(bound_addr)
        } else {
            None
        };

        // prepare HTTPs
        let https_addr = if let Some(config) = https_config {
            let bind_addr = SocketAddr::new(
                config.bind_addr.unwrap_or(Ipv6Addr::UNSPECIFIED.into()),
                config.port,
            );
            let (acceptor, maintenance) = {
                tokio::fs::create_dir_all(&cert_cache_dir)
                    .await
                    .with_std_context(|_| {
                        format!(
                            "failed to create cert cache dir at {}",
                            cert_cache_dir.display()
                        )
                    })?;
                config
                    .cert_mode
                    .build(
                        config.domains,
                        cert_cache_dir,
                        config.letsencrypt_contact,
                        config.letsencrypt_prod.unwrap_or(false),
                    )
                    .await?
            };
            if let Some(maintenance) = maintenance {
                prepared.stage_task(maintenance);
            }
            let listener = TcpListener::bind(bind_addr)
                .await
                .anyerr()?
                .into_std()
                .anyerr()?;
            let bound_addr = listener.local_addr().anyerr()?;
            set_keepalive(&listener).anyerr()?;
            let handle = axum_server::Handle::new();
            prepared.handles.push(handle.clone());
            let fut = axum_server::from_tcp(listener)?
                .handle(handle)
                .acceptor(acceptor)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());
            info!("HTTPS server bound at {bind_addr}");
            prepared.stage_task(fut.boxed());
            Some(bound_addr)
        } else {
            None
        };

        prepared.http_addr = http_addr;
        prepared.https_addr = https_addr;
        Ok(prepared)
    }

    /// Get the bound address of the HTTP socket.
    pub(crate) fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// Get the bound address of the HTTPS socket.
    pub(crate) fn https_addr(&self) -> Option<SocketAddr> {
        self.https_addr
    }

    /// Shutdown the server and wait for all tasks to complete.
    pub(crate) async fn shutdown(mut self) -> Result<()> {
        // Notify native connection tasks too; aborting only the listener does not.
        for handle in &self.handles {
            handle.shutdown();
        }
        self.tasks.abort_all();
        self.drain_tasks().await?;
        Ok(())
    }

    /// Wait for all tasks to complete.
    ///
    /// Runs forever unless tasks fail.
    pub(crate) async fn run_until_done(&mut self) -> Result<()> {
        match self.tasks.join_next().await {
            Some(Ok(Ok(()))) | None => Ok(()),
            Some(Ok(Err(error))) => Err(anyerr!(error, "HTTP/TLS task")),
            Some(Err(error)) => Err(anyerr!(error, "HTTP/TLS task join")),
        }
    }

    async fn drain_tasks(&mut self) -> Result<()> {
        let mut final_res: Result<()> = Ok(());
        while let Some(res) = self.tasks.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Err(err) if err.is_cancelled() => {}
                Ok(Err(err)) => {
                    warn!(?err, "task failed");
                    final_res = Err(anyerr!(err, "task"));
                }
                Err(err) => {
                    warn!(?err, "task panicked");
                    final_res = Err(anyerr!(err, "join"));
                }
            }
        }
        final_res
    }
}

/// Health check response
#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    git_hash: &'static str,
}

async fn healthz() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        git_hash: "unknown",
    })
}

pub(crate) fn create_app(state: AppState, rate_limit_config: &RateLimitConfig) -> Router {
    // configure cors middleware
    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST, Method::PUT])
        // allow requests from any origin
        .allow_origin(cors::Any);

    // configure tracing middleware
    let trace = TraceLayer::new_for_http().make_span_with(|request: &http::Request<_>| {
        let conn_info = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .expect("connectinfo extension to be present");
        let span = span!(
        Level::DEBUG,
            "http_request",
            method = ?request.method(),
            uri = ?request.uri(),
            src = %conn_info.0,
            );
        span
    });

    // configure rate limiting middleware
    let rate_limit = rate_limiting::create(rate_limit_config);

    // configure routes
    //
    // only the pkarr::put route gets a rate limit
    let router = Router::new()
        .route("/dns-query", get(doh::get).post(doh::post))
        .route(
            "/pkarr/{key}",
            if state.backend.is_injected() {
                get(pkarr::get)
            } else if let Some(rate_limit) = rate_limit {
                get(pkarr::get).put(pkarr::put.layer(rate_limit))
            } else {
                get(pkarr::get).put(pkarr::put)
            },
        )
        // Deprecated: use /healthz instead
        .route("/healthcheck", get(|| async { "OK" }))
        .route("/healthz", get(healthz))
        .route("/", get(|| async { "Hi!" }))
        .with_state(state.clone());

    // configure app
    router
        .layer(cors)
        .layer(trace)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            injected_no_store,
        ))
        .route_layer(middleware::from_fn_with_state(state, metrics_middleware))
}

// Also covers HEAD/conditional requests and extractor failures; native handlers
// still select status, body and content type. No HTTP cache bypasses admission.
async fn injected_no_store(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let no_store = state.backend.is_injected()
        && (req.uri().path() == "/dns-query" || req.uri().path().starts_with("/pkarr/"));
    let mut response = next.run(req).await;
    if no_store {
        response.headers_mut().insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        );
    }
    response
}

/// Record request metrics.
// TODO:
// * Request duration would be much better tracked as a histogram.
// * It would be great to attach labels to the metrics, so that the recorded metrics
// can filter by method etc.
//
// See also
// https://github.com/tokio-rs/axum/blob/main/examples/prometheus-metrics/src/main.rs#L114
async fn metrics_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let start = Instant::now();
    let response = next.run(req).await;
    let latency = start.elapsed().as_millis();
    let status = response.status();
    state
        .metrics
        .http_requests_duration_ms
        .inc_by(latency as u64);
    state.metrics.http_requests.inc();
    if status.is_success() {
        state.metrics.http_requests_success.inc();
    } else {
        state.metrics.http_requests_error.inc();
    }
    response
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use iroh::{
        RelayUrl, SecretKey,
        address_lookup::{EndpointInfo, PkarrRelayClient},
        dns::{DNS_TIMEOUT, DnsResolver, NameserverConfig},
        tls::{CaTlsConfig, default_provider},
    };
    use n0_error::StdResultExt;
    use n0_tracing_test::traced_test;
    use rand::{RngExt, SeedableRng};

    use crate::{http::HttpsConfig, server::Server};

    #[tokio::test]
    #[traced_test]
    async fn test_doh() -> n0_error::Result {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(0);
        let dir = tempfile::tempdir()?;
        let https_config = HttpsConfig {
            port: 0,
            bind_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            domains: vec!["localhost".to_string()],
            cert_mode: crate::http::CertMode::SelfSigned,
            letsencrypt_contact: None,
            letsencrypt_prod: None,
        };
        let server =
            Server::spawn_for_tests_with_options(dir.path(), None, None, Some(https_config))
                .await?;

        const RELAY_URL: &str = "https://relay.example./";
        let (name_z32, signed_packet) = {
            let secret_key = SecretKey::from_bytes(&rng.random());
            let endpoint_id = secret_key.public();
            let relay_url: RelayUrl = RELAY_URL.parse().expect("valid url");
            let endpoint_info = EndpointInfo::new(endpoint_id).with_relay_url(relay_url.clone());
            (
                secret_key.public().to_z32(),
                endpoint_info.to_pkarr_signed_packet(&secret_key, 30)?,
            )
        };

        let http_url = server.http_url().expect("http is bound");
        let tls_config = CaTlsConfig::default()
            .client_config(default_provider())
            .expect("infallible");
        let pkarr = PkarrRelayClient::new(
            format!("{http_url}pkarr").parse().anyerr()?,
            tls_config,
            DnsResolver::default(),
        );
        pkarr.publish(&signed_packet).await?;

        // Create a reqwest client that does not verify certificates.
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .use_preconfigured_tls(self::tls::insecure_tls_config())
            .build()
            .anyerr()?;

        // Fetch as JSON via HTTP.
        let url = format!(
            "{http_url}dns-query?name={}&type=txt",
            format_args!("_iroh.{name_z32}."),
        );
        let res = client
            .get(url)
            .header("accept", "application/dns-json")
            .send()
            .await
            .anyerr()?
            .json::<super::doh::response::DnsResponse>()
            .await
            .anyerr()?;
        assert_eq!(res.answer.len(), 1);
        assert_eq!(res.answer[0].name, format!("_iroh.{name_z32}."));
        assert_eq!(res.answer[0].data, format!("relay={RELAY_URL}"));

        // Fetch as JSON via HTTPS.
        let https_url = server.https_url().expect("https is bound");
        let url = format!(
            "{https_url}dns-query?name={}&type=txt",
            format_args!("_iroh.{name_z32}."),
        );
        let res = client
            .get(url)
            .header("accept", "application/dns-json")
            .send()
            .await
            .anyerr()?
            .json::<super::doh::response::DnsResponse>()
            .await
            .anyerr()?;
        assert_eq!(res.answer.len(), 1);
        assert_eq!(res.answer[0].name, format!("_iroh.{name_z32}."));
        assert_eq!(res.answer[0].data, format!("relay={RELAY_URL}"));

        // Fetch over DNS-over-HTTPS.
        let resolver = {
            let https_addr = server.https_addr().expect("https is bound");
            DnsResolver::builder()
                .add_nameserver_config(
                    NameserverConfig::https(https_addr.ip())
                        .with_port(https_addr.port())
                        .with_tls_server_name("localhost"),
                )
                .tls_client_config(self::tls::insecure_tls_config())
                .disable_fallback()
                .build()
        };

        let records: Vec<_> = resolver
            .lookup_txt(format!("_iroh.{name_z32}."), DNS_TIMEOUT)
            .await?
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].to_string(), format!("relay={RELAY_URL}"));

        server.shutdown().await?;
        Ok(())
    }

    mod tls {
        use std::sync::Arc;

        use rustls::{
            DigitallySignedStruct, RootCertStore,
            client::{
                ClientConfig,
                danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
            },
            crypto::{
                CryptoProvider, ring::default_provider, verify_tls12_signature,
                verify_tls13_signature,
            },
            pki_types::{CertificateDer, ServerName, UnixTime},
        };

        #[derive(Debug)]
        struct NoCertificateVerification(CryptoProvider);

        impl Default for NoCertificateVerification {
            fn default() -> Self {
                Self(default_provider())
            }
        }

        impl ServerCertVerifier for NoCertificateVerification {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                verify_tls12_signature(
                    message,
                    cert,
                    dss,
                    &self.0.signature_verification_algorithms,
                )
            }

            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                verify_tls13_signature(
                    message,
                    cert,
                    dss,
                    &self.0.signature_verification_algorithms,
                )
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                self.0.signature_verification_algorithms.supported_schemes()
            }
        }

        pub(super) fn insecure_tls_config() -> ClientConfig {
            let mut cfg = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
            cfg.dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerification::default()));
            cfg
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    struct DropWitness(Arc<AtomicBool>);
    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    #[tokio::test]
    async fn first_error_is_prompt_and_shutdown_destroys_sibling_task() {
        let dropped = Arc::new(AtomicBool::new(false));
        let witness = DropWitness(dropped.clone());
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let _witness = witness;
            std::future::pending::<std::io::Result<()>>().await
        });
        tasks.spawn(async { Err(std::io::Error::other("listener failed")) });
        let mut server = HttpServer {
            tasks,
            handles: vec![],
            http_addr: None,
            https_addr: None,
        };
        assert!(
            tokio::time::timeout(Duration::from_secs(1), server.run_until_done())
                .await
                .expect("first task completion must be prompt")
                .is_err()
        );
        assert!(!dropped.load(Ordering::SeqCst));
        server.shutdown().await.unwrap();
        assert!(dropped.load(Ordering::SeqCst));
    }
    #[tokio::test]
    async fn cancelled_staged_startup_destroys_unpolled_serving_and_maintenance() {
        use std::sync::atomic::AtomicUsize;

        use iroh_base::{PublicKey, SecretKey};

        use crate::{
            lookup::{Backend, PacketLease, PacketLookup},
            util::PublicKeyBytes,
        };

        struct CountingLookup(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl PacketLookup for CountingLookup {
            async fn lookup(&self, _: PublicKey) -> Result<Option<PacketLease>> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            }
        }
        let callbacks = Arc::new(AtomicUsize::new(0));
        let backend = Backend::injected(Arc::new(CountingLookup(callbacks.clone())));
        let key =
            PublicKeyBytes::new_unchecked(*SecretKey::from_bytes(&[7; 32]).public().as_bytes());
        let serving_dropped = Arc::new(AtomicBool::new(false));
        let maintenance_dropped = Arc::new(AtomicBool::new(false));
        let maintenance_started = Arc::new(AtomicBool::new(false));
        let serving_witness = DropWitness(serving_dropped.clone());
        let maintenance_witness = DropWitness(maintenance_dropped.clone());
        let started = maintenance_started.clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let preparation_entered = entered.clone();
        let mut startup = Box::pin(async move {
            let mut prepared = PreparedHttpServer::new();
            // Exercise the production ownership path used by both native serving
            // and ACME work; stage_task must never spawn or poll either future.
            prepared.stage_task(
                async move {
                    let _witness = serving_witness;
                    let _ = backend.packet(&key).await;
                    std::future::pending().await
                }
                .boxed(),
            );
            prepared.stage_task(
                async move {
                    let _witness = maintenance_witness;
                    started.store(true, Ordering::SeqCst);
                    std::future::pending().await
                }
                .boxed(),
            );
            preparation_entered.notify_one();
            std::future::pending::<()>().await;
            prepared.start()
        });
        tokio::select! {
            _ = &mut startup => unreachable!("preparation remains pending"),
            _ = entered.notified() => {},
        }
        // Give any prematurely spawned task a scheduling opportunity while
        // staged ownership remains retained, before cancellation can hide it.
        tokio::task::yield_now().await;
        assert_eq!(callbacks.load(Ordering::SeqCst), 0);
        assert!(!maintenance_started.load(Ordering::SeqCst));
        assert!(!serving_dropped.load(Ordering::SeqCst));
        assert!(!maintenance_dropped.load(Ordering::SeqCst));
        drop(startup);
        tokio::task::yield_now().await;
        assert!(serving_dropped.load(Ordering::SeqCst));
        assert!(maintenance_dropped.load(Ordering::SeqCst));
        assert_eq!(callbacks.load(Ordering::SeqCst), 0);
        assert!(!maintenance_started.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn owned_maintenance_is_destroyed_after_shutdown_and_sibling_failure() {
        for sibling_fails in [false, true] {
            let dropped = Arc::new(AtomicBool::new(false));
            let witness = DropWitness(dropped.clone());
            let entered = Arc::new(tokio::sync::Notify::new());
            let maintenance_entered = entered.clone();
            let mut prepared = PreparedHttpServer::new();
            prepared.stage_task(
                async move {
                    let _witness = witness;
                    maintenance_entered.notify_one();
                    std::future::pending().await
                }
                .boxed(),
            );
            if sibling_fails {
                prepared.stage_task(async { Err(std::io::Error::other("serving failed")) }.boxed());
            }
            let mut server = prepared.start();
            entered.notified().await;
            if sibling_fails {
                assert!(
                    tokio::time::timeout(Duration::from_secs(1), server.run_until_done())
                        .await
                        .expect("first task completion must be prompt")
                        .is_err()
                );
            }
            server.shutdown().await.unwrap();
            assert!(dropped.load(Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn maintenance_failure_is_observed_and_pending_serving_is_drained() {
        let dropped = Arc::new(AtomicBool::new(false));
        let witness = DropWitness(dropped.clone());
        let mut prepared = PreparedHttpServer::new();
        prepared.stage_task(
            async move {
                let _witness = witness;
                std::future::pending().await
            }
            .boxed(),
        );
        prepared.stage_task(async { Err(std::io::Error::other("maintenance failed")) }.boxed());
        let mut server = prepared.start();
        let error = tokio::time::timeout(Duration::from_secs(1), server.run_until_done())
            .await
            .expect("maintenance failure must be prompt")
            .unwrap_err();
        let cause = std::error::Error::source(&error).unwrap();
        assert_eq!(
            cause.downcast_ref::<std::io::Error>().unwrap().to_string(),
            "maintenance failed"
        );
        server.shutdown().await.unwrap();
        assert!(dropped.load(Ordering::SeqCst));
    }
}
