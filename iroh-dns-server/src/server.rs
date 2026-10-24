//! The main server which combines the DNS and HTTP(S) servers.
#[cfg(test)]
use std::path::Path;
use std::{net::SocketAddr, sync::Arc};

use n0_error::{Result, bail_any};
use tracing::info;
#[cfg(test)]
use url::Url;

#[cfg(test)]
use crate::http::HttpsConfig;
use crate::{
    config::Config,
    dns::{DnsHandler, DnsServer},
    http::HttpServer,
    lookup::{Backend, PacketLookup},
    metrics::Metrics,
    state::AppState,
    store::ZoneStore,
};

/// A running iroh-dns server.
///
/// Combines a DNS listener and an HTTP/HTTPS listener into a single handle.
/// Construct with [`Self::bind`], observe completion with [`Self::run_until_done`],
/// then retain and await [`Self::shutdown`]. [`Self::join`] combines waiting and cleanup.
#[derive(Debug)]
pub struct Server {
    http_server: HttpServer,
    dns_server: DnsServer,
    metrics_server: Option<iroh_metrics::service::MetricsServer>,
    metrics: Arc<Metrics>,
    backend: Backend,
}

impl Server {
    /// Binds and spawns the server from a [`Config`].
    ///
    /// Opens the persistent signed-packet store, enables the mainline DHT
    /// fallback when configured, and spawns the DNS, HTTP(S), and metrics tasks.
    /// Returns once all listeners are bound.
    pub async fn bind(config: Config) -> Result<Self> {
        let metrics = Arc::new(Metrics::default());
        let mut store = ZoneStore::persistent(
            config.signed_packet_store_path()?,
            config.zone_store.clone().unwrap_or_default().into(),
            metrics.clone(),
        )?;
        if let Some(bootstrap) = config.mainline_enabled() {
            info!("mainline fallback enabled");
            store = store.with_mainline_fallback(bootstrap);
        };
        Self::bind_with_store(config, store, metrics).await
    }

    /// Bind native listeners using a host-owned lookup for every dynamic request.
    ///
    /// No packet database, LRU or Mainline fallback is created. Mainline must be
    /// disabled. The host owns authority/freshness policy; unavailable evidence
    /// becomes SERVFAIL/503. Pkarr PUT is disabled. Static zones remain native.
    pub async fn bind_with_lookup(config: Config, lookup: Arc<dyn PacketLookup>) -> Result<Self> {
        if config.mainline_enabled().is_some() {
            bail_any!("Mainline must be disabled with an injected packet lookup");
        }
        Self::bind_with_backend(
            config,
            Backend::injected(lookup),
            Arc::new(Metrics::default()),
        )
        .await
    }

    /// Spawn the server.
    ///
    /// This will spawn several background tasks:
    /// * A DNS server task
    /// * A HTTP server task, if `config.http` is not empty
    /// * A HTTPS server task, if `config.https` is not empty
    async fn bind_with_store(
        config: Config,
        store: ZoneStore,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        Self::bind_with_backend(config, store.into(), metrics).await
    }

    async fn bind_with_backend(
        config: Config,
        backend: Backend,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let cert_cache_dir = config.data_dir()?.join("cert_cache");
        let dns_handler = DnsHandler::new(backend.clone(), &config.dns, metrics.clone())?;

        let state = AppState {
            backend: backend.clone(),
            dns_handler,
            metrics: metrics.clone(),
        };

        let metrics_addr = config.metrics_addr();
        let http = HttpServer::prepare(
            config.http,
            config.https,
            config.pkarr_put_rate_limit,
            state.clone(),
            cert_cache_dir,
        )
        .await?;
        let dns = DnsServer::prepare(config.dns, state.dns_handler.clone()).await?;

        // Metrics owns an abort-on-drop task. Its only preparation await is the
        // bind; after it returns there is no await before all ownership returns
        // as Server. No dynamic request or ACME work runs during preparation.
        let metrics_server = if let Some(addr) = metrics_addr {
            let mut registry = iroh_metrics::Registry::default();
            registry.register(metrics.clone());
            let server =
                iroh_metrics::service::MetricsServer::spawn(addr, Arc::new(registry)).await?;
            Some(server)
        } else {
            None
        };

        let http_server = http.start();
        let dns_server = dns.start();

        Ok(Self {
            http_server,
            dns_server,
            metrics_server,
            metrics,
            backend,
        })
    }

    /// Cancels native tasks and awaits entered host lookup destruction.
    ///
    /// Retain and await this consuming future. Dropping it cannot promise an
    /// asynchronous drain or destruction of every operating-system connection.
    pub async fn shutdown(mut self) -> Result<()> {
        self.backend.cancel();
        let (dns, http) = tokio::join!(self.dns_server.shutdown(), self.http_server.shutdown());
        if let Some(server) = self.metrics_server.take() {
            server.shutdown().await;
        }
        self.backend.drain().await;
        dns?;
        http?;
        Ok(())
    }

    /// Wait for native DNS or HTTP/TLS task completion without requesting shutdown.
    ///
    /// Cancelling a pending wait leaves this server owned and running. The caller
    /// may wait again or retain and await [`Self::shutdown`]. After a terminal
    /// result, stop admission and shut down; terminal results are not guaranteed to repeat.
    /// This notification proves neither readiness nor cleanup. HTTP task ownership
    /// includes HTTPS and ACME maintenance; metrics are not observed by this wait.
    pub async fn run_until_done(&mut self) -> Result<()> {
        tokio::select! {
            res = self.dns_server.run_until_done() => res,
            res = self.http_server.run_until_done() => res,
        }
    }

    /// Wait for native listener completion, then cancel and drain siblings.
    ///
    /// Retain and await this consuming future through cleanup, including after an
    /// error. An original listener error takes precedence over a cleanup error.
    pub async fn join(mut self) -> Result<()> {
        let result = self.run_until_done().await;
        let cleanup = self.shutdown().await;
        result?;
        cleanup
    }

    /// Returns the [`Metrics`] for this server.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Spawn a server suitable for testing.
    ///
    /// This will run the DNS and HTTP servers, but not the HTTPS server.
    ///
    /// It returns the server handle, the [`SocketAddr`] of the DNS server and the [`Url`] of the
    /// HTTP server.
    #[cfg(test)]
    pub(crate) async fn spawn_for_tests(dir: impl AsRef<Path>) -> Result<Self> {
        Self::spawn_for_tests_with_options(dir, None, None, None).await
    }

    /// Spawn a server suitable for testing, while optionally enabling mainline with custom
    /// bootstrap addresses.
    #[cfg(test)]
    pub(crate) async fn spawn_for_tests_with_options(
        dir: impl AsRef<Path>,
        mainline: Option<crate::config::BootstrapOption>,
        options: Option<crate::store::Options>,
        https: Option<HttpsConfig>,
    ) -> Result<Self> {
        use std::net::{IpAddr, Ipv4Addr};

        use crate::config::MetricsConfig;

        let mut config = Config::default();
        config.dns.port = 0;
        config.dns.bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        config.http.as_mut().unwrap().port = 0;
        config.http.as_mut().unwrap().bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        config.https = https;
        config.metrics = Some(MetricsConfig::disabled());
        config.data_dir = Some(dir.as_ref().to_owned());

        let mut store = ZoneStore::in_memory(options.unwrap_or_default(), Default::default())?;
        if let Some(bootstrap) = mainline {
            info!("mainline fallback enabled");
            store = store.with_mainline_fallback(bootstrap);
        }
        let server = Self::bind_with_store(config, store, Default::default()).await?;
        Ok(server)
    }

    /// Returns the local address that the DNS listener is bound to.
    pub fn dns_addr(&self) -> SocketAddr {
        self.dns_server.local_addr()
    }

    /// Returns the local address of the HTTP listener, or `None` if no HTTP
    /// listener was configured.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_server.http_addr()
    }

    /// Returns the local address of the HTTPS listener, or `None` if no HTTPS
    /// listener was configured.
    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.http_server.https_addr()
    }

    #[cfg(test)]
    pub(crate) fn http_url(&self) -> Option<Url> {
        let http_addr = self.http_server.http_addr()?;
        Some(
            format!("http://{http_addr}")
                .parse::<url::Url>()
                .expect("valid url"),
        )
    }

    #[cfg(test)]
    pub(crate) fn https_url(&self) -> Option<Url> {
        let https_addr = self.https_addr()?;
        Some(
            format!("https://{https_addr}")
                .parse::<url::Url>()
                .expect("valid url"),
        )
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use std::{
        future::{Future, pending, poll_fn},
        net::{IpAddr, Ipv4Addr},
        sync::atomic::{AtomicUsize, Ordering},
        task::Poll,
        time::Duration,
    };

    use iroh_base::{PublicKey, SecretKey};
    use n0_future::FutureExt;
    use tokio::sync::Notify;

    use super::*;
    use crate::{
        config::MetricsConfig,
        http::{CertMode, HttpConfig},
        lookup::PacketLease,
    };

    async fn complete_scenario(future: impl Future<Output = ()>) {
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .expect("complete scenario, including request entry and retained cleanup, must finish");
    }

    struct DropWitness(Arc<AtomicUsize>);
    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PendingLookup {
        entered: Notify,
        dropped: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl PacketLookup for PendingLookup {
        async fn lookup(&self, _: PublicKey) -> Result<Option<PacketLease>> {
            let _witness = DropWitness(self.dropped.clone());
            self.entered.notify_one();
            pending().await
        }
    }

    async fn fixture(http: bool, https: bool) -> (tempfile::TempDir, Server, Arc<PendingLookup>) {
        let dir = tempfile::tempdir().expect("temporary fixture directory");
        let mut config = Config {
            data_dir: Some(dir.path().to_owned()),
            ..Config::default()
        };
        config.dns.port = 0;
        config.dns.bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        config.metrics = Some(MetricsConfig::disabled());
        config.mainline = None;
        config.http = http.then_some(HttpConfig {
            port: 0,
            bind_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            listen_backlog: None,
        });
        config.https = https.then_some(HttpsConfig {
            port: 0,
            bind_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            listen_backlog: None,
            domains: vec!["localhost".to_owned()],
            cert_mode: CertMode::SelfSigned,
            letsencrypt_contact: None,
            letsencrypt_prod: None,
        });
        let lookup = Arc::new(PendingLookup {
            entered: Notify::new(),
            dropped: Arc::new(AtomicUsize::new(0)),
        });
        let server = Server::bind_with_lookup(config, lookup.clone())
            .await
            .expect("native loopback listeners bind");
        assert_eq!(server.http_addr().is_some(), http);
        assert_eq!(server.https_addr().is_some(), https);
        (dir, server, lookup)
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .tls_backend_preconfigured(crate::http::tests::tls::insecure_tls_config())
            .build()
            .expect("local self-signed fixture client")
    }

    async fn cancel_pending_wait(server: &mut Server) {
        let mut wait = Box::pin(server.run_until_done());
        // Poll the actual native select, rather than cancelling an unentered future.
        poll_fn(|cx| {
            assert!(wait.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(wait);
    }

    async fn cancel_retry_and_shutdown(http: bool, https: bool) {
        complete_scenario(async {
            let (_dir, mut server, lookup) = fixture(http, https).await;
            let client = client();
            let url = server.http_url().or_else(|| server.https_url()).unwrap();
            let key = SecretKey::from_bytes(&[7; 32]).public().to_z32();
            let mut request = client
                .get(url.join(&format!("pkarr/{key}")).unwrap())
                .send()
                .boxed();
            tokio::select! {
                _ = &mut request => panic!("lookup remains entered until shutdown"),
                _ = lookup.entered.notified() => {},
            }
            for _ in 0..2 {
                cancel_pending_wait(&mut server).await;
                assert_eq!(lookup.dropped.load(Ordering::SeqCst), 0);
                // Both configured real listeners still serve after wait cancellation.
                for url in [server.http_url(), server.https_url()]
                    .into_iter()
                    .flatten()
                {
                    assert!(
                        client
                            .get(url.join("healthz").unwrap())
                            .send()
                            .await
                            .unwrap()
                            .status()
                            .is_success()
                    );
                }
            }
            let dns_addr = server.dns_addr();
            let shutdown = server.shutdown();
            tokio::pin!(shutdown);
            shutdown.as_mut().await.expect("retained shutdown succeeds");
            assert_eq!(lookup.dropped.load(Ordering::SeqCst), 1);
            drop(request);
            // Native UDP and TCP listener ownership was released by awaited cleanup.
            let _udp = tokio::net::UdpSocket::bind(dns_addr).await.unwrap();
            let _tcp = tokio::net::TcpListener::bind(dns_addr).await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn borrowed_wait_cancel_retry_http_only() {
        cancel_retry_and_shutdown(true, false).await;
    }

    #[tokio::test]
    async fn borrowed_wait_cancel_retry_https_only() {
        cancel_retry_and_shutdown(false, true).await;
    }

    #[tokio::test]
    async fn borrowed_wait_cancel_retry_http_and_https() {
        cancel_retry_and_shutdown(true, true).await;
    }

    async fn completed_task(server: &mut Server, error: Option<&'static str>) {
        let task = server.http_server.spawn_test_task(
            async move {
                match error {
                    Some(message) => Err(std::io::Error::other(message)),
                    None => Ok(()),
                }
            }
            .boxed(),
        );
        // Ensure this completed result is queued before queuing another result.
        while !task.is_finished() {
            tokio::task::yield_now().await;
        }
    }

    fn contains_cause(error: &(dyn std::error::Error + 'static), message: &str) -> bool {
        error.to_string() == message
            || error
                .source()
                .is_some_and(|source| contains_cause(source, message))
    }

    async fn failure_cleanup(join: bool, original_error: bool) {
        complete_scenario(async {
            let (_dir, mut server, lookup) = fixture(true, false).await;
            let client = client();
            let key = SecretKey::from_bytes(&[7; 32]).public().to_z32();
            let url = server
                .http_url()
                .unwrap()
                .join(&format!("pkarr/{key}"))
                .unwrap();
            let mut request = client.get(url).send().boxed();
            tokio::select! {
                _ = &mut request => panic!("entered lookup must remain pending"),
                _ = lookup.entered.notified() => {},
            }
            let serving_dropped = Arc::new(AtomicUsize::new(0));
            let witness = DropWitness(serving_dropped.clone());
            let entered = Arc::new(Notify::new());
            let task_entered = entered.clone();
            server.http_server.spawn_test_task(
                async move {
                    let _witness = witness;
                    task_entered.notify_one();
                    pending().await
                }
                .boxed(),
            );
            entered.notified().await;
            cancel_pending_wait(&mut server).await;
            completed_task(
                &mut server,
                original_error.then_some("original listener failure"),
            )
            .await;
            if join {
                completed_task(&mut server, Some("competing cleanup failure")).await;
                let error = tokio::time::timeout(Duration::from_secs(2), server.join())
                    .await
                    .expect("completion and cleanup must be prompt")
                    .unwrap_err();
                assert!(contains_cause(
                    &error,
                    if original_error {
                        "original listener failure"
                    } else {
                        "competing cleanup failure"
                    }
                ));
                if original_error {
                    assert!(!contains_cause(&error, "competing cleanup failure"));
                }
            } else {
                let error = tokio::time::timeout(Duration::from_secs(1), server.run_until_done())
                    .await
                    .expect("native HTTP task failure must be prompt")
                    .unwrap_err();
                assert!(contains_cause(&error, "original listener failure"));
                assert_eq!(lookup.dropped.load(Ordering::SeqCst), 0);
                assert_eq!(serving_dropped.load(Ordering::SeqCst), 0);
                completed_task(&mut server, Some("competing cleanup failure")).await;
                let cleanup = server.shutdown().await.unwrap_err();
                assert!(contains_cause(&cleanup, "competing cleanup failure"));
                assert!(contains_cause(&error, "original listener failure"));
            }
            assert_eq!(lookup.dropped.load(Ordering::SeqCst), 1);
            assert_eq!(serving_dropped.load(Ordering::SeqCst), 1);
            drop(request);
        })
        .await;
    }

    #[tokio::test]
    async fn borrowed_failure_preserves_ownership_until_explicit_cleanup() {
        failure_cleanup(false, true).await;
    }

    #[tokio::test]
    async fn consuming_join_drains_before_returning_original_error() {
        failure_cleanup(true, true).await;
    }

    #[tokio::test]
    async fn consuming_join_returns_cleanup_error_after_successful_wait() {
        failure_cleanup(true, false).await;
    }
}
