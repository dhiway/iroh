//! Implementation of a DNS name server for iroh endpoint announces

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use hickory_server::{
    net::{NetError, runtime::TokioTime, xfer::Protocol},
    proto::{
        self,
        op::ResponseCode,
        rr::{
            LowerName, Name, RData, Record, RecordSet, RecordType, RrKey,
            rdata::{self},
        },
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{AxfrPolicy, Catalog, MessageResponse, ZoneType},
};
use n0_error::{Result, StdResultExt, anyerr};
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::broadcast,
};
use tracing::{debug, info};

use self::node_zone_handler::NodeZoneHandler;
use crate::{lookup::Backend, metrics::Metrics};

mod node_zone_handler;

const DEFAULT_NS_TTL: u32 = 60 * 60 * 12; // 12h
const DEFAULT_SOA_TTL: u32 = 60 * 60 * 24 * 14; // 14d
const DEFAULT_A_TTL: u32 = 60 * 60; // 1h

/// Configuration for the DNS listener.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DnsConfig {
    /// Port to bind the DNS listener to, for both UDP and TCP.
    pub port: u16,
    /// Address to bind the DNS listener to (defaults to `::`, i.e. IPv6 wildcard which also covers IPv4).
    pub bind_addr: Option<IpAddr>,
    /// SOA record data served for authoritative zones, in zone-file format.
    pub default_soa: String,
    /// Default time-to-live, in seconds, for returned DNS records.
    pub default_ttl: u32,
    /// Origins under which the server publishes pkarr-signed zones.
    ///
    /// For each origin, the server answers queries for any published
    /// `<endpointid>.<origin>` name.
    pub origins: Vec<String>,

    /// Optional `A` record to serve at each origin apex.
    pub rr_a: Option<Ipv4Addr>,
    /// Optional `AAAA` record to serve at each origin apex.
    pub rr_aaaa: Option<Ipv6Addr>,
    /// Optional `NS` record to serve at each origin apex.
    pub rr_ns: Option<String>,
}

impl DnsConfig {
    /// Creates a new [`DnsConfig`] with the given required fields.
    ///
    /// The optional `bind_addr` and apex resource records (`rr_a`, `rr_aaaa`, `rr_ns`)
    /// default to `None`. Assign them after construction to override.
    pub fn new(port: u16, default_soa: String, default_ttl: u32, origins: Vec<String>) -> Self {
        Self {
            port,
            bind_addr: None,
            default_soa,
            default_ttl,
            origins,
            rr_a: None,
            rr_aaaa: None,
            rr_ns: None,
        }
    }
}

/// A DNS server that serves pkarr signed packets.
#[derive(derive_more::Debug)]
pub(crate) struct DnsServer {
    local_addr: SocketAddr,
    #[debug("hickory_server::Server<DnsHandler> (UDP)")]
    udp: hickory_server::Server<DnsHandler>,
    #[debug("hickory_server::Server<DnsHandler> (TCP)")]
    tcp: hickory_server::Server<DnsHandler>,
}

pub(crate) struct PreparedDnsServer {
    socket: UdpSocket,
    listener: TcpListener,
    handler: DnsHandler,
    local_addr: SocketAddr,
}

impl PreparedDnsServer {
    pub(crate) fn start(self) -> DnsServer {
        const TCP_TIMEOUT: Duration = Duration::from_millis(1000);
        const TCP_RESPONSE_BUFFER: usize = 64 * 1024;
        let mut udp = hickory_server::Server::new(self.handler.clone());
        let mut tcp = hickory_server::Server::new(self.handler);
        udp.register_socket(self.socket);
        tcp.register_listener(self.listener, TCP_TIMEOUT, TCP_RESPONSE_BUFFER);
        DnsServer {
            udp,
            tcp,
            local_addr: self.local_addr,
        }
    }
}

impl DnsServer {
    /// Bind both transports without registering native serving tasks.
    pub(crate) async fn prepare(
        config: DnsConfig,
        dns_handler: DnsHandler,
    ) -> Result<PreparedDnsServer> {
        let bind_addr = SocketAddr::new(
            config.bind_addr.unwrap_or(Ipv6Addr::UNSPECIFIED.into()),
            config.port,
        );

        let socket = UdpSocket::bind(bind_addr).await.anyerr()?;

        let socket_addr = socket.local_addr().anyerr()?;

        // Bind both before spawning native transport work. Port zero still means
        // one selected port for both transports, as required by DnsConfig.
        let listener = TcpListener::bind(socket_addr).await.anyerr()?;
        info!("DNS server listening on {}", bind_addr);

        Ok(PreparedDnsServer {
            socket,
            listener,
            handler: dns_handler,
            local_addr: socket_addr,
        })
    }

    /// Get the local address of the UDP/TCP socket.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Shutdown the server an wait for all tasks to complete.
    pub(crate) async fn shutdown(mut self) -> Result<()> {
        let (udp, tcp) = tokio::join!(
            self.udp.shutdown_gracefully(),
            self.tcp.shutdown_gracefully()
        );
        udp.anyerr()?;
        tcp.anyerr()?;
        Ok(())
    }

    /// Wait for all tasks to complete.
    ///
    /// Runs forever unless tasks fail.
    pub(crate) async fn run_until_done(&mut self) -> Result<()> {
        // One native handle per transport lets ordinary transport errors report
        // promptly instead of waiting forever for the other live transport.
        tokio::select! {
            result = self.udp.block_until_done() => result.anyerr(),
            result = self.tcp.block_until_done() => result.anyerr(),
        }
    }
}

/// State for serving DNS
#[derive(Clone, derive_more::Debug)]
pub(crate) struct DnsHandler {
    #[debug("Catalog")]
    catalog: Arc<Catalog>,
    metrics: Arc<Metrics>,
}

impl DnsHandler {
    /// Create a DNS server given some settings, a connection to the DB for DID-by-username lookups
    /// and the server DID to serve under `_did.<origin>`.
    pub(crate) fn new(
        zone_store: impl Into<Backend>,
        config: &DnsConfig,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let origins = config
            .origins
            .iter()
            .map(Name::from_utf8)
            .collect::<Result<Vec<_>, _>>()
            .anyerr()?;

        let (static_authority, serial) = create_static_authority(&origins, config)?;
        let authority = Arc::new(NodeZoneHandler::new(
            zone_store.into(),
            static_authority,
            origins,
            serial,
        )?);

        let mut catalog = Catalog::new();
        for origin in authority.origins() {
            catalog.upsert(LowerName::from(origin), vec![authority.clone()]);
        }

        Ok(Self {
            catalog: Arc::new(catalog),
            metrics,
        })
    }

    /// Handle a DNS request
    pub(crate) async fn answer_request(&self, request: Request) -> Result<Bytes> {
        let (tx, mut rx) = broadcast::channel(1);
        let response_handle = Handle(tx);
        self.handle_request::<_, TokioTime>(&request, response_handle)
            .await;
        rx.recv().await.anyerr()
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler, T: hickory_server::net::runtime::Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        self.metrics.dns_requests.inc();
        match request.protocol() {
            Protocol::Udp => {
                self.metrics.dns_requests_udp.inc();
            }
            Protocol::Https => {
                self.metrics.dns_requests_https.inc();
            }
            _ => {}
        }
        debug!(protocol=%request.protocol(), queries=?request.queries, "incoming DNS request");

        let unavailable = Arc::new(AtomicBool::new(false));
        let response_handle = AdmissionResponse {
            inner: response_handle,
            unavailable: unavailable.clone(),
        };
        let res = DYNAMIC_UNAVAILABLE
            .scope(
                unavailable,
                self.catalog
                    .handle_request::<_, T>(request, response_handle),
            )
            .await;
        match res.response_code {
            ResponseCode::NoError => match res.counts().answers {
                0 => self.metrics.dns_lookup_notfound.inc(),
                _ => self.metrics.dns_lookup_success.inc(),
            },
            ResponseCode::NXDomain => self.metrics.dns_lookup_notfound.inc(),
            _ => self.metrics.dns_lookup_error.inc(),
        };
        res
    }
}

// Hickory 0.26.3 Catalog's authoritative path turns ServFail lookup errors into
// NoError/NODATA with a negative SOA. Refused is its supported early return.
// Keep the native writer and alter only a marked injected unavailable response;
// revisit this adapter when that upstream limitation is fixed.
tokio::task_local! {
    static DYNAMIC_UNAVAILABLE: Arc<AtomicBool>;
}

fn mark_dynamic_unavailable() {
    let _ = DYNAMIC_UNAVAILABLE.try_with(|marker| marker.store(true, Ordering::Relaxed));
}

#[derive(Clone)]
struct AdmissionResponse<R> {
    inner: R,
    unavailable: Arc<AtomicBool>,
}

#[async_trait]
impl<R: ResponseHandler> ResponseHandler for AdmissionResponse<R> {
    async fn send_response<'a>(
        &mut self,
        mut response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        if self.unavailable.load(Ordering::Relaxed)
            && response.metadata().response_code == ResponseCode::Refused
        {
            response.metadata_mut().response_code = ResponseCode::ServFail;
        }
        self.inner.send_response(response).await
    }
}

/// A handle to the channel over which the response to a DNS request will be sent
#[derive(Debug, Clone)]
pub(crate) struct Handle(pub broadcast::Sender<Bytes>);

#[async_trait]
impl ResponseHandler for Handle {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let mut bytes = Vec::with_capacity(512);
        let info = {
            let mut encoder = proto::serialize::binary::BinEncoder::new(&mut bytes);
            response.destructive_emit(&mut encoder)?
        };
        self.0.send(Bytes::from(bytes)).unwrap();
        Ok(info)
    }
}

fn create_static_authority(
    origins: &[Name],
    config: &DnsConfig,
) -> Result<(InMemoryZoneHandler, u32)> {
    let soa = match RData::try_from_str(RecordType::SOA, &config.default_soa).anyerr()? {
        RData::SOA(soa) => soa,
        _ => return Err(anyerr!("Couldn't parse SOA: {}", config.default_soa)),
    };
    let serial = soa.serial;
    let mut records = BTreeMap::new();
    for name in origins {
        push_record(
            &mut records,
            serial,
            Record::from_rdata(name.clone(), DEFAULT_SOA_TTL, RData::SOA(soa.clone())),
        );
        if let Some(addr) = config.rr_a {
            push_record(
                &mut records,
                serial,
                Record::from_rdata(name.clone(), DEFAULT_A_TTL, RData::A(addr.into())),
            );
        }
        if let Some(addr) = config.rr_aaaa {
            push_record(
                &mut records,
                serial,
                Record::from_rdata(name.clone(), DEFAULT_A_TTL, RData::AAAA(addr.into())),
            );
        }
        if let Some(ns) = &config.rr_ns {
            let ns = Name::parse(ns, Some(&Name::root())).anyerr()?;
            push_record(
                &mut records,
                serial,
                Record::from_rdata(name.clone(), DEFAULT_NS_TTL, RData::NS(rdata::NS(ns))),
            );
        }
    }

    let static_authority =
        InMemoryZoneHandler::new(Name::root(), records, ZoneType::Primary, AxfrPolicy::Deny)
            .map_err(|e| anyerr!("new authority: {e}"))?;

    Ok((static_authority, serial))
}

fn push_record(records: &mut BTreeMap<RrKey, RecordSet>, serial: u32, record: Record) {
    let key = RrKey::new(record.name.clone().into(), record.record_type());
    let mut record_set = RecordSet::new(record.name.clone(), record.record_type(), serial);
    record_set.insert(record, serial);
    records.insert(key, record_set);
}

#[cfg(test)]
mod admission_response_tests {
    use hickory_server::{
        proto::serialize::binary::{BinDecodable, BinEncodable},
        zone_handler::MessageResponseBuilder,
    };

    use super::*;

    #[tokio::test]
    async fn unmarked_native_refused_is_not_relabelled() {
        let (tx, mut rx) = broadcast::channel(1);
        let mut response = AdmissionResponse {
            inner: Handle(tx),
            unavailable: Arc::new(AtomicBool::new(false)),
        };
        let query = Request::from_bytes(
            proto::op::Message::query().to_bytes().unwrap(),
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Https,
        )
        .unwrap();
        let native = MessageResponseBuilder::new(&query.queries, None)
            .error_msg(&query.metadata, ResponseCode::Refused);
        response.send_response(native).await.unwrap();
        let bytes = rx.recv().await.unwrap();
        assert_eq!(
            proto::op::Message::from_bytes(&bytes)
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::Refused
        );
    }
}
