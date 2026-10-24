use std::{
    future::pending,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use hickory_server::proto::{
    op::{Message, Query, ResponseCode},
    serialize::binary::{BinDecodable, BinEncodable},
};
use iroh_base::SecretKey;
use tower::ServiceExt;

use super::*;
use crate::{
    config::Config,
    dns::DnsHandler,
    http::{RateLimitConfig, create_app},
    metrics::Metrics,
    state::AppState,
};

struct Host {
    view: Mutex<Option<PacketLease>>,
    calls: AtomicUsize,
}
#[async_trait]
impl PacketLookup for Host {
    async fn lookup(&self, _: PublicKey) -> Result<Option<PacketLease>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.view.lock().unwrap().clone())
    }
}
fn packet(ttl: u32) -> SignedPacket {
    SignedPacket::from_txt_strings(&SecretKey::from_bytes(&[7; 32]), "_iroh", ["hello"], ttl)
        .unwrap()
}
fn lease(packet: SignedPacket) -> PacketLease {
    PacketLease::new(
        packet,
        Instant::now(),
        Duration::ZERO,
        Duration::from_secs(60),
    )
}
fn host(view: Option<PacketLease>) -> Arc<Host> {
    Arc::new(Host {
        view: Mutex::new(view),
        calls: AtomicUsize::new(0),
    })
}
fn app(backend: Backend) -> axum::Router {
    let metrics = Arc::new(Metrics::default());
    let handler =
        DnsHandler::new(backend.clone(), &Config::default().dns, metrics.clone()).unwrap();
    create_app(
        AppState {
            backend,
            dns_handler: handler,
            metrics,
        },
        &RateLimitConfig::default(),
    )
}
fn request(method: &str, uri: &str, body: Vec<u8>) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
    ));
    request
}

#[test]
fn timing_fails_closed_and_floors_remaining_seconds() {
    let now = Instant::now();
    let mut value = PacketLease::new(
        packet(10),
        now,
        Duration::from_millis(2500),
        Duration::from_secs(6),
    );
    let timing = value.timing_at(now + Duration::from_millis(500)).unwrap();
    assert_eq!(PacketLease::ttl_left(10, timing), Some(5));
    assert_eq!(PacketLease::ttl_left(3, timing), None);
    assert!(value.timing_at(now - Duration::from_millis(1)).is_none());
    assert!(value.timing_at(now + Duration::from_millis(5500)).is_none());
    value.age_at_observation = Duration::MAX;
    assert!(value.timing_at(now + Duration::from_nanos(1)).is_none());
}

#[tokio::test]
async fn reconsults_host_and_rejects_wrong_signer() {
    let original = packet(30);
    let key = PublicKeyBytes::from_signed_packet(&original);
    let host = host(Some(lease(original.clone())));
    let backend = Backend::injected(host.clone());
    assert_eq!(backend.packet(&key).await.unwrap(), Some(original));
    *host.view.lock().unwrap() = None;
    assert!(backend.packet(&key).await.unwrap().is_none());
    *host.view.lock().unwrap() = Some(lease(
        SignedPacket::from_txt_strings(&SecretKey::from_bytes(&[8; 32]), "_iroh", ["hello"], 30)
            .unwrap(),
    ));
    assert!(backend.packet(&key).await.is_err());
    assert_eq!(host.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn pkarr_native_bytes_head_conditional_and_disabled_put() {
    let original = packet(30);
    let key = original.public_key().to_z32();
    let host = host(Some(lease(original.clone())));
    let app = app(Backend::injected(host.clone()));
    let uri = format!("/pkarr/{key}");
    let response = app
        .clone()
        .oneshot(request("GET", &uri, vec![]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.headers()["content-type"],
        "application/x-pkarr-signed-packet"
    );
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .as_ref(),
        original.to_relay_payload()
    );
    let mut conditional = request("GET", &uri, vec![]);
    conditional
        .headers_mut()
        .insert("if-none-match", "*".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(conditional).await.unwrap().status(),
        StatusCode::OK
    );
    let response = app
        .clone()
        .oneshot(request("HEAD", &uri, vec![]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty()
    );
    let response = app
        .clone()
        .oneshot(request("PUT", &uri, vec![255]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(
        response.headers()["allow"]
            .to_str()
            .unwrap()
            .contains("GET")
    );
    assert_eq!(host.calls.load(Ordering::SeqCst), 3);
    *host.view.lock().unwrap() = None;
    let response = app.oneshot(request("GET", &uri, vec![])).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["cache-control"], "no-store");
}

#[tokio::test]
async fn doh_unavailable_and_query_miss_are_servfail_without_negative_soa() {
    for view in [None, Some(lease(packet(30))), Some(lease(packet(0)))] {
        let key = packet(30).public_key().to_z32();
        let app = app(Backend::injected(host(view)));
        let mut query = Message::query();
        query.add_query(Query::query(
            Name::from_utf8(format!("missing.{key}.irohdns.example.")).unwrap(),
            RecordType::TXT,
        ));
        let response = app
            .oneshot(request("POST", "/dns-query", query.to_bytes().unwrap()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.headers()["content-type"],
            "application/dns-message"
        );
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let message = Message::from_bytes(&bytes).unwrap();
        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
        assert!(message.answers.is_empty());
        assert!(message.authorities.is_empty());
    }
}

struct PendingHost {
    entered: tokio::sync::Notify,
    dropped: Arc<AtomicBool>,
    calls: AtomicUsize,
}
struct Witness(Arc<AtomicBool>);
impl Drop for Witness {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
#[async_trait]
impl PacketLookup for PendingHost {
    async fn lookup(&self, _: PublicKey) -> Result<Option<PacketLease>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _witness = Witness(self.dropped.clone());
        self.entered.notify_one();
        pending().await
    }
}
#[tokio::test]
async fn cancellation_destroys_entered_host_future_before_drain() {
    let host = Arc::new(PendingHost {
        entered: tokio::sync::Notify::new(),
        dropped: Arc::new(AtomicBool::new(false)),
        calls: AtomicUsize::new(0),
    });
    let backend = Backend::injected(host.clone());
    let key = PublicKeyBytes::from_signed_packet(&packet(30));
    let worker = backend.clone();
    let task = tokio::spawn(async move { worker.packet(&key).await });
    host.entered.notified().await;
    backend.cancel();
    backend.drain().await;
    assert!(host.dropped.load(Ordering::SeqCst));
    assert!(task.await.unwrap().unwrap().is_none());
    assert!(backend.packet(&key).await.unwrap().is_none());
    assert_eq!(host.calls.load(Ordering::SeqCst), 1);
}

fn signed_records(ttls: &[u32], additional_ttl: Option<u32>) -> SignedPacket {
    use simple_dns::{CLASS, Name as DnsName, Packet, ResourceRecord, rdata::RData};
    let secret = SecretKey::from_bytes(&[7; 32]);
    let name = format!("_iroh.{}", secret.public().to_z32());
    let mut packet = Packet::new_reply(0);
    for (index, ttl) in ttls.iter().enumerate() {
        packet.answers.push(ResourceRecord::new(
            DnsName::new(&name).unwrap(),
            CLASS::IN,
            *ttl,
            RData::TXT(
                simple_dns::rdata::TXT::try_from(format!("value{index}").as_str())
                    .unwrap()
                    .into_owned(),
            ),
        ));
    }
    if let Some(ttl) = additional_ttl {
        packet.additional_records.push(ResourceRecord::new(
            DnsName::new(&name).unwrap(),
            CLASS::IN,
            ttl,
            RData::TXT("extra".try_into().unwrap()),
        ));
    }
    let encoded = packet.build_bytes_vec_compressed().unwrap();
    let timestamp = 123u64;
    let mut signable = format!("3:seqi{timestamp}e1:v{}:", encoded.len()).into_bytes();
    signable.extend_from_slice(&encoded);
    let mut bytes = secret.public().as_bytes().to_vec();
    bytes.extend_from_slice(&secret.sign(&signable).to_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&encoded);
    SignedPacket::from_bytes(&bytes).unwrap()
}

#[tokio::test]
async fn mixed_records_and_rrsets_use_original_age_and_minimum_ttl() {
    for ttls in [&[30, 10, 1][..], &[1, 10, 30][..]] {
        let packet = signed_records(ttls, None);
        let key = PublicKeyBytes::from_signed_packet(&packet);
        let lease = PacketLease::new(
            packet,
            Instant::now(),
            Duration::from_secs(2),
            Duration::from_secs(60),
        );
        let backend = Backend::injected(host(Some(lease)));
        let set = backend
            .resolve(&key, &Name::from_utf8("_iroh.").unwrap(), RecordType::TXT)
            .await
            .unwrap()
            .unwrap();
        // Two still-fresh records survive. Subsecond process elapsed floors TTL.
        assert_eq!(set.records_without_rrsigs().count(), 2);
        assert!((1..=7).contains(&set.ttl()));
        assert!(
            set.records_without_rrsigs()
                .all(|record| record.ttl == set.ttl())
        );
        assert!(backend.packet(&key).await.unwrap().is_none());
    }
}

#[test]
fn pkarr_requires_every_section_and_nonempty_native_packet() {
    let now = Instant::now();
    let value = PacketLease::new(
        signed_records(&[30], Some(1)),
        now,
        Duration::from_secs(2),
        Duration::from_secs(60),
    );
    assert!(!value.pkarr_usable_at(|| now).unwrap());
    let value = PacketLease::new(
        signed_records(&[], None),
        now,
        Duration::ZERO,
        Duration::from_secs(60),
    );
    assert!(!value.pkarr_usable_at(|| now).unwrap());
}

struct ErrorHost;
#[async_trait]
impl PacketLookup for ErrorHost {
    async fn lookup(&self, _: PublicKey) -> Result<Option<PacketLease>> {
        bail_any!("host unavailable")
    }
}
#[tokio::test]
async fn host_error_and_unverified_native_packet_are_unavailable() {
    let original = packet(30);
    let mut bytes = original.as_bytes().to_vec();
    bytes[32] ^= 1;
    let malformed = SignedPacket::from_bytes_unchecked(&bytes).unwrap();
    for backend in [
        Backend::injected(Arc::new(ErrorHost)),
        Backend::injected(host(Some(lease(malformed)))),
    ] {
        let app = app(backend);
        let response = app
            .clone()
            .oneshot(request(
                "GET",
                &format!("/pkarr/{}", original.public_key().to_z32()),
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let mut query = Message::query();
        query.add_query(Query::query(
            Name::from_utf8(format!(
                "_iroh.{}.irohdns.example.",
                original.public_key().to_z32()
            ))
            .unwrap(),
            RecordType::TXT,
        ));
        let response = app
            .oneshot(request("POST", "/dns-query", query.to_bytes().unwrap()))
            .await
            .unwrap();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            Message::from_bytes(&bytes).unwrap().metadata.response_code,
            ResponseCode::ServFail
        );
    }
}

#[tokio::test]
async fn static_soa_does_not_consult_injected_lookup() {
    let host = host(None);
    let app = app(Backend::injected(host.clone()));
    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_utf8("irohdns.example.").unwrap(),
        RecordType::SOA,
    ));
    let response = app
        .oneshot(request("POST", "/dns-query", query.to_bytes().unwrap()))
        .await
        .unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let message = Message::from_bytes(&bytes).unwrap();
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(!message.answers.is_empty());
    assert_eq!(host.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_dns_positive_exposes_aged_ttl() {
    let original = packet(30);
    let key = original.public_key().to_z32();
    let value = PacketLease::new(
        original,
        Instant::now(),
        Duration::from_secs(2),
        Duration::from_secs(60),
    );
    let app = app(Backend::injected(host(Some(value))));
    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_utf8(format!("_iroh.{key}.irohdns.example.")).unwrap(),
        RecordType::TXT,
    ));
    let response = app
        .oneshot(request("POST", "/dns-query", query.to_bytes().unwrap()))
        .await
        .unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let message = Message::from_bytes(&bytes).unwrap();
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 1);
    assert!((1..=27).contains(&message.answers[0].ttl));
}

#[tokio::test]
async fn doh_get_head_and_conditionals_reconsult_host_without_caching() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let original = packet(30);
        let name = format!("_iroh.{}.irohdns.example.", original.public_key().to_z32());
        let mut query = Message::query();
        query.add_query(Query::query(
            Name::from_utf8(&name).unwrap(),
            RecordType::TXT,
        ));
        let wire_uri = format!(
            "/dns-query?dns={}",
            base64_url::encode(&query.to_bytes().unwrap())
        );
        let json_uri = format!("/dns-query?name={name}&type=TXT");
        let host = host(None);
        let app = app(Backend::injected(host.clone()));
        let mut expected_calls = 0;
        for (uri, accept) in [
            (wire_uri, "application/dns-message"),
            (json_uri, "application/dns-json"),
        ] {
            for method in ["GET", "HEAD"] {
                for condition in [
                    None,
                    Some(("if-none-match", "*")),
                    Some(("if-modified-since", "Fri, 01 Jan 2100 00:00:00 GMT")),
                ] {
                    // Observe a usable record, remove available evidence, then recover.
                    // Neither a cached positive nor a cached failure may skip admission.
                    for available in [true, false, true] {
                        *host.view.lock().unwrap() = available.then(|| lease(original.clone()));
                        let mut request = request(method, &uri, vec![]);
                        request
                            .headers_mut()
                            .insert("accept", accept.parse().unwrap());
                        if let Some((name, value)) = condition {
                            request.headers_mut().insert(name, value.parse().unwrap());
                        }
                        let response = app.clone().oneshot(request).await.unwrap();
                        expected_calls += 1;
                        assert_eq!(
                            host.calls.load(Ordering::SeqCst),
                            expected_calls,
                            "{method} {accept}: conditional={condition:?}, available={available}"
                        );
                        // DNS errors are still carried in HTTP 200, never 304.
                        assert_eq!(response.status(), StatusCode::OK);
                        assert_eq!(response.headers()["cache-control"], "no-store");
                        assert_eq!(response.headers()["content-type"], accept);
                        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                        if method == "HEAD" {
                            assert!(bytes.is_empty());
                        } else if accept == "application/dns-message" {
                            let message = Message::from_bytes(&bytes).unwrap();
                            assert_eq!(
                                message.metadata.response_code,
                                if available {
                                    ResponseCode::NoError
                                } else {
                                    ResponseCode::ServFail
                                }
                            );
                            assert_eq!(message.answers.len(), usize::from(available));
                            if !available {
                                assert!(message.authorities.is_empty());
                            }
                        } else {
                            let message: serde_json::Value =
                                serde_json::from_slice(&bytes).unwrap();
                            assert_eq!(message["Status"], if available { 0 } else { 2 });
                            if available {
                                assert_eq!(message["Answer"].as_array().unwrap().len(), 1);
                            } else {
                                assert!(message.get("Answer").is_none());
                            }
                        }
                    }
                }
            }
        }
    })
    .await
    .expect("DoH request variants must complete without an external service");
}

#[tokio::test]
async fn default_store_pkarr_miss_publish_and_native_bytes_remain_available() {
    let store = ZoneStore::in_memory(
        crate::store::Options::default(),
        Arc::new(Metrics::default()),
    )
    .unwrap();
    let app = app(Backend::Store(store));
    let original = packet(30);
    let uri = format!("/pkarr/{}", original.public_key().to_z32());
    let response = app
        .clone()
        .oneshot(request("GET", &uri, vec![]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(response.headers().get("cache-control").is_none());
    let response = app
        .clone()
        .oneshot(request("PUT", &uri, original.to_relay_payload().to_vec()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = app.oneshot(request("GET", &uri, vec![])).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("cache-control").is_none());
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .as_ref(),
        original.to_relay_payload()
    );
}

#[tokio::test]
async fn mainline_rejected_before_bind_or_lookup() {
    let mut config = Config::default();
    config.mainline = Some(crate::config::MainlineConfig {
        enabled: true,
        bootstrap: None,
    });
    let host = host(None);
    let error = crate::Server::bind_with_lookup(config, host.clone())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Mainline must be disabled"));
    assert_eq!(host.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn rrset_minimum_ttl_is_order_independent_at_fixed_observation() {
    for ttls in [&[30, 10, 1][..], &[1, 10, 30][..]] {
        let packet = signed_records(ttls, None);
        let (_, sets) = signed_packet_to_hickory_records_with_ttl(&packet, |record| {
            PacketLease::ttl_left(
                record.ttl,
                (Duration::from_secs(2), Duration::from_secs(60)),
            )
        })
        .unwrap();
        let set = sets.values().next().unwrap();
        assert_eq!(set.ttl(), 8);
        assert_eq!(set.records_without_rrsigs().count(), 2);
        assert!(set.records_without_rrsigs().all(|record| record.ttl == 8));
    }
}

async fn query_code(app: axum::Router, name: &str, kind: RecordType) -> Message {
    let mut query = Message::query();
    query.add_query(Query::query(Name::from_utf8(name).unwrap(), kind));
    let response = app
        .oneshot(request("POST", "/dns-query", query.to_bytes().unwrap()))
        .await
        .unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    Message::from_bytes(&bytes).unwrap()
}

struct BlockUnavailable {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    first: AtomicBool,
}
#[async_trait]
impl PacketLookup for BlockUnavailable {
    async fn lookup(&self, _: PublicKey) -> Result<Option<PacketLease>> {
        if self.first.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        Ok(None)
    }
}
#[tokio::test]
async fn unavailable_marker_is_isolated_between_requests_and_tasks() {
    let lookup = Arc::new(BlockUnavailable {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        first: AtomicBool::new(true),
    });
    let app = app(Backend::injected(lookup.clone()));
    let dynamic = format!(
        "_iroh.{}.irohdns.example.",
        packet(30).public_key().to_z32()
    );
    let request_app = app.clone();
    let request_name = dynamic.clone();
    let unavailable =
        tokio::spawn(async move { query_code(request_app, &request_name, RecordType::TXT).await });
    lookup.entered.notified().await;
    // These requests complete while the unavailable admission remains pending.
    let axfr = query_code(app.clone(), "irohdns.example.", RecordType::AXFR).await;
    let soa = query_code(app.clone(), "irohdns.example.", RecordType::SOA).await;
    lookup.release.notify_one();
    let unavailable = unavailable.await.unwrap();
    assert_eq!(unavailable.metadata.response_code, ResponseCode::ServFail);
    assert!(unavailable.authorities.is_empty());
    assert_eq!(soa.metadata.response_code, ResponseCode::NoError);
    let store = ZoneStore::in_memory(
        crate::store::Options::default(),
        Arc::new(Metrics::default()),
    )
    .unwrap();
    let baseline = query_code(
        self::app(Backend::Store(store)),
        "irohdns.example.",
        RecordType::AXFR,
    )
    .await;
    assert_eq!(axfr.metadata.response_code, baseline.metadata.response_code);
    assert!(axfr.answers.is_empty());
    // Same Tokio task after a marked request must not inherit the marker.
    assert_eq!(
        query_code(app.clone(), &dynamic, RecordType::TXT)
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    assert_eq!(
        query_code(app, "irohdns.example.", RecordType::AXFR)
            .await
            .metadata
            .response_code,
        baseline.metadata.response_code
    );
}

#[test]
fn native_tsig_record_ttl_is_included_in_whole_packet_expiry() {
    use hickory_server::proto::rr::{
        RData, Record,
        rdata::{TSIG, tsig::TsigAlgorithm},
    };
    let secret = SecretKey::from_bytes(&[7; 32]);
    let mut message = signed_packet_to_hickory_message(&packet(30)).unwrap();
    // Native TSIG has TTL zero. It is an actual record even when a unified
    // DNSSEC feature moves it from additionals into Message::signature().
    message.additionals.push(Record::from_rdata(
        Name::from_utf8(secret.public().to_z32()).unwrap(),
        0,
        RData::TSIG(TSIG::new(
            TsigAlgorithm::HmacSha256,
            123,
            300,
            vec![],
            0,
            None,
            vec![],
        )),
    ));
    let encoded = message.to_bytes().unwrap();
    let timestamp = 123u64;
    let mut signable = format!("3:seqi{timestamp}e1:v{}:", encoded.len()).into_bytes();
    signable.extend_from_slice(&encoded);
    let mut bytes = secret.public().as_bytes().to_vec();
    bytes.extend_from_slice(&secret.sign(&signable).to_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&encoded);
    let native = SignedPacket::from_bytes(&bytes).unwrap();
    let observed = Instant::now();
    let lease = PacketLease::new(native, observed, Duration::ZERO, Duration::from_secs(60));
    assert!(!lease.pkarr_usable_at(|| observed).unwrap());
}

#[test]
fn native_signature_field_ttl_cannot_escape_whole_packet_expiry() {
    use hickory_server::proto::rr::{
        Record,
        rdata::{TSIG, tsig::TsigAlgorithm},
    };
    let mut message = signed_packet_to_hickory_message(&packet(30)).unwrap();
    let timing = (Duration::ZERO, Duration::from_secs(60));
    assert!(PacketLease::records_usable(&message, timing));
    // Exercise the native feature-unified storage form without enabling a new
    // runtime feature or interpreting/verifying TSIG cryptography ourselves.
    message.signature = Some(Box::new(Record::from_rdata(
        Name::from_utf8("signature.example.").unwrap(),
        0,
        TSIG::new(TsigAlgorithm::HmacSha256, 123, 300, vec![], 0, None, vec![]),
    )));
    assert!(!PacketLease::records_usable(&message, timing));
}
