# Local Commons development patches

Transition base upstream source: `55908a5809b61c72ec8deeff024038f4a9d68ab7` (1.4.0).
The Commons source below is ported from reviewed `5469810f2098460d9a0ffc6d3e921999b733a0ef`,
whose upstream base was `0072d7d84b233f9e7185eb676f049beaf557ac03` (1.3.0).
The descriptions below record the original patches, including the separately
reviewed DNS lookup/lifecycle extension through `d9377db3e7ac784b73b66bedfacc64d5f840a3bd`.

## 1.4.0 transition and evaluation boundary

The source port matches the reviewed AWS evaluation patch with SHA-256
`3ca78b15f260591fb6817ae4befd4ab5ba5d2a2504a42410573b6152b29658c4`.
Its selected Linux evaluation passed 12 groups (58 executions, 56 unique tests)
for strict transport, discovery, injected DNS lookup and lifecycle behavior.
This does not qualify the full workspace, downstream consumers, WAN operation
or performance. The transition preserves both published fork and upstream ancestry.

The production root patch pins Noq, Noq-proto and Noq-udp to
`d9284b76c4480b9771bee49831104578772450c9`, the reviewed, published Noq 1.4.0
source retaining the Retry-before-migration repair and regression tests. Its
AWS default/qlog workspace tests and strict Clippy passed; Windows CI timeouts
remain under investigation, so no whole-CI pass is claimed.
The initial experiment used a sibling path override before the subsequent Noq
security/CI changes. Root-owned AWS Cargo generation must refresh the existing
lock for this Git pin before exact-head qualification; it is not hand-edited.
DNS persistence now requires redb 4.4.0; experimental database features and
table encodings are unchanged. Exact-head native gates and downstream adoption
remain pending qualification.
Downstream Cargo roots must adopt the same patch identities: dependency-local
Cargo patches do not propagate to consumers. There are no evaluation path overrides.

The 1.4.0 manifest versions remain the base. The committed AWS-generated lock
records the Commons tower test edge, the preceding Noq Git source identities
and DNS redb 4.4.0; the current Noq pin refresh remains pending. The DNS test manifest retains the existing public-type
declarations. No 1.3.0 lockfile or Noq pin was copied. Exact-head gates and
cross-version disk compatibility remain pending; no upstream acceptance,
consumer adoption, publication or deployment is claimed by this source preparation.

The relay receive path uses upstream 1.4.0's compact output indexing and bounded
self-wake, with Commons relay filtering inserted before accepting datagrams.
Both upstream oversize/drop regressions and Commons foreign-relay regressions
remain. Three Commons test fixtures destructure the upstream transport helper's
new tuple return. DNS host fixtures explicitly retain the default listen backlog.

Ordinary Pkarr resolution keeps upstream's explicit endpoint proxy behavior;
Commons resolution keeps its separate direct, no-redirect/no-proxy constructor.
Upstream asynchronous endpoint tracing, IPv6 QAD coverage, DNS header deadlines
and listen backlogs, and captive-portal single-response/30-second timeout behavior
are retained alongside Commons staged startup and awaited cleanup ownership.


T268.110 adds `CMNS_TXT_NAME` and three explicit `EndpointInfo` methods for
`_cmns` TXT/Pkarr records. They reuse native attribute codecs and packet types.
Existing `_iroh` methods, N0 defaults and DNS server behavior stay intact.
There is no cross-namespace fallback. A missing selected packet label yields
empty native endpoint data; a wrong-label TXT query is rejected.

Packet parsing uses the packet signer as the endpoint identity. It does not
verify unchecked packet objects; use native `SignedPacket::from_bytes` for
untrusted input. New encoding uses its supplied secret key, native timestamp and
TTL. Retain original bytes when forwarding an existing signed packet.

These primitives do not supply chain authority, network scope, replay storage,
publication policy, a Commons preset, host wiring or qualification evidence.

T268.111 adds `iroh::endpoint::presets::dw()` using native preset hooks. It
selects Minimal's crypto provider and clears prior lookup and relay configuration,
including N0 defaults. Apply caller lookups, relays and crypto overrides afterward.
Identity, ALPNs and IP binds remain intact. The preset contains no infrastructure
addresses or chain client; host discovery wiring and qualification remain separate.
Existing upstream presets are unchanged. Pure builder tests contact no network.

T268.122 adds explicit `DnsAddressLookup::cmns_builder` and
`PkarrResolver::cmns_builder` readers, plus `DnsResolver` Commons endpoint-ID
lookup methods. They select only `_cmns` using existing native TXT/Pkarr parsers,
DNS staggering, resolver inheritance and authenticated HTTP packet retrieval.
Existing constructors still select `_iroh`; publishing is unchanged. Missing
selected records retain native empty-data behavior, without fallback. These
readers do not establish chain authority, packet freshness or host integration.
Offline custom-resolver and loopback HTTP tests exercise the real resolve paths.


T268.128 exposes `iroh_dns_server::Server::run_until_done(&mut self)` for host-owned
completion selection without consuming or stopping the server. Pending wait
cancellation preserves native serving and lookup ownership. Existing `join`
delegates to the borrowed wait, then retains its cleanup and original-error
precedence. Terminal notifications are not repeatable-result, readiness or drain
certificates; hosts must retain and await the single consuming shutdown future.
The HTTP/HTTPS constructor requirement, native DNS transport and complete
HTTP/TLS/ACME task ownership remain unchanged. Bounded loopback tests cover
HTTP-only, HTTPS-only and combined waiting, retry and entered-future destruction,
plus top-level failure and competing cleanup errors. This is a native lifecycle
seam, not chain host, Statement policy or deployment qualification.

T268.129 tracks whether the native relay supervisor result remains owned by
`iroh_relay::server::Server`. A pending cancelled borrowed `join` retains that
ownership; a terminal wait consumes it before returning either error level.
`shutdown` still signals relay/QAD and awaits metrics cleanup, then consumes any
unobserved supervisor result without polling an already-consumed task again.
The public no-services path reproduced Tokio's repeated-poll panic before this
repair. Bounded loopback regressions cover pending cancellation, native serving,
success and inner/outer failures, plus separately owned metrics listener release.
Callers retain the observed join result, await one consuming shutdown future and
then propagate the result; terminal join is not repeatable. Native admission,
wire/configuration, supervisor and public signatures remain unchanged. The
binary's discarded join result remains a separately owned caller correction;
this is not host integration, publication or qualification evidence.

T268.130 corrects the relay binary caller separately from T268.129's library
ownership repair. The actual no-services executable previously exited zero after
logging its native supervisor failure. The caller now retains the nested join
result, awaits one consuming shutdown future and propagates the original failure
before any cleanup error. Without an observed result, cleanup errors propagate.
Native Ctrl-C wildcard handling and branch bias are unchanged. Controlled pending
cleanup tests cover inner failure, outer cancellation/panic, success and cleanup
failure; bounded executable tests cover native no-services failure and healthy
loopback serving followed by owned-PID SIGINT. Process exit/listener release
supplement, rather than prove, awaited cleanup. No public API, dependencies,
configuration, wire behavior, host integration or qualification changes.


T268.133 completes awaited native relay startup rollback and HTTP cleanup. Failed
startup drains already-created HTTP, captive and metrics resources before returning
its original error. The native supervisor tracks consumed results, awaits remaining
HTTP and captive work, and defers primary panic propagation until cleanup. Explicit
HTTP/captive child panics likewise follow connection-group drain. A secondary HTTP
failure propagates after primary success without replacing an earlier error.

WebSocket upgrade admission is closed atomically against tracked spawning. Native
handshake/authorization tasks are cancelled and awaited before registered-client
drain; tasks do not retain their external cancellation owner. Closed upgrades
receive HTTP 503. Reentrant shutdown from an access callback cancels that callback;
an external owner retains and awaits shutdown. Dropped futures, concurrent registry
drains and QAD descendants are outside stronger completion claims. Private tests
exercise actual local native builders/loops, pending bodies and authorization,
startup failures, panic precedence, closure/registration races and owner drop.
No public signature, dependency, wire format, host policy or qualification changes.


## T268.200 — immutable native relay policy and direct Pkarr HTTP

`endpoint::Builder::relay_allowlist` installs a monotonic, endpoint-owned set of
exact native relay URLs; repeated installation intersects sets, and applying a
preset cannot erase an existing restriction. No policy retains upstream behavior;
an empty policy retains direct IP transport with no relay traffic. Restricted
bind checks actual copied relay configs, detaches the candidate map from external
aliases, and refuses explicit proxy settings before endpoint/network effects.
Runtime insertions, native relay send queues, actor creation/home selection and
received relay metadata enforce the same immutable set. Native network reports
use one detached checked map for delayed HTTP probes and QAD; retained QAD
connections outside that view are discarded. Restricted HTTP probes ignore
ambient proxies. This is a relay/service policy, not a classifier of arbitrary
direct-peer IP ownership, and it introduces no custom transport or wire changes.

Native `address_lookup::PkarrRelayClient::new_direct` retains TLS and native
requested-key packet validation while disabling redirects and ambient proxies
for GET and PUT. It normalizes a trailing base-URL slash before appending the
endpoint key. Native `PkarrResolver::cmns_builder` uses this direct client;
ordinary constructors and browser behavior remain unchanged. The direct
constructor is intentionally native-only; browser proxy/redirect enforcement is
not claimed. A staging publisher is not enabled by either API.

Focused tests exercise monotonic preset ordering, copied-map aliasing and
mismatched configs, initial/runtime refusal, native queued/home/receive paths,
report/QAD filtering, IPv4/IPv6 direct bytes and approved relay bytes. HTTP
redirect/proxy traps include ordinary-client positive controls; environment
changes occur only in a bounded subprocess. Qualification and consumer adoption
remain separate from these native source changes.
