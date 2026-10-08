# Local Commons development patches

Base upstream source: `0072d7d84b233f9e7185eb676f049beaf557ac03`.
This branch retains the separately reviewed native DNS lookup/lifecycle extension
through `d9377db3e7ac784b73b66bedfacc64d5f840a3bd` (T268.77/.78).
No upstream acceptance or deployment is claimed.

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
