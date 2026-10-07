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
