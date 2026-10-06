# iroh-dns-server

A server that functions as a [pkarr](https://github.com/Nuhvi/pkarr/) relay and
[DNS](https://de.wikipedia.org/wiki/Domain_Name_System) server.

This server compiles to a binary `iroh-dns-server`. It needs a config file, of
which there are two examples included:

- [`config.dev.toml`](./config.dev.toml) - suitable for local development
- [`config.prod.toml`](./config.prod.toml) - suitable for production, after
  adjusting the domain names and IP addresses

The server will expose the following services:

- A DNS server listening on UDP and TCP for DNS queries
- A HTTP and/or HTTPS server which provides the following routes:
  - `/pkarr`: `GET` and `PUT` for pkarr signed packets
  - `/dns-query`: Answer DNS queries over
    [DNS-over-HTTPS](https://datatracker.ietf.org/doc/html/rfc8484)

All received and valid pkarr signed packets will be served over DNS. The pkarr
packet origin will be appended with the origin as configured by this server.

## Embedded host lookup

`Server::bind_with_lookup(config, Arc<dyn PacketLookup>)` serves the same native
DNS, DoH and Pkarr formats with a host-owned admission source. Implement the async
`PacketLookup::lookup(PublicKey)` method to return `Option<PacketLease>` containing
an original `iroh_dns::pkarr::SignedPacket`, its process-local `Instant` observation,
signed age at observation and remaining authorization/freshness budget. These
trusted inputs are not a serialized proof. The host owns authority, namespace,
revocation, finality and persistence policy. It must return a coherent accepted
view and must not reset signed age after refresh, restart or a finality outage.

Each dynamic request directly awaits the host. The server verifies native signed
bytes and the requested signer, accounts for elapsed process time, and serves DNS
records only while their original TTL and host budget leave a whole second.
Retained RRsets use their minimum TTL. DNS can serve fresh records from a mixed
packet; Pkarr requires every actual record in every section to remain fresh and
returns the original relay bytes. Unavailable evidence, lookup errors and dynamic
query misses return DNS SERVFAIL or Pkarr HTTP 503. Injected DoH and Pkarr responses
use `Cache-Control: no-store`; HEAD and conditional requests still consult the host.
Static zones and native parsing remain unchanged. Locked Hickory 0.26.3 maps
zone-handler SERVFAIL to negative NOERROR. A request-scoped adapter uses its native
early-error path and changes only marked injected failures to SERVFAIL before
native serialization. Revisit this adapter when that upstream behavior is fixed.

In this mode Pkarr PUT is disabled with HTTP 405. Mainline must be disabled before
binding; no packet database, LRU or Mainline fallback is created. TLS certificate
configuration and its native cache still apply. The ordinary `Server::bind` path
retains its persistent store, publishing and configured fallback behavior.

Constructor preparation binds native sockets and builds TLS without starting
request-serving or ACME tasks. Cancelled preparation drops unstarted work; all
DNS, HTTP and ACME start synchronously after the last startup await. ACME maintenance is
owned with the HTTP tasks and participates in completion, failure and shutdown.

Retain and await `Server::shutdown` or `Server::join` through completion, including
errors. Cleanup notifies native HTTP connections, cancels native DNS transports,
awaits listener tasks, and drains entered host lookup futures. That drain proves
host lookup destruction, not destruction of every operating-system connection;
dropping the consuming cleanup future cannot promise an asynchronous drain.
DNS UDP and TCP use the same selected port, including when configured with port
zero. Listener behavior requires separate deployment qualification.

# License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
