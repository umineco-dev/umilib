# umilib developer documentation

For people and tools that change umilib. User documentation is in [`docs/`](../docs/README.md).

| Document | Contents |
| --- | --- |
| [design.md](design.md) | Design rules every module follows |
| [feature-system.md](feature-system.md) | How features map to modules, and how that is checked |
| [ffi.md](ffi.md) | How the C ABI, the manifest, the headers and the Python bindings fit together |
| [compression.md](compression.md) | How the compressed formats are built, and the rules their decoders follow |
| [platform.md](platform.md) | Where the system declarations come from, and how the OS layers are tested |
| [runtime.md](runtime.md) | How the runtime avoids `unsafe` and reference cycles |
| [service.md](service.md) | Why services and routers are shaped as they are |
| [calendar.md](calendar.md) | Why the calendar is one type of its own, where it lives and the placements not taken |
| [cert.md](cert.md) | How the X.509 public-key infrastructure is built: keys, dispatch, consistency checks, path validation, OCSP, stringprep, interoperability, test suites |
| [sasl.md](sasl.md) | How SASL is built: messages and state machines without I/O, SCRAM, the vectors and their errors |
| [network.md](network.md) | How the network layers are built: codecs and state machines without I/O, the decisions of fragmentation, ARP, ICMP, UDP and TCP, the C layout, the Linux packets the tests use |
| [http.md](http.md) | How HTTP, HPACK, QPACK and WebSocket are built: one interface for every version, HTTP/3 over a borrowed QUIC connection, the Huffman code as a canonical code, the rules against smuggling and of tunnels (RFC 9931), floods, strict WebSocket framing, the C ABI |
| [quic.md](quic.md) | How QUIC is built: versions as profiles, TLS in QUIC mode, the connection's decisions (keys, acknowledgments, recovery, pacing, migration, Version Negotiation, Retry) and the endpoint's |
| [dns.md](dns.md) | How DNS is built: the authoritative server's lookup and policies, the stub resolver's retries and cache, the decisions of DNSSEC validation (algorithms, KeyTrap, NSEC3 iterations, Opt-Out), the transports and the C ABI |
| [dhcp.md](dhcp.md) | How DHCPv4 and DHCPv6 are built: options, times, retransmission, the matching of replies, the server's destinations, encoders that agree with decoders |
| [coap.md](coap.md) | How CoAP is built: one endpoint for client and server, deduplication, what ends with an event, RST, tokens, observation |
| [mail.md](mail.md) | How mail and file transfer are built: the shape the four protocols share, passwords before TLS, fields kept as written, SMTP smuggling, the IMAP grammar, the FTP bounce attack, the C ABI of text on the wire |
| [tls.md](tls.md) | How TLS is built: the driver and the engines of each version, the decisions of TLS 1.2, record size limits, resumption and early data, post-handshake authentication, OCSP, ECH and the C ABI |
| [uri.md](uri.md) | Why URI components are kept as written, the choices RFC 3986 leaves open, and where the form reader differs from WHATWG |
| [oauth.md](oauth.md) | How OAuth is built: the specifications taken, no HTTP types, the tables and families of the server, DPoP, the resource server, WWW-Authenticate, the C ABI |
| [jose.md](jose.md) | How JOSE and JWT are built: the shape of the API, key management, the vectors and their errors |
| [constant-time.md](constant-time.md) | How secret data is handled, and the limits of what Rust guarantees |
| [testing.md](testing.md) | What the automated and manual tests check, and how to run them |
| [release.md](release.md) | How the release scripts and workflows work |

Repository layout:

```
src/<module path>/          the crate; src/platform is the only part using std
src/ffi/<module path>/      the C ABI of src/<module path>
include/                    C headers, generated from the FFI manifest
port/python/                the Python package (ctypes over the C ABI)
tests/<module>/main.rs      integration tests, one crate per top-level module
tests/vectors/<path>/       test vectors from specifications
benches/, fuzz/             benchmarks and fuzz targets, one file per module
tools/                      CI and release scripts (Python, standard library only)
```
