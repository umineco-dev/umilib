# umilib documentation

For users of umilib: Rust programs, C programs and Python programs.

| Document | Contents |
| --- | --- |
| [features.md](features.md) | Selecting modules with Cargo features |
| [bytes.md](bytes.md) | `umilib::bytes`: reading and writing integers and byte sequences |
| [calendar.md](calendar.md) | `umilib::calendar`: dates of the Gregorian calendar and their days since 1970 |
| [codec-asn1.md](codec-asn1.md) | `umilib::codec::asn1`: ASN.1 DER and BER |
| [codec-base.md](codec-base.md) | `umilib::codec::base`: Base16, Base32, Base58, Base64, Base85 |
| [codec-brotli.md](codec-brotli.md) | `umilib::codec::brotli`: Brotli |
| [codec-compression.md](codec-compression.md) | `umilib::codec`: the streaming interface of the compressed formats |
| [codec-deflate.md](codec-deflate.md) | `umilib::codec::deflate`, `zlib`, `gzip`: Deflate, zlib and gzip |
| [codec-filter.md](codec-filter.md) | `umilib::codec::filter`: Delta and BCJ filters |
| [codec-fse.md](codec-fse.md) | `umilib::codec::fse`: Finite State Entropy (tANS) |
| [codec-hpack.md](codec-hpack.md) | `umilib::codec::hpack`: HPACK, the field compression of HTTP/2 |
| [codec-huffman.md](codec-huffman.md) | `umilib::codec::huffman`: canonical and adaptive Huffman coding |
| [codec-lz4.md](codec-lz4.md) | `umilib::codec::lz4`: LZ4 blocks and frames |
| [codec-lzma.md](codec-lzma.md) | `umilib::codec::lzma`: .lzma files and LZMA2 |
| [codec-xz.md](codec-xz.md) | `umilib::codec::xz`: .xz files |
| [codec-zstandard.md](codec-zstandard.md) | `umilib::codec::zstandard`: Zstandard |
| [codec-lz.md](codec-lz.md) | `umilib::codec::lz77`, `lz78`, `lzss`: LZ77, LZ78 and LZSS |
| [codec-rle.md](codec-rle.md) | `umilib::codec::rle`: PackBits |
| [codec-json.md](codec-json.md) | `umilib::codec::json`: JSON |
| [codec-pem.md](codec-pem.md) | `umilib::codec::pem`: PEM |
| [codec-mail.md](codec-mail.md) | `umilib::codec::mail`: Internet messages (RFC 5322, RFC 6532) and MIME: fields, addresses, dates, entities and multiparts, parameters, encoded words, quoted-printable |
| [codec-qpack.md](codec-qpack.md) | `umilib::codec::qpack`: QPACK, the field compression of HTTP/3 |
| [codec-uri.md](codec-uri.md) | `umilib::codec::uri`: URI references (RFC 3986): parsing, resolution, normalization, percent-encoding, and the form encoding |
| [codec-stringprep.md](codec-stringprep.md) | `umilib::codec::stringprep`: stringprep, SASLprep, LDAPPrep and Unicode 3.2 normalization |
| [crypto.md](crypto.md) | `umilib::crypto`: ciphers, modes, AEADs, MACs, key derivation and random bit generators |
| [crypto-public-key.md](crypto-public-key.md) | `umilib::crypto`: curves, key agreement, signatures, RSA, HPKE, SM2 and SM9 |
| [crypto-post-quantum.md](crypto-post-quantum.md) | `umilib::crypto`: ML-KEM, ML-DSA, SLH-DSA and the hybrids of RFC 10024 |
| [hash.md](hash.md) | `umilib::hash`: hash functions, SipHash, xxHash and CRC |
| [math-bigint.md](math-bigint.md) | `umilib::math::bigint`: big integers of fixed precision |
| [math-modular.md](math-modular.md) | `umilib::math::modular`: modular arithmetic |
| [math-ec.md](math-ec.md) | `umilib::math::ec`: elliptic curves |
| [math-pairing.md](math-pairing.md) | `umilib::math::pairing`: pairings |
| [math-lattice.md](math-lattice.md) | `umilib::math::lattice`: polynomial rings of lattices and the NTT |
| [secret.md](secret.md) | `umilib::secret`: constant-time operations and zeroization |
| [ffi.md](ffi.md) | The C ABI (`ffi` feature) and the headers in `include/` |
| [python.md](python.md) | The Python bindings in `port/python` |
| [runtime.md](runtime.md) | `umilib::runtime`: executors, channels, timers and I/O traits without `std` |
| [service.md](service.md) | `umilib::service`: services, rules, patterns and routers |
| [auth-totp.md](auth-totp.md) | `umilib::auth::totp`: one-time passwords (HOTP, TOTP) |
| [auth-oauth.md](auth-oauth.md) | `umilib::auth::oauth`: OAuth 2.0 clients, authorization servers and protected resources (PKCE, metadata, introspection, revocation, PAR, device grant, JWT access tokens, DPoP) |
| [auth-sasl.md](auth-sasl.md) | `umilib::auth::sasl`: SASL mechanisms (PLAIN, EXTERNAL, ANONYMOUS, SCRAM, OAUTHBEARER) |
| [auth-cert-key.md](auth-cert-key.md) | `umilib::auth::cert::key`: keys and algorithm identifiers of X.509 (SPKI, PKCS #8, PBES2) |
| [auth-cert-x509.md](auth-cert-x509.md) | `umilib::auth::cert::x509`: certificates, CRLs, names and extensions (RFC 5280) |
| [auth-cert-csr.md](auth-cert-csr.md) | `umilib::auth::cert::csr`: certification requests (PKCS #10) |
| [auth-cert-path.md](auth-cert-path.md) | `umilib::auth::cert::path`: certification path building and validation (RFC 5280 §6) |
| [auth-cert-ocsp.md](auth-cert-ocsp.md) | `umilib::auth::cert::ocsp`: OCSP requests and responses (RFC 6960) |
| [protocol-ethernet.md](protocol-ethernet.md) | `umilib::protocol::ethernet`: MAC addresses, VLAN tags, headers and frame check sequences (IEEE 802.3) |
| [protocol-arp.md](protocol-arp.md) | `umilib::protocol::arp`: ARP packets and the address cache (RFC 826, RFC 1122, RFC 5227) |
| [protocol-icmp.md](protocol-icmp.md) | `umilib::protocol::icmp`: ICMP and ICMPv6 messages, the rules of errors, Neighbor Discovery and the Neighbor Cache (RFC 792, RFC 4443, RFC 4861) |
| [protocol-udp.md](protocol-udp.md) | `umilib::protocol::udp`: UDP datagrams, the zero checksum of IPv6 tunnels, jumbograms and the rule that routes datagrams |
| [protocol-tcp.md](protocol-tcp.md) | `umilib::protocol::tcp`: segments and options, connections and listeners, retransmission, congestion control and the configuration |
| [protocol-dns.md](protocol-dns.md) | `umilib::protocol::dns`: DNS messages, zone files, an authoritative server, a stub resolver and cache, DNSSEC validation and signing, DNS over UDP, TCP, TLS, HTTPS and QUIC |
| [protocol-dhcp.md](protocol-dhcp.md) | `umilib::protocol::dhcp`: DHCPv4 and DHCPv6 clients and servers, options, DUIDs, relays |
| [protocol-coap.md](protocol-coap.md) | `umilib::protocol::coap`: CoAP messages and options, the endpoint, observation, block-wise transfers, the Link Format, routing |
| [protocol-smtp.md](protocol-smtp.md) | `umilib::protocol::smtp`: SMTP replies, commands and mail data, a client and a server with the extensions of ESMTP, the choice of MX hosts |
| [protocol-pop.md](protocol-pop.md) | `umilib::protocol::pop::v3`: POP3 commands and responses, a client and a server with CAPA, STLS, AUTH and UTF8, APOP |
| [protocol-imap.md](protocol-imap.md) | `umilib::protocol::imap::v4`: IMAP4rev2 and IMAP4rev1 commands and responses, literals, mailbox names, ENVELOPE, BODYSTRUCTURE and sections, a client and a server |
| [protocol-ftp.md](protocol-ftp.md) | `umilib::protocol::ftp`: the FTP control connection, data addresses, FEAT, MLST facts and times, a client and a server with FTPS |
| [protocol-quic.md](protocol-quic.md) | `umilib::protocol::quic`: QUIC versions 1 and 2, endpoints, connections, streams, 0-RTT, migration, DATAGRAM frames, routing |
| [protocol-http.md](protocol-http.md) | `umilib::protocol::http`: HTTP/1.1, HTTP/2 and HTTP/3 connections, messages, tunnels, routing, structured fields, priorities, content codings |
| [protocol-websocket.md](protocol-websocket.md) | `umilib::protocol::websocket` and `http::websocket`: WebSocket, permessage-deflate and the opening handshake over every HTTP version |
| [protocol-tls.md](protocol-tls.md) | `umilib::protocol::tls`: TLS 1.3 and 1.2 connections, configuration, certificates, resumption and early data, ECH, routing |
| [protocol-ip.md](protocol-ip.md) | `umilib::protocol::ip`: addresses, the Internet checksum, IPv4 and IPv6 headers, fragmentation and reassembly |
| [protocol-jwt.md](protocol-jwt.md) | `umilib::protocol::jwt`: JWK, JWS, JWE and JWT (RFC 7515 to RFC 7519, RFC 8725) |
| [platform.md](platform.md) | `umilib::platform`: the operating system layers |
| [platform-runtime.md](platform-runtime.md) | `umilib::platform::runtime`: the thread pool, reactor, sockets and worker processes |
| [bench.md](bench.md) | `umilib::platform::bench` and running the benchmarks |
| [fuzz.md](fuzz.md) | `umilib::platform::fuzz` and running the fuzz targets |
| [ci.md](ci.md) | Continuous integration, releases and the settings they need |

Developer documentation (how umilib is built and why) is in [`.docs/`](../.docs/README.md).
