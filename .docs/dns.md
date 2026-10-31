# DNS

How `protocol::dns` is built and why. The user's view is `docs/protocol-dns.md`.

## Shape

- **No I/O, like the rest.** `DNSAuthority::respond` takes a query's bytes
  and gives the responses' bytes. `DNSResolver` and `DNSSECResolver` give
  transmissions and take responses and the time. The transports are layers
  of their own over TCP, TLS, HTTP and QUIC connections the caller drives.
- **Owned data, the wire form inside.** `DNSName` keeps the wire form (with
  label offsets computed on demand) and `DNSRecord` owns its data. A
  borrowed message view was rejected: the server and the resolver keep
  records across messages (zones, caches, chains of trust), so they would
  copy anyway, and two representations would double the codec.
- **The transport is part of the peer.** `DNSPeer` is the endpoint and the
  transport. The same query gets other answers over UDP (size, TC, cookies)
  than over TCP (zone transfers, keepalive) or encrypted transports
  (padding, ID 0). One function decides from the peer, not five servers.
- **DNSSEC is a subfeature that the root does not need,** except that
  NSEC3 hashing (SHA-1) is in the root. An authoritative server serves a
  signed zone's NSEC3 proofs without validating anything. So the root
  depends on `hash-sha-v1` (NSEC3) and `hash-siphash` (server cookies,
  RFC 9018).

## Decisions

### The authoritative server

- **Lookup follows RFC 1034 §4.3.2 step by step** (`DNSZone::descend`
  gives the closest node: authoritative data, a cut, or a DNAME). The
  answers of RFC 4035 and RFC 5155 Appendix B are reproduced from their
  Appendix A zones in the tests. That is the reference: a lookup that only
  looked right would not reproduce the authorities and additionals.
- **Minimal responses by default.** Positive answers carry no apex NS and
  no addresses beyond glue and the targets of MX/SRV/NS (`minimal: true`).
  This is what BIND, Knot and NSD do by default today. RFC 4035 B.1 shows
  the NS. The test of that example allows them as extras rather than
  require them.
- **Glue (RFC 9471).** In-domain glue that does not fit sets TC; sibling
  glue (of the zone's data, or below another of its cuts, §2.2) is added
  after it and dropped without TC when it does not fit. Additional records
  are kept apart (`DNSResponse.glue`) so that truncation can tell which they
  are. Sibling glue below another cut was first left out, which made the
  cyclic delegations of RFC 9471 §2.3 unresolvable.
- **Searches up the tree stop at the origin** (`closest_encloser`,
  `provable_encloser`). A zone of NSEC3PARAM without a matching apex NSEC3
  (a chain not built yet, another salt) once made the search climb past
  the origin and loop at the root.
- **One SOA in a zone,** a CNAME alone at its name (RFC 2181 §10.1). A
  zone that breaks these is refused when built, not served wrong.
  Identical records are deduplicated (RFC 2181 §5).
- **AXFR only to `transfers`, over TCP or TLS (RFC 5936 §6, RFC 9103).**
  Over UDP it is FORMERR. IXFR is answered with the whole zone (RFC 1995
  §4 allows it) and, over UDP, with the SOA alone (§2) so that the client
  asks over TCP. Incremental deltas need a history of the zone, which a
  server of static zones does not have.
- **Meta-types get FORMERR with EDE 30** (RFC 9824 §3.5). NXNAME in a
  query is a client's error, and the extended error says which.
- **Cookies (RFC 7873, RFC 9018).** With no secrets the option is ignored,
  which is the behaviour of a server without cookies. With secrets: SipHash-2-4
  over the client cookie, version, reserved bytes, timestamp and client
  address. A cookie made with an older secret is accepted and renewed, so
  secrets roll without failures (§5). A server cookie that does not verify
  is answered normally with a fresh one, never with BADCOOKIE: RFC 7873
  §5.2.3 leaves BADCOOKIE to servers that require cookies, and requiring
  them would refuse every resolver that does not send them. The exception
  is a query without question that only asks for the server cookie (§5.4):
  NOERROR with it, BADCOOKIE if the one sent is not valid. A malformed
  COOKIE is FORMERR only with secrets; without, the option is not read.
- **Padding (RFC 8467).** Responses to padded queries over encrypted
  transports are padded to a multiple of 468. A response is never padded
  for an unpadded query, nor over UDP and TCP, where padding gives nothing
  and costs bytes.
- **Keepalive (RFC 7828).** It is told only over TCP and TLS, and only to a
  query that has the option. Over UDP the option is ignored (§3.3.1), and
  DoQ (RFC 9250 §5.5.2) forbids it.
- **A query trickled in keeps its first deadline.** `DNSTCPServer` counts
  `read_timeout` from the first byte of a message; later bytes of the same
  message do not extend it, or a client sending a byte now and then would
  hold the connection forever.

### The stub resolver

- **Retries.** A round tries every server in order. The timeout doubles
  each round (2 s, up to 8 s), and there are 2 rounds by default (RFC 1536,
  RFC 1035 §4.2.1). SERVFAIL, REFUSED, NOTIMP and BADVERS move to the next server.
  TC means asking the same server over TCP (RFC 7766 §5). FORMERR without
  OPT means asking without EDNS (RFC 6891 §7). BADCOOKIE means asking again
  with the server cookie once, then over TCP (RFC 7873 §5.3). A response
  without a cookie, from a server that gave its cookie, to a query with
  one is discarded (§5.3 MUST): such a server speaks EDNS, so its FORMERR
  without OPT is taken as forged, not as a reason to drop EDNS.
- **Matching (RFC 5452 §9.1).** A response must have the query's ID,
  question (case-insensitive), server and transport, or it is ignored. It
  is not an error: an attacker's response must not end the query.
- **IDs are random, except 0 over DoH and DoQ** (RFC 8484 §4.1, RFC 9250
  §4.2.1), where the HTTP request or the stream matches the response and a
  fixed ID helps caching.
- **Cookies over UDP and TCP only.** Over encrypted transports they add
  nothing (RFC 7873 §1), and over DoQ they would be the only varying
  bytes, against caching.
- **The cache** keeps an answer for its least TTL, capped at a day (RFC
  8767's cap of 7 days was judged too long for a stub). A negative answer
  is kept for the SOA's TTL capped at 3 hours (RFC 2308 §5), and a failure
  for 5 seconds (RFC 9520 §3.2, which says at least 1 and at most 5
  minutes; 5 s is chosen so that a stub recovers quickly once the server
  is back). Entries are evicted oldest-expiring first at the limit. A
  record's TTL given back is at most the time its entry is still kept.
- **Names inside records.** A receiver decompresses the names of RFC
  1035's types and of the ones RFC 3597 §4 lists (`decompresses_names`); a
  sender compresses only the RFC 1035 types it writes. Types kept as bytes
  whose data hold names (MB, MINFO, RP, AFSDB, RT, KX, PX, SIG, NXT) have a
  layout (`DNSField`), so that their names are stored uncompressed and
  lowercased in the canonical form (RFC 4034 §6.2). Data of other types is
  kept whole: reading it once failed for any non-empty record of a type
  without a structure, which made the whole message unreadable.
- **Malformed data of a known type is `Unknown` where its bytes stand
  alone** (audit finding: the documentation said so, but `decode` failed
  the whole message, while the zone-file `\#` form fell back to `Unknown`
  for every type). A record of a well-formed message whose data breaks its
  type's rules (an SVCB of malformed parameters, a CAA tag not
  alphanumeric, an NSEC3 of an empty hash, an A of 3 bytes) is malformed
  alone; RFC 9460 §2.2 says such an SVCB is to be ignored, not the message,
  and failing the message would let one record hide the rest. `decode`
  keeps the bytes as `Unknown` when the type has no name that may be
  compressed (`decompresses_names`, RFC 3597 §4) or lowercased in the
  canonical form (`lowercases_names`, RFC 4034 §6.2): then the bytes are
  the record in any message and in the canonical form, so it is written
  again and validated the same. For the other types the bytes may hold a
  pointer into the message, meaningless alone, or a name whose canonical
  form differs: the message is refused, as before. The `\#` form goes
  through `decode_uncompressed`, the same rules with no name compressed:
  RFC 3597 §5 makes it the RDATA uncompressed, and decoding it as a message
  followed a pointer within the data itself (a SOA whose RNAME pointed at
  its MNAME was read), so a zone file and a message accept the same data;
  it once fell back to `Unknown` for every type, which kept data of MX or
  RRSIG whose canonical form would have been wrong. Text in a type's own
  presentation format that breaks its rules is still a syntax error: an
  operator wrote it. `decode_strict` is the decoder that refuses all
  malformed data, for callers that want that. Rejected: failing every
  malformed record (one bad record hides an answer; RFC 9460 says to
  ignore it), and keeping every malformed record as `Unknown` (compressed
  names cannot be kept as bytes).

### DNSSEC

- **Every algorithm RFC 9904 says MUST or RECOMMENDED for validation,
  all enabled by default, SHA-1 included.** Validating SHA-1 zones is still
  required (RFC 9904 lists 5 and 7 as MUST NOT for signing, not for
  validation). Turning SHA-1 off makes those zones insecure, not bogus (RFC
  4035 §5.2). That is configurable for those who want it.
- **A SHA-1 DS is ignored when a stronger one is there** (RFC 4509 §3).
  Otherwise a downgrade to the weakest digest would be possible.
- **RSA below 1024 bits is unsupported, not bogus.** A zone that uses only
  such keys is insecure. A 512-bit key verifying "secure" would be a lie,
  and bogus would break zones that work everywhere else.
- **KeyTrap (CVE-2023-50387).** At most 8 signature verifications per
  RRset, and keys are matched by tag and algorithm before verifying. The
  limit is configurable (`maximum_verifications`). RSA keys of a public
  exponent above 64 bits (`maximum_rsa_exponent_bits`) are unsupported:
  RFC 3110 allows exponents as long as the modulus, which make a
  verification hundreds of times slower (44 ms instead of 0.1 ms for 4096
  bits), and keys use 3 or 65537. OpenSSL bounds the exponent alike.
- **NSEC3 iterations (RFC 9276 §3.2).** Above 50 the proof is insecure,
  above 150 it is bogus, both configurable. Mixed parameters in one
  response are bogus (RFC 5155 §8.2 requires one chain).
- **Opt-Out.** A name error, a wildcard answer or a wildcard no-data whose
  next closer name is covered by an Opt-Out NSEC3 is insecure, as BIND and
  Unbound treat it. The span may hide an unsigned delegation (RFC 5155
  §9.2), so the absence is not proven. Bogus was rejected: it fails zones
  that are correct.
- **RFC 5155 §8.5 as Erratum 3441 corrects it:** an empty non-terminal
  under an Opt-Out span may have no NSEC3, so the no-data proof uses the
  closest encloser.
- **RFC 8080's examples are wrong;** the tests use Erratum 4935's corrected
  ones, stored in the vectors with their source.
- **The trust anchors** are IANA's root-anchors.xml as of 2026-10-29
  (KSK-2017 and KSK-2024), kept as DS data in the code
  (`DNSSECTrustAnchor::root`). The tests check them against the XML (RFC
  9718), stored in the vectors. Their validity times are honoured. RFC
  5011 (automatic rollover) is not implemented: it needs state kept across
  restarts. The caller updates the anchors from the XML.
- **The validating resolver fetches its own DS and DNSKEY** (RFC 4035
  §4.9.3) through the stub resolver, and caches each zone's trust, Secure
  with its keys or Insecure, for the TTL that tells it. Bogus is not kept:
  the next question asks again. The responses it asked for are kept as
  long as the resolver's cache would keep them (a failure for its failure
  TTL), at most as many as the cache: kept until idle, they once served a
  failure or old keys for as long as the resolver stayed busy. An error
  rcode other than NOERROR and NXDOMAIN is Insecure(None): a SERVFAIL says
  nothing that could be validated, and calling it secure would be wrong.
- **What a response carries is validated by its zones.** A recursive's
  response may hold records of several zones (a CNAME into another zone,
  its target's denial). Each denial uses only the RRsets its zone signs
  (`signed_by`), and its SOA is the one above the name it denies.
- **The rcode is checked against the answer.** NXDOMAIN is of the last
  name of the CNAME chain (RFC 6604 §3), and an answer there contradicts
  it: bogus. A question of CNAME or ANY is answered at its name, without
  following the CNAME.
- **A CNAME at a name asked for its DS** means no zone is cut there (RFC
  2181 §10.1): the name is of its parent's zone, which signs the CNAME if
  it is secure. Unsigned CNAMEs of insecure zones were once bogus, because
  the DS question met the CNAME and its target's denial.
- **A secure response keeps only what was validated** (RFC 4035 §3.2.3):
  its answer, the denial records of its authority section, no additional
  section; and every TTL at most the original TTL and the time left of its
  signatures (§5.3.3).
- **Signing exists for tests and for the server's own zones:** NSEC chains
  and RRSIGs, with hedged ECDSA signatures (deterministic plus random,
  RFC 6979 §3.6). NSEC3 zone generation is left out: online signing and
  NSEC3 chains belong to a signer, and serving zones signed elsewhere is
  what an authoritative library needs.

### Transports

- **TCP framing is one type (`DNSTCPFramer`),** used by TCP, DoT and DoQ
  alike. DoQ uses the same 2-byte length prefix on each stream (RFC 9250
  §4.2).
- **DoT holds queries until the handshake completes** and refuses an ALPN
  other than `dot`. A server that does not negotiate ALPN is accepted
  (RFC 7858 does not require it).
- **DoH never builds its own HTTP.** `DNSHTTPS` makes and reads
  `HTTPRequest`s and responses for the HTTP connections of `protocol-http`.
  The freshness of a response is its least TTL (RFC 8484 §5.1).
- **DoQ** (RFC 9250): one query per stream, and all its responses on that
  stream: one, or the messages of a zone transfer, which a client accepts
  only for AXFR and IXFR (§4.2, §4.3). A message with an ID other than 0,
  or with keepalive, is a protocol error, as is a stream that ends inside
  a message or without one, and a STOP_SENDING to a client (§4.3.3).
- **What a stream does not take is kept.** `DNSQUICConnection` keeps, by
  stream, the bytes the QUIC stream has not taken and writes them on
  `StreamWritable`; a stream is forgotten once both its halves ended. The
  first design wrote a response whole or failed with TooLarge, and ended
  the stream after one message: a zone larger than the stream's buffer
  could not be transferred, and an AXFR's second message could not be sent.
  The interoperability runs found this.
- **A server choosing by ALPN** (`dot` or `h2` on one port, as the example
  does) takes TLS's events itself: `DNSTLS::take_events` refuses any ALPN
  but `dot`, as a DoT-only server must.

## The C ABI

- Names and records cross as their presentation format, one record a line.
  A structure per record type was rejected: about 30 types, each changing
  with RFCs, against a format every DNS tool reads.
- A function that needs randomness takes a generator of `crypto::random`
  (a handle and its type name), as in Rust. A seed and a DRBG inside the
  handle (as QUIC and WebSocket do) were rejected: they would hide a hash
  dependency (SHA-256) that `protocol-dns-udp` alone does not have, and the
  Rust API takes `&mut R` on each call.
- Parameters are not named `class` (a C++ keyword): `record_class`.
- A cdylib must be built with a platform feature (`platform-native`), or it
  has no allocator and no panic handler. The tests build it with
  `cargo rustc --lib --crate-type cdylib`.

## Not implemented

An iterative resolver, RFC 8198 (aggressive NSEC), EDNS Client Subnet (RFC
7871), 0x20 case randomization, NOTIFY, UPDATE and TSIG, IXFR deltas, NSEC3
zone signing, online signing, RFC 5011 rollover. Each is a feature of its
own that none of the RFCs implemented here needs.
