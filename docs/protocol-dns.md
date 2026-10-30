# DNS: `umilib::protocol::dns`

`protocol-dns` (no `std`) is the Domain Name System without doing any I/O:
messages and records (RFC 1034, RFC 1035), zone files, an authoritative
server, a stub resolver with a cache, and, in its subfeatures, DNSSEC and the
transports. `protocol-dns` is all of them.

| Feature | Module | What it is |
| --- | --- | --- |
| `protocol-dns` (the root) | `dns` | Names, messages, records, EDNS, zone files, `DNSAuthority`, `DNSResolver`, `DNSCache`, `DNSRule` |
| `protocol-dns-dnssec` | `dns::dnssec` | Validation, keys, signing, trust anchors, `DNSSECResolver` |
| `protocol-dns-udp` | `dns::udp` | The rules of DNS over UDP |
| `protocol-dns-tcp` | `dns::tcp` | The framing of messages on a stream, client and server connections (RFC 7766) |
| `protocol-dns-tls` (alias `protocol-dot`) | `dns::tls` | DNS over TLS (RFC 7858) |
| `protocol-dns-https` (alias `protocol-doh`) | `dns::https` | DNS queries over HTTPS (RFC 8484) |
| `protocol-dns-quic` (alias `protocol-doq`) | `dns::quic` | DNS over dedicated QUIC connections (RFC 9250) |

## Names, records and messages

`DNSName` is a name in its wire form. It compares without ASCII case (RFC
4343) and orders canonically (RFC 4034 §6.1); `DNSName::parse` reads its
text (RFC 1035 §5.1, with `\X` and `\DDD`) and `Display` writes it.

`DNSRecord` is a record: owner, type (`DNSType`), class (`DNSClass`), TTL
and data (`DNSData`). `DNSData` has a variant for each type it reads (A,
AAAA, NS, CNAME, DNAME, PTR, SOA, MX, TXT, HINFO, SRV, NAPTR, CAA, DS/CDS,
DNSKEY/CDNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, TLSA, SVCB/HTTPS with the
`ech` key of RFC 9848), and keeps any other type as opaque data (RFC 3597),
written `\# length hex`. Records read from and write to the presentation
format of zone files.

`DNSMessage` is a message: header, question, the three sections, and EDNS
(`DNSEDNS`, RFC 6891) apart from the additional records. `encode(limit)`
writes it in at most `limit` bytes, leaving out whole RRsets from the end and
setting TC when the answer or authority section loses some (RFC 2181 §9).
`decode` checks one OPT record at most, owned by the root, and a query of one
question (RFC 9619).

```rust
use umilib::protocol::dns::{DNSMessage, DNSName, DNSQuestion, DNSType};

let question = DNSQuestion::new(DNSName::parse("www.example.", None)?, DNSType::AAAA);
let query = DNSMessage::query(0x1234, question);
let bytes = query.encode(DNSMessage::UDP_SIZE)?;
```

`DNSZoneFile` reads zone files (RFC 1035 §5): `$ORIGIN`, `$TTL` (RFC 2308
§4), blank owners, parentheses, comments; `$INCLUDE` needs a file system and
fails.

## An authoritative server

`DNSAuthority` answers queries for its `DNSZone`s. A zone checks that its
data can be served (one SOA at the origin, a CNAME alone at its name), and
its `lookup` follows RFC 1034 §4.3.2: answers, CNAME chains in the zone,
referrals at zone cuts with their glue (in-domain glue first, which a
response must keep or be truncated, RFC 9471), DNAME (RFC 6672), wildcards
(RFC 4592), NXDOMAIN and no data with the SOA of the TTL of RFC 2308 §3. A
signed zone answers queries with DO with its signatures and the proofs of
NSEC or NSEC3 (RFC 4035 §3.1, RFC 5155 §7.2).

```rust
use umilib::protocol::dns::{DNSAuthority, DNSAuthorityConfig, DNSName, DNSPeer, DNSTransport, DNSZone, DNSZoneFile};

let origin = DNSName::parse("example.", None)?;
let records = DNSZoneFile::new(Some(origin.clone())).parse(text)?;
let authority = DNSAuthority::new(vec![DNSZone::new(origin, records)?], DNSAuthorityConfig::default());
// For each query received:
let peer = DNSPeer { endpoint: client, transport: DNSTransport::UDP };
for response in authority.respond(&datagram, &peer, unix_time) {
    // send `response` to the client
}
```

`respond` checks the query: a response is not answered; another opcode is
NOTIMP; more than one question FORMERR; an EDNS version above 0 BADVERS (RFC
6891 §6.1.3); NXNAME and the other meta-types FORMERR with the extended
error Invalid Query Type (RFC 9824 §3.5); a name of no zone REFUSED. A DS is
answered by the zone above it when the server has both (RFC 4035 §3.1.4.1).

`DNSAuthorityConfig`:

| Field | Default | What it does |
| --- | --- | --- |
| `minimal` | `true` | Positive answers without the apex's NS and additional addresses |
| `udp_size` | 1232 | The largest response over UDP (RFC 9715) |
| `maximum_chain` | 16 | The most CNAME and DNAME a lookup follows |
| `cookie_secrets` | none | Server cookies of RFC 9018: the first secret makes them, any verifies them (for rolling secrets, §5); none ignores cookies |
| `transfers` | none | The clients that may transfer zones (AXFR, RFC 5936; IXFR is answered with the whole zone, RFC 1995 §4) |
| `padding` | 468 | Responses over encrypted transports to padded queries are padded to a multiple of this (RFC 8467) |
| `transfer_size` | 16384 | The largest message of a zone transfer |
| `keepalive` | 10 s | The idle timeout told over TCP and TLS to queries that ask for it (RFC 7828) |

## A stub resolver

`DNSResolver` sends questions to servers (`DNSUpstream`, each of a
transport) and gives their answers, without I/O:

```rust
let query = resolver.resolve(question, now, &mut random)?;
while let Some(transmission) = resolver.transmit() {
    // send transmission.message to resolver.config.upstreams[transmission.upstream]
    // over transmission.transport: UDP from a new random port (RFC 5452 §9.3),
    // TCP and TLS with tcp::DNSTCPFramer, HTTPS with https::DNSHTTPS, QUIC with quic::DNSQUICConnection
}
// for each response received: resolver.receive(query, upstream, transport, &bytes, now, &mut random)
// at resolver.poll_timeout(): resolver.expire(now, &mut random)
while let Some(DNSResolverEvent::Resolved { query, question, result }) = resolver.poll_event() { /* ... */ }
```

It gives each query a random ID (0 over HTTPS and QUIC, RFC 8484 §4.1, RFC
9250 §4.2.1) and ignores responses that do not match their query, server and
transport (RFC 5452 §9.1). It asks the next server on a timeout, SERVFAIL,
REFUSED, NOTIMP or BADVERS, waiting twice as long each round; asks again over TCP
when a UDP response is truncated (RFC 7766 §5), without EDNS after a FORMERR
without OPT (RFC 6891 §7), and with the server's cookie after BADCOOKIE (RFC
7873 §5.3). Queries over UDP and TCP carry a client cookie; over encrypted
transports they are padded to a multiple of 128 bytes (RFC 8467). `DNSCache`
keeps answers for their least TTL, negative answers for the TTL of RFC 2308
§5, and failures for a few seconds (RFC 9520).

## DNSSEC

`DNSSECValidator` checks signatures and denials; `DNSSECResolver` validates
every answer of a `DNSResolver` from a trust anchor down, asking the DS and
DNSKEY questions it needs (RFC 4035 §4.9.3):

```rust
use umilib::protocol::dns::dnssec::{DNSSECConfig, DNSSECResolver, DNSSECResolverEvent, DNSSECStatus, DNSSECTrustAnchor};

let mut resolver = DNSSECResolver::new(config, DNSSECConfig::default(), DNSSECTrustAnchor::root(), &mut random)?;
let query = resolver.resolve(question, now, unix_time, &mut random)?;
// the same exchange of transmissions as DNSResolver, with `unix_time` too
match resolver.poll_event() {
    Some(DNSSECResolverEvent::Resolved { result: Ok((response, DNSSECStatus::Secure)), .. }) => { /* AD set */ }
    Some(DNSSECResolverEvent::Resolved { result: Ok((response, DNSSECStatus::Insecure(_))), .. }) => { /* an unsigned zone */ }
    Some(DNSSECResolverEvent::Resolved { result: Err(error), .. }) => { /* bogus (DNSError::Bogus { code, .. }) or a failure */ }
    None => {}
}
```

- Algorithms: RSA/SHA-1, RSA/SHA-1-NSEC3, RSA/SHA-256, RSA/SHA-512, ECDSA
  P-256 and P-384, Ed25519 and Ed448 — every one RFC 9904 says to implement
  for validation. DS digests SHA-1, SHA-256, SHA-384. `DNSSECConfig` chooses
  which are used: a zone whose DS records name none is insecure (RFC 4035
  §5.2), as is one with RSA keys below `minimum_rsa_bits` (1024).
- One valid signature is enough (RFC 6840 §5.11); at most
  `maximum_verifications` (8) signatures are checked per RRset, against
  responses built to take long (CVE-2023-50387).
- Denials: NSEC (RFC 4035 §5.4, with the rules of RFC 6840 §4.1 on zone cuts
  and DNAME), NSEC3 (RFC 5155 §8, as Erratum 3441 corrects §8.5), Compact
  Denial with NXNAME (RFC 9824). An NSEC3 chain of more than 50 iterations
  makes a denial insecure, of more than 150 bogus (RFC 9276 §3.2; both
  configurable). A name error, a wildcard's answer or its no data whose
  next closer name is in an Opt-Out span is insecure: an unsigned delegation
  may be there.
- The extended error of a failure is in `DNSError::Bogus { code, .. }`
  (`DNSExtendedError`, RFC 8914): DNSSEC Bogus, Signature Expired, DNSKEY
  Missing, RRSIGs Missing, NSEC Missing, Unsupported NSEC3 Iterations Value…
- `DNSSECTrustAnchor::root()` is IANA's anchors of the root as of
  2026-10-29 (KSK-2017 and KSK-2024); `DNSSECTrustAnchor::parse` reads the
  XML of RFC 9718 that IANA publishes, for a newer list.
- `DNSSECPrivateKey` generates and reads keys (the private key format v1.2
  of BIND, as the RFCs' examples use), `DNSSECSigner` signs RRsets, and
  `DNSZone::sign` signs a zone with an NSEC chain (RFC 4035 §2).

## Transports

- UDP: `udp::DNSUDP::accepts` checks the source of a response (RFC 5452
  §9.1); `DNSMessage::udp_response_limit` is the size a response may have.
- TCP: `tcp::DNSTCPFramer` frames and unframes messages; `tcp::DNSTCPClient`
  pipelines queries and matches responses by ID in any order (RFC 7766
  §6.2.1.1); `tcp::DNSTCPServer` answers the queries of a connection with a
  `DNSAuthority`, with idle timeouts (RFC 7766 §6.2.3).
- TLS (port 853): `tls::DNSTLSClient` and `tls::DNSTLSServer` carry the TCP
  framing over a `TLSConnection`; a negotiated ALPN other than `dot` is an
  error.
- HTTPS: `https::DNSHTTPS` makes GET and POST requests and reads them, and
  makes and reads responses fresh for their least TTL (RFC 8484 §5.1); the
  HTTP connection is `protocol-http`'s.
- QUIC (port 853, ALPN `doq`): `quic::DNSQUICConnection` puts each query
  and its responses (one, or the messages of a zone transfer) on a stream
  of a `QUICConnection`, keeping what a stream does not take at once until
  it can; a breach of RFC 9250 closes the connection with PROTOCOL_ERROR.

## Routing

`DNSRule` is a [`service::Rule`](service.md) of `DNSMessage`: a zone (the
name or a name below it, without case) and, if given, a type and a class.
A `Router<DNSRule, _>` sends each query to the service of its zone; a
message without a question matches no rule.

## Trying it

`examples/dns.rs` is a server, a resolver and a key generator over every
transport; `examples/dns.sh` runs them against dig, BIND's dig and delv,
Knot's kdig and Unbound (in Docker), and against themselves.

## FFI and Python

The C ABI (`include/umilib/protocol/dns*.h`) and `umilib.protocol.dns` carry
names and records as their presentation format, one record a line. Messages,
servers and resolvers are handles; see the headers for every function. In
Python:

```python
from umilib.protocol.dns import DNSAuthority, DNSMessage, DNSResolver, DNSTransport, DNSType, DNSUpstream
from umilib.protocol.ip import IPEndpoint

server = DNSAuthority()
server.add_zone("example.", "@ 3600 IN SOA ns admin 1 3600 600 86400 300\nwww 300 IN A 192.0.2.80")
query = DNSMessage.query("www.example.", DNSType.A)
for response in server.respond(query.encode(), IPEndpoint.parse("198.51.100.1:40000"), DNSTransport.UDP):
    print(DNSMessage.decode(response).answers)
```

## Not implemented

A recursive resolver that iterates from the root itself, dynamic updates
(RFC 2136), NOTIFY (RFC 1996), TSIG (RFC 8945), incremental zone transfers
(IXFR answers with the whole zone), NSEC3 zone signing (zones signed with
NSEC3 elsewhere are served), aggressive use of NSEC (RFC 8198), EDNS Client
Subnet (RFC 7871). DNSSEC's GOST, SM2 and private algorithms (MAY in RFC
9904) are not implemented.
