# UDP: `umilib::protocol::udp`

`protocol-udp` (no `std`) reads and writes the datagrams of the User
Datagram Protocol (RFC 768) over IPv4 and IPv6, without doing any I/O. It
has these types:

| Type | What it is |
| --- | --- |
| `UDPHeader` | The 8 bytes of the header, its fields as they are |
| `UDPDatagram` | A datagram whose length and checksum are checked when read and computed when written |
| `UDPConfig` | The ports that may use the zero checksum of IPv6 (RFC 6935, RFC 6936) |
| `UDPRequest`, `UDPRule` | A datagram as a service receives it, and the rule that routes it by its endpoints |

The endpoints and patterns that `UDPRule` uses are in `protocol::ip`
(`IPEndpoint`, `IPEndpointPattern`; see [protocol-ip.md](protocol-ip.md)).

## Datagrams

A `UDPDatagram` has the ports, whether it carries a checksum
(`checksummed`), and its data (`payload`, borrowed from the input). The
length and the checksum are not fields:

- `decode` checks them.
- `encode` and `header` compute them over the pseudo-header of the
  addresses that carry the datagram (RFC 768, RFC 8200 §8.1).

That is why both take the source and destination addresses, which must be
of one IP version (otherwise `UDPError::Family`). Neither accepts a source
address that names no single host, a multicast address or the IPv4 limited
broadcast (`UDPError::Source`, RFC 1122 §4.1.3.6). Whether a source is a
broadcast address of one of your subnets, or one of your own addresses, is
yours to check.

```rust
use umilib::protocol::udp::{UDPConfig, UDPDatagram};

let config = UDPConfig::default();
let datagram = UDPDatagram::decode(ip_payload, source, destination, &config)?;
let reply = datagram.reply(b"answer");               // from its destination port to its source port
reply.encode(destination, source, &config, &mut buffer)?;
```

When reading:

- The length field must be at least 8 and at most the bytes given;
  otherwise `decode` fails with `UDPError::Length`. Bytes after the length
  are not part of the datagram: they are padding of the link or of IP, and
  are ignored, as Linux does.
- A checksum that is not zero must be right (`UDPError::Checksum`).
- A zero checksum means none was computed (RFC 768). Over IPv4 it is
  accepted, and `checksummed` is false. Over IPv6 it fails with
  `UDPError::ZeroChecksum`, unless the destination port is in
  `config.zero_checksum_receive_ports` (RFC 6936 §4 (5, 6)).
- Over IPv6, a length field of 0 is a jumbogram (RFC 2675 §4): the datagram
  is all the bytes given.

When writing:

- A computed checksum of zero is sent as all ones (RFC 768).
- A datagram with `checksummed` false gets a zero checksum. Over IPv6 that
  needs its source port in `config.zero_checksum_send_ports`; otherwise
  `encode` fails with `UDPError::ZeroChecksum` (RFC 6936 §4 (2, 3)). A
  datagram may always be sent with a checksum (§4 (4)).
- Over IPv6, a datagram longer than 65,535 bytes is written with a length
  field of 0 and its real length in the pseudo-header (RFC 2675 §4). Over
  IPv4 it fails with `UDPError::Length`. That check is of the 16-bit field
  only: an IPv4 packet holds at most 65,535 bytes with its header, so the
  largest datagram it carries is 65,515 bytes, or less with options. The
  IP layer refuses a longer packet.

`UDPHeader::decode` reads the 8 bytes of a header and checks nothing else.
Use it for the quote of an ICMP error, which is cut short and has no valid
checksum. A source port of zero means none (RFC 768).

## The zero checksum of IPv6

RFC 8200 §8.1 makes the UDP checksum mandatory over IPv6. RFC 6935 lets
tunnel protocols turn it off on chosen ports, and RFC 6936 sets the rules:

- It is off by default: `UDPConfig::default()` allows it on no port.
- The ports are chosen apart for sending and for receiving:
  `zero_checksum_send_ports` (the local, source port) and
  `zero_checksum_receive_ports` (the local, destination port).
- On those ports, a datagram with a checksum is still accepted and checked
  (§4 (7)).

Before you act on an ICMPv6 error about a datagram that had no checksum,
check that its addresses and ports are those of one of your flows
(§4 (10)). The quote was not protected.

## Routing

`UDPRule` is a `service::Rule`. It matches a request whose local endpoint
is in `local` and whose remote endpoint is in `remote`. Any request type
that implements `ip::IPEndpoints` can be routed this way. `UDPRequest` is
the one for datagrams: the local endpoint, the remote endpoint and the
data.

```rust
use umilib::protocol::ip::IPEndpointPattern;
use umilib::protocol::udp::UDPRule;
use umilib::service::Router;

let dns = UDPRule::new(IPEndpointPattern::port(53));
let internal = UDPRule::new(IPEndpointPattern::port(161))
    .with_remote(IPEndpointPattern::ANY.with_prefix("192.0.2.0".parse()?, 24));
let router = Router::new().route(dns, dns_service).route(internal, snmp_service);
```

## C and Python

The C functions are `umilib_protocol_udp_*` (`include/umilib/protocol/udp.h`):

- A header is a structure passed by value.
- A datagram is an `umilib_protocol_udp_UDPDatagram` of its fields, with
  the payload passed beside it.
- Addresses are their octets (4 or 16) and their number.
- The ports of `UDPConfig` that a call needs are an array: the receive ports
  for `decode`, and the send ports for `header` and `encode`.

The Python package `umilib.protocol.udp` has the same classes:

- Datagrams are frozen dataclasses that own their payload.
- `UDPConfig` holds tuples of ports.
- `UDPRule.matches` takes a `UDPRequest`.
