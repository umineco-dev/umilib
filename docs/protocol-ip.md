# The Internet Protocol: `umilib::protocol::ip`

`protocol-ip-v4` and `protocol-ip-v6` (no `std`) read and write IP packets
without doing any I/O: you hand them bytes and the time, and they hand you
headers, data and deadlines. Either feature also enables `umilib::protocol::ip`,
which holds what both versions share:

| Type | What it is |
| --- | --- |
| `IPv4Address`, `IPv6Address`, `IPAddress` | Addresses and their text forms (RFC 4291 §2.2, RFC 5952) |
| `IPProtocol` | A protocol number (the IANA registry "Assigned Internet Protocol Numbers") |
| `InternetChecksum` | The checksum of RFC 1071, updated incrementally as RFC 1624 |
| `IPPseudoHeader` | The pseudo-header that UDP, TCP and ICMPv6 checksums cover |
| `IPFragmentBuffer` | The data of one datagram being reassembled from fragments |
| `IPEndpoint`, `IPEndpointPattern` | An address and a port of a transport protocol, and sets of them by prefix and port range |

```rust
use umilib::protocol::ip::{IPAddress, IPv6Address, InternetChecksum};

let address: IPv6Address = "2001:0DB8:0:0:1:0:0:1".parse()?;
assert_eq!(address.to_string(), "2001:db8::1:0:0:1");             // RFC 5952
let any: IPAddress = "192.0.2.1".parse()?;                         // IPv6 if the text has a colon
let checksum = InternetChecksum::checksum(&header_bytes);          // RFC 1071
```

## Addresses

`IPv4Address` and `IPv6Address` are their octets in network byte order
(`address.0`), with `from_bits`/`to_bits` for the number they make.

Text:

- `"…".parse::<IPv4Address>()` reads dotted decimal: four numbers from 0 to
  255. Leading zeros are refused (`010.0.0.1`), because some readers take
  them as octal (RFC 6943 §3.1.1).
- `"…".parse::<IPv6Address>()` reads every form of RFC 4291 §2.2, including
  one `::`, upper and lower case, and the last 32 bits in dotted decimal
  (`::ffff:192.0.2.1`). Zone identifiers (`fe80::1%eth0`) are not part of
  an address: split them off before reading it.
- `to_string()` writes the one text form of RFC 5952. Leading zeros are
  dropped, letters are lowercase, and the first longest run of two or more
  zero groups becomes `::`. An IPv4-mapped address is written
  `::ffff:a.b.c.d`; other embedded IPv4 addresses are written in hexadecimal.

The predicates follow the IANA special-purpose registries (RFC 6890):

| Predicate | IPv4 | IPv6 |
| --- | --- | --- |
| `is_unspecified` | `0.0.0.0` | `::` |
| `is_loopback` | `127.0.0.0/8` | `::1` |
| `is_private` | `10/8`, `172.16/12`, `192.168/16` (RFC 1918) | |
| `is_unique_local` | | `fc00::/7` (RFC 4193) |
| `is_link_local` | `169.254/16` (RFC 3927) | `fe80::/10` |
| `is_multicast` | `224/4` | `ff00::/8` (`multicast_scope` gives the scope) |
| `is_broadcast` | `255.255.255.255` | |
| `is_documentation` | `192.0.2/24`, `198.51.100/24`, `203.0.113/24` (RFC 5737) | `2001:db8::/32` (RFC 3849), `3fff::/20` (RFC 9637) |

Other helpers:

- `prefix` and `has_prefix` handle prefixes. A prefix length beyond the
  address keeps every bit.
- `to_ipv6_mapped`, `to_ipv4_mapped` and `IPAddress::to_canonical` convert
  IPv4-mapped addresses.
- `solicited_node` gives the solicited-node multicast address used by
  Neighbor Discovery.
- `link_local`, `from_interface_identifier` and `interface_identifier` build
  addresses from their two halves (RFC 4291 §2.5.1).

## Endpoints

An `IPEndpoint` is an address and a port of a transport protocol (UDP, TCP).
Its text is `address:port` for IPv4 and `[address]:port` for IPv6, the forms
of RFC 3986 §3.2.2. `parse` refuses anything else with `IPError::Syntax`,
including an IPv6 address without brackets.

An `IPEndpointPattern` is a set of endpoints: those whose address has a
prefix, and whose port is in a range. The transport protocols route requests
with it (`UDPRule`, for example). The constructors:

| Constructor | Matches |
| --- | --- |
| `IPEndpointPattern::ANY` | every endpoint |
| `IPEndpointPattern::port(53)` | port 53, any address |
| `IPEndpointPattern::ports(5000, 5999)` | ports 5000 to 5999, any address |
| `.with_address(address)` | the same, of that address only |
| `.with_prefix(address, 24)` | the same, of the addresses whose first 24 bits are those of `address` |

IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`, RFC 4291 §2.5.5.2) match as
the IPv4 address they map, so a pattern for IPv4 also covers dual-stack
sockets. In the same way, a prefix of at least 96 bits of mapped addresses
is the IPv4 prefix it maps: `::ffff:198.51.100.0/120` is `198.51.100.0/24`
(`IPAddress::to_canonical_prefix`). Any other prefix never matches an
address of the other version; `::/0` matches no IPv4 address.

`with_prefix` keeps the prefix in that canonical form, with the bits after
the length cleared, so equal sets of endpoints are equal patterns. A length
beyond the address's bits (above 32 for IPv4) means all of them.

An endpoint has no zone. Its text refuses `%` (RFC 6874), so a link-local
endpoint is on an interface that you choose.

`IPEndpoints` is the trait of what a pattern is matched against: anything
with a local and a remote endpoint.

## The checksum

`InternetChecksum` sums 16-bit big-endian words in one's complement. The
last odd byte is padded with a zero byte.

- `update` may be called any number of times; the result does not depend on
  where the data is split.
- `finish` gives the checksum to write.
- `InternetChecksum::verify(bytes)` checks data that contains its own
  checksum: it sums to all one bits (RFC 1071 §1).
- `adjust(checksum, old, new)` and `adjust_bytes` update a checksum after a
  field changes, with equation 3 of RFC 1624. A router uses this, for
  example, when it decrements the time to live.

`IPPseudoHeader::new(source, destination, protocol, length)` builds the
pseudo-header of either version:

- IPv4: RFC 768 and RFC 9293 §3.1, with a 16-bit length.
- IPv6: RFC 8200 §8.1, with a 32-bit length.

It fails with `IPError::Family` if the two addresses are of different
versions, and with `IPError::Length` if the length does not fit.
`checksum()` gives an `InternetChecksum` that already includes the
pseudo-header; add the upper-layer header (with its checksum field set to
zero) and its data.

## IPv4: `umilib::protocol::ip::v4`

`IPv4Header` holds every field of RFC 791 §3.1 except the header checksum:
`decode` checks it and `encode` computes it.

```rust
use umilib::protocol::ip::v4::IPv4Header;
use umilib::protocol::ip::{IPProtocol, IPv4Address};

let (header, data) = IPv4Header::decode(&packet)?;
let mut header = IPv4Header::new(source, destination, IPProtocol::UDP, data.len())?;   // TTL 64, no options
header.identification = next_identification;                                            // see below
header.encode(&mut buffer)?;
```

`decode` refuses a packet that is not consistent:

| Error | When |
| --- | --- |
| `IPv4Error::Version` | The version is not 4. |
| `IPv4Error::Length` | The header length is below 20 bytes, or the total length is below the header or beyond the bytes. |
| `IPv4Error::Checksum` | The header checksum is wrong (RFC 1122 §3.2.1.2: the packet is discarded). |
| `IPv4Error::Option` | The options are malformed. |

The data it returns stops at the total length, so the padding of a link
layer is left out. The reserved flag is ignored on receipt and sent as zero.
Whether a packet's addresses are acceptable (for example, a broadcast
source) is for the receiver to decide; the header only reads them.

`IPv4Header::new` leaves the identification at zero. A datagram that may be
fragmented (Don't Fragment clear) needs an identification unique for its
source, destination and protocol for as long as its fragments may live
(RFC 6864 §4), and unpredictable (RFC 7739). An atomic datagram (Don't
Fragment set, not a fragment) may have any identification.

Options:

- `IPv4Options` holds up to 40 bytes of options. `iter()` gives each
  `IPv4Option` (its kind and data), skipping No Operation and stopping at
  End of Option List.
- `push` appends an option. `encode` pads the options to a multiple of
  4 bytes.
- `IPv4OptionKind` gives the copied flag, the class and the number of an
  option type.

Fragmentation and reassembly:

- `IPv4Fragmenter::new(header, data, mtu)` gives the fragments of a datagram
  (RFC 791 §3.2): a header and a part of the data for each.
  - Every part but the last is a multiple of 8 bytes.
  - The first fragment carries every option; the others carry only the
    copied ones.
  - A fragment can itself be fragmented again.
  - A datagram that fits the MTU is one fragment.
  - It fails with `IPv4Error::Fragment` if the datagram has Don't Fragment
    set and does not fit, or if the MTU cannot carry 8 bytes per fragment.
- `IPv4Reassembler` puts datagrams back together; see
  [Reassembly](#reassembly).

## IPv6: `umilib::protocol::ip::v6`

`IPv6Header` is the fixed 40-byte header (RFC 8200 §3).

- `decode` refuses a version other than 6, and a payload length beyond the
  bytes it is given.
- Jumbograms (RFC 2675) are not read: a payload length of zero is an empty
  payload.

The extension headers follow the header.

- `IPv6ExtensionHeaders::new(next_header, payload)` walks the chain. It gives
  each `IPv6ExtensionHeader` (its kind, its Next Header value and its bytes)
  and ends at the upper layer. A Hop-by-Hop Options header anywhere but
  first fails with `IPv6Error::ExtensionHeader` (RFC 8200 §4.1).
- `IPv6ExtensionHeaders::upper_layer(next_header, payload)` gives the
  upper-layer protocol and where its data starts.
- An Encapsulating Security Payload header ends the chain, because what
  follows it is encrypted.
- Which numbers are extension headers follows RFC 7045
  (`IPv6ExtensionHeader::is_extension`).

The header types:

- `IPv6OptionsHeader` reads and writes Hop-by-Hop and Destination Options
  headers. `encode` pads them to a multiple of 8 bytes with Pad1 or PadN.
  `iter()` gives each option with the offset of its type, which is where an
  ICMPv6 Parameter Problem message points.
- `IPv6OptionKind::action()` says what to do with an unrecognized option
  (RFC 8200 §4.2).
- `IPv6RoutingHeader` reads and writes Routing headers. Type 0 is deprecated
  (RFC 5095) and must not be processed.
- `IPv6FragmentHeader` reads and writes Fragment headers.

Fragmentation and reassembly:

- `IPv6Fragmenter::new(header, payload, identification, mtu)` fragments a
  packet at its source (RFC 8200 §4.5).
  - The per-fragment headers repeat in every fragment. These are the
    extension headers up to the last Routing header, or else a Hop-by-Hop
    Options header.
  - The rest of the header chain goes in the first fragment (RFC 7112). If it
    does not fit, `IPv6Error::HeaderChain` is returned.
  - A packet that already has a Fragment header is refused with
    `IPv6Error::ExtensionHeader`: only the source fragments a packet, once.
  - Use an unpredictable identification (RFC 7739).
  - Each fragment's `encode` writes the whole packet.
- `IPv6Reassembler` puts packets back together; see
  [Reassembly](#reassembly).

## Reassembly

`IPv4Reassembler` and `IPv6Reassembler` work the same way.

`receive(header, payload, now)` takes a packet and the current time:

- It returns the datagram, or packet, that the fragment completes.
- A packet that is not a fragment is complete at once. For IPv6, this
  includes an atomic fragment (RFC 6946).
- `now` is a `umilib::runtime::Instant` of your monotonic clock.
- Call `expire(now)` before `receive`: a fragment of a datagram whose
  deadline is past fails with `Expired` until `expire` gives that datagram
  back, so that a datagram is never completed after its deadline.

The rules of reassembly:

- The deadline of a datagram starts at its first-arriving fragment and lasts
  `config.timeout`: 60 seconds by default (RFC 1122 §3.3.2, RFC 8200 §4.5).
- A fragment that overlaps another abandons its datagram: the bytes received
  are released, and every fragment of that datagram, those not yet received
  too, is refused with `Overlap` until the deadline. This follows RFC 5722
  for IPv6 and RFC 1858 for IPv4; Linux does the same.
- Only an exact duplicate of a received fragment is ignored: the same
  offset, the same length, the same bytes and the same More Fragments flag.
  A fragment that covers part of another, even with the same bytes, is an
  overlap.
- A fragment but the last must carry a multiple of 8 bytes.
- A fragment without data adds no byte. A last one without data still sets
  the end of the datagram.
- A fragment that would make the datagram larger than allowed is refused,
  and only that fragment is dropped.
- The header of the datagram is that of the first fragment received at
  offset zero; a later copy of that fragment does not replace it.
- For IPv6, a Hop-by-Hop Options header named by a Fragment header fails
  with `IPv6Error::ExtensionHeader`: it may only follow the IPv6 header.

`poll_timeout()` gives the earliest deadline. `expire(now)` removes one
datagram that has passed its deadline and returns it; call it until it
returns `None`. If the returned datagram's `first` is set, its first fragment
arrived, so send an ICMP Time Exceeded message (code 1) quoting it. An
abandoned datagram (`abandoned`) has no `first`: no ICMP message is sent for
it (RFC 8200 §4.5).

Every limit is in the configuration:

| Field | Default | Limits |
| --- | --- | --- |
| `timeout` | 60 s | How long a datagram has to be completed |
| `maximum_length` | 65,535 | The largest datagram reassembled (EMTU_R) |
| `maximum_datagrams` | 64 | Datagrams being reassembled at once |
| `maximum_buffered` | 4 MiB | Bytes held at once, approximately: the data and a record of each fragment |

A fragment is checked first. One that fails its own checks (`Overlap`,
`Length`) or that could not fit the limits even alone (`Limit`) changes
nothing else. When an accepted fragment would go beyond a limit, other
datagrams with the earliest deadlines are dropped, silently, to make room:
any of them for the count of datagrams, only those that hold bytes for the
bytes, so that an abandoned datagram keeps refusing its fragments. This
keeps a flood of incomplete datagrams from blocking every later one.

Both reassemblers keep their datagrams in an `IPReassemblyTable` (in
`umilib::protocol::ip`), the same for both versions: `table.entries` are the
datagrams by key and `table.buffered` the bytes they hold.
`IPFragmentBuffer::check` tells, without changing anything, whether a
fragment would be accepted and how much memory it would take.

## C and Python

The C ABI is in `include/umilib/protocol/ip.h`, `ip/v4.h` and `ip/v6.h`.
The Python package is `umilib.protocol.ip` with `.v4` and `.v6`. Both have
the same types and methods as Rust, with these differences:

- In C, addresses, headers and checksums are structures passed by value.
  Fragmenters, reassemblers and the datagrams `expire` gives back are handles.
- In C, an endpoint or a pattern is a structure of 16 octets, the number of
  them used (4 or 16; 0 for any address in a pattern), and the ports.
- In Python, `IPAddress` is the base class of `IPv4Address` and
  `IPv6Address`.
- In Python, the method `class` of `IPv4OptionKind` is named `class_`,
  because `class` is a keyword.
