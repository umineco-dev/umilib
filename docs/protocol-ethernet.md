# Ethernet: `umilib::protocol::ethernet`

`protocol-ethernet` (no `std`) reads and writes Ethernet frames (IEEE 802.3):

| Type | What it is |
| --- | --- |
| `MACAddress` | A 48-bit address and its text form |
| `EtherType` | The type field: an EtherType, or the length of an IEEE 802.3 frame |
| `VLANTag` | A VLAN tag (IEEE 802.1Q, or IEEE 802.1ad for a service tag) |
| `EthernetHeader` | The addresses, up to two tags and the type field |
| `EthernetFrame` | The padding and the frame check sequence of a frame |

IPv4 over Ethernet follows RFC 894, and IPv6 over Ethernet follows RFC 2464.

```rust
use umilib::protocol::ethernet::{EtherType, EthernetHeader, MACAddress};

let (header, data) = EthernetHeader::decode(&frame)?;
if header.ether_type == EtherType::IPV4 { /* data is an IPv4 packet */ }
let reply = EthernetHeader::new(header.source, own_address, EtherType::ARP);
reply.encode(&mut buffer)?;
```

## Addresses

A `MACAddress` is its six octets in transmission order (`address.0`).

Text:

- `parse` reads six pairs of hexadecimal digits. They may be separated by
  colons or, as IEEE writes them, by hyphens, but one separator throughout.
- `to_string` writes lowercase pairs separated by colons.

The bits of the first octet:

- The Individual/Group bit is read by `is_multicast` and `is_unicast`.
  `is_broadcast` is the all-ones address.
- The Universal/Local bit is read by `is_local`.

The mappings to other addresses:

- `modified_eui64` gives the IPv6 interface identifier of the address
  (RFC 4291 appendix A, RFC 2464 §4).
- `from_ipv4_multicast` maps an IPv4 group to `01-00-5E` and its low 23 bits
  (RFC 1112 §6.4).
- `from_ipv6_multicast` maps an IPv6 group to `33-33` and its last 32 bits
  (RFC 2464 §7).

## The header

`EthernetHeader::decode` reads the destination, the source, the tags and the
type field. It returns the header and the data after it.

The type field decides what the data is:

- **Up to 1,500:** the field is the length of an IEEE 802.3 frame. The data
  is that many bytes, so padding after it is dropped. A frame shorter than
  its length fails with `EthernetError::Length`.
- **From 1,501 to 1,535:** the field is neither a length nor an EtherType,
  and decoding fails with `EthernetError::EtherType`.
- **From 0x0600:** the field is an EtherType (`EtherType::IPV4`, `ARP`,
  `IPV6`…). The data is everything after the header, including any padding.
  The protocol inside knows its own length; for example, `IPv4Header::decode`
  stops at the total length.

Tags:

- Tags with the tag protocol identifier 0x8100 (`EtherType::VLAN`) or 0x88A8
  (`EtherType::SERVICE_VLAN`) are read into `tags`, outermost first.
- A third tag fails with `EthernetError::Tag`.
- `VLANTag` holds the priority (0 to 7), the drop eligible indicator and the
  VLAN identifier. Identifiers 0 to 4,095 are read; 4,095 is reserved by
  IEEE 802.1Q and is not written.

`encode` writes the header. It fails with `EthernetError::Tag` for a tag
whose fields do not fit, for a tag that follows an absent one, and for a type
field that is a tag protocol identifier (it would be read back as one more
tag); with `EthernetError::EtherType` for a type field from 1,501 to 1,535.

## The frame

Interfaces that hand over whole frames add what the header and data lack:

- `EthernetFrame::padding(length)` is the number of zero bytes that make the
  smallest frame: 60 bytes before the frame check sequence.
- `EthernetFrame::fcs(frame)` is the frame check sequence: the CRC-32 of the
  header and the data, in the byte order it is sent.
- `EthernetFrame::verify(frame)` checks a frame that ends with its frame
  check sequence.

Packet sockets and TAP devices hand over frames without the frame check
sequence, so these are not needed with them.

## C and Python

The C ABI is in `include/umilib/protocol/ethernet.h`, and the Python package
is `umilib.protocol.ethernet`. Both have the same types and methods as Rust,
with these differences:

- In C, a header's tags are the first `tag_count` of its array.
- In Python, a header's tags are a list.
