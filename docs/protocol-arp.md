# ARP: `umilib::protocol::arp`

`protocol-arp` (no `std`) resolves IPv4 addresses to hardware addresses
with the Address Resolution Protocol (RFC 826), without doing any I/O. It
has two parts:

- `ARPPacket` reads and writes packets.
- `ARPCache` keeps the table of addresses and decides what to send.

## Packets

An `ARPPacket<H, P>` has hardware addresses `H` and protocol addresses `P`.
The defaults are `MACAddress` and `IPv4Address`, which is what ARP on
Ethernet uses.

RFC 826 allows addresses of any length. Any fixed-length type that
implements `ARPAddress` works, and byte arrays (`[u8; N]`) already do.
`decode` refuses a packet whose address lengths are not those of `H` and
`P`.

```rust
use umilib::protocol::arp::ARPPacket;

let packet: ARPPacket = ARPPacket::decode(&frame_data)?;
let request = ARPPacket::ethernet_request(own_mac, own_ip, wanted_ip);
request.encode(&mut buffer)?;            // send it to MACAddress::BROADCAST
```

Building packets:

- `ethernet_request` builds a request. Its target hardware address is all
  zeros, as RFC 5227 §2.1.1 asks.
- `reply(hardware)` builds the reply to a request, as RFC 826 describes. It
  swaps the sender and target fields and puts the local addresses as the
  sender.

The packets of RFC 5227:

- A probe is a request whose sender protocol address is `0.0.0.0`
  (`is_probe`).
- An announcement is a packet whose sender and target protocol addresses are
  the same (`is_announcement`).

## The cache

`ARPCache` maps protocol addresses to hardware addresses. You drive it with
the current time (a `umilib::runtime::Instant` of your monotonic clock).

`resolve(address, packet, now)` is called when you have something to send:

- `Resolved(hardware)` means you can send it now.
- `Request` means the address is unknown. The packet is kept, and you send a
  request now.
- `Pending` means a request is outstanding. The packet is kept.

The packets kept for one address are the latest `maximum_queued` (RFC 1122
§2.3.2.2). The default is 1. When the table is full, resolving a new address
forgets the entries that are due soonest until it fits. Static entries count
against `maximum_entries` but are never forgotten, so `resolve` fails with
`ARPError::Limit` when only static entries are left to forget (or when
`maximum_entries` is zero).

`receive(packet, hardware, local, now)` is called for every ARP packet that
arrives on an interface. `hardware` is the interface's hardware address and
`local` its protocol addresses. The cache follows "Packet Reception" in
RFC 826:

- It ignores packets of another hardware type or protocol.
- It updates the sender if the sender is already known.
- It adds the sender if the packet is for a local address.
- It answers requests for a local address (`reception.reply`).
- It returns the packets that were waiting for the sender's address
  (`reception.resolved`), now that the address is known.

Two cases from RFC 5227:

- A probe is answered, but its sender (`0.0.0.0`) is not learned (§2.5).
- A packet that claims a local address from another hardware address sets
  `reception.conflict` (§2.4). It is neither learned nor answered; what to
  do then (defend the address or give it up) is up to you.

A sender whose hardware address is a group address (multicast or broadcast)
is never learned, as no host has one as its own (RFC 1812 §3.3.2).

`poll(now)` is called when `poll_timeout()` is reached. Call it until it
returns `None`. It gives one event at a time:

- `ARPEvent::Request(address)`: send the request again. Requests for one
  address are at least `retransmission_interval` apart (RFC 1122 §2.3.2.1:
  at most one per second).
- `ARPEvent::Unreachable(address, packets)`: `maximum_requests` requests
  went unanswered. The packets kept for the address are dropped; you may
  answer them with ICMP Destination Unreachable.

Learned addresses expire after `timeout` (RFC 1122 §2.3.2.1). An address set
with `insert_static` never expires and is not replaced by what packets say.

Every limit is in the configuration:

| Field | Default | Meaning |
| --- | --- | --- |
| `hardware_type`, `protocol_type` | Ethernet, IPv4 | The packets the cache handles |
| `timeout` | 60 s | How long a learned address is used |
| `retransmission_interval` | 1 s | The time between requests for one address |
| `maximum_requests` | 3 | Requests before an address is unreachable |
| `maximum_entries` | 512 | Addresses known and being resolved |
| `maximum_queued` | 1 | Packets kept per address being resolved |

A full table does not stop requests from being answered; their senders are
just not learned. What packets say never pushes an entry out of the table, so
that a flood of forged requests cannot make the cache forget the addresses in
use; only `resolve`, which the host itself calls, does.

## C and Python

The C ABI is in `include/umilib/protocol/arp.h`, and the Python package is
`umilib.protocol.arp`. Both are for MAC and IPv4 addresses only. They differ
from Rust as follows:

- What `receive` and `poll` return are objects of their own (handles in C).
- In Python, `resolve` returns the kind of the answer and the hardware
  address.
