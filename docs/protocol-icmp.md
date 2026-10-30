# ICMP: `umilib::protocol::icmp`

`protocol-icmp-v4` and `protocol-icmp-v6` (no `std`) read and write the
messages of the Internet Control Message Protocol, without doing any I/O:

- `protocol::icmp::v4`: ICMP for IPv4 (RFC 792, with the rules of RFC 1122
  §3.2.2). Alias `protocol-icmpv4`.
- `protocol::icmp::v6`: ICMPv6 (RFC 4443) and Neighbor Discovery (RFC 4861,
  with RFC 4191 and RFC 8106), including the Neighbor Cache. Alias
  `protocol-icmpv6`.
- `protocol::icmp` (compiled with either version): what both versions
  share. These are the multi-part extensions of error messages (RFC 4884),
  the rate limit of the errors a node sends, and `ICMPError`.

`protocol-icmp` enables both versions.

## Messages

`ICMPv4Message` and `ICMPv6Message` have the same fields:

- `kind`: the type (`ICMPv4Type`, `ICMPv6Type`).
- `code`.
- `rest`: the four bytes after the checksum, whose meaning depends on the
  type.
- `body`: the bytes after the first eight, borrowed from the input.

Every type, known or not, is read and written the same way. The accessors
return `None` when the message is not of their type.

The checksum is not a field: `decode` checks it and `encode` computes it.
The ICMPv6 checksum covers the addresses of the packet (RFC 4443 §2.3,
RFC 8200 §8.1), so `ICMPv6Message::decode` and `encode` take the source and
destination addresses.

```rust
use umilib::protocol::icmp::v4::ICMPv4Message;
use umilib::protocol::icmp::v6::ICMPv6Message;

let request = ICMPv4Message::decode(ip_payload)?;          // ICMPError::Checksum if it is wrong
if let Some(reply) = request.echo_reply() {                // the same identifier, sequence and data
    reply.encode(&mut buffer)?;
}

let message = ICMPv6Message::decode(payload, header.source, header.destination)?;
// RFC 4443 §4.2: reply from a unicast address of the interface the request came in on;
// that is the request's destination only when it was unicast.
let reply = message.echo_reply();
reply.map(|reply| reply.encode(local_unicast_address, header.source, &mut buffer)).transpose()?;
```

The fields of each type:

| Method | Messages | Meaning |
|---|---|---|
| `identifier`, `sequence` | Echo (v4 and v6), Timestamp (v4) and their replies | the identifier and sequence number |
| `timestamps` | Timestamp, Timestamp Reply (v4) | originate, receive and transmit, in milliseconds since midnight UT |
| `next_hop_mtu` | Fragmentation Needed (v4) | the MTU of the next hop (RFC 1191 §4); 0 from a router older than RFC 1191 |
| `mtu` | Packet Too Big (v6) | the MTU of the next hop (RFC 4443 §3.2) |
| `pointer` | Parameter Problem | the octet of the invoking packet that is wrong |
| `gateway` | Redirect (v4) | the gateway to use |
| `original` | error messages | the quoted packet and the extension structure, if any |
| `invoking` | error messages | the header of the quoted packet and the part of its data quoted |

## Error messages

Errors quote the packet that caused them. `invoking()` decodes the quoted
header. The quote is usually truncated, so the header is read with
`decode_truncated`, which does not require the whole packet. It returns the
header and the data that was quoted, which is what the upper layer that
sent the packet needs to find its flow. If the message's extensions are
malformed, `original()` fails, but `invoking()` still reads the quote from
the start of the body. Before acting on an error, the upper
layer checks that the quote matches one of its flows. For TCP, for example,
the quoted sequence number must be in the window (RFC 5927).

`may_report` says whether an error may be sent about a packet that was
received. It does not choose which error to send. The ICMPv6 version takes
the error you mean to send (its type, code and the four bytes after the
checksum; the body is not read), because the exceptions depend on it. It
returns `false` in these cases:

- ICMPv4 (RFC 1122 §3.2.2):
  - the packet is itself an ICMP error;
  - it was sent to a broadcast or multicast address, or `broadcast` is set
    because it was received as a link-layer broadcast;
  - it is a fragment other than the first;
  - its source is not a single host.
- ICMPv6 (RFC 4443 §2.4 (e)):
  - the packet is an ICMPv6 error or a Redirect, or it may be ICMPv6 but its
    type cannot be read, so it might be an error. This is the case when it is
    cut short, or when it is a fragment other than the first whose data
    starts with ICMPv6 or another extension header. A packet whose header
    chain cannot be read, or that ends in an ESP header, is not known to be
    ICMPv6 and may be reported, so that a Parameter Problem can be sent
    about the chain;
  - it was sent to a multicast address, or `multicast` is set because it was
    received as a link-layer multicast or broadcast. Two errors are still
    sent in this case: Packet Too Big, and a Parameter Problem of code 2
    whose pointer names an unrecognized option with the highest two bits of
    its type 10 (RFC 8200 §4.2);
  - its source is unspecified or multicast.

Whether a destination is an anycast address, or a broadcast address of one
of your interfaces, is known only to you.

`quote(packet, headers)` cuts the packet to what the error carries, and
`quote_length` gives its length. The
whole error must fit in 576 bytes for IPv4 (RFC 1812 §4.3.2.3) and in
1,280 bytes for IPv6 (RFC 4443 §2.4 (c)).

`ICMPRateLimiter` limits the errors you send. It is the token bucket of
RFC 4443 §2.4 (f), and RFC 1812 §4.3.2.8 asks the same of IPv4. The default
`ICMPRateLimitConfig` is the example of the RFC: bursts of 10 and 10 errors
a second. Keep one limiter for the whole node, or one per destination,
whichever your policy is.

```rust
use umilib::protocol::icmp::{ICMPRateLimitConfig, ICMPRateLimiter};

let mut limiter = ICMPRateLimiter::new(ICMPRateLimitConfig::default(), now);
// `error` is the ICMPv6Message you mean to send, its body empty for now.
if ICMPv6Message::may_report(&header, payload, multicast, &error) && limiter.allow(now) {
    // send the error, quoting ICMPv6Message::quote(packet, 0)
}
```

These are your responsibility, because they need state that the messages
do not have:

- **The Path MTU.** `next_hop_mtu` and `mtu` return what the message says.
  Keeping a path MTU per destination, and its bounds, is for the caller: an
  IPv6 node never lowers it below 1,280 (RFC 8201 §4), and the plateau
  search of RFC 1191 §7 applies when an IPv4 router reports 0.
- **Deprecated types.** `ICMPv4Type::is_deprecated` names the types that
  RFC 6633 and RFC 6918 deprecate, such as Source Quench. Do not send them,
  and ignore them when they arrive.

## Multi-part extensions

RFC 4884 lets these errors carry an extension structure after the quoted
packet:

- ICMPv4 Destination Unreachable, Time Exceeded and Parameter Problem;
- ICMPv6 Destination Unreachable and Time Exceeded.

`is_extensible()` names these types. The second byte of `rest` (the first
for ICMPv6) is then the length attribute: the length of the quote, in words
of 4 bytes (8 for ICMPv6). `original()` uses it to split the body.

- `ICMPExtensions::decode` checks the version (2) and the checksum. A
  checksum of zero means none was sent (RFC 4884 §7).
- `iter()` gives the objects (`ICMPExtensionObject`), each with its class
  and sub-type. The Interface Information Object of RFC 5837 has class
  `INTERFACE_INFORMATION`; Linux adds it to errors when asked.
- `encode_body(original, word)` writes the body of an extended error. It
  pads the quote to a multiple of the word and to at least 128 bytes, then
  appends the structure. It returns the length attribute to put in `rest`.
- The word is 4 or 8 bytes; any other fails with `ICMPError::Invalid`.
- A structure has one or more objects, each a whole number of 32-bit words
  (RFC 4884 §7, §8), and the quote before it has at least 128 bytes (§4).
  `decode` and `split_body` refuse anything else with `ICMPError::Length`,
  and `encode` refuses to write it.

## Neighbor Discovery

The messages of RFC 4861 are read from an `ICMPv6Message` and the
`IPv6Header` of the packet that carried it:

- `NDPRouterSolicitation`;
- `NDPRouterAdvertisement`, with the preference of RFC 4191;
- `NDPNeighborSolicitation`;
- `NDPNeighborAdvertisement`;
- `NDPRedirect`.

`decode` makes the validity checks of RFC 4861 §6.1, §7.1 and §8.1, and
fails with `ICMPError::Invalid` if one fails. Among them:

- the hop limit is 255, so the packet was not forwarded;
- the code is 0;
- the body is long enough;
- no option has a length of zero;
- the addresses are allowed for the message. For example, a solicitation
  from the unspecified address goes to a solicited-node address and has no
  link-layer address, and Router Advertisements come from link-local
  addresses.

`NDPRedirect::decode` does not check that the sender is your current first
hop for the destination, because that needs your routing table. Check it
yourself.

Preferences (RFC 4191) are the constants of `NDPPreference`: `HIGH`,
`MEDIUM` and `LOW`. `NDPRouterAdvertisement::decode` reads the reserved value,
and any preference that comes with a router lifetime of 0, as `MEDIUM`
(§2.2). `encode` refuses both with `ICMPError::Invalid`, because they are
never sent.

The flags that have no field of their own are kept as received in `flags`,
and written back as they are. `encode` refuses with `ICMPError::Invalid` a
`flags` value with other bits than its mask, so that a flag with a field of
its own is never set or lost through `flags` by mistake:

- In a Router Advertisement, the mask is `NDPRouterAdvertisement::FLAGS` (0x27). It
  covers the H flag of RFC 6275, the P flag of RFC 4389 and the reserved
  bits.
- In a Prefix Information option, the mask is `NDPPrefixInformation::FLAGS` (0x3F).
  It covers the R flag of RFC 6275, the P flag of RFC 9762 and the reserved
  bits.

Set the reserved bits to zero when you build a message.

`encode(source, destination, out)` writes a message with hop limit 255 in
mind: send it in an IPv6 header with `hop_limit` set to
`NDPMessage::HOP_LIMIT`.

**Fragments.** RFC 6980 §5 requires Neighbor Discovery messages that arrive
in a packet with a Fragment header to be ignored. The decoders see only the
IPv6 header, so look for the header with `IPv6ExtensionHeaders` before
decoding. Do not pass a reassembled packet to them. Neighbor Discovery
messages are never sent in fragments.

Options are in the `options` field of each message, as bytes:

- `NDPOptions::new(bytes)` iterates them as `NDPOption`s, each with its type
  and data.
- `NDPOptions::find(bytes, kind)` returns the data of the first option of a
  type.
- `source_link_address()` and `target_link_address()` return the link-layer
  address option of a message.
- `NDPPrefixInformation`, `NDPRouteInformation` (RFC 4191) and
  `NDPRecursiveDNSServers` (RFC 8106) read and write the data of their
  options. Their `decode` refuses these options:
  - a prefix length above 128 (RFC 4861 §4.6.2);
  - a preferred lifetime above the valid lifetime. RFC 4862 §5.5.3 (c) and
    Linux ignore such an option. RFC 4861 itself sets no such rule on
    receipt, so if you use Prefix Information for on-link determination
    only, read the option's bytes from `NDPOptions` yourself;
  - a Route Information option with the reserved preference, or a length
    that is not a whole number of 8-byte units (RFC 4191 §2.3);
  - a Recursive DNS Server option without an address (RFC 8106 §5.1).

  `NDPPrefixInformation::check` makes the same checks, and checks `flags`.

  The bits of a prefix after its length are ignored when read and written
  as zero.
- `NDPOption::encode(kind, data, out)` writes any option, padded to 8 bytes.

Options of unknown types are kept and ignored (RFC 4861 §4.6).

## The Neighbor Cache

`NeighborCache<L>` is the Neighbor Cache of RFC 4861 §5.1 with its
reachability state machine (§7.3 and Appendix C). `L` is the link-layer
address and defaults to `[u8; 6]`, a MAC address; any `[u8; N]` works. You
drive the cache with the current time and send what it asks:

- `resolve(address, packet, now)` is called when you have a packet to send.
  - `Resolved(link)`: send it to `link`. Sending to a STALE neighbor starts
    unreachability detection (DELAY).
  - `Solicit`: the packet is kept. Send a multicast Neighbor Solicitation
    to the address's solicited-node address now.
  - `Pending`: the packet is kept.
- `receive_advertisement(advertisement, now)` processes a valid Neighbor
  Advertisement as §7.2.5 describes. These advertisements are ignored:
  - one for an address with no entry;
  - one without a link-layer address, for an address being resolved;
  - one that does not override a different cached address. This kind only
    turns a REACHABLE entry into STALE.
- `learn(address, link, router, now)` records what a Neighbor Solicitation,
  Router Solicitation, Router Advertisement or Redirect says of a node
  (§6.2.6, §6.3.4, §7.2.3, §8.3):
  - `link` is its link-layer address, if the message carries one.
  - `router` is what the message says of it: `Some(true)` for a Router
    Advertisement or a Redirect's router, `Some(false)` for a Router
    Solicitation, and `None` for no indication.

Both return a `NeighborReception`:

- `packets` are those that were waiting for the address; send them.
- `no_longer_router` is set when the node was a router and is no longer one.
  Remove it from your Default Router List (§7.2.5).

The other methods:

- `confirm(address, now)` records an upper layer's proof of reachability,
  such as an acknowledgment of new TCP data (§7.3.1).
- `poll_timeout()` returns when the cache next has something to do. Call
  `poll(now)` then, until it returns `None`. It reports two events:
  - `Solicit { target, link }`: a solicitation to send. It is multicast
    while the address is being resolved (`link` is `None`) and unicast to
    `link` while an entry is being probed.
  - `Unreachable { target, packets }`: the neighbor did not answer, or it was
    forgotten to make room while being resolved. Its entry is gone, and the
    packets kept for it are returned so that you can send an ICMPv6
    Destination Unreachable (code 3, Address Unreachable) for each (§7.2.2).

`NeighborConfig` holds the constants of RFC 4861 §10 and the limits. The
defaults are:

| Field | Default |
|---|---|
| `reachable_time` | 30 seconds |
| `retransmission_timer` | 1 second |
| `delay_first_probe_time` | 5 seconds |
| `maximum_multicast_solicitations` | 3 |
| `maximum_unicast_solicitations` | 3 |
| `maximum_entries` | 512 |
| `maximum_queued` | 1 |

RFC 4861 §6.3.2 asks a host to draw its ReachableTime at random, between 0.5
and 1.5 times the BaseReachableTime, and to draw it again every few hours.
The cache does not draw it. Set `reachable_time` from your own random source,
and from the Reachable Time of Router Advertisements when they give one.

`maximum_queued` is the number of packets kept for one neighbor; the latest
are kept (§7.2.2).

When the cache is full, `resolve` makes room by forgetting entries, and
fails with `ICMPError::Limit` if it cannot:

1. It forgets addresses still being resolved first, so that resolutions
   nobody answers do not push out the neighbors in use (RFC 6583 §7.1). This
   matters on a router, or on a host that answers scans. Their packets come
   back from `poll` as `Unreachable` events, and `poll_timeout` returns
   `Instant::ZERO` until they have all been reported. At most
   `maximum_entries` such reports are kept.
2. Then it forgets the entries refreshed longest ago. A received message, a
   confirmation and a successful `resolve` refresh an entry; a timer does
   not.

Messages received never forget an entry: `learn` makes no new entry in a
full cache. Otherwise forged solicitations could flush the neighbors in use.

```rust
use umilib::protocol::icmp::v6::{NeighborCache, NeighborConfig, NeighborEvent, NeighborResolution};

let mut cache: NeighborCache = NeighborCache::new(NeighborConfig::default());
match cache.resolve(next_hop, Some(packet_bytes.clone()), now)? {
    NeighborResolution::Resolved(mac) => send_frame(mac, &packet_bytes),
    NeighborResolution::Solicit => send_solicitation(next_hop, None),
    NeighborResolution::Pending => {}
}
while let Some(event) = cache.poll(now) {
    match event {
        NeighborEvent::Solicit { target, link } => send_solicitation(target, link),
        NeighborEvent::Unreachable { target, packets } => report_unreachable(target, packets),
    }
}
```

## C and Python

The C functions are `umilib_protocol_icmp_*`, `umilib_protocol_icmp_v4_*`
and `umilib_protocol_icmp_v6_*` (see `include/umilib/protocol/icmp.h` and
the files under `include/umilib/protocol/icmp/`):

- A message is an `umilib_protocol_icmp_ICMPHeader` (type, code and the
  four bytes) and its body.
- The Neighbor Cache is a handle for 6-byte link-layer addresses. The
  packets it returns are `NeighborPackets` handles, and the events of
  `poll` are `NeighborEvent` handles.

The Python package `umilib.protocol.icmp` has the same classes:

- `ICMPExtensionObject` names its class `class_`, since `class` is a Python
  keyword.
- `ICMPExtensions.check`, `ICMPExtensions.check_word` and
  `NDPPrefixInformation.check` raise `ICMPError` as the Rust methods return it.
- Messages are frozen dataclasses that own their body.
- `NeighborCache.resolve` returns a `(NeighborResolution, link)` pair, and
  `learn` and `receive_advertisement` return a `NeighborReception`.
- `ICMPv6Message.may_report` takes the error as an `ICMPv6Message`.
- `NeighborCache.poll` returns a `NeighborEvent` with `kind`, `target`,
  `link` and `packets`.
