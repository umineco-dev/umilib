# The network layers

How `protocol-ethernet`, `protocol-arp`, `protocol-ip`, `protocol-ip-v4`,
`protocol-ip-v6`, `protocol-icmp-v4`, `protocol-icmp-v6`, `protocol-udp` and
`protocol-tcp` are built.

## Shape

The layers do no I/O and keep no sockets. They have two kinds of type:

- **Codecs.** A header type has `decode(&[u8]) -> (Header, &[u8])`, which
  returns the header and the data it covers. It has `encode(&mut impl
  Writer)` to write itself back. Checksums and lengths that follow from the
  other fields are not stored: `decode` checks them and `encode` computes
  them. `decode(encode(h)) == h` holds for every header whose fields fit
  their widths: `encode` masks a field that does not (an IPv4 DSCP above 63,
  a flow label above 20 bits) rather than fail, as the C layout of the
  headers allows such values. Where a value would change how the bytes read
  back (a tag protocol identifier in the Ethernet type field), `encode`
  fails instead.
- **State machines.** These are the reassemblers, the ARP cache, the
  Neighbor Cache, and the TCP connection and listener. They
  take the current time as a `runtime::Instant` (nanoseconds of the caller's
  monotonic clock). They give their next deadline with `poll_timeout()`, and
  give expired work with `expire`/`poll`, one item per call. A caller stacks
  them in a loop; nothing in the crate composes them.

The modules depend on each other in one direction only:

- `protocol::ip` holds what both versions share: addresses, the checksum,
  the pseudo-header, `IPFragmentBuffer` and the reassembly table. The root module has no feature
  of its own and is compiled with either version.
- `IPFragmentBuffer` holds the bytes of one datagram and the ranges
  received. It is generic over the IP version: `v4` and `v6` keep their
  own keys, headers, deadlines and limits around it.
- ARP is generic over its address types (`ARPAddress`), as RFC 826 is. Its
  defaults are MAC and IPv4 addresses.
- Ethernet does not depend on IP. `MACAddress::from_ipv4_multicast` and
  `from_ipv6_multicast` take byte arrays, not IP address types.

## Decisions

Each entry gives the choice, why it was made, and what was not chosen.

- **IPv4 text refuses leading zeros** (`010.0.0.1`), the strict form of
  RFC 6943 §3.1.1. Some readers take `010` as octal (8) and others as
  decimal (10), so one text would name two addresses; refusing is the only
  reading that cannot disagree with another implementation. Accepting
  them as decimal, as some libraries do, was rejected for that reason.
- **IPv6 text uses mixed notation only for IPv4-mapped addresses.** RFC 5952
  §5 recommends it for well-known prefixes "defined in RFC 4291 and
  RFC 2765"; RFC 2765 is obsolete, and the other forms (`64:ff9b::/96`) are
  not distinguished by the address alone. Zone identifiers are not part of
  `IPv6Address`: they name an interface of one host, not an address.
- **Overlapping fragments abandon the datagram, for IPv4 as well as IPv6.**
  RFC 5722 and RFC 8200 §4.5 require it for IPv6. RFC 1858 and RFC 3128 show
  the attacks overlaps allow on IPv4, and Linux refuses them too. RFC 791's
  reassembly, which lets later fragments overwrite earlier ones, was
  rejected: the bytes a receiver keeps would depend on arrival order.
- **The datagram stays abandoned until its deadline.** RFC 5722 §4 says the
  datagram's fragments, "including those not yet received", are discarded.
  Forgetting the datagram at once was rejected: its remaining fragments would
  start a new reassembly, which an attacker could complete with fragments of
  its own. An abandoned datagram releases its bytes and keeps only its key
  and deadline; it counts against `maximum_datagrams`.
- **Only exact duplicates are ignored** (the same offset, length, bytes and
  More Fragments flag), as RFC 8200 §4.5 allows. Treating any fragment
  inside the received bytes with the same contents as a duplicate was
  rejected: RFC 5722 makes every other overlap an error, and a fragment that
  covers part of another is not a copy of it. This is why
  `IPFragmentBuffer` keeps the range of each fragment, not a merged range:
  only the original boundaries show whether a fragment is the same one.
  Completion is the count of bytes received equalling the length, which the
  ranges being disjoint makes exact.
- **A fragment without data adds no bytes.** Growing the data to its offset
  let an empty fragment far beyond the others reserve memory and, with a
  shorter last fragment, pad the reassembled datagram with zeros.
- **Errors that are not overlaps drop only the fragment** (beyond the limit,
  beyond the known end, a second end), as RFC 8200 §4.5 says for the length
  errors.
- **Deadlines run from the first-arriving fragment and are never extended**
  (RFC 8200 §4.5), so later fragments cannot keep a datagram alive.
- **When a limit is reached, other datagrams with the earliest deadlines
  are dropped.** Refusing every new datagram was rejected: a few tiny
  fragments a minute would then block all reassembly. Dropping the oldest
  favours the datagrams most likely still to complete, as Linux does. Two
  rules keep this from being turned against the reassembler:
  - A fragment is checked in full (`IPFragmentBuffer::check`) before
    anything is dropped. A fragment that fails its own checks, or that could
    not fit `maximum_buffered` even alone, drops nothing. Without this, one
    packet with a large offset could wipe every datagram.
  - Only datagrams that hold bytes are dropped for the byte limit. An
    abandoned datagram holds none; dropping it would free nothing and would
    let its fragments start a new reassembly, undoing RFC 5722 §4. It is
    dropped only for the count limit.
  The memory counted is the data and two words per fragment (`memory()`):
  an approximation that leaves out spare capacity and the inner nodes of
  the map, which are proportional to it.
- **Fragments are recorded one by one, in a `BTreeMap` from start to end.**
  A sorted `Vec` cost O(n) per insertion, O(n²) for a datagram sent in
  reverse in 8-byte fragments (8,191 of them); merged ranges lose the
  original boundaries that tell an exact duplicate from an overlap. Where
  the last fragment starts is kept, so that a copy of the fragment before
  an empty last fragment is recognised as the same fragment.
- **A fragment after the deadline fails with `Expired`.** RFC 1122 §3.3.2
  and RFC 8200 §4.5 bound reassembly by the deadline. Expiring the datagram
  inside `receive` was rejected: the caller would lose the first fragment
  it needs to send ICMP Time Exceeded. The caller calls `expire` first; until
  it does, the datagram neither completes nor accepts fragments.
- **One table for both versions.** `IPReassemblyTable<K, F>` holds the
  datagrams, their accounting, eviction, abandonment, deadlines and expiry;
  `IPReassembly<F>` is one datagram. Each version gives only its key, its
  first-fragment type `F` (`IPFirstFragment`) and the rules of its headers.
  Copies of the same logic in `v4` and `v6` were rejected: they had already
  drifted apart once (which first fragment was kept).
- **The first fragment received at offset zero gives the header** and is
  not replaced by a later copy, the same in both versions.
- **ICMP Time Exceeded.** `expire` gives back the whole reassembly, with the
  first fragment's header and data when it arrived. This is what RFC 1122
  §3.3.2 and RFC 8200 §4.5 say a Time Exceeded message is sent for. An
  abandoned datagram has none: no ICMP error is sent for overlaps.
- **IPv6 fragmentation.** The per-fragment part ends after the last Routing
  header, or else after a Hop-by-Hop Options header. Destination Options
  headers before a Routing header are inside it. `IPv6Fragmenter` checks
  that the rest of the chain fits in the first fragment (RFC 7112). It
  cannot check the upper-layer header, whose length it does not know. A
  packet that already has a Fragment header is refused: only its source
  fragments a packet, once, and fragmenting it again would nest Fragment
  headers.
- **A Hop-by-Hop Options header behind a Fragment header is refused** by the
  reassembler. RFC 8200 §4.1 allows it only right after the IPv6 header;
  reassembling it would put it after the per-fragment headers.
- **Jumbograms** (RFC 2675) are not supported: a payload length of zero is
  an empty payload. They need a Hop-by-Hop option the rest of the stack does
  not use, and links with an MTU above 65,575 bytes are rare.
- **The reserved IPv4 flag** is ignored on receipt and sent as zero, as
  RFC 791 asks of senders; dropping packets that set it was rejected, as no
  RFC asks receivers to.
- **ARP learns only from what the host can trust.** A probe's sender
  (`0.0.0.0`), a sender with a group hardware address (RFC 1812 §3.3.2) and
  a packet that claims a local address from another hardware address
  (RFC 5227 §2.4) are not learned; the last is not answered either (RFC 5227
  §2.5 excepts conflicting packets). A static entry is never replaced.
- **A full ARP table forgets only for the host's own resolutions.** When
  `resolve` needs room, the entries due soonest are forgotten until it fits;
  static entries count against the limit but are never forgotten. A received packet
  never forgets an entry: forged requests could otherwise flush the
  addresses in use. Requests are answered even when the table is full.
- **VLAN identifier 4,095** is read but not written: IEEE 802.1Q reserves it
  and forbids sending it in a tag.
- **The checksum folds a sum set from outside** before adding to it, so a
  C caller that does not start from zero cannot overflow it.

## ICMP decisions

- **One message type per version, not an enum of message types.**
  `ICMPv4Message` and `ICMPv6Message` keep the type, code, the four bytes
  after the checksum and the body, and give each field through an accessor
  that returns `None` for other types. IANA registers new types often
  (Extended Echo, RFC 8335, is recent), and a message of an unknown type
  must still be read, passed on or ignored as the RFCs say (RFC 4443
  §2.4 (a) and (b)). An enum with one variant per type was rejected: it
  needs a catch-all variant, which is this structure again, and converting
  between the two would be a second place to add every type.
- **Neighbor Discovery messages are separate types** read from an
  `ICMPv6Message` and the `IPv6Header`. The validity checks of RFC 4861
  §6.1, §7.1 and §8.1 need the hop limit and the addresses of the packet.
  Decoding them from the ICMPv6 bytes alone was rejected: a decoder that
  cannot make the checks would hand out messages that must be dropped.
- **The ICMPv6 checksum is checked in `decode`,** which therefore takes the
  addresses. A separate `verify` step was rejected for the same reason as for
  IP headers: a message whose checksum was never checked could be acted on.
- **A Redirect is checked except for its sender.** RFC 4861 §8.1 requires
  the source to be the current first hop for the destination. That needs
  the routing table, which this layer does not have, so the caller checks
  it. Taking a routing callback was rejected: it would tie the codec to one
  form of routing table.
- **Fragmented Neighbor Discovery is the caller's to drop** (RFC 6980 §5).
  The decoders see the IPv6 header only, not the extension headers, and a
  reassembled packet has none left. Passing the extension headers to every
  decoder was rejected: they are already available from
  `IPv6ExtensionHeaders`, and the reassembler's output would still need the
  caller to say it was reassembled.
- **`may_report` for ICMPv6 takes the error to be sent.** The exceptions
  of RFC 4443 §2.4 (e.3) depend on the error, and for a Parameter Problem
  on the option it points to: only an option type whose highest bits are
  10 may be reported to a multicast destination (RFC 8200 §4.2). Taking the
  type and code alone was rejected, because it allowed every unrecognized
  option. A packet that may be ICMPv6 but whose type cannot be read counts
  as an error message. A fragment other than the first carries part of a
  message, and sending an error about an error is forbidden (§2.4 (e.1)),
  while not sending one is always allowed. Such a fragment counts only if its
  data may hold ICMPv6, that is, if its Fragment header names ICMPv6 or
  another extension header; its data is not parsed as headers. A packet
  whose header chain cannot be read is not counted: RFC 8200 §4.5 and
  RFC 7112 ask for a Parameter Problem about such chains, and treating them
  as errors would forbid it.
- **`may_report` answers a question; it does not build errors.** Which error
  to send, and whether to send any, depends on the caller's forwarding and
  socket state. RFC 1122 §3.2.2 and RFC 4443 §2.4 (e) list the packets never
  to report, and that list is what `may_report` checks. Facts the packet
  does not show are arguments: a link-layer broadcast or multicast. Facts the
  caller alone knows are left to it: a broadcast address of an interface, an
  anycast address.
- **The quote fills the error up to 576 bytes for IPv4,** as RFC 1812
  §4.3.2.3 asks of routers. Quoting only the header and 8 bytes, the minimum
  of RFC 792, was rejected: the extensions of RFC 4884 need at least 128
  bytes, and upper layers match errors more reliably with more of the
  packet. IPv6 fills up to 1,280 bytes (RFC 4443 §2.4 (c)).
- **One rate limiter for both versions,** a token bucket, as RFC 4443
  §2.4 (f) recommends. Its defaults are the example of that section (B = 10,
  N = 10 a second). The caller decides whether one bucket covers the node
  or each destination has one. A timer-based limit (one error per interval)
  was rejected: RFC 4443 §2.4 (f) explains that it cuts off traceroute,
  which sends bursts.
- **An extension checksum of zero is accepted** as none sent, as RFC 4884
  §7 says. `encode` always writes one.
- **The extensions are checked as RFC 4884 defines them, in both
  directions.** A structure has one or more objects (§7), objects are whole
  32-bit words (§8), the quote before them has at least 128 bytes (§4), and
  the word is 4 or 8 bytes. `decode`, `split_body` and `encode` all refuse
  anything else, so that what is read can be written back and the reverse.
  A word chosen by the caller was rejected: a word of a megabyte made
  `encode_body` write a megabyte of padding. When the extensions are
  malformed, `invoking` still reads the quote from the start of the body.
  Dropping the whole error was rejected, because the quote is intact and the
  upper layer needs it.
- **Values the RFCs say to ignore are refused or normalized when read.** A
  Route Information option with the reserved preference is refused (RFC 4191
  §2.3 says to ignore it). A Router Advertisement's reserved preference, and
  any preference that comes with a router lifetime of 0, read as medium
  (§2.2). A Prefix Information option with a prefix length above 128, or
  with a preferred lifetime above the valid one, is refused; RFC 4862 §5.5.3
  ignores it, and so does Linux. Bits of a prefix after its length are
  cleared, as the receiver ignores them. `encode` refuses what is never
  sent, rather than masking it, so that a value is never changed without the
  caller knowing. The one exception is the preferred lifetime of Prefix
  Information: RFC 4861 sets no rule on receipt, but RFC 4862 §5.5.3 (c) and
  Linux ignore an option whose preferred lifetime exceeds its valid
  lifetime, and `decode` refuses it so that what it reads can be written.
- **Flags without a field are kept.** Router Advertisements and Prefix
  Information options have flags defined after RFC 4861: H and P (RFC 6275,
  RFC 4389), and R and P (RFC 6275, RFC 9762). They are kept as received in
  `flags` and written back, so that a relay or a rewriter does not lose them
  and a future flag needs no new field. `encode` refuses bits outside the
  mask, so that M, O, the preference, L and A are only set through their
  fields. A field for each flag was rejected: every new flag would change the
  structures and the C layout.
- **The Neighbor Cache does not draw ReachableTime.** RFC 4861 §6.3.2 draws
  it at random around BaseReachableTime. The cache takes it in
  `NeighborConfig` and the caller draws it. Taking a random source was
  rejected: the module would depend on `crypto-random`, and the tests of
  the state machine would no longer be deterministic.
- **A neighbor that does not answer is forgotten,** with its packets
  returned in `NeighborEvent::Unreachable`. RFC 7048 adds an UNREACHABLE state
  that keeps the entry and goes on soliciting with an exponential backoff.
  Its §3 also lets a node garbage-collect an entry at any time, and
  forgetting it at that point is such a collection. The next `resolve`
  starts again with multicast solicitations, which handles a changed
  link-layer address, the case that RFC 7048 is about. The UNREACHABLE state was
  not implemented: it would keep sending packets to an address that did not
  answer, and it makes the state machine larger. It can be added later as
  an option of `NeighborConfig`.
- **A full Neighbor Cache forgets only for the host's own resolutions,** as
  the ARP cache does, and for the same reason. A received message never
  makes room: `learn` makes no entry in a full cache, and
  `receive_advertisement` ignores advertisements for addresses without an
  entry (RFC 4861 §7.2.5).
- **Resolutions in progress are forgotten first.** On a router, `resolve`
  runs for destinations that remote parties choose, so a scan of a subnet
  could otherwise push out the neighbors in use (RFC 6583 §7.1). Among the
  rest, the entry refreshed longest ago goes. A received message, a
  confirmation and a successful `resolve` refresh it; a timer does not,
  because an idle entry turning STALE has not been used. The packets of a forgotten resolution are
  reported as `Unreachable` by `poll`, as RFC 4861 §7.2.2 requires for a
  resolution that fails. Those reports are bounded by `maximum_entries`.
  Two alternatives were rejected. A separate limit on resolutions in progress
  would refuse new ones while old ones wait, which is worse for a host. Not
  forgetting them at all would let a scan fill the cache.
- **`NeighborReception` reports a router that became a host.** RFC 4861
  §7.2.5 requires such a node to be removed from the Default Router List,
  which the caller keeps. `receive_advertisement` and `learn` therefore
  return `no_longer_router` alongside the released packets. Reading
  `entries` before and after every call was rejected: the caller would have
  to reproduce the rules of §7.2.5.
- **An advertisement that may not update an entry does not touch it.**
  RFC 4861 §7.2.5 lets an advertisement that does not override a different
  cached address only turn REACHABLE into STALE, and forbids any other
  change. In particular IsRouter is not changed: otherwise any on-link node
  could make a host drop its default router.
- **The Neighbor Cache is generic over the link-layer address**
  (`NDPLinkAddress`, implemented for `[u8; N]`), as ARP is. The C ABI
  offers it for 6-byte addresses only: one instance per length would
  multiply the functions, and Ethernet is the only link the crate has.

## UDP decisions

- **Two types: a raw header and a checked datagram.** `UDPHeader` is the 8
  bytes as they are; `UDPDatagram` is a datagram whose length and checksum
  were checked. An ICMP error quotes a datagram cut short, whose checksum
  cannot be checked, and the upper layer still needs its ports (RFC 5927,
  RFC 6936 §4 (10)). One type that skipped its checks on request was
  rejected: whether a value was checked would not show in its type.
- **`checksummed` is a field, the checksum is not.** As for IP and ICMP,
  `decode` checks the checksum and `encode` computes it. Whether one is sent
  at all is a choice of the sender (RFC 768, RFC 6935), so it is kept.
- **The zero checksum of IPv6 is per port, and apart for sending and
  receiving** (`UDPConfig`), as RFC 6936 §4 (3, 6) requires. A single switch
  for all ports was rejected: the RFC requires the default to stay on for
  every other port. The codec does not know which socket a datagram is
  for, so the ports are its only key.
- **Bytes after the length field are ignored, not refused.** RFC 768 does not
  say. An IP payload longer than the datagram happens with link padding
  that a layer below did not remove, and Linux trims it. Refusing was
  rejected because it would drop datagrams Linux accepts.
- **A length field of 0 over IPv6 takes the whole payload,** as RFC 2675 §4
  says, even without a Jumbo Payload option. Over IPv4 a 0 is refused.
- **Endpoints and their patterns are in `protocol::ip`,** not in UDP: TCP
  and later transports route on the same address-and-port pairs.
  `UDPRule` is a thin type over two `IPEndpointPattern`s that implements
  `service::Rule`. A rule in `protocol::ip` was rejected, because the IP
  root would then depend on `service`. A generic transport rule was
  rejected too: routers are built per protocol, and the rule names the one
  it routes. Patterns compare IPv4-mapped IPv6 addresses as IPv4 addresses,
  because dual-stack sockets report IPv4 peers that way. A prefix of at
  least 96 bits of mapped addresses is therefore the IPv4 prefix it maps
  (`IPAddress::to_canonical_prefix`). Keeping its length unchanged was
  rejected: the IPv4 mask takes any length from 32 on as all bits, so
  `::ffff:198.51.100.0/120` would match a single address. `with_prefix`
  stores the canonical, masked prefix, so that equal sets are equal
  patterns; `matches` canonicalizes again for patterns built by hand. A
  length beyond the address's bits is all of them, as the masks of
  `IPv4Address` and `IPv6Address` already treat it. Refusing such lengths
  was rejected: the builders are `const` and infallible, and the C ABI and
  Python behave the same way.
- **Sources that name no single host are refused** (`UDPError::Source`):
  multicast, and the IPv4 limited broadcast (RFC 1122 §4.1.3.6, a MUST, and
  RFC 4291 §2.7). The IP layer of this crate does not check sources, so UDP
  does, as RFC 1122 allows ("by UDP or by the IP layer"). A subnet's
  broadcast address depends on the interface and is for the caller. The
  unspecified address is accepted: hosts send from it while they learn an
  address (RFC 2131).
- **Endpoints have no zone.** A zone (RFC 6874) names an interface of one
  host and would make endpoints from two hosts incomparable. Link-local
  endpoints are therefore on an interface the caller chooses, and the text
  form refuses `%`.
- **The builders are named `with_…`** (`with_address`, `with_prefix`,
  `with_remote`), because `prefix` is also a field. Python cannot have a
  method and a field of one name, and the bindings keep Rust's names.

## TCP decisions

- **A segment codec and a connection, nothing between.** `TCPSegment` reads
  and writes one segment. `TCPConnection` is the state machine of one
  connection, and `TCPListener` holds the connections of a passive OPEN.
  A TCP "stack" that owns a table of connections and demultiplexes was
  rejected. Demultiplexing is a lookup by endpoints that the caller already
  does for UDP, and it differs per host: a kernel module keys by interface,
  a user-space stack by socket. `TCPRule` routes with `service::Router` for
  those who want a table.
- **`transmit` writes one segment per call.** The caller wraps it in an IP
  header and calls again until it returns `None`. Writing a batch into one
  buffer was rejected: each segment needs its own IP header, and the
  caller would have to split the buffer again. The connection keeps "due"
  flags (a SYN, an ACK, a retransmission, a probe, a reset), and `transmit`
  turns the first of them into a segment. Because the receive path only
  sets flags, every segment given to `receive` before `transmit` shares one
  acknowledgment (MUST-58, MUST-59). The order of a call is: expire timers,
  a pending reset, the handshake, data (retransmissions first), a
  keep-alive, a bare ACK.
- **Time is the caller's `runtime::Instant`**, and timers are deadlines
  that `poll_timeout` returns. `transmit` calls `expire` itself, so a
  caller that transmits on time needs no other call.
- **The listener is apart from the connection.** It holds its connections
  in one map keyed by both endpoints, from the SYN until `accept`. It also
  queues resets for ACKs that match none, at most `backlog` of them.
  `ready` lists the keys of the established ones in order, and `accept`
  takes them out of the map. Until then the listener gives them their
  segments and runs their timers. The first version moved established
  connections out of the map into a queue of their own. An ACK and data
  that came together before `accept` then found no connection, and the
  data segment was answered with a reset at the client's RCV.NXT, which
  closed the client (MUST-41). The waiting connections also had no timers.
  Thereafter the caller gives the connections their segments.
  Keeping LISTEN as a state of `TCPConnection`, as RFC 9293 draws it, was
  rejected. A listening connection would have to turn into many
  connections, which a value cannot do. The backlog counts connections in
  SYN-RECEIVED and in `ready`, as `listen(2)` does on BSD. SYN cookies are
  not implemented. They lose the options of the SYN, and the backlog limit
  already bounds memory.
- **Initial sequence numbers follow RFC 6528 with SipHash-2-4.** RFC 6528
  suggests MD5 for F. SipHash is a keyed PRF designed for short inputs,
  already in the crate, and cheaper. M ticks every 4 µs of the caller's
  clock. The key is the caller's, from a source of random bytes, because
  the protocol layer has no entropy source.
- **RFC 6298's minimum RTO of 1 second is the default.** Linux uses 200 ms.
  A default below the RFC's SHOULD was rejected; `minimum_rto` changes it.
  The RTT is measured from timestamps when they are in use, once per
  window otherwise, and never from a retransmitted segment (Karn).
- **The delayed ACK is 40 ms**, Linux's minimum, below the 500 ms limit
  of MUST-40 and 200 ms of RFC 5681 §4.2. A full-sized segment (SHLD-19)
  is RMSS: the MSS this end advertised, less the 12 bytes of the
  Timestamps option when timestamps are in use. Without that subtraction,
  Linux's segments, which carry the option inside the MSS, never counted
  as full, and every ACK waited 40 ms.
- **The options are written in Linux's layout.** Any layout is valid
  (MUST-64). Linux's is the one middleboxes see most, and it lets the
  tests compare every segment written with Linux's bytes. A known option
  of a wrong size is ignored rather than refused, as Linux does. MUST-7
  refuses only lengths that make the list unreadable. A Window Scale above
  14 reads as 14 (RFC 7323 §2.3).
- **The initial window is that of RFC 5681 §3.1** (2 to 4 segments by
  MSS). RFC 6928's ten segments is Experimental; `initial_window` sets it.
  After a lost SYN, the initial window is one segment (RFC 5681 §3.1). After
  an idle RTO, cwnd restarts at the initial window (RFC 5681 §4.1).
- **CUBIC is computed in integers.** C = 4/10, β = 7/10 and α = 9/17 are
  fractions, K is in milliseconds and signed (negative when a stage starts
  above W_max, RFC 9438 Figure 2), and the cube root is an integer root.
  The fractions of a byte that W_est and cwnd gain on each ACK are kept as
  remainders, so slow ACK rates still grow the window. Floating point was
  rejected: the crate is `no_std`, some targets have no FPU, and integer
  results do not depend on the target. The time an application spends
  without data is removed from t (RFC 9438 §5.8), so an idle connection
  does not jump to W_max when it resumes. CUBIC is the default, as in Linux,
  macOS and Windows. NewReno is there for comparison and for peers on
  short paths. Congestion control is a trait so that callers can add
  their own (BBR, HyStart++) without changing the connection.
- **Loss recovery is RFC 6675 with SACK, RFC 6582 without it,** each with
  its own Limited Transmit. RFC 6675's is gated by pipe, RFC 5681 §3.2's by
  a segment per duplicate. Limited Transmit was added after a test with a
  small window and one lost segment never got three duplicate ACKs and
  waited for the RTO.
  - **Duplicate ACKs:** with SACK they are counted as RFC 6675 §2 defines
    them, ACKs that SACK new data. The first version used RFC 5681's
    definition with SACK too. It counted ACKs that carried nothing new, and
    missed those that SACK new data while the window changes.
  - **The SACK recovery is NextSeg in full:** (1) lost data above HighRxt,
    (2) new data, (3) unSACKed data below the highest SACK, (4) one rescue
    retransmission per recovery. It runs while cwnd − pipe is at least a
    segment. The first version had only rule (1), and it sent nothing on
    entry. Segments too small for IsLost then waited for the RTO, and no new
    data was sent during a recovery. Entry now sends the segment at SND.UNA
    at once, up to the SACKed data (4.3).
  - **RescueRxt moves past the segment retransmitted on entry**, as (4.3)
    says. The rescue retransmission is then for the tail loss that no
    later ACK reveals, the case RACK-TLP handles otherwise. The first
    version left RescueRxt undefined, and the rescue resent the segment
    just retransmitted.
  - **`recover`:** a timeout or a recovery records SND.MAX there. Duplicates
    below it start no new recovery (RFC 6582 §3.2, RFC 6675 §5.1). It
    follows SND.UNA up, so that it is never 2^31 behind and compares right.
  - **Bounded scoreboard:** it keeps at most one block per segment in
    flight (`TCPScoreboard::limit`), counted from the smallest data segment
    sent since nothing was in flight (`smallest_segment`). An honest
    receiver never exceeds that. The first version counted segments of an
    MSS. With smaller segments, Nagle off, it dropped honest blocks, and
    the recovery never started.
    `holes` is linear. Before, a receiver SACKing single bytes could make
    every duplicate ACK cost time quadratic in the window.
  - **RACK-TLP (RFC 8985) is not implemented.** It is a Standards Track
    alternative that needs per-segment send times. The plain RTO stays
    correct without it, only slower on tail losses.
- **Out-of-order data is a map of blocks keyed by 64-bit positions.**
  - Positions count bytes from the start of the connection, so keys never
    wrap and an insert is O(log n).
  - The blocks are at most `receive_buffer / 64`
    (`TCPReceiveBuffer::BLOCK_COST`), and a segment that would make another
    is dropped.
  - The SACK order comes from the positions of the latest segments, not
    from a sort.
  - The first version kept a vector that it rebuilt and sorted on every
    segment. One-byte segments then cost about 1 s of CPU per 40,000, and
    each held a vector header besides its byte.
  - Charging each block's overhead against the window was rejected. A peer
    that fills the window honestly with full segments would have lost the
    last ones.
- **The FIN is acknowledged by any ACK past it.** The first version checked
  a flag that a timeout clears when it makes the FIN due again. An ACK of
  the first FIN that came after the timeout then left the connection in
  LAST-ACK, writing a pure ACK on every call to `transmit`. Any ACK past
  the FIN proves that it was sent, because ACKs beyond SND.MAX are refused
  first.
- **A zero-window probe of data does not advance SND.NXT.** It sends one
  byte beyond the window and then restores SND.NXT. The earlier version
  left SND.NXT past the byte. No retransmission timer covered it, because
  the persist timer was running instead, and the connection stalled once
  the window opened. The probe is retransmitted by the persist timer until
  the window opens.
- **Window updates are sent only after the application reads.** The first
  version sent one whenever the computed window grew, which after the
  handshake was every segment. The receiver's SWS avoidance (MUST-39)
  sends an update once the window grows by min(MSS, half the buffer).
- **The sender's SWS avoidance has an override timer** (RFC 9293 §3.8.6.2.1,
  "a timeout of 0.1 to 1.0 seconds"): after it, a segment smaller than both
  limits is sent. Without it, a peer that never opens its window by an MSS
  would block the sender.
- **RFC 5961 is implemented in full:** RST, SYN and ACK checks, and a rate
  limit on challenge ACKs. The limit is per connection, not global.
  RFC 5961 §7 suggests a global limit, but a global counter would be a
  side channel between connections (CVE-2016-5696), so the crate has no
  shared state.
- **ECN is `Accept` by default**: used when the peer asks, never asked for.
  This is Linux's default (`tcp_ecn = 2`). `Request` asks for it. The
  connection marks ECT(0) through `TCPTransmission::ect`, because it does
  not write IP headers.
  - **One guard, `reduced_until`, serves losses and ECEs**, because RFC
    3168 §6.1.2 asks for one reduction per window for both together. It
    is forgotten once SND.UNA reaches it. Kept, it compared as "after"
    again once 2^31 more bytes had passed, and losses then reduced
    nothing.
  - **An ACK with ECE does not grow cwnd.**
  - **With cwnd at one segment, an ECE sets `ecn_hold`** to the RTO: new
    data waits for it, as RFC 3168 asks of the retransmit timer. Using the
    retransmission timeout itself was rejected, because its expiry would
    retransmit and back off for no loss.
  - **Window probes carry neither ECT nor CWR (§6.1.6).** The first version
    sent probes as new data. `write_range` now takes whether the data is
    new, which also decides the RTT sample.
  - **A CWR ends the echo before the CE of the same segment is looked at**,
    so a CE on it starts the echo again.
- **TIME-WAIT reuse is a question, not an action.** `accepts_syn`
  implements RFC 6191 §2 (timestamps, or sequence numbers without them),
  and the caller replaces the old connection. Letting the listener reach
  into connections it does not hold was rejected.
- **An ICMP hard error does not close a synchronized connection**
  (RFC 5927 §4.2, RFC 9293 MUST-56 for soft errors). Errors are only taken
  if their quoted sequence number is in flight (RFC 5927 §4.1). Packet Too
  Big lowers the MTU and sends again from SND.UNA at once, without backing
  off the RTO or reducing cwnd, because it is not a loss (RFC 8201 §5.4).
  The first version took it as a timeout and halved the window on every
  path MTU change.
- **The configuration is the user's; what the connection learns is
  state.** The path MTU from Packet Too Big is `path_mtu`, not a rewrite of
  `config.mtu`. The first version lowered `config.mtu`, so the
  configuration read back was not the one set, and replacing the
  configuration undid path MTU discovery. `set_config` is a method, not a
  field write, because the buffers and the keep-alive timer follow the
  configuration. The C ABI first did this in its own function, and a Rust
  caller writing the field skipped it.
- **What is received follows RFC 9293 §3.10.7.4 to the letter:**
  - **The SYN of IRS is trimmed only for a simultaneous open's SYN-ACK.**
    In ESTABLISHED, a SYN-ACK that comes again is not acceptable and is
    answered with an ACK. The first version trimmed it everywhere and
    processed the rest as an old ACK, so the peer's handshake never
    completed when the first ACK was lost.
  - **A zero window still processes the ACK, URG and RST of a segment at
    RCV.NXT**, and acknowledges it. Before, the peer's data and probes
    carried ACKs that were dropped, and the peer recovered only by its RTO.
  - **The FIN counts only inside the window.** RCV.WND is computed as 0
    once RCV.NXT reaches the right edge. A FIN just past the window once
    moved RCV.NXT past the edge, and the window then wrapped to 2^31.
  - **In TIME-WAIT only the remote FIN sent again restarts the timer**
    (SEG.SEQ + SEG.LEN = RCV.NXT, as Linux checks), so a blind FIN cannot
    keep the connection there.
  - **A SYN in the window of a passive SYN-RECEIVED connection** returns it
    to LISTEN, and the listener forgets it.
  - **Only an ACK in [SND.UNA, SND.NXT] updates the window.**
- **The configuration's check refuses only what cannot work.**
  - An MTU below 68.
  - A buffer that is empty or larger than 65535 << 14 bytes. That is the
    largest window, and sequence numbers compare only within 2^31; a
    larger buffer once truncated its window to 32 bits.
  - No keep-alive probe.
  - A minimum RTO of zero, with which `transmit` never stopped writing.
  - RTO bounds that exclude the initial RTO.
  - A granularity of zero.
  - An initial window of zero.
  Enforcing every MUST was rejected: users need a 200 ms minimum RTO, as
  Linux uses, or a short connect timeout, and the defaults already follow
  the RFCs. The fields' documentation says which values the RFCs ask for.
- **Hard ICMP errors abort only when `hard_error_abort` says so.** SHLD-26
  asks for the abort. RFC 9293 itself notes that implementations do not do
  it in synchronized states, and RFC 5927 §4.2 advises against it, because
  an off-path attacker who guesses a sequence number in flight could end
  the connection. The safer behaviour is the default, and the SHOULD is a
  setting.
- **The answers to window probes are not duplicate ACKs.** A probe of
  data puts one byte in flight, and its answers change nothing, so they
  met RFC 5681's definition. Three probes then started a recovery, and the
  RTO that followed collapsed cwnd, for a window that was only closed.
  No ACK counts as a duplicate while SND.WND is 0.
- **Packet Too Big before the handshake completes only lowers the MTU.**
  Rewinding SND.NXT to SND.UNA there made the SYN-ACK's ACK look beyond
  SND.NXT, and it was answered with a reset.
- **The idle period of RFC 5681 §4.1 counts from data** (`last_data_sent`).
  Counting from any segment let a pure ACK sent while idle keep the grown
  cwnd.
- **`set_config` keeps what the connection chose**: the handshake options
  and the congestion control, which also read back as they were. Before,
  a SYN sent with Window Scale could be followed by a configuration
  without it, and the SYN-ACK was then read with a shift of 0 that the
  peer did not use. The RTO's bounds and granularity are applied to the
  timer, and the RTT measured is kept.
- **The listener's `transmit` goes on from the connection after the last
  that sent** (`cursor`). Each call before scanned from the first
  connection, so a burst of SYN-ACKs to a full backlog cost time quadratic
  in its size.
- **An urgent pointer read past is forgotten**, as `reduced_until` is.
- **Unanswered window probes give up after R2.** MUST-37 keeps a connection
  open while probes are answered. One whose peer never answers would
  otherwise hold its buffers forever, since keep-alives do not run while
  the probe byte is outstanding.
- **Events are coalesced.** `Readable`, `Writable`, `Urgent` and `Trouble`
  are not queued again while one waits. An application that reads by
  `readable()` and never polls events would otherwise grow the queue with
  every segment. `close` and `abort` of a closed connection fail, and the
  close is reported once.
- **`poll_timeout` gives timers only.** What an input makes due is written
  by the `transmit` calls after that input. A "due now" deadline was
  rejected: whether data can be sent depends on the windows and Nagle, so
  it would be either wrong or as costly as `transmit` itself. The listener
  first returned a zero deadline for its queued resets; it now follows the
  same rule.
- **Not implemented:**
  - the half-duplex close of MAY-1, a MAY;
  - D-SACK generation (RFC 2883), whose benefit is to the peer's
    heuristics; a D-SACK block that arrives below SND.UNA is ignored, and
    one above it is read as an ordinary SACK block;
  - TCP Fast Open (RFC 7413, Experimental, and a replay risk);
  - HyStart++ (RFC 9406), which a congestion control of the trait can
    add;
  - PRR (RFC 6937, Experimental);
  - RACK-TLP (above);
  - the User Timeout Option (RFC 5482), which `user_timeout` replaces
    locally.

  The IP-layer requirements (MUST-44, MUST-48, MUST-49, MUST-51 to MUST-53,
  MUST-55) belong to the caller, which builds the IP packets.

## C layout

The value types that cross the C ABI are `#[repr(C)]` (or
`#[repr(transparent)]` for one-field numbers), so the FFI passes them as
they are, with no conversion type:

- addresses, `InternetChecksum`, `IPv4Header`, `IPv4Options`, `IPv6Header`,
  `IPv6FragmentHeader`, the reassembly keys, `VLANTag` and `ARPPacket`;
- `IPProtocol`, `EtherType` and the option kinds, as one-field numbers.

The FFI has its own structures only where a Rust field has no C form:

- `FFIIPEndpoint` and `FFIIPEndpointPattern` exist because `IPAddress` is an
  enum and the prefix an `Option`. They hold 16 octets and the number used.
- `FFIUDPDatagram` exists because the datagram borrows its payload, and
  `FFIUDPRule` because it holds patterns. `UDPHeader` is `#[repr(C)]` and
  crosses as it is. The ports of `UDPConfig` cross as an array for the
  direction a call needs, since a `Vec` has no C form.
- `FFITCPSegment` exists because the segment borrows its options and data,
  which are passed beside it. `TCPHeader`, `TCPSequence`, `TCPFlags`,
  `TCPSACKBlock` and `TCPTimestamps` are `#[repr(C)]` and cross as they
  are. `FFITCPOptionSet` exists for its `Option`s and SACK blocks;
  `FFITCPConfig` and `FFITCPRetransmissionTimer` exist for their
  `Duration`s. Connections, listeners, congestion controls and ISN
  generators are handles. `FFITCPConnectionInfo` is a copy of what a
  connection holds, for diagnostics, because its fields are too many to
  give a function each. `FFITCPEndpoints` and `FFITCPRule` carry the
  endpoints of a connection and the patterns of a rule.
- `FFIEthernetHeader` exists because tags are `Option`s.
- The reassembly, ARP and Neighbor Cache configurations exist because they
  hold `Duration`s.
- `FFINDPRouterAdvertisement` and `FFINDPNeighborAdvertisement` exist
  because their Rust types borrow their options. The options are passed
  beside them as bytes.
- ICMP messages cross as `FFIICMPHeader` (type, code and the four bytes)
  with the body passed beside it. `NDPPrefixInformation` and
  `NDPRouteInformation` are `#[repr(C)]` and cross as they are.
- The Neighbor Cache's resolutions, states and events are numbers, and its
  packets and events are handles (`FFINeighborPackets`,
  `FFINeighborEvent`), because the Rust enums hold queues of packets.

`tests/ffi/manifest.rs` checks the size, alignment and some offsets of every
one of these structures against the manifest. Add new structures to that
list.

The Python bindings declare every structure of the manifest before any
function (`Library.declare`). The ARP module comes before the IP module in
the manifest but uses its address structure; before this order was used,
such types fell back to `c_void_p`.

## Tests

- `tests/vectors/protocol/ethernet/linux.txt` holds frames that the Linux
  kernel sent between two network namespaces: ARP, NDP, MLDv2,
  fragmented echoes, IPv4 options, VLAN and QinQ tags, UDP and TCP. They
  were made by `linux.sh` in Docker, with checksum offloading turned off so
  that every checksum is the kernel's. The tests check the decoded fields
  against tcpdump's description of each frame. They also check that what
  this library writes is the kernel's bytes. For example, the fragmenter
  cuts the reassembled echoes into the same fragments as Linux, and the ARP
  cache answers Linux's requests with Linux's replies.
- The rules of the RFCs are tested directly: the examples of RFC 1071,
  RFC 1624, RFC 4291 and RFC 5952, overlap handling, limits and deadlines.
- The Python tests compare the checksum with an independent computation,
  the IPv6 text with Python's `ipaddress`, and the frame check sequence
  with `zlib.crc32`.
- `tests/vectors/protocol/icmp/linux.txt` holds the ICMP messages of four
  Linux network namespaces: a host, a router running radvd, a second router,
  and a host on a far link with a smaller MTU. They include every error the
  kernel sends (Time Exceeded, Fragmentation Needed and Packet Too Big,
  Unreachable, Redirect, Parameter Problem), the multi-part extensions of
  RFC 4884, and Neighbor and Router Discovery. The tests check the fields
  against tcpdump. They also check that the echo replies written are the
  kernel's, that the Router Advertisement and its options written are
  radvd's, and that the Neighbor Cache resolves from the kernel's
  advertisements. `linux.sh` made them (see `SOURCE`).
- `tests/vectors/protocol/udp/linux.txt` holds the UDP datagrams of two
  Linux namespaces: echoes over IPv4 and IPv6, empty and odd-length
  payloads, no checksum over IPv4 and the zero checksum of RFC 6935 over
  IPv6, fragmented datagrams, and the Port Unreachable errors of a closed
  port. The tests check the ports against tcpdump and the checksums against
  an independent computation. They check that the replies written are the
  kernel's echoes, and that the reassembled datagrams read whole.
- The ICMP rules are tested directly from the RFCs: the packets of RFC 1122
  §3.2.2 and RFC 4443 §2.4 (e), the quote sizes, the example of the token
  bucket, the validity checks of RFC 4861 §6.1, §7.1 and §8.1, the option
  formats of RFC 4191 and RFC 8106, and the state machine of RFC 4861
  Appendix C, case by case.
- The Python ICMP tests compute the checksums independently, with the
  pseudo-header for ICMPv6.
- `tests/vectors/protocol/tcp/linux.txt` holds the TCP segments of two
  Linux namespaces: handshakes with every option over IPv4 and IPv6, data
  and a graceful close, a refused connection, a zero window and its
  probes, urgent data, keep-alives, a bulk transfer with periodic losses
  (SACK and recovery), a connection without options, and the negotiation
  of ECN. The tests check that every segment and its options decode and
  re-encode to the kernel's bytes, and the fields against tcpdump.
- TCP connections are tested in pairs over a simulated network
  (`tests/protocol/tcp/connection.rs`) that delays, drops, reorders and
  duplicates segments with a seeded generator. The tests check the
  handshakes and closes of RFC 9293 §3.5 and §3.6, simultaneous ones too,
  RFC 5961's challenge ACKs, PAWS, zero windows, Nagle, the delayed ACK,
  keep-alives, R1 and R2, recovery with and without SACK, ECN, ICMP
  errors, RFC 6191, and that every byte arrives once and in order under
  loss. The retransmission timer is checked against the formulas of
  RFC 6298, and CUBIC against those of RFC 9438.
- End-to-end transfers pass even with wrong recovery or acceptance rules:
  the RTO repairs what fast recovery misses. Each rule therefore has a test
  of its own in `receiving.rs` and `recovery.rs`, which builds the exact
  segments of the case. Among them are the SYN-ACK sent again in
  ESTABLISHED, data before `accept`, the duplicate ACKs of RFC 6675 §2,
  small segments in a SACK recovery, duplicates below `recover`, probes and
  ECN, zero windows, a FIN past the window, TIME-WAIT, and the bounds of
  the out-of-order queue and the scoreboard. Segments queued together
  share one ACK (MUST-58), so a test that needs one ACK per segment
  delivers them one at a time.
- The fuzz targets `protocol-ip`, `protocol-ip-v4`, `protocol-ip-v6`,
  `protocol-ethernet`, `protocol-arp`, `protocol-icmp`, `protocol-icmp-v4`,
  `protocol-icmp-v6`, `protocol-udp` and `protocol-tcp` check round trips,
  checksum identities, the accounting of the reassemblers, and the limits
  of the caches. `protocol-tcp` also feeds forged segments to a
  connection and runs two connections over a lossy network built from the
  input, checking that what arrives is a prefix of what was sent.
