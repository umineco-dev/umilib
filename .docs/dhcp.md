# DHCP

How `protocol::dhcp` is built and why. The user's view is `docs/protocol-dhcp.md`.

## Shape

- **Two versions, two modules, one root.** DHCPv4 and DHCPv6 share almost
  nothing on the wire: other headers, options, ports, state machines and
  retransmission rules. They are `v4` and `v6`. A base trait over both was
  rejected because no method would mean the same in each. The root holds
  only what both use: `DHCPDUID` (DHCPv6 needs it, and a DHCPv4 client
  identifier of RFC 4361 carries it) and `DHCPError`.
- **No I/O.** Clients and servers take bytes and the time, and give
  messages, deadlines and events. Sockets, interfaces and the configuration
  of addresses are the caller's. Such a client cannot set an address, and
  it must not pretend to.
- **The caller checks what only it can.** A `Bound` event tells the caller
  to check the address (ARP for DHCPv4, DAD for DHCPv6) and to decline it
  if another host has it. The client cannot send ARP or DAD itself.

## Decisions

### DHCPv4

- **Options are normalized when read.** Each option appears once, with the
  parts of a long option joined in order (RFC 3396 §7). The `file` and
  `sname` fields are read when Option Overload says so, and only then.
  When written, a long option is split into parts of 255 bytes. Keeping
  the parts apart was rejected: every reader would have to join them, and
  RFC 3396 says the parts are one option.
- **A message is at least 300 bytes,** padded as BOOTP relays expect (RFC
  1542 §2.1). A message without the magic cookie is BOOTP, not DHCP, and
  is refused.
- **Classless routes (RFC 3442) have their host bits cleared** when read.
  The RFC's own example has none, but a router given 10.1.2.3/8 must not
  install a host route.
- **Times run from the start of the exchange** the ACK ends: its DISCOVER,
  or the REQUEST of INIT-REBOOT, RENEWING or REBINDING. RFC 2131 §4.4.1
  counts from the REQUEST; starting earlier only shortens the lease, never
  lengthens it, and a slow server does not lengthen it either. T1 and T2
  default to half and seven eighths of it (§4.4.5). An ACK without a valid
  lease time (MUST, Table 3) is ignored rather than taken as infinite.
- **IPv6-only (RFC 8925) is checked before the offered address,** which a
  server SHOULD make 0.0.0.0 (§3.3). An ACK with option 108 stops only an
  INIT-REBOOT (§3.2); in REQUESTING the address is used.
- **Retransmission:** 4 s doubled up to 64 s, each ±1 s at random (§4.1).
  In RENEWING and REBINDING the REQUEST is sent again at half the time
  left, at least 60 s (§4.4.5).
- **Replies are matched by xid, hardware address and client identifier**
  (RFC 6842 §3: a server echoes the identifier). A reply of another client
  on the same broadcast domain must not be taken.
- **INFORM is an exchange of its own:** its xid is new and its secs 0, and
  the client's exchange (DISCOVER, REQUEST, renewal) goes on. Restarting the
  client's exchange was the first design and was a bug. An INFORM sent while
  renewing dropped the renewal's ACK and skewed the lease's times.
- **IPv6-only (RFC 8925).** With `ipv6_only` the client asks for option 108.
  An OFFER with it is told (`IPv6Only`, at least MIN_V6ONLY_WAIT of 300 s),
  and the client stops instead of requesting.
- **The server's replies go where §4.1 says.** That is the relay (giaddr),
  the client's address (ciaddr), the offered address at the client's
  hardware address (`link`, for a client without an address), or broadcast
  when the client asks for it. The caller's socket must do the link-layer
  delivery for `link`; `DHCPv4Reply` says which.
- **`authoritative` is off by default.** A server that NAKs every address it
  does not know would break networks with another server (§4.3.2), so NAKs
  must be asked for. An INIT-REBOOT of an address of this network by a
  client the server has no record of gets no answer (§4.3.2 MUST), and an
  INFORM without ciaddr none either (§4.3.5).
- **An offer does not undo a lease.** A DISCOVER from a client that holds a
  lease leaves its binding bound; a reservation another host was found to
  use (declined) is not offered.

### DHCPv6

- **RFC 9915, not RFC 8415.** IA_TA, Server Unicast and UseMulticast are
  gone. An IA_TA is ignored by the server (§21.5).
- **Retransmission is one type (`DHCPv6Retransmission`)** holding the four
  parameters of §15 (IRT, MRT, MRC, MRD), with a constant for each message.
  The rules are written once.
- **The Advertise is kept for the Request:** the best one (§18.2.9: the
  highest preference, at once at 255) is what the Request names. Clearing
  it when the Request began was a bug the tests found.
- **The §16 checks are the server's first step,** in one place. A Solicit,
  Rebind or Confirm must have a Client Identifier and no Server Identifier.
  A Request, Renew, Release or Decline must name this server. An
  Information-request may name no other server and carry no IA. A message
  that fails is dropped silently, as §16 says.
- **Relays nest at most HOP_COUNT_LIMIT (8) deep** (§7.6): a deeper
  Relay-forward is not answered. Unbounded, one datagram nested a thousand
  times deep took tens of megabytes and could overflow the stack.
- **Bindings are kept by address** (and prefix length), so that finding a
  free address costs a lookup per candidate rather than a scan of every
  binding. Each IA has addresses of its own (§12): the addresses of a
  client's other IAs, and those already given in the same reply, are not
  free for it.
- **A client keeps what is usable, and what a Reply does not name**
  (§18.2.10.1): an IA of T1 above a nonzero T2 is discarded (§21.4), as are
  addresses and prefixes of a preferred lifetime above the valid one
  (§21.6, §21.22) or of a valid lifetime of 0. A Reply to Renew or Rebind
  that names some IAs leaves the others as they were, aged since bound. T1
  and T2 are of the IAs the Reply names; set to 0, they come from the least
  nonzero preferred lifetime, so that a deprecated address does not make
  the client renew at once (§14.2).
- **A Reconfigure is discarded.** It needs the authentication of §20.4, and
  without it a Reconfigure is a way for anyone on the link to move clients.
  The client does not send Reconfigure Accept.

### Encoding and decoding agree

Every encoder refuses what its decoder refuses: a DUID without the data of
its type, of more than 130 bytes, or of a known type as `Other`; a client's
message of a relay type or of a transaction ID over 24 bits; a relay message
of another type; a prefix over 128 bits. A message that encodes must decode
to itself. The C ABI depended on this, and it once checked these itself.

## The C ABI

- DHCPv4 options cross as an options area (each option once, then END),
  DHCPv6 options as their bytes, durations as milliseconds with `u64::MAX`
  for infinity.
- A function that needs randomness takes a generator of `crypto::random`,
  as in Rust (the same decision as DNS, `.docs/dns.md`).

## Not implemented

Authentication (RFC 3118, RFC 9915 §20) and so Reconfigure, relay agent
options (RFC 3046), failover, leases kept across restarts (the bindings are
public for the caller to store), DHCPv4-over-DHCPv6 (RFC 7341).
