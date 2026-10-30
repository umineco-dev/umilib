# DHCP: `umilib::protocol::dhcp`

`protocol-dhcp` (no `std`) is the Dynamic Host Configuration Protocol for
IPv4 and IPv6, clients and servers, without doing any I/O. `protocol-dhcp`
is both versions.

| Feature | Module | What it is |
| --- | --- | --- |
| `protocol-dhcp-v4` (alias `protocol-dhcpv4`) | `dhcp::v4` | DHCP for IPv4 (RFC 2131, RFC 2132) |
| `protocol-dhcp-v6` (alias `protocol-dhcpv6`) | `dhcp::v6` | DHCP for IPv6 (RFC 9915) |
| either | `dhcp` | `DHCPDUID` (RFC 9915 §11) and `DHCPError` |

The clients and servers are state machines of the same shape as the rest of
umilib: `receive` takes a message, `transmit` gives the next to send,
`poll_timeout` is when to call `expire`, and `poll_event` tells what
happened. Times are `runtime::Instant`s of the caller's monotonic clock.
Sockets are the caller's: a DHCPv4 client sends from port 68 to port 67,
before it has an address from 0.0.0.0, and a DHCPv6 client from port 546
to `ff02::1:2` port 547.

## DHCPv4

`DHCPv4Message` is a message (RFC 2131 §2) and `DHCPv4Options` its options
(RFC 2132): each option once, the parts of a long option joined (RFC 3396),
the `file` and `sname` fields read when Option Overload says so; typed
getters for addresses, times, the message type, and the classless static
routes of RFC 3442 (`DHCPv4Route`, their host bits cleared).

```rust
use umilib::protocol::dhcp::v4::{DHCPv4Client, DHCPv4ClientConfig, DHCPv4ClientEvent};

let mut client = DHCPv4Client::new(DHCPv4ClientConfig::new(mac), now);
client.start(None, now, &mut random)?;
while let Some(transmission) = client.transmit() {
    // send transmission.message.encode() to transmission.destination, port 67
}
// for each datagram received on port 68: client.receive(&bytes, now, &mut random)
// at client.poll_timeout(): client.expire(now, &mut random)
match client.poll_event() {
    Some(DHCPv4ClientEvent::Bound(lease)) => { /* configure lease.address and lease.options */ }
    Some(DHCPv4ClientEvent::Expired | DHCPv4ClientEvent::Refused) => { /* remove the address */ }
    _ => {}
}
```

`DHCPv4Client` goes through the states of RFC 2131 §4.4: it discovers
servers and requests the first offer, or with `start(Some(address), …)`
asks again for the address it had (INIT-REBOOT). It renews at T1 with its
server and rebinds at T2 with any, and the lease ends at its time. It sends
again after 4 seconds, doubled up to 64, each a second more or less at
random (§4.1). It replies only to messages of its exchange, hardware
address and client identifier (RFC 6842). `decline` declines an address
another host has (§4.4.1), `release` gives it back, and `inform` asks for
configuration only under an exchange of its own (§3.4).
`DHCPv4ClientConfig` has the client identifier (RFC 4361's, of an IAID and
a DUID, or none to be known by the hardware address), the options to ask
for, the broadcast flag, and the retransmissions. With `ipv6_only` it asks
for option 108, and an offer of it is told as `IPv6Only` with its wait (RFC
8925).

`DHCPv4Server` leases the addresses of a pool and reservations, giving its
options, those a client asks for first (RFC 2131 §4.3.1). It keeps an
offered address for the client for `offer_time`. A DECLINE takes the
address out for `decline_time`. When `authoritative`, it NAKs a REQUEST for
an address it does not know. `receive` gives a `DHCPv4Reply`: its
destination as §4.1 says (the relay, the client's address, its hardware
address with `link`, or broadcast). `DHCPv4ServerConfig::new(address,
first, last)` is a server of a day's leases and no options.

## DHCPv6

`DHCPv6Message` and `DHCPv6RelayMessage` are the messages of RFC 9915 §8
and §9. `DHCPv6Options` holds their options. `DHCPv6IA` is an IA_NA or an
IA_PD, with `DHCPv6IAAddress`, `DHCPv6IAPrefix` and `DHCPv6StatusCode`.
Encoding refuses what decoding refuses: a relay type in a client's message,
a transaction ID of more than 24 bits, a prefix longer than 128.

```rust
use umilib::protocol::dhcp::DHCPDUID;
use umilib::protocol::dhcp::v6::{DHCPv6Client, DHCPv6ClientConfig, DHCPv6ClientEvent};

let duid = DHCPDUID::LL { hardware: DHCPDUID::ETHERNET, address: mac.0.to_vec() };
let config = DHCPv6ClientConfig { prefix: Some(Some(56)), ..DHCPv6ClientConfig::new(duid, 1) };
let mut client = DHCPv6Client::new(config, now);
client.start(now, &mut random)?;
// the same exchange: client.transmit() gives messages to ff02::1:2, port 547
```

`DHCPv6Client` asks for addresses (IA_NA), a prefix (IA_PD) or both: it
solicits, takes the best Advertise (§18.2.9: the highest preference, at
once at 255), requests, renews and rebinds. With neither it asks for
configuration only (Information-request, §18.2.6) and refreshes it. Rapid
Commit takes a Reply to the Solicit (§18.2.1). `release`, `decline` and
`confirm` are the exchanges of §18.2.7, §18.2.8 and §18.2.3. Each
exchange retransmits as §15 says (`DHCPv6Retransmission`, with SOL_MAX_RT
and INF_MAX_RT as the server sets them). A Reconfigure is discarded: it
needs the authentication of §20.4, which the client does not offer.

`DHCPv6Server` leases addresses of a range and delegates prefixes of a
prefix. It checks every message as §16 says, answers a Relay-forward
inside a Relay-reply (§19.3), and gives each client the options it asks
for. `DHCPv6ServerConfig::new(duid)` is a server leasing nothing, of
lifetimes of a day preferred and two valid, T1 and T2 derived (§21.4).

## Trying it

`examples/dhcp.rs` is a server and a client of each version over UDP
sockets (Linux); `examples/dhcp.sh` runs them in Docker between two network
namespaces, against ISC dhclient, BusyBox udhcpc, dnsmasq and themselves.

## FFI and Python

The C ABI (`include/umilib/protocol/dhcp*.h`) and `umilib.protocol.dhcp`
mirror the types above. DHCPv4 options cross as an options area, DHCPv6
options as their bytes, durations as milliseconds (`u64::MAX` for
infinity). A function that needs randomness takes a generator of
`crypto::random`, as in Rust.

## Not implemented

The authentication of RFC 3118 and RFC 9915 §20 (and so Reconfigure), the
DHCPv4 relay agent's options (RFC 3046), failover between servers, leases
kept across restarts (the bindings are public, for the caller to store),
DHCPv4-over-DHCPv6 (RFC 7341), and IA_TA (removed by RFC 9915).
