# The operating system layers of `umilib::platform`

The modules of `umilib::platform` that talk to an operating system. Each is
compiled only on its system; `native` gives the system the library is built
for under one set of names. They use `std` and their own declarations of
the system's C functions (no other crate).

| Feature | Module | Compiled on | Contents |
| --- | --- | --- | --- |
| `platform-unix` | `unix` | Linux, Android, Darwin | `Socket` (every option), `RawSocketAddress`, `NetworkInterface`, the readiness types `Interest`, `PollEvent`, `PollMode` |
| `platform-linux` | `linux` | Linux, Android | `Poller` (epoll), `EventFD`, `Random` (`getrandom`), `PacketSocket` and `LinkAddress` (`AF_PACKET`), `TUNDevice` (TUN and TAP interfaces) |
| `platform-android` | `android` | Android | `AndroidSystem` (system properties, the API level) |
| `platform-darwin` | `darwin` | macOS, iOS | `Poller` (kqueue), `Random` (`getentropy`) |
| `platform-windows` | `windows` | Windows | `Socket` (every option) and `SocketDuplicate`, `CompletionPort` (IOCP), `Random` (`ProcessPrng`) |
| `platform-native` | `native` | everywhere | the types of the system above under one set of names, and `System` |
| `platform-runtime` | `runtime` | Linux, Android, Darwin, Windows | the thread pool, reactor, asynchronous sockets and supervisor of worker processes: see [platform-runtime.md](platform-runtime.md) |

```rust
use umilib::platform::native::{Random, Socket, SocketKind};

let mut key = [0u8; 32];
Random::new().fill(&mut key)?;

let address = "127.0.0.1:8080".parse()?;
let listener = Socket::for_address(&address, SocketKind::Stream)?;
listener.set_reuse_address(true)?;
listener.bind(&address)?;
listener.listen(1024)?;                        // the backlog std does not let you choose
let listener = listener.into_tcp_listener();   // a std::net::TcpListener
```

## Random bytes

`Random::new().fill(buffer)` fills `buffer` with the system's random bytes:
the `getrandom` system call on Linux and Android (falling back to
`/dev/urandom` on kernels older than 3.17), `getentropy` on Darwin and
`ProcessPrng` on Windows 10 and later. With `crypto-random`, `Random`
implements `crypto::random::Random`, the entropy source of the DRBGs.

## Sockets

`Socket::new(domain, kind, protocol)` (or `Socket::for_address(address,
kind)`) creates a socket that is not inherited by child processes (and,
on Windows, overlapped, for completion ports), with the options std does
not expose and those it does: the listen backlog, `SO_REUSEADDR`,
`SO_REUSEPORT` (Unix: several sockets of one user bind one address and the
system spreads connections between them; Windows has no such option and
fails with `Unsupported`), `SO_EXCLUSIVEADDRUSE` (Windows), `IPV6_V6ONLY`,
`TCP_NODELAY`, `SO_KEEPALIVE`, `SO_BROADCAST`, buffer sizes, the TTL, the
nonblocking mode and the pending error (`take_error`, which ends a
nonblocking `connect`). A closed peer gives `EPIPE`, never a signal.
`accept(nonblocking)` gives a socket of the mode asked on every system
(Darwin would otherwise inherit the listener's). Raw sockets
(`SocketKind::Raw`) and, on Linux, packet sockets (`PacketSocket::open`,
with `LinkAddress`) need privileges. Sockets convert to and from
`std::net::TcpListener`, `TcpStream` and `UdpSocket`.

On Linux, `TUNDevice::open(name, kind)` opens a TUN interface
(`TUNKind::TUN`, IP packets) or a TAP interface (`TUNKind::TAP`, Ethernet
frames) through `/dev/net/tun`, creating it if it does not exist:

- An empty name, or one with `%d` such as `tun%d`, lets the kernel choose,
  and `name` is the one it chose. A name has at most 15 bytes.
- Each `receive` reads one packet the kernel routed to the interface, and
  each `send` gives the kernel one packet as if it arrived there. The
  packets have no packet information header (`IFF_NO_PI`).
- Give `receive` room for the MTU. The kernel copies what fits of a longer
  packet and reports the whole length, so `receive` fails with
  `InvalidData` and the packet is lost.
- Writing while the interface is down fails with `EIO`.
- It needs `CAP_NET_ADMIN`. You bring the interface up and give it
  addresses yourself, with `ip link` and `ip address` or netlink.
- Closing the device removes an interface it created.
- `TUNDevice` implements `AsRawFd`, so `Poller` waits on it.

`examples/tun.rs` is a host built on one from the protocol layers of this
crate (see [protocol-tcp.md](protocol-tcp.md)).

On Windows, `Socket::duplicate(process)` gives the `SocketDuplicate` (the
protocol information) another process turns into the same socket with
`Socket::from_duplicate`: how processes share a listener there.

## Waiting for I/O

On Linux, Android and Darwin, `Poller` waits for descriptors to be ready:
`add(descriptor, token, interest, mode)`, `modify`, `delete`, and
`wait(events, timeout)`, which fills `events` with `PollEvent`s (the
token, readable, writable, hang-up, error; a hang-up or an error also makes
the descriptor readable, so that the next read reports it). `PollMode` is
`Level` (reported while ready), `Edge` (once per change: read or write until
`WouldBlock`) or `Oneshot` (once until modified). `notify()`, from any
thread, ends the current or next wait with an event of token
`PollEvent::NOTIFY`, which descriptors may not use. A wait interrupted by
a signal returns early with no events (as `epoll_wait` and `kevent` do,
since neither is restarted after a signal handler), so a caller waits in a
loop. One wait returns at most `maximum_events()` events:
`Poller::DEFAULT_MAXIMUM_EVENTS` (256) for `Poller::new()`, or the number
given to `Poller::with_maximum_events` (1 to `i32::MAX`); the others are
returned by the next wait.

On Windows, `CompletionPort` reports completed operations instead:
`associate(handle, key)` attaches a socket created overlapped, `wait`
gives `Completion`s (the key, the address of the `OVERLAPPED`, the bytes),
`post` queues one, and `notify()` posts one of key `Completion::NOTIFY`.
One wait returns at most `maximum_completions()` completions
(`CompletionPort::DEFAULT_MAXIMUM_COMPLETIONS`, 256, or the number given to
`CompletionPort::with_maximum_completions`).

On Linux and Android, the layers build only for the architectures whose
socket and file constants are those of the kernel's generic headers: x86,
x86-64, ARM, AArch64, RISC-V, LoongArch64, PowerPC and s390x. MIPS, SPARC
and the other architectures that number them differently fail to compile
rather than run with wrong values.

## C and Python

The OS modules have no C ABI of their own (it would differ between
systems): `umilib_platform_native_random_fill(data, length)` and
`umilib_platform_native_system_name(out)` give what C needs, and Python's
`umilib.platform.native` mirrors them with `Random` and `System` (its own
`socket` and `selectors` modules cover the rest).
