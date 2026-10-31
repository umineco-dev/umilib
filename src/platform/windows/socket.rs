use core::ffi::{c_int, c_void};
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::windows::io::RawSocket as StdRawSocket;
use std::os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket, FromRawSocket, IntoRawSocket, OwnedSocket};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use super::RawSocketAddress;
use super::sys::{self, RawSocket, Windows};

/// The address families of [`Socket::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SocketDomain {
    IPv4,
    IPv6,
}

impl SocketDomain {
    pub fn of(address: &SocketAddr) -> SocketDomain {
        if address.is_ipv4() { SocketDomain::IPv4 } else { SocketDomain::IPv6 }
    }

    pub const fn constant(self) -> c_int {
        match self {
            SocketDomain::IPv4 => Windows::AF_INET,
            SocketDomain::IPv6 => Windows::AF_INET6,
        }
    }
}

/// The socket types of [`Socket::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SocketKind {
    Stream,
    Datagram,
    Raw,
}

impl SocketKind {
    pub const fn constant(self) -> c_int {
        match self {
            SocketKind::Stream => Windows::SOCK_STREAM,
            SocketKind::Datagram => Windows::SOCK_DGRAM,
            SocketKind::Raw => Windows::SOCK_RAW,
        }
    }
}

/// The protocol information of a socket for another process
/// (`WSAPROTOCOL_INFOW`), from [`Socket::duplicate`]: that process makes a
/// socket of it with [`Socket::from_duplicate`]. It has the alignment of
/// `WSAPROTOCOL_INFOW` (4: its widest fields are `DWORD`s and `int`s), since
/// Winsock reads and writes it in place as that structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(4))]
pub struct SocketDuplicate {
    pub bytes: [u8; Windows::PROTOCOL_INFO_SIZE],
}

/// A Winsock socket, closed when dropped, with the options std does not
/// expose (the listen backlog, `SO_EXCLUSIVEADDRUSE`, buffer sizes, raw
/// sockets), created overlapped (for completion ports) and not inherited by
/// child processes. It converts to and from the std socket types.
#[derive(Debug)]
pub struct Socket {
    socket: OwnedSocket,
    /// Whether it is nonblocking (Winsock cannot be asked).
    nonblocking: AtomicBool,
    /// Whether it was made from another process's socket ([`Socket::from_duplicate`]).
    duplicated: bool,
}

impl Socket {
    /// Starts Winsock 2.2 once per process (std does too, when its sockets are first used).
    pub fn start() -> io::Result<()> {
        static RESULT: OnceLock<c_int> = OnceLock::new();
        let result = *RESULT.get_or_init(|| {
            let mut data = [0u64; 64];
            // SAFETY: a buffer larger than WSADATA (408 bytes at most).
            unsafe { sys::WSAStartup(Windows::WINSOCK_VERSION, data.as_mut_ptr().cast()) }
        });
        match result {
            0 => Ok(()),
            code => Err(io::Error::from_raw_os_error(code)),
        }
    }

    /// The error of the last Winsock call.
    pub fn last_error() -> io::Error {
        // SAFETY: no arguments.
        io::Error::from_raw_os_error(unsafe { sys::WSAGetLastError() })
    }

    pub fn check(result: c_int) -> io::Result<c_int> {
        if result == Windows::SOCKET_ERROR { Err(Socket::last_error()) } else { Ok(result) }
    }

    /// The socket of a raw handle just made (or the error of its making).
    pub fn adopt(raw: RawSocket) -> io::Result<Socket> {
        if raw == Windows::INVALID_SOCKET {
            return Err(Socket::last_error());
        }
        // SAFETY: the socket was just created and is owned by nothing else.
        Ok(Socket {
            socket: unsafe { OwnedSocket::from_raw_socket(raw as StdRawSocket) },
            nonblocking: AtomicBool::new(false),
            duplicated: false,
        })
    }

    /// Makes sure child processes do not inherit the socket (an accepted
    /// socket takes the listener's attributes, which need not include it).
    pub fn set_not_inherited(&self) -> io::Result<()> {
        // SAFETY: a valid socket handle; the result is checked.
        if unsafe { sys::SetHandleInformation(self.raw() as sys::Handle, Windows::HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn raw(&self) -> RawSocket {
        self.socket.as_raw_socket() as RawSocket
    }

    /// A new socket of `domain`, `kind` and `protocol` (0 for the default of the kind).
    pub fn new(domain: SocketDomain, kind: SocketKind, protocol: i32) -> io::Result<Socket> {
        Socket::start()?;
        let flags = Windows::WSA_FLAG_OVERLAPPED | Windows::WSA_FLAG_NO_HANDLE_INHERIT;
        // SAFETY: plain values and no protocol information; the result is checked.
        let raw = unsafe { sys::WSASocketW(domain.constant(), kind.constant(), protocol, core::ptr::null(), 0, flags) };
        Socket::adopt(raw)
    }

    /// A socket of the domain of `address` and `kind` (TCP or UDP).
    pub fn for_address(address: &SocketAddr, kind: SocketKind) -> io::Result<Socket> {
        Socket::new(SocketDomain::of(address), kind, 0)
    }

    /// The protocol information of the socket for the process `process`.
    pub fn duplicate(&self, process: u32) -> io::Result<SocketDuplicate> {
        let mut duplicate = SocketDuplicate { bytes: [0; Windows::PROTOCOL_INFO_SIZE] };
        // SAFETY: a buffer of the size of WSAPROTOCOL_INFOW; the result is checked.
        Socket::check(unsafe { sys::WSADuplicateSocketW(self.raw(), process, duplicate.bytes.as_mut_ptr().cast()) })?;
        Ok(duplicate)
    }

    /// The socket of the protocol information `duplicate` another process made for this one.
    pub fn from_duplicate(duplicate: &SocketDuplicate) -> io::Result<Socket> {
        Socket::start()?;
        let flags = Windows::WSA_FLAG_OVERLAPPED | Windows::WSA_FLAG_NO_HANDLE_INHERIT;
        let protocol = Windows::FROM_PROTOCOL_INFO;
        // SAFETY: the protocol information is readable; the result is checked.
        let raw = unsafe { sys::WSASocketW(protocol, protocol, protocol, duplicate.bytes.as_ptr().cast(), 0, flags) };
        let mut socket = Socket::adopt(raw)?;
        socket.set_not_inherited()?;
        socket.duplicated = true;
        Ok(socket)
    }

    /// Whether the socket was made from another process's socket
    /// ([`Socket::from_duplicate`]). It then shares that socket's underlying
    /// socket, which only one completion port may be associated with.
    pub fn is_duplicate(&self) -> bool {
        self.duplicated
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let mut value = nonblocking as u32;
        // SAFETY: the argument lives during the call; the result is checked.
        Socket::check(unsafe { sys::ioctlsocket(self.raw(), Windows::FIONBIO, &mut value) })?;
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
        Ok(())
    }

    /// Whether the socket was made nonblocking through this object.
    pub fn nonblocking(&self) -> io::Result<bool> {
        Ok(self.nonblocking.load(Ordering::Relaxed))
    }

    pub fn set_option(&self, level: c_int, name: c_int, value: c_int) -> io::Result<()> {
        let length = size_of::<c_int>() as c_int;
        // SAFETY: the value lives during the call and has the length given.
        let result =
            unsafe { sys::setsockopt(self.raw(), level, name, (&value as *const c_int).cast::<c_void>(), length) };
        Socket::check(result).map(|_| ())
    }

    /// Sets the option `name` of `level` to the bytes `value`.
    pub fn set_option_bytes(&self, level: c_int, name: c_int, value: &[u8]) -> io::Result<()> {
        let pointer = if value.is_empty() { core::ptr::null() } else { value.as_ptr().cast::<c_void>() };
        // SAFETY: the bytes live during the call and have the length given.
        Socket::check(unsafe { sys::setsockopt(self.raw(), level, name, pointer, value.len() as c_int) }).map(|_| ())
    }

    pub fn option(&self, level: c_int, name: c_int) -> io::Result<c_int> {
        let mut value: c_int = 0;
        let mut length = size_of::<c_int>() as c_int;
        // SAFETY: the value and length are writable and of the size given.
        let result = unsafe {
            sys::getsockopt(self.raw(), level, name, (&mut value as *mut c_int).cast::<c_void>(), &mut length)
        };
        Socket::check(result).map(|_| value)
    }

    /// `SO_REUSEADDR`, which on Windows lets other sockets bind the same
    /// address even while this one is active (see [`Socket::set_exclusive_address`]).
    pub fn set_reuse_address(&self, reuse: bool) -> io::Result<()> {
        self.set_option(Windows::SOL_SOCKET, Windows::SO_REUSEADDR, reuse as c_int)
    }

    pub fn reuse_address(&self) -> io::Result<bool> {
        Ok(self.option(Windows::SOL_SOCKET, Windows::SO_REUSEADDR)? != 0)
    }

    /// `SO_EXCLUSIVEADDRUSE`: no other socket may bind the address.
    pub fn set_exclusive_address(&self, exclusive: bool) -> io::Result<()> {
        self.set_option(Windows::SOL_SOCKET, Windows::SO_EXCLUSIVEADDRUSE, exclusive as c_int)
    }

    pub fn exclusive_address(&self) -> io::Result<bool> {
        Ok(self.option(Windows::SOL_SOCKET, Windows::SO_EXCLUSIVEADDRUSE)? != 0)
    }

    /// Windows has no `SO_REUSEPORT`: processes share a listener through
    /// [`Socket::duplicate`] instead. Fails with `Unsupported`.
    pub fn set_reuse_port(&self, _reuse: bool) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub fn reuse_port(&self) -> io::Result<bool> {
        Ok(false)
    }

    pub fn set_only_v6(&self, only: bool) -> io::Result<()> {
        self.set_option(Windows::IPPROTO_IPV6, Windows::IPV6_V6ONLY, only as c_int)
    }

    pub fn only_v6(&self) -> io::Result<bool> {
        Ok(self.option(Windows::IPPROTO_IPV6, Windows::IPV6_V6ONLY)? != 0)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.set_option(Windows::IPPROTO_TCP, Windows::TCP_NODELAY, nodelay as c_int)
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        Ok(self.option(Windows::IPPROTO_TCP, Windows::TCP_NODELAY)? != 0)
    }

    pub fn set_keepalive(&self, keepalive: bool) -> io::Result<()> {
        self.set_option(Windows::SOL_SOCKET, Windows::SO_KEEPALIVE, keepalive as c_int)
    }

    pub fn keepalive(&self) -> io::Result<bool> {
        Ok(self.option(Windows::SOL_SOCKET, Windows::SO_KEEPALIVE)? != 0)
    }

    pub fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        self.set_option(Windows::SOL_SOCKET, Windows::SO_BROADCAST, broadcast as c_int)
    }

    pub fn broadcast(&self) -> io::Result<bool> {
        Ok(self.option(Windows::SOL_SOCKET, Windows::SO_BROADCAST)? != 0)
    }

    pub fn set_send_buffer(&self, size: usize) -> io::Result<()> {
        self.set_option(Windows::SOL_SOCKET, Windows::SO_SNDBUF, c_int::try_from(size).unwrap_or(c_int::MAX))
    }

    pub fn send_buffer(&self) -> io::Result<usize> {
        Ok(self.option(Windows::SOL_SOCKET, Windows::SO_SNDBUF)?.max(0) as usize)
    }

    pub fn set_receive_buffer(&self, size: usize) -> io::Result<()> {
        self.set_option(Windows::SOL_SOCKET, Windows::SO_RCVBUF, c_int::try_from(size).unwrap_or(c_int::MAX))
    }

    pub fn receive_buffer(&self) -> io::Result<usize> {
        Ok(self.option(Windows::SOL_SOCKET, Windows::SO_RCVBUF)?.max(0) as usize)
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.set_option(Windows::IPPROTO_IP, Windows::IP_TTL, c_int::try_from(ttl).unwrap_or(c_int::MAX))
    }

    pub fn ttl(&self) -> io::Result<u32> {
        Ok(self.option(Windows::IPPROTO_IP, Windows::IP_TTL)?.max(0) as u32)
    }

    /// The pending error of the socket, cleared (`SO_ERROR`).
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        let code = self.option(Windows::SOL_SOCKET, Windows::SO_ERROR)?;
        Ok((code != 0).then(|| io::Error::from_raw_os_error(code)))
    }

    pub fn bind(&self, address: &SocketAddr) -> io::Result<()> {
        let raw = RawSocketAddress::from_std(address);
        // SAFETY: the address lives during the call and has the length given.
        Socket::check(unsafe { sys::bind(self.raw(), raw.bytes.as_ptr().cast(), raw.length) }).map(|_| ())
    }

    pub fn listen(&self, backlog: i32) -> io::Result<()> {
        // SAFETY: plain values; the result is checked.
        Socket::check(unsafe { sys::listen(self.raw(), backlog) }).map(|_| ())
    }

    /// Connects to `address`: true once connected; false if a nonblocking
    /// connection is in progress (it is writable when it ends).
    pub fn connect(&self, address: &SocketAddr) -> io::Result<bool> {
        let raw = RawSocketAddress::from_std(address);
        // SAFETY: as in bind.
        match Socket::check(unsafe { sys::connect(self.raw(), raw.bytes.as_ptr().cast(), raw.length) }) {
            Ok(_) => Ok(true),
            Err(error) if error.raw_os_error() == Some(Windows::WSAEWOULDBLOCK) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Accepts a connection: its socket (nonblocking if `nonblocking`) and the peer's address.
    pub fn accept(&self, nonblocking: bool) -> io::Result<(Socket, SocketAddr)> {
        let mut raw = RawSocketAddress::empty();
        // SAFETY: the address buffer and its length are writable.
        let accepted = unsafe { sys::accept(self.raw(), raw.bytes.as_mut_ptr().cast(), &mut raw.length) };
        let socket = Socket::adopt(accepted)?;
        socket.set_not_inherited()?;
        // The accepted socket inherits the listener's mode: set it as asked.
        socket.set_nonblocking(nonblocking)?;
        let address = raw.to_std().ok_or(io::Error::from(io::ErrorKind::InvalidData))?;
        Ok((socket, address))
    }

    pub fn local_address(&self) -> io::Result<SocketAddr> {
        let mut raw = RawSocketAddress::empty();
        // SAFETY: the address buffer and its length are writable.
        Socket::check(unsafe { sys::getsockname(self.raw(), raw.bytes.as_mut_ptr().cast(), &mut raw.length) })?;
        raw.to_std().ok_or(io::Error::from(io::ErrorKind::InvalidData))
    }

    pub fn peer_address(&self) -> io::Result<SocketAddr> {
        let mut raw = RawSocketAddress::empty();
        // SAFETY: as above.
        Socket::check(unsafe { sys::getpeername(self.raw(), raw.bytes.as_mut_ptr().cast(), &mut raw.length) })?;
        raw.to_std().ok_or(io::Error::from(io::ErrorKind::InvalidData))
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how = match how {
            Shutdown::Read => Windows::SD_RECEIVE,
            Shutdown::Write => Windows::SD_SEND,
            Shutdown::Both => Windows::SD_BOTH,
        };
        // SAFETY: plain values; the result is checked.
        Socket::check(unsafe { sys::shutdown(self.raw(), how) }).map(|_| ())
    }

    /// The length of `data` for a Winsock call (at most `i32::MAX`).
    pub fn length(data: &[u8]) -> c_int {
        c_int::try_from(data.len()).unwrap_or(c_int::MAX)
    }

    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        // SAFETY: the bytes are readable for the length given.
        Socket::check(unsafe { sys::send(self.raw(), data.as_ptr().cast(), Socket::length(data), 0) })
            .map(|count| count as usize)
    }

    pub fn receive(&self, data: &mut [u8]) -> io::Result<usize> {
        let length = Socket::length(data);
        // SAFETY: the bytes are writable for the length given.
        Socket::check(unsafe { sys::recv(self.raw(), data.as_mut_ptr().cast(), length, 0) }).map(|count| count as usize)
    }

    pub fn send_to(&self, data: &[u8], address: &SocketAddr) -> io::Result<usize> {
        let raw = RawSocketAddress::from_std(address);
        // SAFETY: the bytes and the address are readable for their lengths.
        Socket::check(unsafe {
            sys::sendto(
                self.raw(),
                data.as_ptr().cast(),
                Socket::length(data),
                0,
                raw.bytes.as_ptr().cast(),
                raw.length,
            )
        })
        .map(|count| count as usize)
    }

    pub fn receive_from(&self, data: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut raw = RawSocketAddress::empty();
        let length = Socket::length(data);
        // SAFETY: the bytes and the address buffer are writable for their lengths.
        let count = Socket::check(unsafe {
            sys::recvfrom(
                self.raw(),
                data.as_mut_ptr().cast(),
                length,
                0,
                raw.bytes.as_mut_ptr().cast(),
                &mut raw.length,
            )
        })?;
        Ok((count as usize, raw.to_std().ok_or(io::Error::from(io::ErrorKind::InvalidData))?))
    }

    pub fn into_tcp_listener(self) -> TcpListener {
        TcpListener::from(self.socket)
    }

    pub fn into_tcp_stream(self) -> TcpStream {
        TcpStream::from(self.socket)
    }

    pub fn into_udp_socket(self) -> UdpSocket {
        UdpSocket::from(self.socket)
    }

    pub fn into_owned_socket(self) -> OwnedSocket {
        self.socket
    }
}

impl AsRawSocket for Socket {
    fn as_raw_socket(&self) -> StdRawSocket {
        self.socket.as_raw_socket()
    }
}

impl AsSocket for Socket {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        self.socket.as_socket()
    }
}

impl IntoRawSocket for Socket {
    fn into_raw_socket(self) -> StdRawSocket {
        self.socket.into_raw_socket()
    }
}

impl From<OwnedSocket> for Socket {
    fn from(socket: OwnedSocket) -> Socket {
        Socket { socket, nonblocking: AtomicBool::new(false), duplicated: false }
    }
}

impl From<TcpListener> for Socket {
    fn from(listener: TcpListener) -> Socket {
        Socket::from(OwnedSocket::from(listener))
    }
}

impl From<TcpStream> for Socket {
    fn from(stream: TcpStream) -> Socket {
        Socket::from(OwnedSocket::from(stream))
    }
}

impl From<UdpSocket> for Socket {
    fn from(socket: UdpSocket) -> Socket {
        Socket::from(OwnedSocket::from(socket))
    }
}
