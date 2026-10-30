use core::ffi::{c_int, c_void};
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use super::RawSocketAddress;
use super::sys::{self, POSIX, SocketLength};

/// The address families of [`Socket::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SocketDomain {
    IPv4,
    IPv6,
    /// Linux and Android link-layer packets (`AF_PACKET`).
    Packet,
}

impl SocketDomain {
    /// The domain of the address `address`.
    pub fn of(address: &SocketAddr) -> SocketDomain {
        if address.is_ipv4() { SocketDomain::IPv4 } else { SocketDomain::IPv6 }
    }

    /// The `AF_` constant; `None` for a family the system does not have.
    pub fn constant(self) -> Option<c_int> {
        match self {
            SocketDomain::IPv4 => Some(POSIX::AF_INET),
            SocketDomain::IPv6 => Some(POSIX::AF_INET6),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            SocketDomain::Packet => Some(POSIX::AF_PACKET),
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            SocketDomain::Packet => None,
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
            SocketKind::Stream => POSIX::SOCK_STREAM,
            SocketKind::Datagram => POSIX::SOCK_DGRAM,
            SocketKind::Raw => POSIX::SOCK_RAW,
        }
    }
}

/// A socket of the system, closed when dropped, with the options std does
/// not expose (the listen backlog, `SO_REUSEPORT`, buffer sizes, raw and
/// packet sockets). It is created close-on-exec; on Darwin `SO_NOSIGPIPE`
/// is set and on Linux sends use `MSG_NOSIGNAL`, so a closed peer gives
/// `EPIPE` rather than a signal. It converts to and from the std socket types.
#[derive(Debug)]
pub struct Socket {
    descriptor: OwnedFd,
}

impl Socket {
    /// The result of a call that returns -1 on failure (with `errno`).
    pub fn check(result: c_int) -> io::Result<c_int> {
        if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result) }
    }

    /// The result of a call that returns a size, or -1 on failure.
    pub fn check_size(result: isize) -> io::Result<usize> {
        if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result as usize) }
    }

    /// A new socket of `domain`, `kind` and `protocol` (0 for the default of
    /// the kind; the IP protocol of a raw socket; the EtherType, in network
    /// byte order, of a packet socket); fails with `Unsupported` for a domain
    /// the system lacks.
    pub fn new(domain: SocketDomain, kind: SocketKind, protocol: i32) -> io::Result<Socket> {
        let family = domain.constant().ok_or(io::Error::from(io::ErrorKind::Unsupported))?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let flags = POSIX::SOCK_CLOEXEC;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let flags = 0;
        // SAFETY: plain values; the result is checked.
        let descriptor = Socket::check(unsafe { sys::socket(family, kind.constant() | flags, protocol) })?;
        // SAFETY: the descriptor was just created and is owned by nothing else.
        let socket = Socket { descriptor: unsafe { OwnedFd::from_raw_fd(descriptor) } };
        #[cfg(target_vendor = "apple")]
        {
            socket.set_close_on_exec()?;
            socket.set_option(POSIX::SOL_SOCKET, POSIX::SO_NOSIGPIPE, 1)?;
        }
        Ok(socket)
    }

    /// A socket of the domain of `address` and `kind` (TCP or UDP).
    pub fn for_address(address: &SocketAddr, kind: SocketKind) -> io::Result<Socket> {
        Socket::new(SocketDomain::of(address), kind, 0)
    }

    /// Sets close-on-exec (systems without `SOCK_CLOEXEC`).
    pub fn set_close_on_exec(&self) -> io::Result<()> {
        // SAFETY: a valid descriptor; the result is checked.
        Socket::check(unsafe { sys::fcntl(self.as_raw_fd(), POSIX::F_SETFD, POSIX::FD_CLOEXEC) }).map(|_| ())
    }

    /// Sets or clears `O_NONBLOCK`.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        // SAFETY: a valid descriptor; the results are checked.
        let flags = Socket::check(unsafe { sys::fcntl(self.as_raw_fd(), POSIX::F_GETFL) })?;
        let flags = if nonblocking { flags | POSIX::O_NONBLOCK } else { flags & !POSIX::O_NONBLOCK };
        Socket::check(unsafe { sys::fcntl(self.as_raw_fd(), POSIX::F_SETFL, flags) }).map(|_| ())
    }

    /// Whether `O_NONBLOCK` is set.
    pub fn nonblocking(&self) -> io::Result<bool> {
        // SAFETY: a valid descriptor; the result is checked.
        let flags = Socket::check(unsafe { sys::fcntl(self.as_raw_fd(), POSIX::F_GETFL) })?;
        Ok(flags & POSIX::O_NONBLOCK != 0)
    }

    /// Sets the integer option `name` of `level`.
    pub fn set_option(&self, level: c_int, name: c_int, value: c_int) -> io::Result<()> {
        let length = size_of::<c_int>() as SocketLength;
        // SAFETY: the value lives during the call and has the length given.
        let result = unsafe {
            sys::setsockopt(self.as_raw_fd(), level, name, (&value as *const c_int).cast::<c_void>(), length)
        };
        Socket::check(result).map(|_| ())
    }

    /// The integer option `name` of `level`.
    pub fn option(&self, level: c_int, name: c_int) -> io::Result<c_int> {
        let mut value: c_int = 0;
        let mut length = size_of::<c_int>() as SocketLength;
        // SAFETY: the value and length are writable and of the size given.
        let result = unsafe {
            sys::getsockopt(self.as_raw_fd(), level, name, (&mut value as *mut c_int).cast::<c_void>(), &mut length)
        };
        Socket::check(result).map(|_| value)
    }

    pub fn set_reuse_address(&self, reuse: bool) -> io::Result<()> {
        self.set_option(POSIX::SOL_SOCKET, POSIX::SO_REUSEADDR, reuse as c_int)
    }

    pub fn reuse_address(&self) -> io::Result<bool> {
        Ok(self.option(POSIX::SOL_SOCKET, POSIX::SO_REUSEADDR)? != 0)
    }

    /// `SO_REUSEPORT`: several sockets (of processes of one user) may bind
    /// the same address, the system spreading connections between them.
    pub fn set_reuse_port(&self, reuse: bool) -> io::Result<()> {
        self.set_option(POSIX::SOL_SOCKET, POSIX::SO_REUSEPORT, reuse as c_int)
    }

    pub fn reuse_port(&self) -> io::Result<bool> {
        Ok(self.option(POSIX::SOL_SOCKET, POSIX::SO_REUSEPORT)? != 0)
    }

    /// `IPV6_V6ONLY`: an IPv6 socket accepts IPv6 only (not IPv4-mapped addresses).
    pub fn set_only_v6(&self, only: bool) -> io::Result<()> {
        self.set_option(POSIX::IPPROTO_IPV6, POSIX::IPV6_V6ONLY, only as c_int)
    }

    pub fn only_v6(&self) -> io::Result<bool> {
        Ok(self.option(POSIX::IPPROTO_IPV6, POSIX::IPV6_V6ONLY)? != 0)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.set_option(POSIX::IPPROTO_TCP, POSIX::TCP_NODELAY, nodelay as c_int)
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        Ok(self.option(POSIX::IPPROTO_TCP, POSIX::TCP_NODELAY)? != 0)
    }

    pub fn set_keepalive(&self, keepalive: bool) -> io::Result<()> {
        self.set_option(POSIX::SOL_SOCKET, POSIX::SO_KEEPALIVE, keepalive as c_int)
    }

    pub fn keepalive(&self) -> io::Result<bool> {
        Ok(self.option(POSIX::SOL_SOCKET, POSIX::SO_KEEPALIVE)? != 0)
    }

    pub fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        self.set_option(POSIX::SOL_SOCKET, POSIX::SO_BROADCAST, broadcast as c_int)
    }

    pub fn broadcast(&self) -> io::Result<bool> {
        Ok(self.option(POSIX::SOL_SOCKET, POSIX::SO_BROADCAST)? != 0)
    }

    /// The size of the send buffer (the system may round it, and Linux doubles it).
    pub fn set_send_buffer(&self, size: usize) -> io::Result<()> {
        self.set_option(POSIX::SOL_SOCKET, POSIX::SO_SNDBUF, c_int::try_from(size).unwrap_or(c_int::MAX))
    }

    pub fn send_buffer(&self) -> io::Result<usize> {
        Ok(self.option(POSIX::SOL_SOCKET, POSIX::SO_SNDBUF)?.max(0) as usize)
    }

    /// The size of the receive buffer (the system may round it, and Linux doubles it).
    pub fn set_receive_buffer(&self, size: usize) -> io::Result<()> {
        self.set_option(POSIX::SOL_SOCKET, POSIX::SO_RCVBUF, c_int::try_from(size).unwrap_or(c_int::MAX))
    }

    pub fn receive_buffer(&self) -> io::Result<usize> {
        Ok(self.option(POSIX::SOL_SOCKET, POSIX::SO_RCVBUF)?.max(0) as usize)
    }

    /// The time to live (hop limit) of IPv4 packets.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.set_option(POSIX::IPPROTO_IP, POSIX::IP_TTL, c_int::try_from(ttl).unwrap_or(c_int::MAX))
    }

    pub fn ttl(&self) -> io::Result<u32> {
        Ok(self.option(POSIX::IPPROTO_IP, POSIX::IP_TTL)?.max(0) as u32)
    }

    /// The pending error of the socket, cleared (`SO_ERROR`): how a
    /// nonblocking connection ended.
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        let code = self.option(POSIX::SOL_SOCKET, POSIX::SO_ERROR)?;
        Ok((code != 0).then(|| io::Error::from_raw_os_error(code)))
    }

    /// Binds the socket to `address`.
    pub fn bind(&self, address: &SocketAddr) -> io::Result<()> {
        let raw = RawSocketAddress::from_std(address);
        // SAFETY: the address lives during the call and has the length given.
        Socket::check(unsafe { sys::bind(self.as_raw_fd(), raw.bytes.as_ptr().cast(), raw.length) }).map(|_| ())
    }

    /// Binds the socket to the raw address `address` (such as a `sockaddr_ll`).
    pub fn bind_raw(&self, address: &RawSocketAddress) -> io::Result<()> {
        // SAFETY: as above.
        Socket::check(unsafe { sys::bind(self.as_raw_fd(), address.bytes.as_ptr().cast(), address.length) }).map(|_| ())
    }

    /// Listens for connections, at most `backlog` of them waiting to be accepted.
    pub fn listen(&self, backlog: i32) -> io::Result<()> {
        // SAFETY: plain values; the result is checked.
        Socket::check(unsafe { sys::listen(self.as_raw_fd(), backlog) }).map(|_| ())
    }

    /// Connects to `address`: true once connected; false if a nonblocking
    /// connection is in progress (it is writable when it ends; then
    /// [`Socket::take_error`] tells how).
    pub fn connect(&self, address: &SocketAddr) -> io::Result<bool> {
        let raw = RawSocketAddress::from_std(address);
        // SAFETY: as in bind.
        match Socket::check(unsafe { sys::connect(self.as_raw_fd(), raw.bytes.as_ptr().cast(), raw.length) }) {
            Ok(_) => Ok(true),
            Err(error) if error.raw_os_error() == Some(Socket::EINPROGRESS) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// `EINPROGRESS`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub const EINPROGRESS: i32 = 115;
    #[cfg(target_vendor = "apple")]
    pub const EINPROGRESS: i32 = 36;

    /// Accepts a connection: its socket (close-on-exec, nonblocking if
    /// `nonblocking`) and the peer's address.
    pub fn accept(&self, nonblocking: bool) -> io::Result<(Socket, SocketAddr)> {
        let mut raw = RawSocketAddress::empty();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let descriptor = {
            let flags = POSIX::SOCK_CLOEXEC | if nonblocking { POSIX::SOCK_NONBLOCK } else { 0 };
            // SAFETY: the address buffer and its length are writable.
            Socket::check(unsafe {
                sys::accept4(self.as_raw_fd(), raw.bytes.as_mut_ptr().cast(), &mut raw.length, flags)
            })?
        };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let descriptor = {
            // SAFETY: as above.
            Socket::check(unsafe { sys::accept(self.as_raw_fd(), raw.bytes.as_mut_ptr().cast(), &mut raw.length) })?
        };
        // SAFETY: the descriptor was just accepted and is owned by nothing else.
        let socket = Socket { descriptor: unsafe { OwnedFd::from_raw_fd(descriptor) } };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            // The BSDs make the accepted socket inherit O_NONBLOCK: set it as asked.
            socket.set_close_on_exec()?;
            socket.set_nonblocking(nonblocking)?;
            #[cfg(target_vendor = "apple")]
            socket.set_option(POSIX::SOL_SOCKET, POSIX::SO_NOSIGPIPE, 1)?;
        }
        let address = raw.to_std().ok_or(io::Error::from(io::ErrorKind::InvalidData))?;
        Ok((socket, address))
    }

    /// The address the socket is bound to.
    pub fn local_address(&self) -> io::Result<SocketAddr> {
        let mut raw = RawSocketAddress::empty();
        // SAFETY: the address buffer and its length are writable.
        Socket::check(unsafe { sys::getsockname(self.as_raw_fd(), raw.bytes.as_mut_ptr().cast(), &mut raw.length) })?;
        raw.to_std().ok_or(io::Error::from(io::ErrorKind::InvalidData))
    }

    /// The address of the peer of a connected socket.
    pub fn peer_address(&self) -> io::Result<SocketAddr> {
        let mut raw = RawSocketAddress::empty();
        // SAFETY: as above.
        Socket::check(unsafe { sys::getpeername(self.as_raw_fd(), raw.bytes.as_mut_ptr().cast(), &mut raw.length) })?;
        raw.to_std().ok_or(io::Error::from(io::ErrorKind::InvalidData))
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how = match how {
            Shutdown::Read => POSIX::SHUT_RD,
            Shutdown::Write => POSIX::SHUT_WR,
            Shutdown::Both => POSIX::SHUT_RDWR,
        };
        // SAFETY: plain values; the result is checked.
        Socket::check(unsafe { sys::shutdown(self.as_raw_fd(), how) }).map(|_| ())
    }

    /// Sends from `data`; the bytes sent.
    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        // SAFETY: the bytes are readable for their length.
        Socket::check_size(unsafe {
            sys::send(self.as_raw_fd(), data.as_ptr().cast(), data.len(), POSIX::MSG_NOSIGNAL)
        })
    }

    /// Receives into `data`; the bytes received, 0 at the end of a stream.
    pub fn receive(&self, data: &mut [u8]) -> io::Result<usize> {
        // SAFETY: the bytes are writable for their length.
        Socket::check_size(unsafe { sys::recv(self.as_raw_fd(), data.as_mut_ptr().cast(), data.len(), 0) })
    }

    /// Sends the datagram `data` to `address`.
    pub fn send_to(&self, data: &[u8], address: &SocketAddr) -> io::Result<usize> {
        self.send_to_raw(data, &RawSocketAddress::from_std(address))
    }

    /// Sends the datagram `data` to the raw address `address`.
    pub fn send_to_raw(&self, data: &[u8], address: &RawSocketAddress) -> io::Result<usize> {
        // SAFETY: the bytes and the address are readable for their lengths.
        Socket::check_size(unsafe {
            sys::sendto(
                self.as_raw_fd(),
                data.as_ptr().cast(),
                data.len(),
                POSIX::MSG_NOSIGNAL,
                address.bytes.as_ptr().cast(),
                address.length,
            )
        })
    }

    /// Receives a datagram into `data` (the rest of a longer one is
    /// dropped): the bytes received and the sender's raw address.
    pub fn receive_from_raw(&self, data: &mut [u8]) -> io::Result<(usize, RawSocketAddress)> {
        let mut raw = RawSocketAddress::empty();
        // SAFETY: the bytes and the address buffer are writable for their lengths.
        let count = Socket::check_size(unsafe {
            sys::recvfrom(
                self.as_raw_fd(),
                data.as_mut_ptr().cast(),
                data.len(),
                0,
                raw.bytes.as_mut_ptr().cast(),
                &mut raw.length,
            )
        })?;
        Ok((count, raw))
    }

    /// Receives a datagram into `data`: the bytes received and the sender's address.
    pub fn receive_from(&self, data: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (count, raw) = self.receive_from_raw(data)?;
        Ok((count, raw.to_std().ok_or(io::Error::from(io::ErrorKind::InvalidData))?))
    }

    pub fn into_tcp_listener(self) -> TcpListener {
        TcpListener::from(self.descriptor)
    }

    pub fn into_tcp_stream(self) -> TcpStream {
        TcpStream::from(self.descriptor)
    }

    pub fn into_udp_socket(self) -> UdpSocket {
        UdpSocket::from(self.descriptor)
    }

    pub fn into_owned_fd(self) -> OwnedFd {
        self.descriptor
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.descriptor.as_raw_fd()
    }
}

impl AsFd for Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

impl IntoRawFd for Socket {
    fn into_raw_fd(self) -> RawFd {
        self.descriptor.into_raw_fd()
    }
}

impl FromRawFd for Socket {
    /// # Safety
    /// `descriptor` is an open socket owned by nothing else.
    unsafe fn from_raw_fd(descriptor: RawFd) -> Socket {
        // SAFETY: the caller's promise.
        Socket { descriptor: unsafe { OwnedFd::from_raw_fd(descriptor) } }
    }
}

impl From<OwnedFd> for Socket {
    fn from(descriptor: OwnedFd) -> Socket {
        Socket { descriptor }
    }
}

impl From<TcpListener> for Socket {
    fn from(listener: TcpListener) -> Socket {
        Socket { descriptor: OwnedFd::from(listener) }
    }
}

impl From<TcpStream> for Socket {
    fn from(stream: TcpStream) -> Socket {
        Socket { descriptor: OwnedFd::from(stream) }
    }
}

impl From<UdpSocket> for Socket {
    fn from(socket: UdpSocket) -> Socket {
        Socket { descriptor: OwnedFd::from(socket) }
    }
}
