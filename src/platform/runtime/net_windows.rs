use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::os::windows::io::{AsRawSocket, RawSocket as StdRawSocket};
use std::sync::Arc;
use std::vec;
use std::vec::Vec;

use super::{CompletionRoute, Conversion, ListenerConfig, Operation, Reactor};
use crate::platform::windows::sys::{self, ConnectEx, Windows};
use crate::platform::windows::{RawSocketAddress, Socket, SocketDomain, SocketKind};
use crate::runtime::{AsyncDatagram, AsyncRead, AsyncWrite, IOError, IOErrorKind, SocketAddress};

/// A TCP listener of a [`Reactor`].
#[derive(Debug)]
pub struct TCPListener {
    reactor: Reactor,
    socket: Socket,
    domain: SocketDomain,
    route: CompletionRoute,
}

impl TCPListener {
    /// A listener bound to `address` with the parameters `config`.
    pub fn bind(reactor: &Reactor, address: SocketAddress, config: &ListenerConfig) -> Result<TCPListener, IOError> {
        TCPListener::from_socket(reactor, config.bind(address)?)
    }

    /// A listener of a listening socket created overlapped (as [`Socket::new`] does).
    pub fn from_socket(reactor: &Reactor, socket: Socket) -> Result<TCPListener, IOError> {
        let domain = SocketDomain::of(&socket.local_address().map_err(Conversion::error)?);
        let route = reactor.register(&socket).map_err(Conversion::error)?;
        Ok(TCPListener { reactor: reactor.clone(), socket, domain, route })
    }

    pub fn local_address(&self) -> Result<SocketAddress, IOError> {
        self.socket.local_address().map(Conversion::address).map_err(Conversion::error)
    }

    /// The next connection and the peer's address.
    pub async fn accept(&self) -> Result<(TCPStream, SocketAddress), IOError> {
        let accepted = Socket::new(self.domain, SocketKind::Stream, 0).map_err(Conversion::error)?;
        let (listener, target) = (self.socket.raw(), accepted.raw());
        // AcceptEx writes the local and the peer address, each in 16 bytes more than its largest size.
        let output = vec![0; 2 * Windows::ACCEPT_ADDRESS_LENGTH];
        let operation = Arc::new(Operation::new(&self.reactor, listener, self.route, output).with_accepted(accepted));
        let length = Windows::ACCEPT_ADDRESS_LENGTH as u32;
        let pending = operation.start(|operation| {
            let output = operation.buffer(0).data;
            let mut received = 0u32;
            // SAFETY: the sockets, the output buffer (held by the operation until it is done) and the OVERLAPPED are valid.
            unsafe {
                sys::AcceptEx(listener, target, output.cast(), 0, length, length, &mut received, operation.overlapped())
                    != 0
            }
        });
        pending.await.map_err(Conversion::error)?;
        let accepted = operation.take_accepted().ok_or(IOError::new(IOErrorKind::Other))?;
        accepted
            .set_option_bytes(Windows::SOL_SOCKET, Windows::SO_UPDATE_ACCEPT_CONTEXT, &listener.to_ne_bytes())
            .map_err(Conversion::error)?;
        let peer = accepted.peer_address().map_err(Conversion::error)?;
        let stream = TCPStream::from_socket(&self.reactor, accepted)?;
        Ok((stream, Conversion::address(peer)))
    }

    pub fn socket(&self) -> &Socket {
        &self.socket
    }
}

impl AsRawSocket for TCPListener {
    fn as_raw_socket(&self) -> StdRawSocket {
        self.socket.as_raw_socket()
    }
}

/// A TCP connection of a [`Reactor`].
#[derive(Debug)]
pub struct TCPStream {
    reactor: Reactor,
    socket: Socket,
    route: CompletionRoute,
}

impl TCPStream {
    /// The `ConnectEx` function of the provider of `socket`, which Winsock
    /// gives only through `WSAIoctl`.
    pub fn connect_function(socket: &Socket) -> io::Result<ConnectEx> {
        let guid = Windows::WSAID_CONNECTEX;
        let mut function: Option<ConnectEx> = None;
        let mut returned = 0u32;
        // SAFETY: the GUID and the output (a nullable function pointer) are valid for the sizes given; no overlapped call.
        let result = unsafe {
            sys::WSAIoctl(
                socket.raw(),
                Windows::SIO_GET_EXTENSION_FUNCTION_POINTER,
                (&raw const guid).cast(),
                size_of::<sys::GUID>() as u32,
                (&raw mut function).cast(),
                size_of::<Option<ConnectEx>>() as u32,
                &mut returned,
                core::ptr::null_mut(),
                core::ptr::null(),
            )
        };
        Socket::check(result)?;
        function.ok_or(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Connects to `address`.
    pub async fn connect(reactor: &Reactor, address: SocketAddress) -> Result<TCPStream, IOError> {
        let address = Conversion::std_address(address);
        let socket = Socket::for_address(&address, SocketKind::Stream).map_err(Conversion::error)?;
        // ConnectEx needs a bound socket.
        let unspecified = match address {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        socket.bind(&unspecified).map_err(Conversion::error)?;
        let route = reactor.register(&socket).map_err(Conversion::error)?;
        let connect = TCPStream::connect_function(&socket).map_err(Conversion::error)?;
        let raw = socket.raw();
        let target = RawSocketAddress::from_std(&address);
        let operation = Arc::new(Operation::new(reactor, raw, route, Vec::new()).with_address(target));
        let pending = operation.start(|operation| {
            let address = operation.address();
            // SAFETY: the address (held by the operation until it is done) and the OVERLAPPED are valid.
            unsafe {
                connect(
                    raw,
                    (&raw const (*address).bytes).cast(),
                    target.length,
                    core::ptr::null(),
                    0,
                    core::ptr::null_mut(),
                    operation.overlapped(),
                ) != 0
            }
        });
        pending.await.map_err(Conversion::error)?;
        socket
            .set_option_bytes(Windows::SOL_SOCKET, Windows::SO_UPDATE_CONNECT_CONTEXT, &[])
            .map_err(Conversion::error)?;
        Ok(TCPStream { reactor: reactor.clone(), socket, route })
    }

    /// A stream of a connected socket created overlapped (as [`Socket::new`] does).
    pub fn from_socket(reactor: &Reactor, socket: Socket) -> Result<TCPStream, IOError> {
        let route = reactor.register(&socket).map_err(Conversion::error)?;
        Ok(TCPStream { reactor: reactor.clone(), socket, route })
    }

    pub fn local_address(&self) -> Result<SocketAddress, IOError> {
        self.socket.local_address().map(Conversion::address).map_err(Conversion::error)
    }

    pub fn peer_address(&self) -> Result<SocketAddress, IOError> {
        self.socket.peer_address().map(Conversion::address).map_err(Conversion::error)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> Result<(), IOError> {
        self.socket.set_nodelay(nodelay).map_err(Conversion::error)
    }

    pub fn socket(&self) -> &Socket {
        &self.socket
    }
}

impl AsRawSocket for TCPStream {
    fn as_raw_socket(&self) -> StdRawSocket {
        self.socket.as_raw_socket()
    }
}

impl AsyncRead for TCPStream {
    async fn read(&mut self, buffer: Vec<u8>) -> (Result<usize, IOError>, Vec<u8>) {
        let mut buffer = buffer;
        let start = buffer.len();
        if buffer.capacity() == start {
            return (Err(IOError::new(IOErrorKind::InvalidInput)), buffer);
        }
        buffer.resize(buffer.capacity(), 0);
        let raw = self.socket.raw();
        let operation = Arc::new(Operation::new(&self.reactor, raw, self.route, buffer));
        let pending = operation.start(|operation| {
            let target = operation.buffer(start);
            // SAFETY: the WSABUF points into the operation's buffer, which with the flags and the OVERLAPPED stays valid until it is done.
            unsafe {
                sys::WSARecv(
                    raw,
                    &target,
                    1,
                    core::ptr::null_mut(),
                    operation.flags(),
                    operation.overlapped(),
                    core::ptr::null(),
                ) == 0
            }
        });
        let result = pending.await;
        let mut buffer = operation.take_buffer().unwrap_or_default();
        buffer.truncate(start + *result.as_ref().unwrap_or(&0) as usize);
        (result.map(|count| count as usize).map_err(Conversion::error), buffer)
    }
}

impl AsyncWrite for TCPStream {
    async fn write(&mut self, buffer: Vec<u8>) -> (Result<usize, IOError>, Vec<u8>) {
        if buffer.is_empty() {
            return (Ok(0), buffer);
        }
        let raw = self.socket.raw();
        let operation = Arc::new(Operation::new(&self.reactor, raw, self.route, buffer));
        let pending = operation.start(|operation| {
            let source = operation.buffer(0);
            // SAFETY: the WSABUF points into the operation's buffer, which with the OVERLAPPED stays valid until it is done.
            unsafe {
                sys::WSASend(raw, &source, 1, core::ptr::null_mut(), 0, operation.overlapped(), core::ptr::null()) == 0
            }
        });
        let result = pending.await;
        let buffer = operation.take_buffer().unwrap_or_default();
        (result.map(|count| count as usize).map_err(Conversion::error), buffer)
    }

    async fn flush(&mut self) -> Result<(), IOError> {
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<(), IOError> {
        self.socket.shutdown(Shutdown::Write).map_err(Conversion::error)
    }
}

/// A UDP socket of a [`Reactor`].
#[derive(Debug)]
pub struct UDPSocket {
    reactor: Reactor,
    socket: Socket,
    route: CompletionRoute,
}

impl UDPSocket {
    /// A socket bound to `address`.
    pub fn bind(reactor: &Reactor, address: SocketAddress) -> Result<UDPSocket, IOError> {
        let address = Conversion::std_address(address);
        let socket = Socket::for_address(&address, SocketKind::Datagram).map_err(Conversion::error)?;
        socket.bind(&address).map_err(Conversion::error)?;
        UDPSocket::from_socket(reactor, socket)
    }

    /// A socket of a datagram socket created overlapped (as [`Socket::new`] does).
    /// An ICMP port unreachable (for a datagram sent earlier) does not fail
    /// its receives, as on Unix.
    pub fn from_socket(reactor: &Reactor, socket: Socket) -> Result<UDPSocket, IOError> {
        UDPSocket::ignore_resets(&socket).map_err(Conversion::error)?;
        let route = reactor.register(&socket).map_err(Conversion::error)?;
        Ok(UDPSocket { reactor: reactor.clone(), socket, route })
    }

    /// Turns off `SIO_UDP_CONNRESET` on `socket`.
    pub fn ignore_resets(socket: &Socket) -> io::Result<()> {
        let enabled: u32 = 0;
        let mut returned = 0u32;
        // SAFETY: the input is valid for its size; no output and no overlapped call.
        let result = unsafe {
            sys::WSAIoctl(
                socket.raw(),
                Windows::SIO_UDP_CONNRESET,
                (&raw const enabled).cast(),
                size_of::<u32>() as u32,
                core::ptr::null_mut(),
                0,
                &mut returned,
                core::ptr::null_mut(),
                core::ptr::null(),
            )
        };
        Socket::check(result).map(|_| ())
    }

    pub fn local_address(&self) -> Result<SocketAddress, IOError> {
        self.socket.local_address().map(Conversion::address).map_err(Conversion::error)
    }

    pub fn socket(&self) -> &Socket {
        &self.socket
    }
}

impl AsRawSocket for UDPSocket {
    fn as_raw_socket(&self) -> StdRawSocket {
        self.socket.as_raw_socket()
    }
}

impl AsyncDatagram for UDPSocket {
    async fn send_to(&mut self, buffer: Vec<u8>, address: SocketAddress) -> (Result<usize, IOError>, Vec<u8>) {
        let raw = self.socket.raw();
        let target = RawSocketAddress::from_std(&Conversion::std_address(address));
        let operation = Arc::new(Operation::new(&self.reactor, raw, self.route, buffer).with_address(target));
        let pending = operation.start(|operation| {
            let source = operation.buffer(0);
            let address = operation.address();
            // SAFETY: the WSABUF, the address and the OVERLAPPED belong to the operation and stay valid until it is done.
            unsafe {
                sys::WSASendTo(
                    raw,
                    &source,
                    1,
                    core::ptr::null_mut(),
                    0,
                    (&raw const (*address).bytes).cast(),
                    target.length,
                    operation.overlapped(),
                    core::ptr::null(),
                ) == 0
            }
        });
        let result = pending.await;
        let buffer = operation.take_buffer().unwrap_or_default();
        (result.map(|count| count as usize).map_err(Conversion::error), buffer)
    }

    async fn receive_from(&mut self, buffer: Vec<u8>) -> (Result<(usize, SocketAddress), IOError>, Vec<u8>) {
        let mut buffer = buffer;
        let start = buffer.len();
        if buffer.capacity() == start {
            return (Err(IOError::new(IOErrorKind::InvalidInput)), buffer);
        }
        let room = u32::try_from(buffer.capacity() - start).unwrap_or(u32::MAX);
        buffer.resize(buffer.capacity(), 0);
        let raw = self.socket.raw();
        let operation = Arc::new(Operation::new(&self.reactor, raw, self.route, buffer));
        let pending = operation.start(|operation| {
            let target = operation.buffer(start);
            let address = operation.address();
            // SAFETY: the WSABUF, the address, its length, the flags and the OVERLAPPED belong to the operation and stay valid until it is done.
            unsafe {
                sys::WSARecvFrom(
                    raw,
                    &target,
                    1,
                    core::ptr::null_mut(),
                    operation.flags(),
                    (&raw mut (*address).bytes).cast(),
                    &raw mut (*address).length,
                    operation.overlapped(),
                    core::ptr::null(),
                ) == 0
            }
        });
        let result = pending.await;
        // A datagram longer than the buffer is cut to it, as on Unix.
        let result = match result {
            Err(error) if error.raw_os_error() == Some(Windows::WSAEMSGSIZE) => Ok(room),
            result => result,
        };
        let mut buffer = operation.take_buffer().unwrap_or_default();
        buffer.truncate(start + *result.as_ref().unwrap_or(&0) as usize);
        let result = result.map_err(Conversion::error).and_then(|count| {
            let address = operation.received_address().and_then(|address| address.to_std());
            address
                .map(|address| (count as usize, Conversion::address(address)))
                .ok_or(IOError::new(IOErrorKind::InvalidData))
        });
        (result, buffer)
    }
}
