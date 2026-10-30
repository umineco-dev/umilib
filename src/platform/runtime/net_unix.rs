use std::future::poll_fn;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, RawFd};
use std::vec::Vec;

use super::{Conversion, Direction, ListenerConfig, Reactor, Registration};
use crate::platform::native::{Socket, SocketKind};
use crate::runtime::{AsyncDatagram, AsyncRead, AsyncWrite, IOError, IOErrorKind, SocketAddress};

/// A TCP listener of a [`Reactor`].
#[derive(Debug)]
pub struct TCPListener {
    registration: Registration,
    socket: Socket,
}

impl TCPListener {
    /// A listener bound to `address` with the parameters `config`.
    pub fn bind(reactor: &Reactor, address: SocketAddress, config: &ListenerConfig) -> Result<TCPListener, IOError> {
        TCPListener::from_socket(reactor, config.bind(address)?)
    }

    /// A listener of a listening socket (made nonblocking).
    pub fn from_socket(reactor: &Reactor, socket: Socket) -> Result<TCPListener, IOError> {
        socket.set_nonblocking(true).map_err(Conversion::error)?;
        let registration = Registration::new(reactor, &socket).map_err(Conversion::error)?;
        Ok(TCPListener { registration, socket })
    }

    pub fn local_address(&self) -> Result<SocketAddress, IOError> {
        self.socket.local_address().map(Conversion::address).map_err(Conversion::error)
    }

    /// The next connection and the peer's address.
    pub async fn accept(&self) -> Result<(TCPStream, SocketAddress), IOError> {
        let (socket, address) = poll_fn(|context| {
            self.registration.source().poll_io(Direction::Read, context, || self.socket.accept(true))
        })
        .await
        .map_err(Conversion::error)?;
        let stream = TCPStream::from_socket(self.registration.reactor(), socket)?;
        Ok((stream, Conversion::address(address)))
    }

    pub fn socket(&self) -> &Socket {
        &self.socket
    }
}

impl AsRawFd for TCPListener {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// A TCP connection of a [`Reactor`].
#[derive(Debug)]
pub struct TCPStream {
    registration: Registration,
    socket: Socket,
}

impl TCPStream {
    /// Connects to `address`.
    pub async fn connect(reactor: &Reactor, address: SocketAddress) -> Result<TCPStream, IOError> {
        let address = Conversion::std_address(address);
        let socket = Socket::for_address(&address, SocketKind::Stream).map_err(Conversion::error)?;
        socket.set_nonblocking(true).map_err(Conversion::error)?;
        let connected = socket.connect(&address).map_err(Conversion::error)?;
        let stream = TCPStream::from_socket(reactor, socket)?;
        if !connected {
            poll_fn(|context| {
                stream.registration.source().poll_io(Direction::Write, context, || {
                    match stream.socket.take_error()? {
                        Some(error) => Err(error),
                        None => stream.socket.peer_address().map(|_| ()).map_err(|error| match error.kind() {
                            std::io::ErrorKind::NotConnected => std::io::Error::from(std::io::ErrorKind::WouldBlock),
                            _ => error,
                        }),
                    }
                })
            })
            .await
            .map_err(Conversion::error)?;
        }
        Ok(stream)
    }

    /// A stream of a connected socket (made nonblocking).
    pub fn from_socket(reactor: &Reactor, socket: Socket) -> Result<TCPStream, IOError> {
        socket.set_nonblocking(true).map_err(Conversion::error)?;
        let registration = Registration::new(reactor, &socket).map_err(Conversion::error)?;
        Ok(TCPStream { registration, socket })
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

impl AsRawFd for TCPStream {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl AsyncRead for TCPStream {
    async fn read(&mut self, buffer: Vec<u8>) -> (Result<usize, IOError>, Vec<u8>) {
        let mut buffer = buffer;
        let start = buffer.len();
        let room = buffer.capacity() - start;
        if room == 0 {
            return (Err(IOError::new(IOErrorKind::InvalidInput)), buffer);
        }
        buffer.resize(start + room, 0);
        let result = poll_fn(|context| {
            self.registration.source().poll_io(Direction::Read, context, || self.socket.receive(&mut buffer[start..]))
        })
        .await;
        let count = *result.as_ref().unwrap_or(&0);
        buffer.truncate(start + count);
        (result.map_err(Conversion::error), buffer)
    }
}

impl AsyncWrite for TCPStream {
    async fn write(&mut self, buffer: Vec<u8>) -> (Result<usize, IOError>, Vec<u8>) {
        if buffer.is_empty() {
            return (Ok(0), buffer);
        }
        let result = poll_fn(|context| {
            self.registration.source().poll_io(Direction::Write, context, || self.socket.send(&buffer))
        })
        .await;
        (result.map_err(Conversion::error), buffer)
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
    registration: Registration,
    socket: Socket,
}

impl UDPSocket {
    /// A socket bound to `address`.
    pub fn bind(reactor: &Reactor, address: SocketAddress) -> Result<UDPSocket, IOError> {
        let address = Conversion::std_address(address);
        let socket = Socket::for_address(&address, SocketKind::Datagram).map_err(Conversion::error)?;
        socket.bind(&address).map_err(Conversion::error)?;
        UDPSocket::from_socket(reactor, socket)
    }

    /// A socket of a datagram socket (made nonblocking).
    pub fn from_socket(reactor: &Reactor, socket: Socket) -> Result<UDPSocket, IOError> {
        socket.set_nonblocking(true).map_err(Conversion::error)?;
        let registration = Registration::new(reactor, &socket).map_err(Conversion::error)?;
        Ok(UDPSocket { registration, socket })
    }

    pub fn local_address(&self) -> Result<SocketAddress, IOError> {
        self.socket.local_address().map(Conversion::address).map_err(Conversion::error)
    }

    pub fn socket(&self) -> &Socket {
        &self.socket
    }
}

impl AsRawFd for UDPSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl AsyncDatagram for UDPSocket {
    async fn send_to(&mut self, buffer: Vec<u8>, address: SocketAddress) -> (Result<usize, IOError>, Vec<u8>) {
        let address = Conversion::std_address(address);
        let result = poll_fn(|context| {
            self.registration.source().poll_io(Direction::Write, context, || self.socket.send_to(&buffer, &address))
        })
        .await;
        (result.map_err(Conversion::error), buffer)
    }

    async fn receive_from(&mut self, buffer: Vec<u8>) -> (Result<(usize, SocketAddress), IOError>, Vec<u8>) {
        let mut buffer = buffer;
        let start = buffer.len();
        let room = buffer.capacity() - start;
        if room == 0 {
            return (Err(IOError::new(IOErrorKind::InvalidInput)), buffer);
        }
        buffer.resize(start + room, 0);
        let result = poll_fn(|context| {
            self.registration
                .source()
                .poll_io(Direction::Read, context, || self.socket.receive_from(&mut buffer[start..]))
        })
        .await;
        let count = result.as_ref().map_or(0, |(count, _)| *count);
        buffer.truncate(start + count);
        (result.map(|(count, address)| (count, Conversion::address(address))).map_err(Conversion::error), buffer)
    }
}
