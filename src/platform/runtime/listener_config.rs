use std::io;
use std::net::SocketAddr;

use super::Conversion;
use crate::platform::native::{Socket, SocketKind};
use crate::runtime::{IOError, SocketAddress};

/// The parameters of a listening socket: of a [`TCPListener`](super::TCPListener),
/// or of one a [`Supervisor`](super::Supervisor) shares with its workers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerConfig {
    /// The connections waiting to be accepted at most (the system may cap it).
    pub backlog: i32,
    /// `SO_REUSEADDR` (Unix: bind while old connections linger; true by default).
    /// On Windows, where it lets other sockets take the address, it is false
    /// by default and `SO_EXCLUSIVEADDRUSE` is set instead.
    pub reuse_address: bool,
    /// `SO_REUSEPORT` (Unix only): several listeners of one user on one address.
    pub reuse_port: bool,
    /// `IPV6_V6ONLY` for an IPv6 address, if not the system's default.
    pub only_v6: Option<bool>,
}

impl ListenerConfig {
    /// A TCP socket listening on `address` with these parameters.
    pub fn bind(&self, address: SocketAddress) -> Result<Socket, IOError> {
        let address = Conversion::std_address(address);
        let socket = Socket::for_address(&address, SocketKind::Stream).map_err(Conversion::error)?;
        self.apply(&socket, &address).map_err(Conversion::error)?;
        Ok(socket)
    }

    /// Sets the options of `socket`, binds it to `address` and listens.
    pub fn apply(&self, socket: &Socket, address: &SocketAddr) -> io::Result<()> {
        #[cfg(unix)]
        socket.set_reuse_address(self.reuse_address)?;
        #[cfg(windows)]
        if self.reuse_address {
            socket.set_reuse_address(true)?;
        } else {
            socket.set_exclusive_address(true)?;
        }
        if self.reuse_port {
            socket.set_reuse_port(true)?;
        }
        if let (Some(only), true) = (self.only_v6, address.is_ipv6()) {
            socket.set_only_v6(only)?;
        }
        socket.bind(address)?;
        socket.listen(self.backlog)
    }
}

impl Default for ListenerConfig {
    fn default() -> ListenerConfig {
        ListenerConfig { backlog: 1024, reuse_address: cfg!(unix), reuse_port: false, only_v6: None }
    }
}
