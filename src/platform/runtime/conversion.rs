use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::runtime::{IOError, IOErrorKind, SocketAddress};

/// Conversions between the types of std and those of `umilib::runtime`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Conversion;

impl Conversion {
    pub fn address(address: SocketAddr) -> SocketAddress {
        match address {
            SocketAddr::V4(address) => SocketAddress::V4 { address: address.ip().octets(), port: address.port() },
            SocketAddr::V6(address) => SocketAddress::V6 {
                address: address.ip().octets(),
                port: address.port(),
                flow: address.flowinfo(),
                scope: address.scope_id(),
            },
        }
    }

    pub fn std_address(address: SocketAddress) -> SocketAddr {
        match address {
            SocketAddress::V4 { address, port } => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(address), port)),
            SocketAddress::V6 { address, port, flow, scope } => {
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(address), port, flow, scope))
            }
        }
    }

    pub fn error_kind(kind: io::ErrorKind) -> IOErrorKind {
        match kind {
            io::ErrorKind::NotFound => IOErrorKind::NotFound,
            io::ErrorKind::PermissionDenied => IOErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionRefused => IOErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset => IOErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted => IOErrorKind::ConnectionAborted,
            io::ErrorKind::NotConnected => IOErrorKind::NotConnected,
            io::ErrorKind::AddrInUse => IOErrorKind::AddressInUse,
            io::ErrorKind::AddrNotAvailable => IOErrorKind::AddressNotAvailable,
            io::ErrorKind::BrokenPipe => IOErrorKind::BrokenPipe,
            io::ErrorKind::AlreadyExists => IOErrorKind::AlreadyExists,
            io::ErrorKind::WouldBlock => IOErrorKind::WouldBlock,
            io::ErrorKind::InvalidInput => IOErrorKind::InvalidInput,
            io::ErrorKind::InvalidData => IOErrorKind::InvalidData,
            io::ErrorKind::TimedOut => IOErrorKind::TimedOut,
            io::ErrorKind::WriteZero => IOErrorKind::WriteZero,
            io::ErrorKind::Interrupted => IOErrorKind::Interrupted,
            io::ErrorKind::Unsupported => IOErrorKind::Unsupported,
            io::ErrorKind::UnexpectedEof => IOErrorKind::UnexpectedEnd,
            io::ErrorKind::OutOfMemory => IOErrorKind::OutOfMemory,
            _ => IOErrorKind::Other,
        }
    }

    /// The runtime error of `error`, with the system's code.
    pub fn error(error: io::Error) -> IOError {
        IOError { kind: Conversion::error_kind(error.kind()), code: error.raw_os_error() }
    }
}
