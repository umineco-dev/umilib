use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::sys::Windows;

/// A socket address in the form of Winsock's `SOCKADDR_IN` and
/// `SOCKADDR_IN6`, in a buffer of the size and alignment of `SOCKADDR_STORAGE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(8))]
pub struct RawSocketAddress {
    pub bytes: [u8; Windows::SOCKADDR_STORAGE],
    pub length: i32,
}

impl RawSocketAddress {
    pub const IPV4_LENGTH: usize = 16;
    pub const IPV6_LENGTH: usize = 28;

    /// An empty buffer of the size of `SOCKADDR_STORAGE`, for the system to fill.
    pub const fn empty() -> RawSocketAddress {
        RawSocketAddress { bytes: [0; Windows::SOCKADDR_STORAGE], length: Windows::SOCKADDR_STORAGE as i32 }
    }

    pub fn family(&self) -> i32 {
        u16::from_ne_bytes([self.bytes[0], self.bytes[1]]) as i32
    }

    pub fn from_std(address: &SocketAddr) -> RawSocketAddress {
        let mut raw = RawSocketAddress::empty();
        match address {
            SocketAddr::V4(address) => {
                raw.bytes[..2].copy_from_slice(&(Windows::AF_INET as u16).to_ne_bytes());
                raw.bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
                raw.bytes[4..8].copy_from_slice(&address.ip().octets());
                raw.length = RawSocketAddress::IPV4_LENGTH as i32;
            }
            SocketAddr::V6(address) => {
                raw.bytes[..2].copy_from_slice(&(Windows::AF_INET6 as u16).to_ne_bytes());
                raw.bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
                raw.bytes[4..8].copy_from_slice(&address.flowinfo().to_ne_bytes());
                raw.bytes[8..24].copy_from_slice(&address.ip().octets());
                raw.bytes[24..28].copy_from_slice(&address.scope_id().to_ne_bytes());
                raw.length = RawSocketAddress::IPV6_LENGTH as i32;
            }
        }
        raw
    }

    /// The address, if it is of an IP family.
    pub fn to_std(&self) -> Option<SocketAddr> {
        let port = u16::from_be_bytes([self.bytes[2], self.bytes[3]]);
        let word = |start: usize| u32::from_ne_bytes(self.bytes[start..start + 4].try_into().expect("four bytes"));
        match self.family() {
            Windows::AF_INET => {
                let octets: [u8; 4] = self.bytes[4..8].try_into().expect("four bytes");
                Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port)))
            }
            Windows::AF_INET6 => {
                let octets: [u8; 16] = self.bytes[8..24].try_into().expect("sixteen bytes");
                Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, word(4), word(24))))
            }
            _ => None,
        }
    }
}
