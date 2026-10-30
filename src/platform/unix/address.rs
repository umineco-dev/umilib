use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::sys::{POSIX, SocketLength};

/// A socket address in the form of the system's `sockaddr` structures
/// (`sockaddr_in`, `sockaddr_in6`, with the `sin_len` byte of the BSDs),
/// in a buffer of the size of `sockaddr_storage`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawSocketAddress {
    pub bytes: [u8; POSIX::SOCKADDR_STORAGE],
    pub length: SocketLength,
}

impl RawSocketAddress {
    /// The size of `sockaddr_in` and `sockaddr_in6`.
    pub const IPV4_LENGTH: usize = 16;
    pub const IPV6_LENGTH: usize = 28;

    /// An empty buffer of the size of `sockaddr_storage`, for the system to fill.
    pub const fn empty() -> RawSocketAddress {
        RawSocketAddress { bytes: [0; POSIX::SOCKADDR_STORAGE], length: POSIX::SOCKADDR_STORAGE as SocketLength }
    }

    /// Writes the family field: a 16-bit value, or the length byte and an 8-bit value on the BSDs.
    pub fn write_family(&mut self, family: i32, length: usize) {
        if cfg!(target_vendor = "apple") {
            self.bytes[0] = length as u8;
            self.bytes[1] = family as u8;
        } else {
            self.bytes[..2].copy_from_slice(&(family as u16).to_ne_bytes());
        }
    }

    /// The family field.
    pub fn family(&self) -> i32 {
        if cfg!(target_vendor = "apple") {
            self.bytes[1] as i32
        } else {
            u16::from_ne_bytes([self.bytes[0], self.bytes[1]]) as i32
        }
    }

    pub fn from_std(address: &SocketAddr) -> RawSocketAddress {
        let mut raw = RawSocketAddress::empty();
        match address {
            SocketAddr::V4(address) => {
                raw.write_family(POSIX::AF_INET, RawSocketAddress::IPV4_LENGTH);
                raw.bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
                raw.bytes[4..8].copy_from_slice(&address.ip().octets());
                raw.length = RawSocketAddress::IPV4_LENGTH as SocketLength;
            }
            SocketAddr::V6(address) => {
                raw.write_family(POSIX::AF_INET6, RawSocketAddress::IPV6_LENGTH);
                raw.bytes[2..4].copy_from_slice(&address.port().to_be_bytes());
                raw.bytes[4..8].copy_from_slice(&address.flowinfo().to_ne_bytes());
                raw.bytes[8..24].copy_from_slice(&address.ip().octets());
                raw.bytes[24..28].copy_from_slice(&address.scope_id().to_ne_bytes());
                raw.length = RawSocketAddress::IPV6_LENGTH as SocketLength;
            }
        }
        raw
    }

    /// The address, if it is of an IP family.
    pub fn to_std(&self) -> Option<SocketAddr> {
        let port = u16::from_be_bytes([self.bytes[2], self.bytes[3]]);
        let word = |start: usize| u32::from_ne_bytes(self.bytes[start..start + 4].try_into().expect("four bytes"));
        match self.family() {
            POSIX::AF_INET => {
                let octets: [u8; 4] = self.bytes[4..8].try_into().expect("four bytes");
                Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port)))
            }
            POSIX::AF_INET6 => {
                let octets: [u8; 16] = self.bytes[8..24].try_into().expect("sixteen bytes");
                Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, word(4), word(24))))
            }
            _ => None,
        }
    }
}
