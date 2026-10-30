use std::io;

use super::sys::Linux;
use crate::platform::unix::sys::POSIX;
use crate::platform::unix::{RawSocketAddress, Socket, SocketDomain, SocketKind};

/// A link-layer address of a packet socket (`struct sockaddr_ll`): the
/// interface, the EtherType, the packet type and the hardware address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct LinkAddress {
    pub interface: u32,
    /// The EtherType (host byte order).
    pub protocol: u16,
    pub hardware_type: u16,
    /// Whose packet it is (`PACKET_HOST`, `PACKET_BROADCAST`, `PACKET_OUTGOING`...).
    pub packet_type: u8,
    pub address: [u8; 8],
    pub address_length: u8,
}

impl LinkAddress {
    /// The address of the hardware address `address` (at most 8 bytes) on `interface`, for `protocol`.
    pub fn new(interface: u32, protocol: u16, address: &[u8]) -> LinkAddress {
        let mut bytes = [0u8; 8];
        let length = address.len().min(8);
        bytes[..length].copy_from_slice(&address[..length]);
        LinkAddress { interface, protocol, address: bytes, address_length: length as u8, ..LinkAddress::default() }
    }

    pub fn to_raw(&self) -> RawSocketAddress {
        let mut raw = RawSocketAddress::empty();
        raw.bytes[..2].copy_from_slice(&(POSIX::AF_PACKET as u16).to_ne_bytes());
        raw.bytes[2..4].copy_from_slice(&self.protocol.to_be_bytes());
        raw.bytes[4..8].copy_from_slice(&(self.interface as i32).to_ne_bytes());
        raw.bytes[8..10].copy_from_slice(&self.hardware_type.to_ne_bytes());
        raw.bytes[10] = self.packet_type;
        raw.bytes[11] = self.address_length;
        raw.bytes[12..20].copy_from_slice(&self.address);
        raw.length = Linux::SOCKADDR_LL as u32;
        raw
    }

    /// The address of a `sockaddr_ll`; `None` for another family.
    pub fn from_raw(raw: &RawSocketAddress) -> Option<LinkAddress> {
        if raw.family() != POSIX::AF_PACKET {
            return None;
        }
        let bytes = &raw.bytes;
        Some(LinkAddress {
            protocol: u16::from_be_bytes([bytes[2], bytes[3]]),
            interface: i32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u32,
            hardware_type: u16::from_ne_bytes([bytes[8], bytes[9]]),
            packet_type: bytes[10],
            address_length: bytes[11],
            address: bytes[12..20].try_into().expect("eight bytes"),
        })
    }
}

/// Packet sockets (`AF_PACKET`): frames of a link, with their link-layer
/// header (raw) or without it (datagram). They need `CAP_NET_RAW`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketSocket;

impl PacketSocket {
    /// A packet socket of the frames of `protocol` (an EtherType; `ETH_P_ALL`
    /// for all), with their link-layer header if `kind` is raw, bound to
    /// `interface` (or every interface if `None`).
    pub fn open(kind: SocketKind, protocol: u16, interface: Option<u32>) -> io::Result<Socket> {
        if kind == SocketKind::Stream {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let socket = Socket::new(SocketDomain::Packet, kind, protocol.to_be() as i32)?;
        if let Some(interface) = interface {
            socket.bind_raw(&LinkAddress { interface, protocol, ..LinkAddress::default() }.to_raw())?;
        }
        Ok(socket)
    }

    /// Every protocol (`ETH_P_ALL`).
    pub const ALL: u16 = Linux::ETH_P_ALL;
}
