use super::{IPAddress, IPError, IPProtocol, IPv4Address, IPv6Address, InternetChecksum};

/// The pseudo-header that the checksums of upper-layer protocols cover
/// along with their own header and data: the addresses, the protocol and
/// the upper-layer length of the packet that carries them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IPPseudoHeader {
    /// RFC 768, RFC 9293 §3.1: source, destination, zero, protocol and a
    /// 16-bit length.
    V4 { source: IPv4Address, destination: IPv4Address, protocol: IPProtocol, length: u16 },
    /// RFC 8200 §8.1: source, destination (the final one for a Routing
    /// header), a 32-bit length, three zero bytes and the next header of
    /// the upper layer.
    V6 { source: IPv6Address, destination: IPv6Address, next_header: IPProtocol, length: u32 },
}

impl IPPseudoHeader {
    pub const V4_LENGTH: usize = 12;
    pub const V6_LENGTH: usize = 40;

    /// The pseudo-header of `length` upper-layer bytes of `protocol` between
    /// addresses of the same version.
    pub fn new(
        source: IPAddress,
        destination: IPAddress,
        protocol: IPProtocol,
        length: usize,
    ) -> Result<IPPseudoHeader, IPError> {
        match (source, destination) {
            (IPAddress::V4(source), IPAddress::V4(destination)) => Ok(IPPseudoHeader::V4 {
                source,
                destination,
                protocol,
                length: u16::try_from(length).map_err(|_| IPError::Length)?,
            }),
            (IPAddress::V6(source), IPAddress::V6(destination)) => Ok(IPPseudoHeader::V6 {
                source,
                destination,
                next_header: protocol,
                length: u32::try_from(length).map_err(|_| IPError::Length)?,
            }),
            _ => Err(IPError::Family),
        }
    }

    /// The bytes of the pseudo-header: [`IPPseudoHeader::V4_LENGTH`] or
    /// [`IPPseudoHeader::V6_LENGTH`] of the array.
    pub fn to_bytes(&self) -> ([u8; IPPseudoHeader::V6_LENGTH], usize) {
        let mut bytes = [0u8; IPPseudoHeader::V6_LENGTH];
        match *self {
            IPPseudoHeader::V4 { source, destination, protocol, length } => {
                bytes[..4].copy_from_slice(&source.0);
                bytes[4..8].copy_from_slice(&destination.0);
                bytes[9] = protocol.0;
                bytes[10..12].copy_from_slice(&length.to_be_bytes());
                (bytes, IPPseudoHeader::V4_LENGTH)
            }
            IPPseudoHeader::V6 { source, destination, next_header, length } => {
                bytes[..16].copy_from_slice(&source.0);
                bytes[16..32].copy_from_slice(&destination.0);
                bytes[32..36].copy_from_slice(&length.to_be_bytes());
                bytes[39] = next_header.0;
                (bytes, IPPseudoHeader::V6_LENGTH)
            }
        }
    }

    /// A checksum to which the pseudo-header is added: the upper layer adds
    /// its header (with a zero checksum field) and data.
    pub fn checksum(&self) -> InternetChecksum {
        let (bytes, length) = self.to_bytes();
        let mut checksum = InternetChecksum::new();
        checksum.update(&bytes[..length]);
        checksum
    }
}
