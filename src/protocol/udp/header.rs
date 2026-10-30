use crate::bytes::Writer;

use super::UDPError;

/// The header of a UDP datagram (RFC 768), its fields as they are: nothing
/// is checked but its length. [`UDPDatagram`](super::UDPDatagram) reads and
/// writes a datagram with its rules; this type reads the header that an
/// ICMP error quotes, whose datagram is cut short.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct UDPHeader {
    /// Zero if not used (RFC 768).
    pub source_port: u16,
    pub destination_port: u16,
    /// The header and the data, in bytes; zero in an IPv6 jumbogram (RFC 2675 §4).
    pub length: u16,
    /// Zero if none was computed.
    pub checksum: u16,
}

impl UDPHeader {
    pub const LENGTH: usize = 8;

    /// The header at the start of `bytes`; fails with [`UDPError::Length`] if they are fewer than 8.
    pub fn decode(bytes: &[u8]) -> Result<UDPHeader, UDPError> {
        let header = bytes.first_chunk::<{ UDPHeader::LENGTH }>().ok_or(UDPError::Length)?;
        let field = |index: usize| u16::from_be_bytes([header[index], header[index + 1]]);
        Ok(UDPHeader { source_port: field(0), destination_port: field(2), length: field(4), checksum: field(6) })
    }

    pub fn to_bytes(&self) -> [u8; UDPHeader::LENGTH] {
        let [a, b] = self.source_port.to_be_bytes();
        let [c, d] = self.destination_port.to_be_bytes();
        let [e, f] = self.length.to_be_bytes();
        let [g, h] = self.checksum.to_be_bytes();
        [a, b, c, d, e, f, g, h]
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), UDPError> {
        Ok(out.write(&self.to_bytes())?)
    }
}
