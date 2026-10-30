use crate::bytes::Writer;

use super::super::IPProtocol;
use super::IPv6Error;

/// A Fragment header (RFC 8200 §4.5). The reserved fields, which senders
/// set to zero, are ignored on receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct IPv6FragmentHeader {
    /// The first header of the fragmentable part.
    pub next_header: IPProtocol,
    /// The offset of the fragment's data, in units of 8 bytes.
    pub fragment_offset: u16,
    pub more_fragments: bool,
    pub identification: u32,
}

impl IPv6FragmentHeader {
    pub const LENGTH: usize = 8;
    /// The unit of fragment offsets.
    pub const FRAGMENT_UNIT: usize = 8;

    pub fn decode(bytes: &[u8]) -> Result<IPv6FragmentHeader, IPv6Error> {
        let bytes = bytes.get(..IPv6FragmentHeader::LENGTH).ok_or(IPv6Error::Length)?;
        let field = u16::from_be_bytes([bytes[2], bytes[3]]);
        Ok(IPv6FragmentHeader {
            next_header: IPProtocol(bytes[0]),
            fragment_offset: field >> 3,
            more_fragments: field & 1 != 0,
            identification: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; IPv6FragmentHeader::LENGTH] {
        let field = (self.fragment_offset & 0x1FFF) << 3 | self.more_fragments as u16;
        let [a, b] = field.to_be_bytes();
        let [c, d, e, f] = self.identification.to_be_bytes();
        [self.next_header.0, 0, a, b, c, d, e, f]
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), IPv6Error> {
        Ok(out.write(&self.to_bytes())?)
    }

    /// Whether the fragment is a whole packet (an atomic fragment: offset
    /// zero and no more fragments), which is processed on its own (RFC 6946).
    pub fn is_atomic(&self) -> bool {
        self.fragment_offset == 0 && !self.more_fragments
    }
}
