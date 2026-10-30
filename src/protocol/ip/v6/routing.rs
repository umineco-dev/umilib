use crate::bytes::Writer;

use super::super::IPProtocol;
use super::IPv6Error;

/// A Routing header (RFC 8200 §4.4): its type, the segments left and the
/// type-specific data. Type 0 is deprecated (RFC 5095) and is not to be
/// processed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IPv6RoutingHeader<'a> {
    pub next_header: IPProtocol,
    pub routing_type: u8,
    pub segments_left: u8,
    /// The bytes after the first four.
    pub data: &'a [u8],
}

impl<'a> IPv6RoutingHeader<'a> {
    /// The header that `bytes` is (the bytes of an [`super::IPv6ExtensionHeader`]).
    pub fn decode(bytes: &'a [u8]) -> Result<IPv6RoutingHeader<'a>, IPv6Error> {
        if bytes.len() < 8 || (bytes[1] as usize + 1) * 8 != bytes.len() {
            return Err(IPv6Error::Length);
        }
        Ok(IPv6RoutingHeader {
            next_header: IPProtocol(bytes[0]),
            routing_type: bytes[2],
            segments_left: bytes[3],
            data: &bytes[4..],
        })
    }

    /// Writes the header; the data must make it a multiple of 8 bytes, at most 2,048.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), IPv6Error> {
        let length = self.data.len() + 4;
        if !length.is_multiple_of(8) {
            return Err(IPv6Error::Length);
        }
        let units = u8::try_from(length / 8 - 1).map_err(|_| IPv6Error::Length)?;
        out.write(&[self.next_header.0, units, self.routing_type, self.segments_left])?;
        Ok(out.write(self.data)?)
    }
}
