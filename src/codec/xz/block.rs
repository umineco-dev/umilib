use alloc::vec::Vec;

use super::{XZFilter, XZFormat};
use crate::codec::CompressionError;

/// A Block Header (section 3.1): the sizes it records and the filter chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XZBlockHeader {
    pub compressed_size: Option<u64>,
    pub uncompressed_size: Option<u64>,
    pub filters: Vec<XZFilter>,
}

impl XZBlockHeader {
    /// The size of the Block Header whose first byte is `byte` (not 0, which is the Index Indicator).
    pub const fn size(byte: u8) -> usize {
        (byte as usize + 1) * 4
    }

    /// The Block Header: its size byte, flags, sizes, Filter Flags, padding and CRC32.
    pub fn encode(&self) -> Vec<u8> {
        let mut header = Vec::from([0u8, 0u8]);
        let mut flags = (self.filters.len() - 1) as u8;
        if let Some(size) = self.compressed_size {
            flags |= 0x40;
            XZFormat::write_integer(size, &mut header);
        }
        if let Some(size) = self.uncompressed_size {
            flags |= 0x80;
            XZFormat::write_integer(size, &mut header);
        }
        header[1] = flags;
        for filter in &self.filters {
            filter.write_flags(&mut header);
        }
        header.resize((header.len() + 4).next_multiple_of(4) - 4, 0);
        header[0] = (header.len() / 4) as u8;
        let crc = XZFormat::crc32(&header);
        header.extend(crc.to_le_bytes());
        header
    }

    /// Reads the whole Block Header `header` (its size byte to its CRC32):
    /// fails with `InvalidData` for a wrong CRC32 or a malformed header,
    /// and `Unsupported` for reserved flags, non-zero padding (a field this
    /// implementation would not know) or an unsupported filter chain.
    pub fn decode(header: &[u8]) -> Result<XZBlockHeader, CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        if header.len() < 8 || header.len() != XZBlockHeader::size(header[0]) {
            return Err(invalid("block header of a wrong size"));
        }
        let (content, crc) = header.split_at(header.len() - 4);
        if XZFormat::crc32(content).to_le_bytes() != crc {
            return Err(invalid("block header CRC32 mismatch"));
        }
        let flags = content[1];
        if flags & 0x3C != 0 {
            return Err(CompressionError::Unsupported { feature: "reserved block flags" });
        }
        let mut position = 2;
        let integer = |position: &mut usize| -> Result<u64, CompressionError> {
            let (value, length) = XZFormat::read_integer(&content[*position..])?;
            *position += length;
            Ok(value)
        };
        let compressed_size = if flags & 0x40 != 0 { Some(integer(&mut position)?) } else { None };
        let uncompressed_size = if flags & 0x80 != 0 { Some(integer(&mut position)?) } else { None };
        if compressed_size == Some(0) {
            return Err(invalid("compressed size of zero"));
        }
        let mut filters = Vec::new();
        for _ in 0..(flags & 3) + 1 {
            let id = integer(&mut position)?;
            let length = integer(&mut position)?;
            if id >= XZFormat::RESERVED_FILTER {
                return Err(invalid("reserved filter ID"));
            }
            let properties = content
                .get(position..)
                .and_then(|rest| rest.get(..usize::try_from(length).ok()?))
                .ok_or(invalid("filter properties beyond the block header"))?;
            position += properties.len();
            filters.push(XZFilter::from_flags(id, properties)?);
        }
        if content[position..].iter().any(|byte| *byte != 0) {
            return Err(CompressionError::Unsupported { feature: "non-zero block header padding" });
        }
        XZFilter::check_chain(&filters)?;
        Ok(XZBlockHeader { compressed_size, uncompressed_size, filters })
    }
}
