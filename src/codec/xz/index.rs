use alloc::vec::Vec;

use super::{XZFormat, XZIntegerReader};
use crate::codec::CompressionError;
use crate::hash::Digest;
use crate::hash::crc::{CRC, CRCCatalogue};
use crate::hash::sha::v2::SHA256;

/// A summary of Index Records (section 4.3) in constant memory: their
/// number, the sums of their sizes, and the SHA-256 of their values, as the
/// format suggests for verifying an Index against the Blocks decoded.
#[derive(Clone, Debug)]
pub struct XZIndexHash {
    pub records: u64,
    pub unpadded_size: u64,
    pub uncompressed_size: u64,
    hash: SHA256,
}

impl XZIndexHash {
    pub fn new() -> XZIndexHash {
        XZIndexHash { records: 0, unpadded_size: 0, uncompressed_size: 0, hash: SHA256::new() }
    }

    /// Adds a Record; fails with `InvalidData` for an Unpadded Size out of
    /// range or sums beyond 2^63 - 1 bytes (the size of the Blocks counts their padding).
    pub fn append(&mut self, unpadded_size: u64, uncompressed_size: u64) -> Result<(), CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        if !(XZFormat::MINIMUM_UNPADDED..=XZFormat::MAXIMUM_UNPADDED).contains(&unpadded_size) {
            return Err(invalid("invalid unpadded size"));
        }
        self.unpadded_size = self
            .unpadded_size
            .checked_add(unpadded_size.next_multiple_of(4))
            .filter(|sum| *sum <= XZFormat::MAXIMUM_INTEGER)
            .ok_or(invalid("blocks larger than 2^63 - 1 bytes"))?;
        self.uncompressed_size = self
            .uncompressed_size
            .checked_add(uncompressed_size)
            .filter(|sum| *sum <= XZFormat::MAXIMUM_INTEGER)
            .ok_or(invalid("data larger than 2^63 - 1 bytes"))?;
        self.records += 1;
        self.hash.update(&unpadded_size.to_le_bytes());
        self.hash.update(&uncompressed_size.to_le_bytes());
        Ok(())
    }

    /// Whether `other` summarizes the same Records.
    pub fn matches(&self, other: &XZIndexHash) -> bool {
        (self.records, self.unpadded_size, self.uncompressed_size)
            == (other.records, other.unpadded_size, other.uncompressed_size)
            && self.hash.clone().finalize() == other.hash.clone().finalize()
    }
}

impl Default for XZIndexHash {
    fn default() -> XZIndexHash {
        XZIndexHash::new()
    }
}

/// The part of an Index an [`XZIndexReader`] reads next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XZIndexPhase {
    /// Number of Records.
    Count,
    /// Unpadded Size, then Uncompressed Size, of the Records left.
    UnpaddedSize {
        remaining: u64,
    },
    UncompressedSize {
        remaining: u64,
        unpadded_size: u64,
    },
    /// Index Padding, then the CRC32 (`count` of its bytes so far).
    Padding,
    CRC {
        count: usize,
    },
    /// After the CRC32.
    End,
}

/// Reads an Index a byte at a time after its Index Indicator, keeping
/// only an [`XZIndexHash`] of its Records.
#[derive(Clone, Debug)]
pub struct XZIndexReader {
    phase: XZIndexPhase,
    integer: XZIntegerReader,
    crc: CRC<'static, u32>,
    stored: [u8; 4],
    /// The bytes of the Index so far, the Indicator included.
    size: u64,
    pub hash: XZIndexHash,
}

impl XZIndexReader {
    /// A reader after the Index Indicator.
    pub fn new() -> XZIndexReader {
        let mut crc = CRC::new(CRCCatalogue::CRC32_ISO_HDLC);
        crc.update(&[0]);
        XZIndexReader {
            phase: XZIndexPhase::Count,
            integer: XZIntegerReader::new(),
            crc,
            stored: [0; 4],
            size: 1,
            hash: XZIndexHash::new(),
        }
    }

    pub fn phase(&self) -> XZIndexPhase {
        self.phase
    }

    /// The size of the Index, the Indicator and the CRC32 included.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Reads from `input` up to the end of the Index; true once it is read.
    /// Fails with `InvalidData` for malformed integers, Records, padding or a wrong CRC32.
    pub fn read(&mut self, input: &mut &[u8]) -> Result<bool, CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        while self.phase != XZIndexPhase::End {
            let Some((&byte, rest)) = input.split_first() else { return Ok(false) };
            *input = rest;
            self.size += 1;
            if !matches!(self.phase, XZIndexPhase::CRC { .. }) {
                self.crc.update(&[byte]);
            }
            self.phase = match self.phase {
                XZIndexPhase::Count => match self.integer.push(byte)? {
                    None => XZIndexPhase::Count,
                    Some(0) => XZIndexPhase::Padding,
                    Some(remaining) => XZIndexPhase::UnpaddedSize { remaining },
                },
                XZIndexPhase::UnpaddedSize { remaining } => match self.integer.push(byte)? {
                    None => XZIndexPhase::UnpaddedSize { remaining },
                    Some(unpadded_size) => XZIndexPhase::UncompressedSize { remaining, unpadded_size },
                },
                XZIndexPhase::UncompressedSize { remaining, unpadded_size } => match self.integer.push(byte)? {
                    None => XZIndexPhase::UncompressedSize { remaining, unpadded_size },
                    Some(uncompressed_size) => {
                        self.hash.append(unpadded_size, uncompressed_size)?;
                        if remaining > 1 {
                            XZIndexPhase::UnpaddedSize { remaining: remaining - 1 }
                        } else {
                            XZIndexPhase::Padding
                        }
                    }
                },
                XZIndexPhase::Padding => {
                    if byte != 0 {
                        return Err(invalid("non-zero index padding"));
                    }
                    XZIndexPhase::Padding
                }
                XZIndexPhase::CRC { count } => {
                    self.stored[count] = byte;
                    if count < 3 {
                        XZIndexPhase::CRC { count: count + 1 }
                    } else {
                        if self.crc.value().to_le_bytes() != self.stored {
                            return Err(invalid("index CRC32 mismatch"));
                        }
                        XZIndexPhase::End
                    }
                }
                XZIndexPhase::End => XZIndexPhase::End,
            };
            // The padding ends at a multiple of four bytes (before the CRC32).
            if self.phase == XZIndexPhase::Padding && self.size.is_multiple_of(4) {
                self.phase = XZIndexPhase::CRC { count: 0 };
            }
        }
        Ok(true)
    }
}

impl Default for XZIndexReader {
    fn default() -> XZIndexReader {
        XZIndexReader::new()
    }
}

/// The Records of the Blocks a compressor wrote, and their Index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XZIndex {
    /// (Unpadded Size, Uncompressed Size) per Block.
    pub records: Vec<(u64, u64)>,
}

impl XZIndex {
    pub fn new() -> XZIndex {
        XZIndex { records: Vec::new() }
    }

    /// The Index field: Indicator, Number of Records, Records, padding, CRC32.
    pub fn encode(&self) -> Vec<u8> {
        let mut index = Vec::from([0u8]);
        XZFormat::write_integer(self.records.len() as u64, &mut index);
        for (unpadded_size, uncompressed_size) in &self.records {
            XZFormat::write_integer(*unpadded_size, &mut index);
            XZFormat::write_integer(*uncompressed_size, &mut index);
        }
        index.resize(index.len().next_multiple_of(4), 0);
        let crc = XZFormat::crc32(&index);
        index.extend(crc.to_le_bytes());
        index
    }
}
