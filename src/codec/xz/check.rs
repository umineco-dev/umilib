use crate::codec::CompressionError;
use crate::hash::Digest;
use crate::hash::crc::{CRC, CRCCatalogue};
use crate::hash::sha::v2::SHA256;

/// The type of the Check of the Blocks of a Stream (section 2.1.1.2), of
/// those the format defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XZCheck {
    None,
    CRC32,
    CRC64,
    SHA256,
}

impl XZCheck {
    /// The Check ID.
    pub const fn id(self) -> u8 {
        match self {
            XZCheck::None => 0x00,
            XZCheck::CRC32 => 0x01,
            XZCheck::CRC64 => 0x04,
            XZCheck::SHA256 => 0x0A,
        }
    }

    /// The check of the Check ID `id` (0 to 15); fails with `Unsupported` for the reserved ones.
    pub fn from_id(id: u8) -> Result<XZCheck, CompressionError> {
        match id {
            0x00 => Ok(XZCheck::None),
            0x01 => Ok(XZCheck::CRC32),
            0x04 => Ok(XZCheck::CRC64),
            0x0A => Ok(XZCheck::SHA256),
            _ => Err(CompressionError::Unsupported { feature: "reserved check type" }),
        }
    }

    /// The size of the Check field.
    pub const fn size(self) -> usize {
        match self {
            XZCheck::None => 0,
            XZCheck::CRC32 => 4,
            XZCheck::CRC64 => 8,
            XZCheck::SHA256 => 32,
        }
    }
}

/// The computation of a Check over the uncompressed data of a Block.
#[derive(Clone, Debug)]
pub enum XZChecksum {
    None,
    CRC32(CRC<'static, u32>),
    CRC64(CRC<'static, u64>),
    SHA256(SHA256),
}

impl XZChecksum {
    pub fn new(check: XZCheck) -> XZChecksum {
        match check {
            XZCheck::None => XZChecksum::None,
            XZCheck::CRC32 => XZChecksum::CRC32(CRC::new(CRCCatalogue::CRC32_ISO_HDLC)),
            XZCheck::CRC64 => XZChecksum::CRC64(CRC::new(CRCCatalogue::CRC64_XZ)),
            XZCheck::SHA256 => XZChecksum::SHA256(SHA256::new()),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            XZChecksum::None => {}
            XZChecksum::CRC32(crc) => crc.update(data),
            XZChecksum::CRC64(crc) => crc.update(data),
            XZChecksum::SHA256(hash) => hash.update(data),
        }
    }

    /// The Check field of the data so far (the CRCs little endian) in the
    /// first bytes of the result, and its size; the computation starts again.
    pub fn finish(&mut self) -> ([u8; 32], usize) {
        let mut field = [0u8; 32];
        let size = match self {
            XZChecksum::None => 0,
            XZChecksum::CRC32(crc) => {
                field[..4].copy_from_slice(&crc.value().to_le_bytes());
                crc.reset();
                4
            }
            XZChecksum::CRC64(crc) => {
                field[..8].copy_from_slice(&crc.value().to_le_bytes());
                crc.reset();
                8
            }
            XZChecksum::SHA256(hash) => {
                field.copy_from_slice(&hash.finalize_reset());
                32
            }
        };
        (field, size)
    }
}
