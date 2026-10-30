use alloc::vec::Vec;

use crate::codec::CompressionError;
use crate::hash::crc::{CRC, CRCCatalogue};

/// The constants of the .xz file format (The .xz File Format, version
/// 1.2.1) and its integers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XZFormat;

impl XZFormat {
    /// The Header Magic Bytes and Footer Magic Bytes.
    pub const HEADER_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];
    pub const FOOTER_MAGIC: [u8; 2] = *b"YZ";
    /// The sizes of the Stream Header and the Stream Footer.
    pub const STREAM_HEADER_SIZE: usize = 12;
    pub const STREAM_FOOTER_SIZE: usize = 12;
    /// The largest Block Header.
    pub const MAXIMUM_BLOCK_HEADER: usize = 1024;
    /// The most filters of a Block.
    pub const MAXIMUM_FILTERS: usize = 4;
    /// The largest value of a variable-length integer (and of sizes): 2^63 - 1.
    pub const MAXIMUM_INTEGER: u64 = (1 << 63) - 1;
    /// The most bytes of a variable-length integer.
    pub const MAXIMUM_INTEGER_BYTES: usize = 9;
    /// The smallest and largest Unpadded Size of a Block.
    pub const MINIMUM_UNPADDED: u64 = 5;
    pub const MAXIMUM_UNPADDED: u64 = XZFormat::MAXIMUM_INTEGER & !3;
    /// The filter IDs of section 5.3.
    pub const DELTA: u64 = 0x03;
    pub const X86: u64 = 0x04;
    pub const POWER_PC: u64 = 0x05;
    pub const IA64: u64 = 0x06;
    pub const ARM: u64 = 0x07;
    pub const ARM_THUMB: u64 = 0x08;
    pub const SPARC: u64 = 0x09;
    pub const ARM64: u64 = 0x0A;
    pub const RISCV: u64 = 0x0B;
    pub const LZMA2: u64 = 0x21;
    /// The first filter ID reserved for implementations' internal use.
    pub const RESERVED_FILTER: u64 = 1 << 62;

    /// The CRC32 of the format (CRC-32/ISO-HDLC).
    pub fn crc32(data: &[u8]) -> u32 {
        CRC::checksum(CRCCatalogue::CRC32_ISO_HDLC, data)
    }

    /// The size of the Check of the Check ID `id` (0 to 15).
    pub const fn check_size(id: u8) -> usize {
        match id {
            0x00 => 0,
            0x01..=0x03 => 4,
            0x04..=0x06 => 8,
            0x07..=0x09 => 16,
            0x0A..=0x0C => 32,
            _ => 64,
        }
    }

    /// Appends the variable-length integer of `value` (at most 2^63 - 1, section 1.2).
    pub fn write_integer(value: u64, out: &mut Vec<u8>) {
        debug_assert!(value <= XZFormat::MAXIMUM_INTEGER);
        let mut value = value;
        while value >= 0x80 {
            out.push(value as u8 | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    /// The variable-length integer at the start of `bytes` and its length;
    /// fails with `InvalidData` if it is longer than 9 bytes, has a
    /// superfluous zero byte, or `bytes` end inside it.
    pub fn read_integer(bytes: &[u8]) -> Result<(u64, usize), CompressionError> {
        let mut reader = XZIntegerReader::new();
        for (index, byte) in bytes.iter().enumerate() {
            if let Some(value) = reader.push(*byte)? {
                return Ok((value, index + 1));
            }
        }
        Err(CompressionError::InvalidData { reason: "truncated integer" })
    }
}

/// Reads a variable-length integer a byte at a time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XZIntegerReader {
    value: u64,
    length: usize,
}

impl XZIntegerReader {
    pub const fn new() -> XZIntegerReader {
        XZIntegerReader { value: 0, length: 0 }
    }

    /// Adds the next byte: the integer once it is complete (the reader then
    /// starts the next one); fails with `InvalidData` for a tenth byte or a
    /// last byte of zero after the first.
    pub fn push(&mut self, byte: u8) -> Result<Option<u64>, CompressionError> {
        if self.length > 0 && byte == 0 {
            return Err(CompressionError::InvalidData { reason: "integer with a superfluous zero byte" });
        }
        self.value |= ((byte & 0x7F) as u64) << (7 * self.length);
        self.length += 1;
        if byte & 0x80 == 0 {
            let value = self.value;
            *self = XZIntegerReader::new();
            return Ok(Some(value));
        }
        if self.length == XZFormat::MAXIMUM_INTEGER_BYTES {
            return Err(CompressionError::InvalidData { reason: "integer longer than 9 bytes" });
        }
        Ok(None)
    }
}
