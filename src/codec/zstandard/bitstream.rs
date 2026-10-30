use alloc::vec::Vec;

use crate::codec::CompressionError;

/// A reader of the backward bitstreams of Zstandard (sections 3.1.1.3.2.1.2
/// and 4.2.2): the bits are read from the end of the slice towards its
/// start, after the padding of zero bits and the 1 bit that end it; a value
/// of several bits is read as little-endian bits below the position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZstandardBitReader<'a> {
    bytes: &'a [u8],
    /// The number of bits left to read (the position counted from the start).
    position: usize,
}

impl<'a> ZstandardBitReader<'a> {
    /// A reader of `bytes`; fails with `InvalidData` if it is empty or its last byte is 0.
    pub fn new(bytes: &'a [u8]) -> Result<ZstandardBitReader<'a>, CompressionError> {
        let last = *bytes.last().ok_or(CompressionError::InvalidData { reason: "empty bitstream" })?;
        if last == 0 {
            return Err(CompressionError::InvalidData { reason: "bitstream without its final bit" });
        }
        let padding = last.leading_zeros() as usize + 1;
        Ok(ZstandardBitReader { bytes, position: bytes.len() * 8 - padding })
    }

    /// The number of bits left.
    pub fn remaining(&self) -> usize {
        self.position
    }

    /// The next `count` bits (at most 32), the missing ones below the start of the stream as zeros.
    pub fn peek(&self, count: u32) -> u32 {
        if count == 0 {
            return 0;
        }
        let end = self.position as isize;
        let start = end - count as isize;
        let mut value = 0u64;
        // The bytes that hold bits from start to end, little-endian.
        let first_byte = (start.max(0) / 8) as usize;
        let last_byte = ((end - 1).max(0) / 8) as usize;
        for index in (first_byte..=last_byte.min(self.bytes.len().saturating_sub(1))).rev() {
            value = value << 8 | self.bytes[index] as u64;
        }
        let shift = start.max(0) as usize - first_byte * 8;
        let value = (value >> shift) as u32;
        let available = (end - start.max(0)) as u32;
        let value = if available >= 32 { value } else { value & ((1u32 << available) - 1) };
        // Bits missing below the start are zeros at the bottom.
        value << (count - available)
    }

    /// Reads `count` bits (at most 32); those beyond the start of the stream are zeros, and the
    /// reader then counts as overflowed (see [`ZstandardBitReader::overflowed`]).
    pub fn read(&mut self, count: u32) -> u32 {
        let value = self.peek(count);
        self.position = self.position.wrapping_sub(count as usize);
        value
    }

    /// Whether more bits were read than the stream holds.
    pub fn overflowed(&self) -> bool {
        self.position > self.bytes.len() * 8
    }

    /// Whether every bit was read, exactly.
    pub fn is_finished(&self) -> bool {
        self.position == 0
    }
}

/// A writer of the bitstreams of Zstandard, read backwards: bits are
/// appended least significant first; [`ZstandardBitWriter::finish`] adds
/// the 1 bit and the zero padding that end the stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZstandardBitWriter {
    bytes: Vec<u8>,
    accumulator: u64,
    count: u32,
}

impl ZstandardBitWriter {
    pub fn new() -> ZstandardBitWriter {
        ZstandardBitWriter::default()
    }

    /// Appends the low `count` bits (at most 32) of `value`.
    pub fn write(&mut self, value: u32, count: u32) {
        let mask = if count >= 32 { u32::MAX } else { (1u32 << count) - 1 };
        self.accumulator |= ((value & mask) as u64) << self.count;
        self.count += count;
        while self.count >= 8 {
            self.bytes.push(self.accumulator as u8);
            self.accumulator >>= 8;
            self.count -= 8;
        }
    }

    /// Ends the stream with a 1 bit and zeros to a byte, and returns its bytes.
    pub fn finish(mut self) -> Vec<u8> {
        self.write(1, 1);
        if self.count > 0 {
            self.bytes.push(self.accumulator as u8);
        }
        self.bytes
    }
}
