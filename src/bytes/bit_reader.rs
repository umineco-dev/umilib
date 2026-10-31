/// A cursor that reads bits from a borrowed byte slice, least significant
/// bit of each byte first, as Deflate (RFC 1951 section 3.1.1) and Brotli
/// (RFC 7932 section 1.5.1) pack them. A value of several bits is read with
/// its least significant bit first.
///
/// The position counts bits; a read either takes all its bits or fails
/// without moving the cursor, so a decoder can retry a step with more input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BitReader<'a> {
    /// The most bits [`BitReader::peek`] and [`BitReader::read`] take at once.
    pub const MAXIMUM_BITS: u32 = 56;

    /// A reader at the first bit of `bytes`.
    pub const fn new(bytes: &'a [u8]) -> BitReader<'a> {
        BitReader { bytes, position: 0 }
    }

    /// A reader at the bit `position` of `bytes` (at most its length in bits).
    pub fn at(bytes: &'a [u8], position: usize) -> BitReader<'a> {
        BitReader { bytes, position: position.min(bytes.len() * 8) }
    }

    /// The number of bits already read.
    pub const fn position(&self) -> usize {
        self.position
    }

    /// The number of bits left.
    pub const fn remaining(&self) -> usize {
        self.bytes.len() * 8 - self.position
    }

    /// Whether the position is at the start of a byte.
    pub fn is_aligned(&self) -> bool {
        self.position.is_multiple_of(8)
    }

    /// The next `count` bits (at most [`BitReader::MAXIMUM_BITS`]), the
    /// missing ones past the end as zeros, without consuming them.
    pub fn peek_padded(&self, count: u32) -> u64 {
        let (first, shift) = (self.position / 8, (self.position % 8) as u32);
        let mut word = 0u64;
        for (index, byte) in self.bytes[first.min(self.bytes.len())..].iter().take(8).enumerate() {
            word |= (*byte as u64) << (8 * index);
        }
        let mask = if count >= 64 { u64::MAX } else { (1u64 << count) - 1 };
        (word >> shift) & mask
    }

    /// The next `count` bits (at most [`BitReader::MAXIMUM_BITS`]) without
    /// consuming them; `None` if fewer remain.
    pub fn peek(&self, count: u32) -> Option<u64> {
        if count as usize > self.remaining() || count > BitReader::MAXIMUM_BITS {
            return None;
        }
        Some(self.peek_padded(count))
    }

    /// Consumes and returns the next `count` bits; `None` (consuming nothing) if fewer remain.
    pub fn read(&mut self, count: u32) -> Option<u64> {
        let value = self.peek(count)?;
        self.position += count as usize;
        Some(value)
    }

    /// Consumes `count` bits; false (consuming nothing) if fewer remain.
    pub fn skip(&mut self, count: usize) -> bool {
        if count > self.remaining() {
            return false;
        }
        self.position += count;
        true
    }

    /// Skips to the start of the next byte unless at the start of one,
    /// returning the bits skipped.
    pub fn align(&mut self) -> u64 {
        let count = ((8 - self.position % 8) % 8) as u32;
        // The bits up to the end of the current byte are present.
        self.read(count).unwrap_or(0)
    }

    /// The next `length` whole bytes, from a position at the start of a
    /// byte; `None` (consuming nothing) if unaligned or fewer remain.
    pub fn read_bytes(&mut self, length: usize) -> Option<&'a [u8]> {
        // Divided, not multiplied: `length * 8` overflows a 32-bit usize.
        if !self.is_aligned() || length > self.remaining() / 8 {
            return None;
        }
        let start = self.position / 8;
        self.position += length * 8;
        Some(&self.bytes[start..start + length])
    }
}
