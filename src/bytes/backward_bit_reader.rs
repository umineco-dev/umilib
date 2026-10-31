/// A reader of backward bitstreams, the bitstreams of Finite State Entropy
/// and of Zstandard (RFC 8878 sections 4.1 and 4.2.2): the last byte ends
/// with a 1 bit followed by zero bits up to its most significant bit, and
/// the bits before it are read from the end of the slice towards its
/// start. A value of several bits is the bits below the position, the
/// first bit read the most significant ([`BackwardBitWriter`](super::BackwardBitWriter)
/// writes them).
///
/// Reads past the start of the stream give zero bits, as decoders of these
/// formats expect at the last symbols; the reader then counts as
/// [`BackwardBitReader::overflowed`] instead of failing, and its position
/// stays at the start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackwardBitReader<'a> {
    bytes: &'a [u8],
    /// The number of bits left to read (the position counted from the start).
    position: usize,
    /// Whether more bits were read than the stream holds.
    overflowed: bool,
}

impl<'a> BackwardBitReader<'a> {
    /// The most bits [`BackwardBitReader::peek`] and [`BackwardBitReader::read`] take at once.
    pub const MAXIMUM_BITS: u32 = 32;

    /// A reader of `bytes`; `None` if it is empty or its last byte is 0
    /// (it has no final 1 bit).
    pub fn new(bytes: &'a [u8]) -> Option<BackwardBitReader<'a>> {
        let last = *bytes.last()?;
        if last == 0 {
            return None;
        }
        let padding = last.leading_zeros() as usize + 1;
        Some(BackwardBitReader { bytes, position: bytes.len() * 8 - padding, overflowed: false })
    }

    /// The number of bits left.
    pub const fn remaining(&self) -> usize {
        self.position
    }

    /// The next `count` bits (at most [`BackwardBitReader::MAXIMUM_BITS`]),
    /// the missing ones below the start of the stream as zeros, without consuming them.
    pub fn peek(&self, count: u32) -> u32 {
        debug_assert!(count <= BackwardBitReader::MAXIMUM_BITS);
        let count = count.min(BackwardBitReader::MAXIMUM_BITS);
        if count == 0 {
            return 0;
        }
        let end = self.position;
        let start = end.saturating_sub(count as usize);
        let available = (end - start) as u32;
        if available == 0 {
            return 0;
        }
        // The bytes that hold the bits from start to end, little-endian (at most 5).
        let first_byte = start / 8;
        let last_byte = (end - 1) / 8;
        let mut value = 0u64;
        for byte in self.bytes[first_byte..=last_byte].iter().rev() {
            value = value << 8 | *byte as u64;
        }
        let value = (value >> (start - first_byte * 8)) & ((1u64 << available) - 1);
        // Bits missing below the start are zeros at the bottom.
        (value << (count - available)) as u32
    }

    /// Reads `count` bits (at most [`BackwardBitReader::MAXIMUM_BITS`]);
    /// those beyond the start of the stream are zeros, and the reader then
    /// counts as overflowed.
    pub fn read(&mut self, count: u32) -> u32 {
        let value = self.peek(count);
        match self.position.checked_sub(count as usize) {
            Some(position) => self.position = position,
            None => {
                self.position = 0;
                self.overflowed = true;
            }
        }
        value
    }

    /// Whether more bits were read than the stream holds.
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Whether every bit was read, exactly.
    pub const fn is_finished(&self) -> bool {
        self.position == 0 && !self.overflowed
    }
}
