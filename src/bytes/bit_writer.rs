use alloc::vec::Vec;

use super::BitOrder;

/// Writes bits into a growing byte vector in a [`BitOrder`]: least
/// significant bit of each byte first by default, the order of
/// [`BitReader`](super::BitReader); most significant first for the formats
/// that [`BitQueue`](super::BitQueue) reads in that order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitWriter {
    bytes: Vec<u8>,
    /// The bits of an unfinished byte, in the low `count` bits: the first
    /// one bit 0 for [`BitOrder::LeastSignificantFirst`], bit `count - 1`
    /// for [`BitOrder::MostSignificantFirst`].
    accumulator: u64,
    count: u32,
    order: BitOrder,
}

impl BitWriter {
    /// The most bits [`BitWriter::write`] takes at once.
    pub const MAXIMUM_BITS: u32 = 56;

    /// A writer of [`BitOrder::LeastSignificantFirst`].
    pub const fn new() -> BitWriter {
        BitWriter::with_order(BitOrder::LeastSignificantFirst)
    }

    /// A writer of `order`.
    pub const fn with_order(order: BitOrder) -> BitWriter {
        BitWriter { bytes: Vec::new(), accumulator: 0, count: 0, order }
    }

    pub const fn order(&self) -> BitOrder {
        self.order
    }

    /// The number of bits written.
    pub fn bit_length(&self) -> usize {
        self.bytes.len() * 8 + self.count as usize
    }

    /// Appends the low `count` bits of `value` (at most
    /// [`BitWriter::MAXIMUM_BITS`]) in the writer's order: the least
    /// significant first, or the most significant of them first; the other
    /// bits of `value` are ignored.
    pub fn write(&mut self, value: u64, count: u32) {
        debug_assert!(count <= BitWriter::MAXIMUM_BITS);
        let count = count.min(BitWriter::MAXIMUM_BITS);
        let mask = (1u64 << count) - 1;
        match self.order {
            BitOrder::LeastSignificantFirst => {
                self.accumulator |= (value & mask) << self.count;
                self.count += count;
                while self.count >= 8 {
                    self.bytes.push(self.accumulator as u8);
                    self.accumulator >>= 8;
                    self.count -= 8;
                }
            }
            BitOrder::MostSignificantFirst => {
                self.accumulator = self.accumulator << count | (value & mask);
                self.count += count;
                while self.count >= 8 {
                    self.count -= 8;
                    self.bytes.push((self.accumulator >> self.count) as u8);
                }
                self.accumulator &= (1u64 << self.count) - 1;
            }
        }
    }

    /// Pads with zero bits to the start of the next byte.
    pub fn align(&mut self) {
        if self.count > 0 {
            self.write(0, 8 - self.count);
        }
    }

    /// Pads to a byte, then appends `bytes`.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.align();
        self.bytes.extend_from_slice(bytes);
    }

    /// The bytes completed so far; the bits of an unfinished byte stay in the writer.
    pub fn completed(&self) -> &[u8] {
        &self.bytes
    }

    /// Moves the completed bytes out, keeping the bits of an unfinished byte.
    pub fn take_completed(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }

    /// Drops the completed bytes, keeping the bits of an unfinished byte and
    /// the allocation (after the caller copied [`BitWriter::completed`]).
    pub fn clear_completed(&mut self) {
        self.bytes.clear();
    }

    /// Pads to a byte and returns all the bytes.
    pub fn finish(mut self) -> Vec<u8> {
        self.align();
        self.bytes
    }
}

impl Default for BitWriter {
    fn default() -> BitWriter {
        BitWriter::new()
    }
}
