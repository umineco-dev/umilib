use alloc::vec::Vec;

/// A writer of backward bitstreams, the streams
/// [`BackwardBitReader`](super::BackwardBitReader) reads: values are
/// appended least significant bit first, in the reverse of the order they
/// will be read, and [`BackwardBitWriter::finish`] adds the 1 bit and the
/// zero bits that end the stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BackwardBitWriter {
    bytes: Vec<u8>,
    /// The bits of an unfinished byte, in the low `count` bits.
    accumulator: u64,
    count: u32,
}

impl BackwardBitWriter {
    /// The most bits [`BackwardBitWriter::write`] takes at once.
    pub const MAXIMUM_BITS: u32 = 32;

    pub const fn new() -> BackwardBitWriter {
        BackwardBitWriter { bytes: Vec::new(), accumulator: 0, count: 0 }
    }

    /// The number of bits written.
    pub fn bit_length(&self) -> usize {
        self.bytes.len() * 8 + self.count as usize
    }

    /// Appends the low `count` bits (at most [`BackwardBitWriter::MAXIMUM_BITS`])
    /// of `value`; the other bits of `value` are ignored.
    pub fn write(&mut self, value: u32, count: u32) {
        debug_assert!(count <= BackwardBitWriter::MAXIMUM_BITS);
        let count = count.min(BackwardBitWriter::MAXIMUM_BITS);
        let mask = (1u64 << count) - 1;
        self.accumulator |= (value as u64 & mask) << self.count;
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
