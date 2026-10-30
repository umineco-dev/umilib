use alloc::vec::Vec;

use super::LZMAModel;

/// The range encoder of LZMA (the reverse of [`LZMARangeDecoder`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZMARangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    /// The bytes written.
    pub out: Vec<u8>,
}

impl LZMARangeEncoder {
    pub const TOP: u32 = 1 << 24;

    pub fn new() -> LZMARangeEncoder {
        LZMARangeEncoder { low: 0, range: u32::MAX, cache: 0, cache_size: 1, out: Vec::new() }
    }

    /// The bytes the encoder would have written after a flush now: those
    /// written, those cached, and the 4 of `low`.
    pub fn pending_size(&self) -> u64 {
        self.out.len() as u64 + self.cache_size + 4
    }

    /// Writes the top byte of `low`, propagating a carry through the cached bytes.
    pub fn shift_low(&mut self) {
        if (self.low as u32) < 0xFF00_0000 || self.low >> 32 != 0 {
            let carry = (self.low >> 32) as u8;
            let mut byte = self.cache;
            loop {
                self.out.push(byte.wrapping_add(carry));
                byte = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = (self.low >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00FF_FFFF) << 8;
    }

    /// Encodes `bit` with the probability at `index` of `probabilities`, updating it.
    pub fn encode_bit(&mut self, probabilities: &mut [u16], index: usize, bit: u32) {
        let probability = probabilities[index] as u32;
        let bound = (self.range >> LZMAModel::PROBABILITY_BITS) * probability;
        if bit == 0 {
            self.range = bound;
            probabilities[index] =
                (probability + (((1 << LZMAModel::PROBABILITY_BITS) - probability) >> LZMAModel::MOVE_BITS)) as u16;
        } else {
            self.low += bound as u64;
            self.range -= bound;
            probabilities[index] = (probability - (probability >> LZMAModel::MOVE_BITS)) as u16;
        }
        while self.range < LZMARangeEncoder::TOP {
            self.range <<= 8;
            self.shift_low();
        }
    }

    /// Encodes the low `count` bits of `value`, most significant first, with even chances.
    pub fn encode_direct_bits(&mut self, value: u32, count: u32) {
        for bit in (0..count).rev() {
            self.range >>= 1;
            if (value >> bit) & 1 == 1 {
                self.low += self.range as u64;
            }
            while self.range < LZMARangeEncoder::TOP {
                self.range <<= 8;
                self.shift_low();
            }
        }
    }

    /// Encodes the `bits` low bits of `value` with the tree at `offset`, most significant first.
    pub fn encode_tree(&mut self, probabilities: &mut [u16], offset: usize, bits: u32, value: u32) {
        let mut node = 1usize;
        for bit in (0..bits).rev() {
            let bit = (value >> bit) & 1;
            self.encode_bit(probabilities, offset + node, bit);
            node = node << 1 | bit as usize;
        }
    }

    /// Encodes the `bits` low bits of `value` with the tree at `offset`, least significant first.
    pub fn encode_reverse_tree(&mut self, probabilities: &mut [u16], offset: usize, bits: u32, value: u32) {
        let mut node = 1usize;
        for bit in 0..bits {
            let bit = (value >> bit) & 1;
            self.encode_bit(probabilities, offset + node, bit);
            node = node << 1 | bit as usize;
        }
    }

    /// Writes the rest of the code: afterwards the decoder has read every bit.
    pub fn flush(&mut self) {
        for _ in 0..5 {
            self.shift_low();
        }
    }

    /// Takes the bytes written so far.
    pub fn take(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out)
    }
}

impl Default for LZMARangeEncoder {
    fn default() -> LZMARangeEncoder {
        LZMARangeEncoder::new()
    }
}

/// The range decoder of LZMA, reading from a slice: a read past its end
/// gives `None`, so that a caller can undo the symbol and wait for more
/// input. The probabilities it changes are logged in `undo` (index, old value).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZMARangeDecoder {
    pub range: u32,
    pub code: u32,
}

impl LZMARangeDecoder {
    /// The decoder after the 5 bytes of `start`; `None` if the first is not 0.
    pub fn new(start: [u8; 5]) -> Option<LZMARangeDecoder> {
        if start[0] != 0 {
            return None;
        }
        Some(LZMARangeDecoder { range: u32::MAX, code: u32::from_be_bytes([start[1], start[2], start[3], start[4]]) })
    }

    /// Whether the code is 0, as after the last bit of a well-formed stream.
    pub fn is_finished(&self) -> bool {
        self.code == 0
    }

    /// Takes a byte of `input` while the range is below 2^24; `None` without one.
    pub fn normalize(&mut self, input: &[u8], position: &mut usize) -> Option<()> {
        if self.range < LZMARangeEncoder::TOP {
            let byte = *input.get(*position)?;
            *position += 1;
            self.range <<= 8;
            self.code = self.code << 8 | byte as u32;
        }
        Some(())
    }

    /// Decodes a bit with the probability at `index`, updating it (and logging the old value).
    pub fn decode_bit(
        &mut self,
        probabilities: &mut [u16],
        index: usize,
        undo: &mut Vec<(u32, u16)>,
        input: &[u8],
        position: &mut usize,
    ) -> Option<u32> {
        let probability = probabilities[index] as u32;
        undo.push((index as u32, probability as u16));
        let bound = (self.range >> LZMAModel::PROBABILITY_BITS) * probability;
        let bit = if self.code < bound {
            self.range = bound;
            probabilities[index] =
                (probability + (((1 << LZMAModel::PROBABILITY_BITS) - probability) >> LZMAModel::MOVE_BITS)) as u16;
            0
        } else {
            self.code -= bound;
            self.range -= bound;
            probabilities[index] = (probability - (probability >> LZMAModel::MOVE_BITS)) as u16;
            1
        };
        self.normalize(input, position)?;
        Some(bit)
    }

    /// Decodes `count` bits of even chances, most significant first.
    pub fn decode_direct_bits(&mut self, count: u32, input: &[u8], position: &mut usize) -> Option<u32> {
        let mut value = 0u32;
        for _ in 0..count {
            self.range >>= 1;
            let bit = (self.code >= self.range) as u32;
            if bit == 1 {
                self.code -= self.range;
            }
            self.normalize(input, position)?;
            value = value << 1 | bit;
        }
        Some(value)
    }

    /// Decodes `bits` bits with the tree at `offset`, most significant first.
    pub fn decode_tree(
        &mut self,
        probabilities: &mut [u16],
        offset: usize,
        bits: u32,
        undo: &mut Vec<(u32, u16)>,
        input: &[u8],
        position: &mut usize,
    ) -> Option<u32> {
        let mut node = 1usize;
        for _ in 0..bits {
            node = node << 1 | self.decode_bit(probabilities, offset + node, undo, input, position)? as usize;
        }
        Some(node as u32 - (1 << bits))
    }

    /// Decodes `bits` bits with the tree at `offset`, least significant first.
    pub fn decode_reverse_tree(
        &mut self,
        probabilities: &mut [u16],
        offset: usize,
        bits: u32,
        undo: &mut Vec<(u32, u16)>,
        input: &[u8],
        position: &mut usize,
    ) -> Option<u32> {
        let (mut node, mut value) = (1usize, 0u32);
        for bit in 0..bits {
            let decoded = self.decode_bit(probabilities, offset + node, undo, input, position)?;
            node = node << 1 | decoded as usize;
            value |= decoded << bit;
        }
        Some(value)
    }
}
