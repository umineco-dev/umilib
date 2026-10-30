use core::fmt;

use super::LatticeError;

/// Packs and unpacks integers of `bits` bits into bytes, least significant
/// bits first, as the bit arrays of FIPS 203 (BitsToBytes) and FIPS 204
/// (IntegerToBits) order them; it carries its bit position between calls.
/// The bytes it touches depend on the position alone, not on the values.
pub struct LatticePacking {
    bits: u32,
    position: usize,
}

impl LatticePacking {
    /// A packing of integers of `bits` bits from bit 0; fails with
    /// `InvalidBits` unless `bits` is 1 to 32.
    pub fn new(bits: u32) -> Result<LatticePacking, LatticeError> {
        if !(1..=32).contains(&bits) {
            return Err(LatticeError::InvalidBits { bits });
        }
        Ok(LatticePacking { bits, position: 0 })
    }

    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// The bit position of the next integer.
    pub fn position(&self) -> usize {
        self.position
    }

    /// The bytes of `count` integers of `bits` bits.
    pub fn length(bits: u32, count: usize) -> usize {
        (bits as usize * count).div_ceil(8)
    }

    /// Writes the low `bits` bits of each of `values` into `out` from the
    /// position, keeping the other bits of `out`; `out` must hold them.
    pub fn write(&mut self, values: &[u32], out: &mut [u8]) {
        let mask = u64::MAX >> (64 - self.bits);
        for value in values {
            let (first, shift) = (self.position / 8, (self.position % 8) as u32);
            let bits = (*value as u64 & mask) << shift;
            let field = mask << shift;
            for (index, byte) in out[first..].iter_mut().take((shift + self.bits).div_ceil(8) as usize).enumerate() {
                let (byte_bits, byte_field) = ((bits >> (8 * index)) as u8, (field >> (8 * index)) as u8);
                *byte = (*byte & !byte_field) | byte_bits;
            }
            self.position += self.bits as usize;
        }
    }

    /// Reads `values.len()` integers of `bits` bits from `bytes` from the
    /// position; `bytes` must hold them.
    pub fn read(&mut self, bytes: &[u8], values: &mut [u32]) {
        let mask = u64::MAX >> (64 - self.bits);
        for value in values.iter_mut() {
            let (first, shift) = (self.position / 8, (self.position % 8) as u32);
            let mut word = 0u64;
            for (index, byte) in bytes[first..].iter().take((shift + self.bits).div_ceil(8) as usize).enumerate() {
                word |= (*byte as u64) << (8 * index);
            }
            *value = ((word >> shift) & mask) as u32;
            self.position += self.bits as usize;
        }
    }
}

impl fmt::Debug for LatticePacking {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "LatticePacking({} bits at {})", self.bits, self.position)
    }
}
