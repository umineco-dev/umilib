use crate::codec::CompressionError;

/// The model properties of LZMA: lc, the bits of the previous byte in the
/// context of a literal (0 to 8); lp, the low bits of the position in it
/// (0 to 4); pb, the low bits of the position in the context of matches
/// (0 to 4). LZMA2 also requires lc + lp <= 4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZMAProperties {
    pub literal_context_bits: u32,
    pub literal_position_bits: u32,
    pub position_bits: u32,
}

impl LZMAProperties {
    /// The byte (pb × 5 + lp) × 9 + lc; fails with `InvalidData` from 225 on.
    pub fn from_byte(byte: u8) -> Result<LZMAProperties, CompressionError> {
        if byte >= 9 * 5 * 5 {
            return Err(CompressionError::InvalidData { reason: "invalid properties" });
        }
        let byte = byte as u32;
        Ok(LZMAProperties {
            literal_context_bits: byte % 9,
            literal_position_bits: byte / 9 % 5,
            position_bits: byte / 45,
        })
    }

    pub fn to_byte(&self) -> u8 {
        ((self.position_bits * 5 + self.literal_position_bits) * 9 + self.literal_context_bits) as u8
    }

    /// Checks the ranges (and lc + lp <= 4 if `lzma2`).
    pub fn check(&self, lzma2: bool) -> Result<(), CompressionError> {
        let valid = self.literal_context_bits <= 8
            && self.literal_position_bits <= 4
            && self.position_bits <= 4
            && (!lzma2 || self.literal_context_bits + self.literal_position_bits <= 4);
        if valid { Ok(()) } else { Err(CompressionError::InvalidParameter) }
    }
}

impl Default for LZMAProperties {
    /// lc = 3, lp = 0, pb = 2.
    fn default() -> LZMAProperties {
        LZMAProperties { literal_context_bits: 3, literal_position_bits: 0, position_bits: 2 }
    }
}
