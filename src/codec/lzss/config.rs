use crate::codec::CompressionError;

/// The parameters of the LZSS format of Haruhiko Okumura ([`LZSSFormat`](super::LZSSFormat)),
/// which a stream does not record: its compressor and its decompressor must
/// use the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LZSSConfig {
    /// EI, the bits of a position: the ring buffer has N = 2^EI bytes (2 to 24).
    pub position_bits: u32,
    /// EJ, the bits of a length: matches have 2 to 2^EJ + 1 bytes (1 to 8,
    /// less than EI). EI + EJ must be at least 7, so that the padding of the
    /// last byte (at most 7 zero bits) cannot be read as a match.
    pub length_bits: u32,
}

impl LZSSConfig {
    /// Checks the ranges of the parameters.
    pub fn check(&self) -> Result<(), CompressionError> {
        let valid = (2..=24).contains(&self.position_bits)
            && (1..=8).contains(&self.length_bits)
            && self.length_bits < self.position_bits
            && self.position_bits + self.length_bits >= 7;
        if valid { Ok(()) } else { Err(CompressionError::InvalidParameter) }
    }

    /// N, the size of the ring buffer.
    pub fn ring_size(&self) -> usize {
        1 << self.position_bits
    }

    /// F, the longest match.
    pub fn maximum_length(&self) -> usize {
        (1 << self.length_bits) + 1
    }

    /// The history before the first byte, oldest first: F zeros, then N - F
    /// spaces (the ring buffer as the reference initializes it, ending
    /// before the position N - F where the first byte goes).
    pub fn dictionary(&self) -> alloc::vec::Vec<u8> {
        let mut dictionary = alloc::vec![0u8; self.ring_size()];
        dictionary[self.maximum_length()..].fill(b' ');
        dictionary
    }
}

impl Default for LZSSConfig {
    /// The parameters of the reference: EI = 11, EJ = 4.
    fn default() -> LZSSConfig {
        LZSSConfig { position_bits: 11, length_bits: 4 }
    }
}
