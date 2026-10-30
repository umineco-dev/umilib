use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::ASN1Error;

/// The value of a BIT STRING: octets whose last `unused_bits` low bits are
/// not part of the string (X.690 section 8.6), borrowed from the input when
/// possible (a BER string made of segments is joined into an owned copy).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BitString<'a> {
    unused_bits: u8,
    bytes: Cow<'a, [u8]>,
}

impl<'a> BitString<'a> {
    /// Creates a bit string; `unused_bits` is 0 to 7, and 0 when `bytes` is empty.
    pub fn new(unused_bits: u8, bytes: impl Into<Cow<'a, [u8]>>) -> Result<BitString<'a>, ASN1Error> {
        let bytes = bytes.into();
        if unused_bits > 7 || (bytes.is_empty() && unused_bits != 0) {
            return Err(ASN1Error::InvalidContent { position: 0 });
        }
        Ok(BitString { unused_bits, bytes })
    }

    /// The same bits with the unused bits set to zero, as DER requires.
    pub fn with_zero_padding(self) -> BitString<'a> {
        if self.has_zero_padding() {
            return self;
        }
        let mut bytes = self.bytes.into_owned();
        if let Some(last) = bytes.last_mut() {
            *last &= !((1u8 << self.unused_bits) - 1);
        }
        BitString { unused_bits: self.unused_bits, bytes: Cow::Owned(bytes) }
    }

    /// Reads the contents octets of a primitive BIT STRING.
    pub fn decode_content(content: &'a [u8]) -> Result<BitString<'a>, ASN1Error> {
        let (&unused_bits, bytes) = content.split_first().ok_or(ASN1Error::InvalidContent { position: 0 })?;
        BitString::new(unused_bits, bytes)
    }

    pub fn unused_bits(&self) -> u8 {
        self.unused_bits
    }

    /// The octets, including the unused bits of the last one.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The octets of a bit string with no unused bits (keys and signatures).
    pub fn as_octets(&self) -> Option<&[u8]> {
        if self.unused_bits == 0 { Some(&self.bytes) } else { None }
    }

    /// The number of bits.
    pub fn bit_length(&self) -> usize {
        self.bytes.len() * 8 - self.unused_bits as usize
    }

    /// Bit `index`, counted from the most significant bit of the first octet
    /// (bit 0 of a named bit list); `false` beyond the end.
    pub fn bit(&self, index: usize) -> bool {
        index < self.bit_length() && self.bytes[index / 8] & (0x80 >> (index % 8)) != 0
    }

    /// Whether the unused bits are zero, as DER requires (X.690 section 11.2.1).
    pub fn has_zero_padding(&self) -> bool {
        self.bytes.last().is_none_or(|&last| last & ((1u8 << self.unused_bits) - 1) == 0)
    }

    /// The bit string of a named bit list (X.690 section 8.6.2) with the
    /// named bits of `bits` set, bit `n` of the list being bit `1 << n`,
    /// without trailing zero bits, as DER requires (section 11.2.2).
    pub fn from_named_bits(bits: u64) -> BitString<'static> {
        let length = (u64::BITS - bits.leading_zeros()) as usize;
        let mut bytes = alloc::vec![0u8; length.div_ceil(8)];
        (0..length).filter(|index| bits & (1 << index) != 0).for_each(|index| bytes[index / 8] |= 0x80 >> (index % 8));
        BitString { unused_bits: (bytes.len() * 8 - length) as u8, bytes: Cow::Owned(bytes) }
    }

    /// The named bits of a named bit list, bit `n` of the list being bit
    /// `1 << n` of the result (the inverse of [`BitString::from_named_bits`]).
    /// Trailing zero bits are accepted; fails with `OutOfRange` if a bit
    /// beyond 63 is set.
    pub fn named_bits(&self) -> Result<u64, ASN1Error> {
        let mut bits = 0u64;
        for index in (0..self.bit_length()).filter(|&index| self.bit(index)) {
            if index >= u64::BITS as usize {
                return Err(ASN1Error::OutOfRange);
            }
            bits |= 1 << index;
        }
        Ok(bits)
    }

    /// A copy that owns its octets.
    pub fn into_owned(self) -> BitString<'static> {
        BitString { unused_bits: self.unused_bits, bytes: Cow::Owned(self.bytes.into_owned()) }
    }

    /// Appends the contents octets.
    pub fn encode_content(&self, output: &mut Vec<u8>) {
        output.push(self.unused_bits);
        output.extend_from_slice(&self.bytes);
    }
}
