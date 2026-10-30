use super::BrotliFormat;
use crate::codec::CompressionError;

/// The distance coding of a stream (RFC 7932 section 4): the ring of the
/// last four distances (kept across meta-blocks) and the NPOSTFIX and
/// NDIRECT parameters of the current meta-block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrotliDistances {
    /// The last distances, the last one first.
    pub last: [u32; 4],
    pub postfix: u32,
    pub direct: u32,
}

impl BrotliDistances {
    /// The most postfix bits and direct distance codes.
    pub const MAXIMUM_POSTFIX: u32 = 3;
    pub const MAXIMUM_DIRECT: u32 = 120;

    /// The ring at the start of a stream, with no postfix bits and direct codes.
    pub const fn new() -> BrotliDistances {
        BrotliDistances { last: BrotliFormat::INITIAL_DISTANCES, postfix: 0, direct: 0 }
    }

    /// The size of the distance alphabet: 16 + NDIRECT + (48 << NPOSTFIX).
    pub fn alphabet_size(&self) -> usize {
        16 + self.direct as usize + (48 << self.postfix)
    }

    /// The extra bits after the distance code `code`.
    pub fn extra_bits(&self, code: u16) -> u32 {
        let code = code as u32;
        if code < 16 + self.direct { 0 } else { 1 + ((code - self.direct - 16) >> (self.postfix + 1)) }
    }

    /// The distance of the distance code `code` and its extra bits `extra`;
    /// fails with `InvalidData` for a short code that resolves to 0 or less.
    pub fn decode(&self, code: u16, extra: u32) -> Result<u32, CompressionError> {
        let code = code as u32;
        if code < 16 {
            // 0 to 3: a last distance; 4 to 9: the last one ± 1 to 3; 10 to 15: the second to last ± 1 to 3.
            let (base, delta) = match code {
                0..=3 => (self.last[code as usize], 0i64),
                _ => {
                    let delta = ((code - 4) % 6 / 2 + 1) as i64;
                    let base = self.last[if code < 10 { 0 } else { 1 }];
                    (base, if code.is_multiple_of(2) { -delta } else { delta })
                }
            };
            let distance = base as i64 + delta;
            if distance <= 0 {
                return Err(CompressionError::InvalidData { reason: "distance of a short code not positive" });
            }
            return Ok(distance as u32);
        }
        if code < 16 + self.direct {
            return Ok(code - 15);
        }
        let x = code - self.direct - 16;
        let bits = 1 + (x >> (self.postfix + 1));
        let high = (x >> self.postfix) & 1;
        let low = x & ((1 << self.postfix) - 1);
        let offset = ((2 + high) << bits) - 4;
        Ok(((offset + extra) << self.postfix) + low + self.direct + 1)
    }

    /// The distance code of `distance` (a short code if one gives it, the
    /// first of them), its extra bits and their number.
    pub fn encode(&self, distance: u32) -> (u16, u32, u32) {
        if let Some(code) = (0..16u16).find(|code| self.decode(*code, 0) == Ok(distance)) {
            return (code, 0, 0);
        }
        if distance <= self.direct {
            return (15 + distance as u16, 0, 0);
        }
        let value = distance - self.direct - 1;
        let low = value & ((1 << self.postfix) - 1);
        let rest = (value >> self.postfix) + 4;
        let bits = u32::BITS - 1 - rest.leading_zeros() - 1;
        let high = (rest >> bits) - 2;
        let x = ((((bits - 1) << 1) | high) << self.postfix) | low;
        ((16 + self.direct + x) as u16, rest - ((2 + high) << bits), bits)
    }

    /// Makes `distance` the last distance (after a code other than 0 that is not a dictionary word).
    pub fn push(&mut self, distance: u32) {
        self.last = [distance, self.last[0], self.last[1], self.last[2]];
    }
}

impl Default for BrotliDistances {
    fn default() -> BrotliDistances {
        BrotliDistances::new()
    }
}
