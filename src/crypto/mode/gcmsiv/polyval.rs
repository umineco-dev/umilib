use core::fmt;

use crate::crypto::mode::gcm::GHASH;
use crate::secret::{Choice, ConditionallySelectable, Zeroize};

/// POLYVAL (RFC 8452 section 3): S_j = dot(S_{j-1} + X_j, H) in
/// GF(2^128) = GF(2)\[x\]/(x^128 + x^127 + x^126 + x^121 + 1) with the
/// little-endian bit order, where dot(a, b) = a · b · x^-128.
///
/// It is computed with [`GHASH`] by the relation of appendix A:
/// POLYVAL(H, X_1, ...) = ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)),
/// ByteReverse(X_1), ...)), so it is as constant-time as GHASH.
#[derive(Clone)]
pub struct POLYVAL {
    ghash: GHASH,
    /// The bytes of a partial block.
    buffer: [u8; 16],
    buffered: usize,
}

impl POLYVAL {
    pub fn new(h: &[u8; 16]) -> POLYVAL {
        let mut key = *h;
        key.reverse();
        POLYVAL::multiply_x_ghash(&mut key);
        let ghash = GHASH::new(&key);
        key.zeroize();
        POLYVAL { ghash, buffer: [0; 16], buffered: 0 }
    }

    /// mulX_GHASH: multiplication by x in the field and bit order of GHASH, in constant time.
    pub fn multiply_x_ghash(block: &mut [u8; 16]) {
        let carry = block[15] & 1;
        for index in (1..16).rev() {
            block[index] = (block[index] >> 1) | (block[index - 1] << 7);
        }
        block[0] >>= 1;
        block[0] ^= u8::select(&0, &0xE1, Choice::from_bit(carry));
    }

    /// S = dot(S + block, H).
    pub fn absorb(&mut self, block: &[u8; 16]) {
        let mut reversed = *block;
        reversed.reverse();
        self.ghash.absorb(&reversed);
        reversed.zeroize();
    }

    /// Adds `data` to the input, in blocks; a partial block waits for more data.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buffered > 0 {
            let take = (16 - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 16 {
                return;
            }
            let block = self.buffer;
            self.absorb(&block);
            self.buffered = 0;
        }
        let (blocks, rest) = data.as_chunks::<16>();
        for block in blocks {
            self.absorb(block);
        }
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// Completes a partial block with zeros, as GCM-SIV pads each of its inputs.
    pub fn pad(&mut self) {
        if self.buffered > 0 {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.absorb(&block);
            self.buffered = 0;
        }
    }

    /// The value S after the input so far, padded.
    pub fn finalize(mut self) -> [u8; 16] {
        self.pad();
        let mut out = self.ghash.clone().finalize();
        out.reverse();
        out
    }
}

impl Zeroize for POLYVAL {
    fn zeroize(&mut self) {
        self.ghash.zeroize();
        self.buffer.zeroize();
        self.buffered.zeroize();
    }
}

impl Drop for POLYVAL {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

impl fmt::Debug for POLYVAL {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("POLYVAL(..)")
    }
}
