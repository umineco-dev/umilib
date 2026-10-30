use core::fmt;

use crate::secret::Zeroize;

/// GHASH (SP 800-38D section 6.4): the universal hash of GCM, multiplication
/// by H in GF(2^128) = GF(2)\[x\]/(x^128 + x^7 + x^2 + x + 1) with the bits of
/// each byte reflected.
///
/// The products are computed without tables or branches: a carry-less product
/// of 64-bit words is four integer multiplications of the words with every
/// fourth bit kept, whose carries cannot reach the bits that are kept, and
/// the 128-bit product is three of those (Karatsuba) on the words and on
/// their bit reversals, which give the high halves. Integer multiplication
/// takes time independent of its operands on the processors umilib targets.
#[derive(Clone)]
pub struct GHASH {
    /// H as two words (high, low), their bit reversals and the xors of the halves.
    h: [u64; 2],
    h_reversed: [u64; 2],
    /// The accumulated value Y as (high, low).
    y: [u64; 2],
    /// The bytes of a partial block.
    buffer: [u8; 16],
    buffered: usize,
}

impl GHASH {
    pub fn new(h: &[u8; 16]) -> GHASH {
        let high = u64::from_be_bytes(h[..8].try_into().expect("eight bytes"));
        let low = u64::from_be_bytes(h[8..].try_into().expect("eight bytes"));
        GHASH {
            h: [high, low],
            h_reversed: [high.reverse_bits(), low.reverse_bits()],
            y: [0; 2],
            buffer: [0; 16],
            buffered: 0,
        }
    }

    /// The low 64 bits of the carry-less product of `x` and `y`.
    pub fn multiply64(x: u64, y: u64) -> u64 {
        const M0: u64 = 0x1111_1111_1111_1111;
        const M1: u64 = 0x2222_2222_2222_2222;
        const M2: u64 = 0x4444_4444_4444_4444;
        const M3: u64 = 0x8888_8888_8888_8888;
        let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
        let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
        let z0 = x0.wrapping_mul(y0) ^ x1.wrapping_mul(y3) ^ x2.wrapping_mul(y2) ^ x3.wrapping_mul(y1);
        let z1 = x0.wrapping_mul(y1) ^ x1.wrapping_mul(y0) ^ x2.wrapping_mul(y3) ^ x3.wrapping_mul(y2);
        let z2 = x0.wrapping_mul(y2) ^ x1.wrapping_mul(y1) ^ x2.wrapping_mul(y0) ^ x3.wrapping_mul(y3);
        let z3 = x0.wrapping_mul(y3) ^ x1.wrapping_mul(y2) ^ x2.wrapping_mul(y1) ^ x3.wrapping_mul(y0);
        (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
    }

    /// Y = (Y ^ block) · H.
    pub fn absorb(&mut self, block: &[u8; 16]) {
        let y1 = self.y[0] ^ u64::from_be_bytes(block[..8].try_into().expect("eight bytes"));
        let y0 = self.y[1] ^ u64::from_be_bytes(block[8..].try_into().expect("eight bytes"));
        let (h1, h0) = (self.h[0], self.h[1]);
        let (h1r, h0r) = (self.h_reversed[0], self.h_reversed[1]);
        let (h2, h2r) = (h0 ^ h1, h0r ^ h1r);
        let (y0r, y1r) = (y0.reverse_bits(), y1.reverse_bits());
        let (y2, y2r) = (y0 ^ y1, y0r ^ y1r);
        let z0 = GHASH::multiply64(y0, h0);
        let z1 = GHASH::multiply64(y1, h1);
        let mut z2 = GHASH::multiply64(y2, h2);
        let mut z0h = GHASH::multiply64(y0r, h0r);
        let mut z1h = GHASH::multiply64(y1r, h1r);
        let mut z2h = GHASH::multiply64(y2r, h2r);
        z2 ^= z0 ^ z1;
        z2h ^= z0h ^ z1h;
        z0h = z0h.reverse_bits() >> 1;
        z1h = z1h.reverse_bits() >> 1;
        z2h = z2h.reverse_bits() >> 1;
        // The 256-bit product, shifted left by one for the reflected bit order.
        let (mut v0, mut v1, mut v2, mut v3) = (z0, z0h ^ z2, z1 ^ z2h, z1h);
        v3 = (v3 << 1) | (v2 >> 63);
        v2 = (v2 << 1) | (v1 >> 63);
        v1 = (v1 << 1) | (v0 >> 63);
        v0 <<= 1;
        // The reduction modulo x^128 + x^7 + x^2 + x + 1.
        v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
        v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
        v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
        v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
        self.y = [v3, v2];
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

    /// Completes a partial block with zeros, as GCM pads each of its inputs.
    pub fn pad(&mut self) {
        if self.buffered > 0 {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.absorb(&block);
            self.buffered = 0;
        }
    }

    /// The value Y after the input so far, padded.
    pub fn finalize(mut self) -> [u8; 16] {
        self.pad();
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.y[0].to_be_bytes());
        out[8..].copy_from_slice(&self.y[1].to_be_bytes());
        out
    }
}

impl Zeroize for GHASH {
    fn zeroize(&mut self) {
        self.h.zeroize();
        self.h_reversed.zeroize();
        self.y.zeroize();
        self.buffer.zeroize();
        self.buffered.zeroize();
    }
}

impl Drop for GHASH {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for GHASH {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GHASH(..)")
    }
}
