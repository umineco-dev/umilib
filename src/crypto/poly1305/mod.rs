//! Poly1305 (RFC 8439 section 2.5): the one-time authenticator of Bernstein.

use core::fmt;

use crate::crypto::{CryptoError, KeyInit, MAC};
use crate::secret::Zeroize;

/// Poly1305 with a 32-byte one-time key (r, s): the tag is
/// (Σ blocks · r^i mod 2^130 - 5) + s mod 2^128.
///
/// A key must authenticate one message only: two tags under one key reveal
/// it. The arithmetic uses three 44-bit limbs and the final reduction
/// selects with a mask, so the time depends only on the length of the message.
#[derive(Clone)]
pub struct Poly1305 {
    /// The clamped r in limbs of 44, 44 and 42 bits, and 20 × r1, 20 × r2 for the reduction.
    r: [u64; 3],
    r_times_20: [u64; 2],
    /// s, added at the end.
    s: [u64; 2],
    /// The accumulator in limbs of 44, 44 and 42 bits (partially reduced).
    h: [u64; 3],
    buffer: [u8; 16],
    buffered: usize,
}

impl Poly1305 {
    pub const KEY_SIZE: usize = 32;
    pub const TAG_SIZE: usize = 16;
    const MASK44: u64 = (1 << 44) - 1;
    const MASK42: u64 = (1 << 42) - 1;

    pub fn new(key: &[u8; 32]) -> Poly1305 {
        let t0 = u64::from_le_bytes(key[..8].try_into().expect("eight bytes"));
        let t1 = u64::from_le_bytes(key[8..16].try_into().expect("eight bytes"));
        // The clamping of r (section 2.5) together with the split into limbs.
        let r = [t0 & 0x0FFC_0FFF_FFFF, ((t0 >> 44) | (t1 << 20)) & 0x0FFF_FFC0_FFFF, (t1 >> 24) & 0x000F_FFFF_FC0F];
        let s = [
            u64::from_le_bytes(key[16..24].try_into().expect("eight bytes")),
            u64::from_le_bytes(key[24..].try_into().expect("eight bytes")),
        ];
        Poly1305 { r, r_times_20: [r[1] * 20, r[2] * 20], s, h: [0; 3], buffer: [0; 16], buffered: 0 }
    }

    /// h = (h + block + `high` · 2^128) · r mod 2^130 - 5, partially reduced;
    /// `high` is 1 for a whole block and 0 for the padded last one.
    pub fn absorb(&mut self, block: &[u8; 16], high: u64) {
        let t0 = u64::from_le_bytes(block[..8].try_into().expect("eight bytes"));
        let t1 = u64::from_le_bytes(block[8..].try_into().expect("eight bytes"));
        let h0 = self.h[0] + (t0 & Poly1305::MASK44);
        let h1 = self.h[1] + (((t0 >> 44) | (t1 << 20)) & Poly1305::MASK44);
        let h2 = self.h[2] + (((t1 >> 24) & Poly1305::MASK42) | (high << 40));
        let [r0, r1, r2] = self.r.map(|limb| limb as u128);
        let [s1, s2] = self.r_times_20.map(|limb| limb as u128);
        let (h0, h1, h2) = (h0 as u128, h1 as u128, h2 as u128);
        // 2^132 ≡ 20 modulo 2^130 - 5: the products above the third limb fold back multiplied by 20.
        let d0 = h0 * r0 + h1 * s2 + h2 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0;
        d1 += d0 >> 44;
        let mut h0 = (d0 as u64) & Poly1305::MASK44;
        d2 += d1 >> 44;
        let mut h1 = (d1 as u64) & Poly1305::MASK44;
        let carry = (d2 >> 42) as u64;
        let h2 = (d2 as u64) & Poly1305::MASK42;
        h0 += carry * 5;
        h1 += h0 >> 44;
        h0 &= Poly1305::MASK44;
        self.h = [h0, h1, h2];
    }

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
            self.absorb(&block, 1);
            self.buffered = 0;
        }
        let (blocks, rest) = data.as_chunks::<16>();
        for block in blocks {
            self.absorb(block, 1);
        }
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// Completes a partial block with zeros, as AEAD_CHACHA20_POLY1305 pads each of its inputs (section 2.8).
    pub fn pad(&mut self) {
        if self.buffered > 0 {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            self.absorb(&block, 1);
            self.buffered = 0;
        }
    }

    /// The tag: the last partial block with the bit 1 after it, the full reduction, then + s.
    pub fn finalize(mut self) -> [u8; 16] {
        if self.buffered > 0 {
            let mut block = [0u8; 16];
            block[..self.buffered].copy_from_slice(&self.buffer[..self.buffered]);
            block[self.buffered] = 1;
            self.absorb(&block, 0);
            block.zeroize();
        }
        let [mut h0, mut h1, mut h2] = self.h;
        // Carry fully: h < 2^130 + a little.
        h1 += h0 >> 44;
        h0 &= Poly1305::MASK44;
        h2 += h1 >> 44;
        h1 &= Poly1305::MASK44;
        h0 += (h2 >> 42) * 5;
        h2 &= Poly1305::MASK42;
        h1 += h0 >> 44;
        h0 &= Poly1305::MASK44;
        h2 += h1 >> 44;
        h1 &= Poly1305::MASK44;
        h0 += (h2 >> 42) * 5;
        h2 &= Poly1305::MASK42;
        h1 += h0 >> 44;
        h0 &= Poly1305::MASK44;
        // g = h + 5 - 2^130; h is replaced by g when g does not borrow (h ≥ p).
        let mut g0 = h0 + 5;
        let mut g1 = h1 + (g0 >> 44);
        g0 &= Poly1305::MASK44;
        let g2 = (h2 + (g1 >> 44)).wrapping_sub(1 << 42);
        g1 &= Poly1305::MASK44;
        let keep_h = 0u64.wrapping_sub(g2 >> 63);
        h0 = (h0 & keep_h) | (g0 & !keep_h);
        h1 = (h1 & keep_h) | (g1 & !keep_h);
        h2 = (h2 & keep_h) | (g2 & !keep_h & Poly1305::MASK42);
        // h + s mod 2^128, from the limbs to two 64-bit words.
        let low = (h0 | (h1 << 44)) as u128 | ((((h1 >> 20) | (h2 << 24)) as u128) << 64);
        let s = self.s[0] as u128 | ((self.s[1] as u128) << 64);
        let tag = low.wrapping_add(s).to_le_bytes();
        self.zeroize();
        tag
    }

    /// The tag of `data` under the one-time key `key`.
    pub fn mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
        let mut poly1305 = Poly1305::new(key);
        poly1305.update(data);
        poly1305.finalize()
    }
}

/// [`MAC::reset`] returns to the empty message under the same key, which
/// must still authenticate one message only.
impl MAC for Poly1305 {
    const OUTPUT_SIZE: usize = 16;
    type Output = [u8; 16];

    fn update(&mut self, data: &[u8]) {
        Poly1305::update(self, data);
    }

    fn finalize(self) -> [u8; 16] {
        Poly1305::finalize(self)
    }

    fn reset(&mut self) {
        self.h = [0; 3];
        self.buffer.zeroize();
        self.buffered = 0;
    }
}

impl KeyInit for Poly1305 {
    const MINIMUM_KEY_SIZE: usize = 32;
    const MAXIMUM_KEY_SIZE: usize = 32;

    fn new_from_slice(key: &[u8]) -> Result<Poly1305, CryptoError> {
        Poly1305::check_key_length(key.len())?;
        let key: &[u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidParameter)?;
        Ok(Poly1305::new(key))
    }
}

impl Zeroize for Poly1305 {
    fn zeroize(&mut self) {
        self.r.zeroize();
        self.r_times_20.zeroize();
        self.s.zeroize();
        self.h.zeroize();
        self.buffer.zeroize();
        self.buffered = 0;
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for Poly1305 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Poly1305(..)")
    }
}
