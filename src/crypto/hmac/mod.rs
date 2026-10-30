//! HMAC, the keyed-hash message authentication code (RFC 2104, FIPS 198-1).

use core::fmt;

use crate::crypto::{MAC, PRF};
use crate::hash::CryptographicDigest;
use crate::secret::{ConstantTimeEq, Zeroize};

/// HMAC over the cryptographic hash function `H`.
///
/// The key, padded to the block size of `H` and xored with ipad and opad,
/// is absorbed once into an inner and an outer state; each message then
/// continues a copy of them.
#[derive(Clone)]
pub struct HMAC<H: CryptographicDigest + Default> {
    inner: H,
    /// The inner state after the key, to which `reset` returns.
    keyed_inner: H,
    keyed_outer: H,
}

impl<H: CryptographicDigest + Default> HMAC<H> {
    pub const INNER_PAD: u8 = 0x36;
    pub const OUTER_PAD: u8 = 0x5C;
    /// The shortest truncated tag [`HMAC::verify_truncated`] accepts: half of
    /// the output and at least 80 bits (RFC 2104 section 5).
    pub const MINIMUM_TRUNCATED_LENGTH: usize = {
        let half = H::OUTPUT_SIZE.div_ceil(2);
        if half > 10 { half } else { 10 }
    };

    /// HMAC with `key`; a key longer than the block size is hashed first.
    pub fn new(key: &[u8]) -> HMAC<H> {
        let (keyed_inner, keyed_outer) = if key.len() > H::BLOCK_SIZE {
            let mut hashed = H::digest(key);
            let states = (
                HMAC::<H>::keyed(hashed.as_ref(), HMAC::<H>::INNER_PAD),
                HMAC::<H>::keyed(hashed.as_ref(), HMAC::<H>::OUTER_PAD),
            );
            hashed.as_mut().zeroize();
            states
        } else {
            (HMAC::<H>::keyed(key, HMAC::<H>::INNER_PAD), HMAC::<H>::keyed(key, HMAC::<H>::OUTER_PAD))
        };
        HMAC { inner: keyed_inner.clone(), keyed_inner, keyed_outer }
    }

    /// `H` after the block of `key`, padded with zeros, xored with `pad`.
    pub fn keyed(key: &[u8], pad: u8) -> H {
        let mut hash = H::default();
        let mut piece = [0u8; 64];
        let mut position = 0;
        while position < H::BLOCK_SIZE {
            let length = piece.len().min(H::BLOCK_SIZE - position);
            for (index, byte) in piece[..length].iter_mut().enumerate() {
                *byte = key.get(position + index).copied().unwrap_or(0) ^ pad;
            }
            hash.update(&piece[..length]);
            position += length;
        }
        piece.zeroize();
        hash
    }

    /// The tag of `data` under `key`.
    pub fn mac(key: &[u8], data: &[u8]) -> H::Output {
        let mut hmac = HMAC::<H>::new(key);
        hmac.update(data);
        hmac.finalize()
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> H::Output {
        let mut inner = self.inner.clone().finalize();
        let mut outer = self.keyed_outer.clone();
        outer.update(inner.as_ref());
        inner.as_mut().zeroize();
        outer.finalize()
    }

    /// The tag of the input so far, after which the state returns to the key.
    pub fn finalize_reset(&mut self) -> H::Output {
        let tag = self.clone().finalize();
        self.reset();
        tag
    }

    /// Whether `tag` is the tag of the input, compared in constant time.
    pub fn verify(self, tag: &[u8]) -> bool {
        let mut expected = self.finalize();
        let valid = expected.as_ref().ct_eq(tag).into_bool();
        expected.as_mut().zeroize();
        valid
    }

    /// Whether `tag` is the leftmost bytes of the tag of the input, compared
    /// in constant time; a tag shorter than
    /// [`HMAC::MINIMUM_TRUNCATED_LENGTH`] or longer than the output never is.
    /// That minimum is the one of RFC 2104; protocols that truncate further
    /// (SP 800-107 allows 32 bits) compare a prefix of [`HMAC::finalize`]
    /// with [`ConstantTimeEq`] themselves.
    pub fn verify_truncated(self, tag: &[u8]) -> bool {
        let mut expected = self.finalize();
        let length = expected.as_ref().len();
        let valid = tag.len() >= HMAC::<H>::MINIMUM_TRUNCATED_LENGTH.min(length)
            && tag.len() <= length
            && expected.as_ref()[..tag.len()].ct_eq(tag).into_bool();
        expected.as_mut().zeroize();
        valid
    }

    /// Returns to the state after the key.
    pub fn reset(&mut self) {
        self.inner = self.keyed_inner.clone();
    }
}

impl<H: CryptographicDigest + Default> PRF for HMAC<H> {}

impl<H: CryptographicDigest + Default> MAC for HMAC<H> {
    const OUTPUT_SIZE: usize = H::OUTPUT_SIZE;
    type Output = H::Output;

    fn update(&mut self, data: &[u8]) {
        HMAC::update(self, data);
    }

    fn finalize(self) -> H::Output {
        HMAC::finalize(self)
    }

    fn reset(&mut self) {
        HMAC::reset(self);
    }

    fn verify(self, tag: &[u8]) -> bool {
        HMAC::verify(self, tag)
    }
}

impl<H: CryptographicDigest + Default> Zeroize for HMAC<H> {
    /// Erases the key and the message; the state is unusable afterwards,
    /// except to be dropped.
    fn zeroize(&mut self) {
        self.inner.zeroize();
        self.keyed_inner.zeroize();
        self.keyed_outer.zeroize();
    }
}

impl<H: CryptographicDigest + Default> fmt::Debug for HMAC<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HMAC(..)")
    }
}
