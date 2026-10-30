//! CMAC (SP 800-38B, RFC 4493 for AES): the MAC of a block cipher.

use core::fmt;

use crate::crypto::{BlockCipher, CryptoError, KeyInit, MAC, PRF};
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// CMAC over the block cipher `C` with 64-bit or 128-bit blocks; the tag is a
/// whole block, which may be truncated by [`CMAC::verify_truncated`].
#[derive(Clone)]
pub struct CMAC<C: BlockCipher> {
    cipher: C,
    /// The subkeys K1 and K2 (section 6.1).
    k1: C::Block,
    k2: C::Block,
    /// The chaining value, and the last block, which is processed with a subkey when the message ends.
    state: C::Block,
    buffer: C::Block,
    buffered: usize,
}

impl<C: BlockCipher> CMAC<C> {
    pub fn new(cipher: C) -> CMAC<C> {
        let mut l = C::Block::default();
        cipher.encrypt_block(&mut l);
        let mut k1 = l;
        CMAC::<C>::double(&mut k1);
        let mut k2 = k1;
        CMAC::<C>::double(&mut k2);
        l.as_mut().zeroize();
        CMAC { cipher, k1, k2, state: C::Block::default(), buffer: C::Block::default(), buffered: 0 }
    }

    /// The constant R_b of the block size: x^4 + x^3 + x + 1 for 64 bits, x^7 + x^2 + x + 1 for 128.
    pub const fn constant() -> u8 {
        if C::BLOCK_SIZE == 8 { 0x1B } else { 0x87 }
    }

    /// Multiplication by x in GF(2^b), big-endian, in constant time.
    pub fn double(block: &mut C::Block) {
        let bytes = block.as_mut();
        let carry = bytes[0] >> 7;
        for index in 0..bytes.len() {
            let next = if index + 1 < bytes.len() { bytes[index + 1] >> 7 } else { 0 };
            bytes[index] = (bytes[index] << 1) | next;
        }
        let last = bytes.len() - 1;
        bytes[last] ^= u8::select(&0, &CMAC::<C>::constant(), Choice::from_bit(carry));
    }

    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            if self.buffered == C::BLOCK_SIZE {
                for (state, value) in self.state.as_mut().iter_mut().zip(self.buffer.as_ref()) {
                    *state ^= value;
                }
                self.cipher.encrypt_block(&mut self.state);
                self.buffered = 0;
            }
            self.buffer.as_mut()[self.buffered] = byte;
            self.buffered += 1;
        }
    }

    /// The tag of the message (section 6.2).
    pub fn finalize(self) -> C::Block {
        let complete = self.buffered == C::BLOCK_SIZE;
        let mut last = self.buffer;
        if !complete {
            last.as_mut()[self.buffered] = 0x80;
            last.as_mut()[self.buffered + 1..].fill(0);
        }
        let mut subkey = if complete { self.k1 } else { self.k2 };
        for ((byte, key), state) in last.as_mut().iter_mut().zip(subkey.as_ref()).zip(self.state.as_ref()) {
            *byte ^= key ^ state;
        }
        subkey.as_mut().zeroize();
        self.cipher.encrypt_block(&mut last);
        last
    }

    /// Whether `tag` is the leftmost bytes (at least 8, or the whole block if
    /// shorter) of the tag of the message, compared in constant time.
    pub fn verify_truncated(self, tag: &[u8]) -> bool {
        self.verify_truncated_with_minimum(tag, 8.min(C::BLOCK_SIZE))
    }

    /// Whether `tag` is the leftmost bytes, at least `minimum` (and one) of
    /// them, of the tag of the message. SP 800-38B appendix A.2 allows tags
    /// shorter than 64 bits only where the protocol limits the failed
    /// verifications per key.
    pub fn verify_truncated_with_minimum(self, tag: &[u8], minimum: usize) -> bool {
        let mut expected = self.finalize();
        let length = expected.as_ref().len();
        let valid =
            tag.len() >= minimum.max(1) && tag.len() <= length && expected.as_ref()[..tag.len()].ct_eq(tag).into_bool();
        expected.as_mut().zeroize();
        valid
    }

    /// The tag of `data` with `cipher`.
    pub fn mac(cipher: C, data: &[u8]) -> C::Block {
        let mut cmac = CMAC::new(cipher);
        cmac.update(data);
        cmac.finalize()
    }

    /// Returns to the empty message.
    pub fn reset(&mut self) {
        self.state.as_mut().zeroize();
        self.buffer.as_mut().zeroize();
        self.buffered = 0;
    }
}

impl<C: BlockCipher> PRF for CMAC<C> {}

impl<C: BlockCipher> MAC for CMAC<C> {
    const OUTPUT_SIZE: usize = C::BLOCK_SIZE;
    type Output = C::Block;

    fn update(&mut self, data: &[u8]) {
        CMAC::update(self, data);
    }

    fn finalize(self) -> C::Block {
        CMAC::finalize(self)
    }

    fn reset(&mut self) {
        CMAC::reset(self);
    }
}

impl<C: BlockCipher + KeyInit> KeyInit for CMAC<C> {
    const MINIMUM_KEY_SIZE: usize = C::MINIMUM_KEY_SIZE;
    const MAXIMUM_KEY_SIZE: usize = C::MAXIMUM_KEY_SIZE;

    fn new_from_slice(key: &[u8]) -> Result<CMAC<C>, CryptoError> {
        Ok(CMAC::new(C::new_from_slice(key)?))
    }
}

impl<C: BlockCipher> Zeroize for CMAC<C> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.k1.as_mut().zeroize();
        self.k2.as_mut().zeroize();
        self.reset();
    }
}

impl<C: BlockCipher> Drop for CMAC<C> {
    fn drop(&mut self) {
        self.k1.as_mut().zeroize();
        self.k2.as_mut().zeroize();
        self.reset();
    }
}

impl<C: BlockCipher> fmt::Debug for CMAC<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CMAC(..)")
    }
}
