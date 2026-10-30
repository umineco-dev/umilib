//! The output feedback mode (SP 800-38A section 6.4).

use core::fmt;

use crate::crypto::{BlockCipher, CryptoError, StreamCipher};
use crate::secret::Zeroize;

/// OFB over the block cipher `C`: the key stream is the cipher applied
/// repeatedly to the IV, so encryption and decryption are the same.
#[derive(Clone)]
pub struct OFB<C: BlockCipher> {
    cipher: C,
    output: C::Block,
    position: usize,
}

impl<C: BlockCipher> OFB<C> {
    pub fn new(cipher: C, iv: &C::Block) -> OFB<C> {
        OFB { cipher, output: *iv, position: C::BLOCK_SIZE }
    }

    /// Xors the next bytes of the key stream into `data`.
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.position == C::BLOCK_SIZE {
                self.cipher.encrypt_block(&mut self.output);
                self.position = 0;
            }
            *byte ^= self.output.as_ref()[self.position];
            self.position += 1;
        }
    }
}

impl<C: BlockCipher> StreamCipher for OFB<C> {
    fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        self.apply(data);
        Ok(())
    }
}

impl<C: BlockCipher> Zeroize for OFB<C> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.output.as_mut().zeroize();
    }
}

impl<C: BlockCipher> Drop for OFB<C> {
    fn drop(&mut self) {
        self.output.as_mut().zeroize();
    }
}

impl<C: BlockCipher> fmt::Debug for OFB<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OFB(..)")
    }
}
