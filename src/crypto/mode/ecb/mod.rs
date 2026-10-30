//! The electronic codebook mode (SP 800-38A section 6.1): every block is
//! encrypted on its own, so equal blocks give equal ciphertexts. Use it only
//! where a protocol requires it.

use core::fmt;

use crate::crypto::mode::Blocks;
use crate::crypto::{BlockCipher, CryptoError};

/// ECB over the block cipher `C`.
#[derive(Clone)]
pub struct ECB<C: BlockCipher> {
    cipher: C,
}

impl<C: BlockCipher> ECB<C> {
    pub fn new(cipher: C) -> ECB<C> {
        ECB { cipher }
    }

    pub fn cipher(&self) -> &C {
        &self.cipher
    }

    /// Encrypts `data`, a whole number of blocks, in place.
    pub fn encrypt(&self, data: &mut [u8]) -> Result<(), CryptoError> {
        ECB::<C>::check(data)?;
        Blocks::apply::<C>(data, |blocks| self.cipher.encrypt_blocks(blocks));
        Ok(())
    }

    /// Decrypts `data`, a whole number of blocks, in place.
    pub fn decrypt(&self, data: &mut [u8]) -> Result<(), CryptoError> {
        ECB::<C>::check(data)?;
        Blocks::apply::<C>(data, |blocks| self.cipher.decrypt_blocks(blocks));
        Ok(())
    }

    /// Fails unless `data` is a whole number of blocks.
    pub fn check(data: &[u8]) -> Result<(), CryptoError> {
        if !data.len().is_multiple_of(C::BLOCK_SIZE) {
            return Err(CryptoError::InputLength { length: data.len() });
        }
        Ok(())
    }
}

impl<C: BlockCipher> fmt::Debug for ECB<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ECB(..)")
    }
}
