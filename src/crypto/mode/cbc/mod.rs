//! The cipher block chaining mode (SP 800-38A section 6.2).

use core::fmt;

use crate::crypto::mode::Blocks;
use crate::crypto::{BlockCipher, CryptoError};
use crate::secret::Zeroize;

/// CBC over the block cipher `C`, with the chaining value carried from one
/// call to the next, so a message may be processed in pieces of whole blocks.
/// Decryption hands blocks to the cipher in groups, which bitsliced ciphers
/// process together; encryption cannot, as each block needs the previous one.
#[derive(Clone)]
pub struct CBC<C: BlockCipher> {
    cipher: C,
    /// The initialization vector, then the last ciphertext block.
    chaining: C::Block,
}

impl<C: BlockCipher> CBC<C> {
    pub fn new(cipher: C, iv: &C::Block) -> CBC<C> {
        CBC { cipher, chaining: *iv }
    }

    /// Encrypts `data`, a whole number of blocks, in place.
    pub fn encrypt(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        CBC::<C>::check(data)?;
        for chunk in data.chunks_mut(C::BLOCK_SIZE) {
            Blocks::xor(self.chaining.as_mut(), chunk);
            self.cipher.encrypt_block(&mut self.chaining);
            chunk.copy_from_slice(self.chaining.as_ref());
        }
        Ok(())
    }

    /// Decrypts `data`, a whole number of blocks, in place.
    pub fn decrypt(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        CBC::<C>::check(data)?;
        let mut previous = self.chaining;
        Blocks::apply::<C>(data, |blocks| {
            let last = *blocks.last().expect("a group is not empty");
            let mut chain = previous;
            let saved: [C::Block; Blocks::GROUP] =
                core::array::from_fn(|index| blocks.get(index).copied().unwrap_or_default());
            self.cipher.decrypt_blocks(blocks);
            for (block, ciphertext) in blocks.iter_mut().zip(saved.iter()) {
                Blocks::xor(block.as_mut(), chain.as_ref());
                chain = *ciphertext;
            }
            previous = last;
        });
        self.chaining = previous;
        previous.as_mut().zeroize();
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

impl<C: BlockCipher> Zeroize for CBC<C> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.chaining.as_mut().zeroize();
    }
}

impl<C: BlockCipher> Drop for CBC<C> {
    fn drop(&mut self) {
        self.chaining.as_mut().zeroize();
    }
}

impl<C: BlockCipher> fmt::Debug for CBC<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CBC(..)")
    }
}
