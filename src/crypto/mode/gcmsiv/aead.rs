use core::fmt;

use super::POLYVAL;
use crate::crypto::mode::Blocks;
use crate::crypto::{AEAD, BlockCipher, CryptoError, KeyInit};
use crate::secret::{ConstantTimeEq, Zeroize};

/// GCM-SIV (RFC 8452) over the 128-bit block cipher `C` with a key-generating
/// key of 16 or 32 bytes (AEAD_AES_128_GCM_SIV and AEAD_AES_256_GCM_SIV with
/// AES) and 12-byte nonces.
///
/// Each nonce derives a message-authentication key and a message-encryption
/// key as long as the key-generating key; the tag is the encrypted POLYVAL of
/// the associated data and the plaintext, and the initial counter of CTR with
/// a 32-bit little-endian counter. A message has at most 2^36 bytes of
/// plaintext and of associated data. Decryption decrypts first; when the tag
/// does not match it encrypts again, so the buffer holds the ciphertext as
/// it was and no plaintext.
#[derive(Clone)]
pub struct GCMSIV<C: BlockCipher<Block = [u8; 16]> + KeyInit> {
    /// The cipher with the key-generating key.
    cipher: C,
    key_size: usize,
}

impl<C: BlockCipher<Block = [u8; 16]> + KeyInit> GCMSIV<C> {
    /// The longest plaintext and associated data of a message (section 6).
    pub const MAXIMUM_INPUT: u64 = 1 << 36;

    /// The message-authentication key and the cipher with the message-encryption key of `nonce` (section 4).
    pub fn derive_keys(&self, nonce: &[u8; 12]) -> Result<([u8; 16], C), CryptoError> {
        let count = 2 + self.key_size / 8;
        let mut blocks = [[0u8; 16]; 6];
        for (index, block) in blocks[..count].iter_mut().enumerate() {
            block[..4].copy_from_slice(&(index as u32).to_le_bytes());
            block[4..].copy_from_slice(nonce);
        }
        self.cipher.encrypt_blocks(&mut blocks[..count]);
        let mut authentication = [0u8; 16];
        authentication[..8].copy_from_slice(&blocks[0][..8]);
        authentication[8..].copy_from_slice(&blocks[1][..8]);
        let mut encryption = [0u8; 32];
        for (chunk, block) in encryption.as_chunks_mut::<8>().0.iter_mut().zip(&blocks[2..count]) {
            chunk.copy_from_slice(&block[..8]);
        }
        let cipher = C::new_from_slice(&encryption[..self.key_size]);
        blocks.zeroize();
        encryption.zeroize();
        match cipher {
            Ok(cipher) => Ok((authentication, cipher)),
            Err(error) => {
                authentication.zeroize();
                Err(error)
            }
        }
    }

    /// The tag of `associated` and `plaintext` (section 4).
    pub fn tag(
        authentication: &[u8; 16],
        cipher: &C,
        nonce: &[u8; 12],
        associated: &[u8],
        plaintext: &[u8],
    ) -> [u8; 16] {
        let mut polyval = POLYVAL::new(authentication);
        polyval.update(associated);
        polyval.pad();
        polyval.update(plaintext);
        polyval.pad();
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&(8 * associated.len() as u64).to_le_bytes());
        lengths[8..].copy_from_slice(&(8 * plaintext.len() as u64).to_le_bytes());
        polyval.update(&lengths);
        let mut tag = polyval.finalize();
        for (byte, value) in tag.iter_mut().zip(nonce) {
            *byte ^= value;
        }
        tag[15] &= 0x7F;
        cipher.encrypt_block(&mut tag);
        tag
    }

    /// CTR from the tag with the most significant bit of its last byte set,
    /// whose first 32 bits are a little-endian counter that wraps at 2^32.
    pub fn apply(cipher: &C, tag: &[u8; 16], data: &mut [u8]) {
        let mut counter = *tag;
        counter[15] |= 0x80;
        let mut keystream = [[0u8; 16]; Blocks::GROUP];
        for chunk in data.chunks_mut(16 * Blocks::GROUP) {
            let count = chunk.len().div_ceil(16);
            for block in keystream[..count].iter_mut() {
                *block = counter;
                let value = u32::from_le_bytes(counter[..4].try_into().expect("four bytes")).wrapping_add(1);
                counter[..4].copy_from_slice(&value.to_le_bytes());
            }
            cipher.encrypt_blocks(&mut keystream[..count]);
            for (byte, value) in chunk.iter_mut().zip(keystream.as_flattened()) {
                *byte ^= value;
            }
        }
        keystream.zeroize();
        counter.zeroize();
    }

    /// Checks the nonce and the lengths of a message (section 6).
    pub fn check<'a>(nonce: &'a [u8], associated: &[u8], data: &[u8]) -> Result<&'a [u8; 12], CryptoError> {
        let nonce =
            nonce.try_into().map_err(|_| CryptoError::NonceLength { length: nonce.len(), minimum: 12, maximum: 12 })?;
        for input in [associated, data] {
            if input.len() as u64 > GCMSIV::<C>::MAXIMUM_INPUT {
                return Err(CryptoError::InputLength { length: input.len() });
            }
        }
        Ok(nonce)
    }
}

impl<C: BlockCipher<Block = [u8; 16]> + KeyInit> AEAD for GCMSIV<C> {
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
    type Tag = [u8; 16];

    fn encrypt_in_place(&self, nonce: &[u8], associated: &[u8], buffer: &mut [u8]) -> Result<[u8; 16], CryptoError> {
        let nonce = GCMSIV::<C>::check(nonce, associated, buffer)?;
        let (mut authentication, cipher) = self.derive_keys(nonce)?;
        let tag = GCMSIV::tag(&authentication, &cipher, nonce, associated, buffer);
        authentication.zeroize();
        GCMSIV::apply(&cipher, &tag, buffer);
        Ok(tag)
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        associated: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        let tag: &[u8; 16] =
            tag.try_into().map_err(|_| CryptoError::TagLength { length: tag.len(), minimum: 16, maximum: 16 })?;
        let nonce = GCMSIV::<C>::check(nonce, associated, buffer)?;
        let (mut authentication, cipher) = self.derive_keys(nonce)?;
        GCMSIV::apply(&cipher, tag, buffer);
        let mut expected = GCMSIV::tag(&authentication, &cipher, nonce, associated, buffer);
        authentication.zeroize();
        let valid = expected.ct_eq(tag).into_bool();
        expected.zeroize();
        if !valid {
            GCMSIV::apply(&cipher, tag, buffer);
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

/// The key-generating key has 16 or 32 bytes, a key of `C`; the
/// message-encryption keys have its length.
impl<C: BlockCipher<Block = [u8; 16]> + KeyInit> KeyInit for GCMSIV<C> {
    const MINIMUM_KEY_SIZE: usize = C::MINIMUM_KEY_SIZE;
    const MAXIMUM_KEY_SIZE: usize = C::MAXIMUM_KEY_SIZE;

    fn new_from_slice(key: &[u8]) -> Result<GCMSIV<C>, CryptoError> {
        if key.len() != 16 && key.len() != 32 {
            return Err(CryptoError::KeyLength { length: key.len(), minimum: 16, maximum: 32 });
        }
        Ok(GCMSIV { cipher: C::new_from_slice(key)?, key_size: key.len() })
    }
}

impl<C: BlockCipher<Block = [u8; 16]> + KeyInit> Zeroize for GCMSIV<C> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
    }
}

impl<C: BlockCipher<Block = [u8; 16]> + KeyInit> fmt::Debug for GCMSIV<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GCMSIV({}-byte key, ..)", self.key_size)
    }
}
