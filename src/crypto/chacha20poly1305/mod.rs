//! AEAD_CHACHA20_POLY1305 (RFC 8439 section 2.8) and
//! AEAD_XCHACHA20_POLY1305 (draft-irtf-cfrg-xchacha section 2).

use core::fmt;

use crate::crypto::chacha20::{ChaCha20, XChaCha20};
use crate::crypto::poly1305::Poly1305;
use crate::crypto::{AEAD, CryptoError, KeyInit, StreamCipher};
use crate::secret::{ConstantTimeEq, Zeroize};

/// ChaCha20-Poly1305 with a 256-bit key and a 96-bit nonce (RFC 8439
/// section 2.8): the one-time Poly1305 key is the first half of the block
/// with counter 0, the plaintext is encrypted from counter 1, and the tag
/// authenticates the associated data and the ciphertext. Decryption checks
/// the tag before it decrypts.
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    pub const KEY_SIZE: usize = 32;
    /// P_MAX of section 2.8: 2^38 - 64 bytes, the key stream of 2^32 - 1 blocks.
    pub const MAXIMUM_INPUT: u64 = (1 << 38) - 64;

    pub fn new(key: &[u8; 32]) -> ChaCha20Poly1305 {
        ChaCha20Poly1305 { key: *key }
    }

    /// The one-time key of section 2.6 and the cipher from counter 1.
    pub fn start(key: &[u8; 32], nonce: &[u8; 12]) -> (Poly1305, ChaCha20) {
        let mut state = ChaCha20::initial_state(key, 0, nonce);
        let mut block = ChaCha20::block(&state);
        let poly1305 = Poly1305::new(block[..32].try_into().expect("32 bytes"));
        state.zeroize();
        block.zeroize();
        (poly1305, ChaCha20::new(key, nonce, 1))
    }

    /// The tag of section 2.8: Poly1305 of the padded associated data, the padded ciphertext and the two lengths.
    pub fn tag(mut poly1305: Poly1305, associated: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        poly1305.update(associated);
        poly1305.pad();
        poly1305.update(ciphertext);
        poly1305.pad();
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&(associated.len() as u64).to_le_bytes());
        lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        poly1305.update(&lengths);
        poly1305.finalize()
    }

    /// Encrypts `buffer` under `key` and `nonce` and returns the tag.
    pub fn seal(
        key: &[u8; 32],
        nonce: &[u8; 12],
        associated: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; 16], CryptoError> {
        ChaCha20Poly1305::check(buffer)?;
        let (poly1305, mut cipher) = ChaCha20Poly1305::start(key, nonce);
        cipher.apply_keystream(buffer)?;
        Ok(ChaCha20Poly1305::tag(poly1305, associated, buffer))
    }

    /// Decrypts `buffer` under `key` and `nonce` if `tag` authenticates it.
    pub fn open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        associated: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        if tag.len() != 16 {
            return Err(CryptoError::TagLength { length: tag.len(), minimum: 16, maximum: 16 });
        }
        ChaCha20Poly1305::check(buffer)?;
        let (poly1305, mut cipher) = ChaCha20Poly1305::start(key, nonce);
        let mut expected = ChaCha20Poly1305::tag(poly1305, associated, buffer);
        let valid = expected[..].ct_eq(tag).into_bool();
        expected.zeroize();
        if !valid {
            return Err(CryptoError::AuthenticationFailed);
        }
        cipher.apply_keystream(buffer)
    }

    pub fn check(data: &[u8]) -> Result<(), CryptoError> {
        if data.len() as u64 > ChaCha20Poly1305::MAXIMUM_INPUT {
            return Err(CryptoError::InputLength { length: data.len() });
        }
        Ok(())
    }

    pub fn check_nonce(nonce: &[u8], size: usize) -> Result<(), CryptoError> {
        if nonce.len() != size {
            return Err(CryptoError::NonceLength { length: nonce.len(), minimum: size, maximum: size });
        }
        Ok(())
    }
}

impl AEAD for ChaCha20Poly1305 {
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
    type Tag = [u8; 16];

    fn encrypt_in_place(&self, nonce: &[u8], associated: &[u8], buffer: &mut [u8]) -> Result<[u8; 16], CryptoError> {
        ChaCha20Poly1305::check_nonce(nonce, 12)?;
        ChaCha20Poly1305::seal(&self.key, nonce.try_into().expect("12 bytes"), associated, buffer)
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        associated: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        ChaCha20Poly1305::check_nonce(nonce, 12)?;
        ChaCha20Poly1305::open(&self.key, nonce.try_into().expect("12 bytes"), associated, buffer, tag)
    }
}

impl KeyInit for ChaCha20Poly1305 {
    const MINIMUM_KEY_SIZE: usize = 32;
    const MAXIMUM_KEY_SIZE: usize = 32;

    fn new_from_slice(key: &[u8]) -> Result<ChaCha20Poly1305, CryptoError> {
        ChaCha20Poly1305::check_key_length(key.len())?;
        Ok(ChaCha20Poly1305::new(key.try_into().map_err(|_| CryptoError::InvalidParameter)?))
    }
}

impl Zeroize for ChaCha20Poly1305 {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for ChaCha20Poly1305 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChaCha20Poly1305(..)")
    }
}

/// XChaCha20-Poly1305 with a 192-bit nonce (draft-irtf-cfrg-xchacha
/// section 2): ChaCha20-Poly1305 with the subkey and the inner nonce of
/// [`XChaCha20::derive`]. Random nonces are safe for it.
#[derive(Clone)]
pub struct XChaCha20Poly1305 {
    key: [u8; 32],
}

impl XChaCha20Poly1305 {
    pub const KEY_SIZE: usize = 32;

    pub fn new(key: &[u8; 32]) -> XChaCha20Poly1305 {
        XChaCha20Poly1305 { key: *key }
    }
}

impl AEAD for XChaCha20Poly1305 {
    const NONCE_SIZE: usize = 24;
    const TAG_SIZE: usize = 16;
    type Tag = [u8; 16];

    fn encrypt_in_place(&self, nonce: &[u8], associated: &[u8], buffer: &mut [u8]) -> Result<[u8; 16], CryptoError> {
        ChaCha20Poly1305::check_nonce(nonce, 24)?;
        let (mut subkey, inner) = XChaCha20::derive(&self.key, nonce.try_into().expect("24 bytes"));
        let result = ChaCha20Poly1305::seal(&subkey, &inner, associated, buffer);
        subkey.zeroize();
        result
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        associated: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        ChaCha20Poly1305::check_nonce(nonce, 24)?;
        let (mut subkey, inner) = XChaCha20::derive(&self.key, nonce.try_into().expect("24 bytes"));
        let result = ChaCha20Poly1305::open(&subkey, &inner, associated, buffer, tag);
        subkey.zeroize();
        result
    }
}

impl KeyInit for XChaCha20Poly1305 {
    const MINIMUM_KEY_SIZE: usize = 32;
    const MAXIMUM_KEY_SIZE: usize = 32;

    fn new_from_slice(key: &[u8]) -> Result<XChaCha20Poly1305, CryptoError> {
        XChaCha20Poly1305::check_key_length(key.len())?;
        Ok(XChaCha20Poly1305::new(key.try_into().map_err(|_| CryptoError::InvalidParameter)?))
    }
}

impl Zeroize for XChaCha20Poly1305 {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for XChaCha20Poly1305 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for XChaCha20Poly1305 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XChaCha20Poly1305(..)")
    }
}
