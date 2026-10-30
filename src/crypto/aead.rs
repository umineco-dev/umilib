use alloc::vec::Vec;

use super::CryptoError;
use crate::secret::Zeroize;

/// Authenticated encryption with associated data (RFC 5116).
///
/// Decryption releases no plaintext unless the tag matches. A construction
/// that can verify the tag before decrypting leaves the buffer as it was on
/// failure; one that must decrypt first restores the ciphertext, or
/// overwrites the buffer with zeros where its specification requires that.
/// Each type documents which it does. Every method takes the nonce as a
/// slice whose length the algorithm checks; `NONCE_SIZE` is the recommended
/// one. Keys are given to constructors (see [`KeyInit`](super::KeyInit)).
pub trait AEAD {
    const NONCE_SIZE: usize;
    const TAG_SIZE: usize;
    /// A tag: `[u8; TAG_SIZE]`.
    type Tag: AsRef<[u8]> + AsMut<[u8]> + Clone + Copy + Eq + core::fmt::Debug;

    /// Encrypts `buffer` in place and returns the tag of it and `associated`.
    fn encrypt_in_place(&self, nonce: &[u8], associated: &[u8], buffer: &mut [u8]) -> Result<Self::Tag, CryptoError>;

    /// Decrypts `buffer` in place if `tag` authenticates it and `associated`;
    /// fails with [`CryptoError::AuthenticationFailed`] otherwise, leaving no
    /// plaintext (see the description of the trait).
    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        associated: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError>;

    /// The ciphertext of `plaintext` with its tag, in the format of the
    /// algorithm's RFC 5116 definition: the tag follows the ciphertext unless
    /// the algorithm places it elsewhere (SIV places it first).
    /// The plaintext copied into the output is zeroized if encryption fails.
    fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut output = Vec::new();
        output.try_reserve_exact(plaintext.len() + Self::TAG_SIZE).map_err(|_| CryptoError::Allocation)?;
        output.extend_from_slice(plaintext);
        match self.encrypt_in_place(nonce, associated, &mut output) {
            Ok(tag) => {
                output.extend_from_slice(tag.as_ref());
                Ok(output)
            }
            Err(error) => {
                output.zeroize();
                Err(error)
            }
        }
    }

    /// The plaintext of `ciphertext`, which holds its tag as
    /// [`AEAD::encrypt`] places it.
    fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let length = ciphertext
            .len()
            .checked_sub(Self::TAG_SIZE)
            .ok_or(CryptoError::InputLength { length: ciphertext.len() })?;
        let (body, tag) = ciphertext.split_at(length);
        let mut output = Vec::new();
        output.try_reserve_exact(body.len()).map_err(|_| CryptoError::Allocation)?;
        output.extend_from_slice(body);
        self.decrypt_in_place(nonce, associated, &mut output, tag)?;
        Ok(output)
    }
}
