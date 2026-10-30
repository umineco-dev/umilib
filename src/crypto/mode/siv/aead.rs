use alloc::vec::Vec;
use core::fmt;

use super::S2V;
use crate::crypto::mode::ctr::CTR;
use crate::crypto::{AEAD, BlockCipher, CryptoError, KeyInit, StreamCipher};
use crate::secret::{ConstantTimeEq, Zeroize};

/// SIV (RFC 5297) over the 128-bit block cipher `C`: S2V with the first half
/// of the key gives the synthetic IV V, which authenticates the associated
/// data and the plaintext and is the initial counter of CTR with the second
/// half of the key.
///
/// [`SIV::encrypt_vector_in_place`] takes the associated data as a vector of
/// up to 126 components (deterministic authenticated encryption, section 4).
/// As an [`AEAD`] (AEAD_AES_SIV_CMAC_256/384/512, section 6) the components
/// are the associated data and the nonce, which has at least 1 byte, and the
/// ciphertext of [`AEAD::encrypt`] is V followed by the encrypted plaintext,
/// as section 6 defines it. Decryption decrypts first; when V does not
/// match it encrypts again, so the buffer holds the ciphertext as it was.
#[derive(Clone)]
pub struct SIV<C: BlockCipher<Block = [u8; 16]>> {
    /// S2V with K1, after the key.
    s2v: S2V<C>,
    /// The cipher of CTR with K2.
    cipher: C,
}

impl<C: BlockCipher<Block = [u8; 16]>> SIV<C> {
    /// The most components of associated data (section 2.6).
    pub const MAXIMUM_COMPONENTS: usize = 126;
    pub const SIV_SIZE: usize = 16;

    /// SIV with `mac` keyed by K1 and `cipher` keyed by K2.
    pub fn new(mac: C, cipher: C) -> SIV<C> {
        SIV { s2v: S2V::new(mac), cipher }
    }

    /// V of the vector `associated` followed by `plaintext`.
    pub fn synthetic_iv(&self, associated: &[&[u8]], plaintext: &[u8]) -> Result<[u8; 16], CryptoError> {
        if associated.len() > SIV::<C>::MAXIMUM_COMPONENTS {
            return Err(CryptoError::InvalidParameter);
        }
        let mut s2v = self.s2v.clone();
        for component in associated {
            s2v.update(component);
        }
        Ok(s2v.finalize(plaintext))
    }

    /// CTR from Q = V with the 31st and 63rd bits cleared, applied to `data`.
    pub fn apply(&self, siv: &[u8; 16], data: &mut [u8]) -> Result<(), CryptoError> {
        let mut counter = *siv;
        counter[8] &= 0x7F;
        counter[12] &= 0x7F;
        let mut ctr = CTR::new(self.cipher.clone(), &counter);
        counter.zeroize();
        ctr.apply_keystream(data)
    }

    /// Encrypts `buffer` in place and returns V, which authenticates it and the components of `associated`.
    pub fn encrypt_vector_in_place(&self, associated: &[&[u8]], buffer: &mut [u8]) -> Result<[u8; 16], CryptoError> {
        let siv = self.synthetic_iv(associated, buffer)?;
        self.apply(&siv, buffer)?;
        Ok(siv)
    }

    /// Decrypts `buffer` in place if `siv` authenticates it and the components of `associated`.
    pub fn decrypt_vector_in_place(
        &self,
        associated: &[&[u8]],
        buffer: &mut [u8],
        siv: &[u8],
    ) -> Result<(), CryptoError> {
        let siv: &[u8; 16] =
            siv.try_into().map_err(|_| CryptoError::TagLength { length: siv.len(), minimum: 16, maximum: 16 })?;
        if associated.len() > SIV::<C>::MAXIMUM_COMPONENTS {
            return Err(CryptoError::InvalidParameter);
        }
        self.apply(siv, buffer)?;
        let mut expected = self.synthetic_iv(associated, buffer)?;
        let valid = expected.ct_eq(siv).into_bool();
        expected.zeroize();
        if !valid {
            self.apply(siv, buffer)?;
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }

    /// The nonce of the AEAD form has at least one byte (section 6).
    pub fn check_nonce(nonce: &[u8]) -> Result<(), CryptoError> {
        if nonce.is_empty() {
            return Err(CryptoError::NonceLength { length: 0, minimum: 1, maximum: usize::MAX });
        }
        Ok(())
    }
}

impl<C: BlockCipher<Block = [u8; 16]>> AEAD for SIV<C> {
    const NONCE_SIZE: usize = 16;
    const TAG_SIZE: usize = 16;
    type Tag = [u8; 16];

    fn encrypt_in_place(&self, nonce: &[u8], associated: &[u8], buffer: &mut [u8]) -> Result<[u8; 16], CryptoError> {
        SIV::<C>::check_nonce(nonce)?;
        self.encrypt_vector_in_place(&[associated, nonce], buffer)
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        associated: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        SIV::<C>::check_nonce(nonce)?;
        self.decrypt_vector_in_place(&[associated, nonce], buffer, tag)
    }

    /// V followed by the ciphertext of `plaintext` (section 6).
    fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut output = Vec::new();
        output.try_reserve_exact(16 + plaintext.len()).map_err(|_| CryptoError::Allocation)?;
        output.extend_from_slice(&[0u8; 16]);
        output.extend_from_slice(plaintext);
        match self.encrypt_in_place(nonce, associated, &mut output[16..]) {
            Ok(siv) => {
                output[..16].copy_from_slice(&siv);
                Ok(output)
            }
            Err(error) => {
                output.zeroize();
                Err(error)
            }
        }
    }

    /// The plaintext of `ciphertext`, which begins with V (section 6).
    fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 16 {
            return Err(CryptoError::InputLength { length: ciphertext.len() });
        }
        let (siv, body) = ciphertext.split_at(16);
        let mut output = Vec::new();
        output.try_reserve_exact(body.len()).map_err(|_| CryptoError::Allocation)?;
        output.extend_from_slice(body);
        self.decrypt_in_place(nonce, associated, &mut output, siv)?;
        Ok(output)
    }
}

/// The key is K1 followed by K2, two keys of `C` of the same length.
impl<C: BlockCipher<Block = [u8; 16]> + KeyInit> KeyInit for SIV<C> {
    const MINIMUM_KEY_SIZE: usize = 2 * C::MINIMUM_KEY_SIZE;
    const MAXIMUM_KEY_SIZE: usize = 2 * C::MAXIMUM_KEY_SIZE;

    fn new_from_slice(key: &[u8]) -> Result<SIV<C>, CryptoError> {
        SIV::<C>::check_key_length(key.len())?;
        if !key.len().is_multiple_of(2) {
            return Err(CryptoError::KeyLength {
                length: key.len(),
                minimum: SIV::<C>::MINIMUM_KEY_SIZE,
                maximum: SIV::<C>::MAXIMUM_KEY_SIZE,
            });
        }
        let (k1, k2) = key.split_at(key.len() / 2);
        Ok(SIV::new(C::new_from_slice(k1)?, C::new_from_slice(k2)?))
    }
}

impl<C: BlockCipher<Block = [u8; 16]>> Zeroize for SIV<C> {
    fn zeroize(&mut self) {
        self.s2v.zeroize();
        self.cipher.zeroize();
    }
}

impl<C: BlockCipher<Block = [u8; 16]>> fmt::Debug for SIV<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SIV(..)")
    }
}
