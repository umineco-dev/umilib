use alloc::vec::Vec;

use super::{JWEEncryption, JWTError};
use crate::crypto::aes::{AES128, AES192, AES256};
use crate::crypto::hmac::HMAC;
use crate::crypto::mode::PKCS7;
use crate::crypto::mode::cbc::CBC;
use crate::crypto::mode::gcm::GCM;
use crate::crypto::{AEAD, BlockCipher, KeyInit};
use crate::hash::CryptographicDigest;
use crate::hash::sha::v2::{SHA256, SHA384, SHA512};
use crate::secret::{ConstantTimeEq, Zeroize};

impl JWEEncryption {
    /// Encrypts `plaintext` under the content encryption key `key` with the
    /// initialization vector `iv` and the additional authenticated data
    /// `aad` (RFC 7516 §5.1 steps 15 and 16): the ciphertext and the tag.
    pub fn encrypt(self, key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), JWTError> {
        self.check(key, iv)?;
        match self {
            JWEEncryption::A128CBCHS256 => JWEEncryption::encrypt_cbc::<AES128, SHA256>(key, iv, aad, plaintext, 16),
            JWEEncryption::A192CBCHS384 => JWEEncryption::encrypt_cbc::<AES192, SHA384>(key, iv, aad, plaintext, 24),
            JWEEncryption::A256CBCHS512 => JWEEncryption::encrypt_cbc::<AES256, SHA512>(key, iv, aad, plaintext, 32),
            JWEEncryption::A128GCM => JWEEncryption::encrypt_gcm::<AES128>(key, iv, aad, plaintext),
            JWEEncryption::A192GCM => JWEEncryption::encrypt_gcm::<AES192>(key, iv, aad, plaintext),
            JWEEncryption::A256GCM => JWEEncryption::encrypt_gcm::<AES256>(key, iv, aad, plaintext),
        }
    }

    /// Decrypts `ciphertext` with its `tag` (RFC 7516 §5.2 step 15); fails
    /// with [`JWTError::Decryption`] whatever is wrong: the sizes of the key,
    /// the IV and the tag, the tag, or the padding.
    pub fn decrypt(
        self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, JWTError> {
        self.check(key, iv).map_err(|_| JWTError::Decryption)?;
        if tag.len() != self.tag_size() {
            return Err(JWTError::Decryption);
        }
        match self {
            JWEEncryption::A128CBCHS256 => JWEEncryption::decrypt_cbc::<AES128, SHA256>(key, iv, aad, ciphertext, tag),
            JWEEncryption::A192CBCHS384 => JWEEncryption::decrypt_cbc::<AES192, SHA384>(key, iv, aad, ciphertext, tag),
            JWEEncryption::A256CBCHS512 => JWEEncryption::decrypt_cbc::<AES256, SHA512>(key, iv, aad, ciphertext, tag),
            JWEEncryption::A128GCM => JWEEncryption::decrypt_gcm::<AES128>(key, iv, aad, ciphertext, tag),
            JWEEncryption::A192GCM => JWEEncryption::decrypt_gcm::<AES192>(key, iv, aad, ciphertext, tag),
            JWEEncryption::A256GCM => JWEEncryption::decrypt_gcm::<AES256>(key, iv, aad, ciphertext, tag),
        }
    }

    /// Fails with [`JWTError::KeyMismatch`] unless the key and the IV have
    /// the sizes of the algorithm.
    pub fn check(self, key: &[u8], iv: &[u8]) -> Result<(), JWTError> {
        if key.len() != self.key_size() || iv.len() != self.iv_size() {
            return Err(JWTError::KeyMismatch);
        }
        Ok(())
    }

    /// The tag of AES-CBC with HMAC (RFC 7518 §5.2.2.1 steps 4 to 6): the
    /// first `size` bytes of HMAC(MAC_KEY, A || IV || E || AL), AL the bit
    /// length of A as 64 bits.
    pub fn cbc_tag<H: CryptographicDigest + Default>(
        mac_key: &[u8],
        aad: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        size: usize,
    ) -> Vec<u8> {
        let mut mac = HMAC::<H>::new(mac_key);
        mac.update(aad);
        mac.update(iv);
        mac.update(ciphertext);
        mac.update(&((aad.len() as u64) * 8).to_be_bytes());
        let mut output = mac.finalize();
        let tag = output.as_ref()[..size].to_vec();
        output.as_mut().zeroize();
        tag
    }

    /// AES-CBC with HMAC (RFC 7518 §5.2.2.1): the first half of the key is
    /// the MAC key, the second the AES key; PKCS #7 padding.
    pub fn encrypt_cbc<C: BlockCipher<Block = [u8; 16]> + KeyInit, H: CryptographicDigest + Default>(
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        size: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), JWTError> {
        let (mac_key, encryption_key) = key.split_at(key.len() / 2);
        let iv: &[u8; 16] = iv.try_into().map_err(|_| JWTError::KeyMismatch)?;
        let mut ciphertext = plaintext.to_vec();
        PKCS7::pad(&mut ciphertext, 16)?;
        CBC::new(C::new_from_slice(encryption_key)?, iv).encrypt(&mut ciphertext)?;
        let tag = JWEEncryption::cbc_tag::<H>(mac_key, aad, iv, &ciphertext, size);
        Ok((ciphertext, tag))
    }

    /// The inverse of [`JWEEncryption::encrypt_cbc`]: the tag is checked
    /// in constant time before anything is decrypted (RFC 7518 §5.2.2.2).
    pub fn decrypt_cbc<C: BlockCipher<Block = [u8; 16]> + KeyInit, H: CryptographicDigest + Default>(
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, JWTError> {
        let (mac_key, encryption_key) = key.split_at(key.len() / 2);
        let expected = JWEEncryption::cbc_tag::<H>(mac_key, aad, iv, ciphertext, tag.len());
        if !expected.as_slice().ct_eq(tag).into_bool() || ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16)
        {
            return Err(JWTError::Decryption);
        }
        let iv: &[u8; 16] = iv.try_into().map_err(|_| JWTError::Decryption)?;
        let mut plaintext = ciphertext.to_vec();
        let cipher = C::new_from_slice(encryption_key).map_err(|_| JWTError::Decryption)?;
        CBC::new(cipher, iv).decrypt(&mut plaintext).map_err(|_| JWTError::Decryption)?;
        if PKCS7::unpad(&mut plaintext, 16).is_err() {
            plaintext.zeroize();
            return Err(JWTError::Decryption);
        }
        Ok(plaintext)
    }

    /// AES-GCM with a 96-bit IV and a 128-bit tag (RFC 7518 §5.3).
    pub fn encrypt_gcm<C: BlockCipher<Block = [u8; 16]> + KeyInit>(
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), JWTError> {
        let gcm = GCM::<C>::new(C::new_from_slice(key)?);
        let mut ciphertext = plaintext.to_vec();
        let tag = gcm.encrypt_in_place(iv, aad, &mut ciphertext)?;
        Ok((ciphertext, tag.to_vec()))
    }

    pub fn decrypt_gcm<C: BlockCipher<Block = [u8; 16]> + KeyInit>(
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, JWTError> {
        let gcm = GCM::<C>::new(C::new_from_slice(key).map_err(|_| JWTError::Decryption)?);
        let mut plaintext = ciphertext.to_vec();
        gcm.decrypt_in_place(iv, aad, &mut plaintext, tag).map_err(|_| JWTError::Decryption)?;
        Ok(plaintext)
    }
}
