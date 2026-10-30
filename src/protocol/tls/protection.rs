use alloc::vec::Vec;

use crate::crypto::AEAD;
use crate::crypto::KeyInit;
use crate::crypto::aes::{AES128, AES256};
use crate::crypto::chacha20poly1305::ChaCha20Poly1305;
use crate::crypto::mode::gcm::GCM;

use super::{TLSAEADAlgorithm, TLSAlertDescription, TLSError};

/// An AEAD keyed for one direction of a connection (RFC 5116). The AES
/// keys are boxed: their expanded keys and tables are near a kilobyte,
/// ChaCha20-Poly1305's a few dozen bytes.
pub enum TLSAEAD {
    AES128GCM(alloc::boxed::Box<GCM<AES128, 16>>),
    AES256GCM(alloc::boxed::Box<GCM<AES256, 16>>),
    ChaCha20Poly1305(ChaCha20Poly1305),
    #[cfg(umilib_feature = "crypto-mode-ccm")]
    AES128CCM(alloc::boxed::Box<crate::crypto::mode::ccm::CCM<AES128, 16>>),
    #[cfg(umilib_feature = "crypto-mode-ccm")]
    AES128CCM8(alloc::boxed::Box<crate::crypto::mode::ccm::CCM<AES128, 8>>),
}

impl core::fmt::Debug for TLSAEAD {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TLSAEAD(..)")
    }
}

impl TLSAEAD {
    /// Whether this crate can use `algorithm`: CCM needs `crypto-mode-ccm`.
    pub fn supports(algorithm: TLSAEADAlgorithm) -> bool {
        let ccm = matches!(algorithm, TLSAEADAlgorithm::AES128CCM | TLSAEADAlgorithm::AES128CCM8);
        !ccm || cfg!(umilib_feature = "crypto-mode-ccm")
    }

    /// The AEAD of `algorithm` under `key`; fails with `internal_error` for a
    /// key of the wrong length or an algorithm not compiled in.
    pub fn new(algorithm: TLSAEADAlgorithm, key: &[u8]) -> Result<TLSAEAD, TLSError> {
        let internal = |_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR);
        Ok(match algorithm {
            TLSAEADAlgorithm::AES128GCM => {
                TLSAEAD::AES128GCM(alloc::boxed::Box::new(GCM::new_from_slice(key).map_err(internal)?))
            }
            TLSAEADAlgorithm::AES256GCM => {
                TLSAEAD::AES256GCM(alloc::boxed::Box::new(GCM::new_from_slice(key).map_err(internal)?))
            }
            TLSAEADAlgorithm::ChaCha20Poly1305 => {
                TLSAEAD::ChaCha20Poly1305(ChaCha20Poly1305::new_from_slice(key).map_err(internal)?)
            }
            #[cfg(umilib_feature = "crypto-mode-ccm")]
            TLSAEADAlgorithm::AES128CCM => {
                TLSAEAD::AES128CCM(alloc::boxed::Box::new(KeyInit::new_from_slice(key).map_err(internal)?))
            }
            #[cfg(umilib_feature = "crypto-mode-ccm")]
            TLSAEADAlgorithm::AES128CCM8 => {
                TLSAEAD::AES128CCM8(alloc::boxed::Box::new(KeyInit::new_from_slice(key).map_err(internal)?))
            }
            #[cfg(not(umilib_feature = "crypto-mode-ccm"))]
            TLSAEADAlgorithm::AES128CCM | TLSAEADAlgorithm::AES128CCM8 => {
                return Err(TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR));
            }
        })
    }

    pub fn tag_length(&self) -> usize {
        match self {
            #[cfg(umilib_feature = "crypto-mode-ccm")]
            TLSAEAD::AES128CCM8(_) => 8,
            _ => 16,
        }
    }

    /// Encrypts `buffer` in place and appends the tag.
    pub fn seal(&self, nonce: &[u8], associated: &[u8], buffer: &mut Vec<u8>) -> Result<(), TLSError> {
        let length = buffer.len();
        buffer.resize(length + self.tag_length(), 0);
        let (data, tag) = buffer.split_at_mut(length);
        self.seal_in_place(nonce, associated, data, tag)
    }

    /// Encrypts `data` in place and writes its tag into `tag`, of
    /// [`TLSAEAD::tag_length`] bytes: for records or packets whose header,
    /// payload and tag share one buffer.
    pub fn seal_in_place(
        &self,
        nonce: &[u8],
        associated: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), TLSError> {
        match self {
            TLSAEAD::AES128GCM(aead) => TLSAEAD::seal_with(&**aead, nonce, associated, data, tag),
            TLSAEAD::AES256GCM(aead) => TLSAEAD::seal_with(&**aead, nonce, associated, data, tag),
            TLSAEAD::ChaCha20Poly1305(aead) => TLSAEAD::seal_with(aead, nonce, associated, data, tag),
            #[cfg(umilib_feature = "crypto-mode-ccm")]
            TLSAEAD::AES128CCM(aead) => TLSAEAD::seal_with(&**aead, nonce, associated, data, tag),
            #[cfg(umilib_feature = "crypto-mode-ccm")]
            TLSAEAD::AES128CCM8(aead) => TLSAEAD::seal_with(&**aead, nonce, associated, data, tag),
        }
    }

    /// [`TLSAEAD::seal_in_place`] with the AEAD `aead`.
    pub fn seal_with<A: AEAD>(
        aead: &A,
        nonce: &[u8],
        associated: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), TLSError> {
        let internal = TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR);
        if tag.len() != A::TAG_SIZE {
            return Err(internal);
        }
        let computed = aead.encrypt_in_place(nonce, associated, data).map_err(|_| internal)?;
        tag.copy_from_slice(computed.as_ref());
        Ok(())
    }

    /// Decrypts `buffer` (ciphertext and tag) in place and removes the tag;
    /// fails with `bad_record_mac` unless it authenticates (RFC 9846 §5.2).
    pub fn open(&self, nonce: &[u8], associated: &[u8], buffer: &mut Vec<u8>) -> Result<(), TLSError> {
        let bad = TLSError::Protocol(TLSAlertDescription::BAD_RECORD_MAC);
        let length = buffer.len().checked_sub(self.tag_length()).ok_or(bad)?;
        let (body, tag) = buffer.split_at_mut(length);
        self.open_in_place(nonce, associated, body, tag)?;
        buffer.truncate(length);
        Ok(())
    }

    /// Decrypts `data` in place if `tag` authenticates it and `associated`;
    /// fails with `bad_record_mac` otherwise.
    pub fn open_in_place(&self, nonce: &[u8], associated: &[u8], data: &mut [u8], tag: &[u8]) -> Result<(), TLSError> {
        let result = match self {
            TLSAEAD::AES128GCM(aead) => aead.decrypt_in_place(nonce, associated, data, tag),
            TLSAEAD::AES256GCM(aead) => aead.decrypt_in_place(nonce, associated, data, tag),
            TLSAEAD::ChaCha20Poly1305(aead) => aead.decrypt_in_place(nonce, associated, data, tag),
            #[cfg(umilib_feature = "crypto-mode-ccm")]
            TLSAEAD::AES128CCM(aead) => aead.decrypt_in_place(nonce, associated, data, tag),
            #[cfg(umilib_feature = "crypto-mode-ccm")]
            TLSAEAD::AES128CCM8(aead) => aead.decrypt_in_place(nonce, associated, data, tag),
        };
        result.map_err(|_| TLSError::Protocol(TLSAlertDescription::BAD_RECORD_MAC))
    }
}
