use alloc::vec::Vec;

use crate::crypto::CryptoError;

/// An AEAD of HPKE (RFC 9180 section 7.3), or the export-only AEAD.
pub trait HPKEAEAD {
    /// The aead_id of section 7.3.
    const ID: u16;
    /// Nk, Nn and Nt.
    const KEY_SIZE: usize;
    const NONCE_SIZE: usize;
    const TAG_SIZE: usize;

    /// The ciphertext and tag of `plaintext` under `key` and `nonce`.
    fn seal(key: &[u8], nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// The plaintext of `ciphertext` (with its tag); fails with
    /// `AuthenticationFailed` unless it authenticates.
    fn open(key: &[u8], nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// The implementation of [`HPKEAEAD`] for an AEAD of the crate.
#[cfg(any(
    all(umilib_feature = "crypto-mode-gcm", umilib_feature = "crypto-aes"),
    umilib_feature = "crypto-chacha20poly1305"
))]
macro_rules! hpke_aead {
    ($aead:ty, $id:literal) => {
        impl HPKEAEAD for $aead {
            const ID: u16 = $id;
            const KEY_SIZE: usize = <$aead as crate::crypto::KeyInit>::MAXIMUM_KEY_SIZE;
            const NONCE_SIZE: usize = <$aead as crate::crypto::AEAD>::NONCE_SIZE;
            const TAG_SIZE: usize = <$aead as crate::crypto::AEAD>::TAG_SIZE;

            fn seal(key: &[u8], nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
                let aead = <$aead as crate::crypto::KeyInit>::new_from_slice(key)?;
                crate::crypto::AEAD::encrypt(&aead, nonce, associated, plaintext)
            }

            fn open(key: &[u8], nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
                let aead = <$aead as crate::crypto::KeyInit>::new_from_slice(key)?;
                crate::crypto::AEAD::decrypt(&aead, nonce, associated, ciphertext)
            }
        }
    };
}

#[cfg(all(umilib_feature = "crypto-mode-gcm", umilib_feature = "crypto-aes"))]
hpke_aead!(crate::crypto::mode::gcm::GCM<crate::crypto::aes::AES128, 16>, 0x0001);
#[cfg(all(umilib_feature = "crypto-mode-gcm", umilib_feature = "crypto-aes"))]
hpke_aead!(crate::crypto::mode::gcm::GCM<crate::crypto::aes::AES256, 16>, 0x0002);
#[cfg(umilib_feature = "crypto-chacha20poly1305")]
hpke_aead!(crate::crypto::chacha20poly1305::ChaCha20Poly1305, 0x0003);

/// The export-only AEAD of section 7.3 (aead_id 0xFFFF): contexts export
/// secrets and refuse to seal or open.
#[derive(Clone, Copy, Debug)]
pub struct HPKEExportOnly;

impl HPKEAEAD for HPKEExportOnly {
    const ID: u16 = 0xFFFF;
    const KEY_SIZE: usize = 0;
    const NONCE_SIZE: usize = 0;
    const TAG_SIZE: usize = 0;

    /// Fails with `InvalidParameter`.
    fn seal(_: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidParameter)
    }

    /// Fails with `InvalidParameter`.
    fn open(_: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::InvalidParameter)
    }
}
