use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{RSAPrivateKey, RSAPublicKey};
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::secret::ConstantTimeEq;

/// A hash function of RSASSA-PKCS1-v1_5 with the DER encoding of its
/// `DigestInfo` up to the digest (RFC 8017 section 9.2, note 1).
pub trait PKCS1Digest: CryptographicDigest + Default {
    const DIGEST_INFO_PREFIX: &'static [u8];
}

#[cfg(umilib_feature = "hash-sha-v1")]
impl PKCS1Digest for crate::hash::sha::v1::SHA1 {
    const DIGEST_INFO_PREFIX: &'static [u8] =
        &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14];
}

/// The prefix of a hash function of NIST (2.16.840.1.101.3.4.2.`last`) whose
/// digest has `length` bytes.
#[cfg(any(umilib_feature = "hash-sha-v2", umilib_feature = "hash-sha-v3"))]
macro_rules! nist_digest_info {
    ($hash:ty, $last:literal, $length:literal) => {
        impl PKCS1Digest for $hash {
            const DIGEST_INFO_PREFIX: &'static [u8] = &[
                0x30,
                0x11 + $length,
                0x30,
                0x0D,
                0x06,
                0x09,
                0x60,
                0x86,
                0x48,
                0x01,
                0x65,
                0x03,
                0x04,
                0x02,
                $last,
                0x05,
                0x00,
                0x04,
                $length,
            ];
        }
    };
}

#[cfg(umilib_feature = "hash-sha-v2")]
nist_digest_info!(crate::hash::sha::v2::SHA256, 0x01, 32);
#[cfg(umilib_feature = "hash-sha-v2")]
nist_digest_info!(crate::hash::sha::v2::SHA384, 0x02, 48);
#[cfg(umilib_feature = "hash-sha-v2")]
nist_digest_info!(crate::hash::sha::v2::SHA512, 0x03, 64);
#[cfg(umilib_feature = "hash-sha-v2")]
nist_digest_info!(crate::hash::sha::v2::SHA224, 0x04, 28);
#[cfg(umilib_feature = "hash-sha-v2")]
nist_digest_info!(crate::hash::sha::v2::SHA512_224, 0x05, 28);
#[cfg(umilib_feature = "hash-sha-v2")]
nist_digest_info!(crate::hash::sha::v2::SHA512_256, 0x06, 32);
#[cfg(umilib_feature = "hash-sha-v3")]
nist_digest_info!(crate::hash::sha::v3::SHA3_224, 0x07, 28);
#[cfg(umilib_feature = "hash-sha-v3")]
nist_digest_info!(crate::hash::sha::v3::SHA3_256, 0x08, 32);
#[cfg(umilib_feature = "hash-sha-v3")]
nist_digest_info!(crate::hash::sha::v3::SHA3_384, 0x09, 48);
#[cfg(umilib_feature = "hash-sha-v3")]
nist_digest_info!(crate::hash::sha::v3::SHA3_512, 0x0A, 64);

/// RSASSA-PKCS1-v1_5 of RFC 8017 section 8.2 with the hash function `H`.
/// Signatures are deterministic and have the bytes of the modulus.
pub struct RSAPKCS1v15<H: PKCS1Digest> {
    hash: PhantomData<H>,
}

impl<H: PKCS1Digest> RSAPKCS1v15<H> {
    /// EMSA-PKCS1-v1_5-ENCODE (section 9.2) of a digest in `length` bytes:
    /// 00 01 FF ... FF 00 DigestInfo. Fails with `InvalidParameter` for a
    /// digest of another length than `H`'s and with `InvalidKey` if `length`
    /// leaves fewer than 8 bytes of FF.
    pub fn encode(digest: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
        if digest.len() != H::OUTPUT_SIZE {
            return Err(CryptoError::InvalidParameter);
        }
        let information = H::DIGEST_INFO_PREFIX.len() + digest.len();
        if length < information + 11 {
            return Err(CryptoError::InvalidKey);
        }
        let mut encoded = Vec::with_capacity(length);
        encoded.extend_from_slice(&[0x00, 0x01]);
        encoded.resize(length - information - 1, 0xFF);
        encoded.push(0x00);
        encoded.extend_from_slice(H::DIGEST_INFO_PREFIX);
        encoded.extend_from_slice(digest);
        Ok(encoded)
    }

    /// The signature of `message` (section 8.2.1); `random` blinds the private operation.
    pub fn sign<R: Random>(key: &RSAPrivateKey, message: &[u8], random: &mut R) -> Result<Vec<u8>, CryptoError> {
        RSAPKCS1v15::<H>::sign_digest(key, H::digest(message).as_ref(), random)
    }

    /// The signature of the digest `digest` of the message under `H`.
    pub fn sign_digest<R: Random>(key: &RSAPrivateKey, digest: &[u8], random: &mut R) -> Result<Vec<u8>, CryptoError> {
        let public = key.public_key();
        let encoded = RSAPKCS1v15::<H>::encode(digest, public.size())?;
        let signature = key.apply(&public.integer(&encoded)?, random)?;
        let mut out = alloc::vec![0u8; public.size()];
        signature.write_be_bytes(&mut out).map_err(|_| CryptoError::InvalidKey)?;
        Ok(out)
    }

    /// Succeeds if `signature` is the signature of `message` under `key`
    /// (section 8.2.2); fails with `InvalidSignature` otherwise.
    pub fn verify(key: &RSAPublicKey, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        RSAPKCS1v15::<H>::verify_digest(key, H::digest(message).as_ref(), signature)
    }

    /// [`RSAPKCS1v15::verify`] of the digest `digest` of the message under `H`.
    pub fn verify_digest(key: &RSAPublicKey, digest: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let invalid = |_| CryptoError::InvalidSignature;
        if signature.len() != key.size() {
            return Err(CryptoError::InvalidSignature);
        }
        let message = key.apply(&key.integer(signature).map_err(invalid)?).map_err(invalid)?;
        let mut encoded = alloc::vec![0u8; key.size()];
        message.write_be_bytes(&mut encoded).map_err(|_| CryptoError::InvalidSignature)?;
        let expected = RSAPKCS1v15::<H>::encode(digest, key.size()).map_err(invalid)?;
        if !encoded.ct_eq(&expected).into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }
}
