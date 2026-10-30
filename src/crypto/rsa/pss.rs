use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{MGF1, RSAPrivateKey, RSAPublicKey};
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::secret::{ConstantTimeEq, Zeroize};

/// RSASSA-PSS of RFC 8017 section 8.1 with the hash function `H` and MGF1
/// over `G`. Signatures have the bytes of the modulus; the length of the
/// salt is a parameter of signing and verification, usually that of the
/// digest ([`RSAPSS::DEFAULT_SALT_LENGTH`]).
pub struct RSAPSS<H: CryptographicDigest + Default, G: CryptographicDigest + Default = H> {
    hashes: PhantomData<(H, G)>,
}

impl<H: CryptographicDigest + Default, G: CryptographicDigest + Default> RSAPSS<H, G> {
    /// The length of the digest of `H`.
    pub const DEFAULT_SALT_LENGTH: usize = H::OUTPUT_SIZE;

    /// H(00 00 00 00 00 00 00 00 || digest || salt), the H of section 9.1.1 step 6.
    pub fn hash_salted(digest: &[u8], salt: &[u8]) -> H::Output {
        let mut hash = H::default();
        hash.update(&[0u8; 8]);
        hash.update(digest);
        hash.update(salt);
        hash.finalize()
    }

    /// EMSA-PSS-ENCODE (section 9.1.1) of `digest` with `salt` in
    /// ⌈`bits`/8⌉ bytes; fails with `InvalidParameter` if they do not fit.
    pub fn encode(digest: &[u8], salt: &[u8], bits: u32) -> Result<Vec<u8>, CryptoError> {
        let length = bits.div_ceil(8) as usize;
        if digest.len() != H::OUTPUT_SIZE || length < H::OUTPUT_SIZE + salt.len() + 2 {
            return Err(CryptoError::InvalidParameter);
        }
        let hash = RSAPSS::<H, G>::hash_salted(digest, salt);
        let mut encoded = alloc::vec![0u8; length];
        let data_length = length - H::OUTPUT_SIZE - 1;
        encoded[data_length - salt.len() - 1] = 0x01;
        encoded[data_length - salt.len()..data_length].copy_from_slice(salt);
        MGF1::<G>::apply(hash.as_ref(), &mut encoded[..data_length]);
        encoded[0] &= 0xFF >> (8 * length as u32 - bits);
        encoded[data_length..length - 1].copy_from_slice(hash.as_ref());
        encoded[length - 1] = 0xBC;
        Ok(encoded)
    }

    /// The signature of `message` (section 8.1.1) with a salt of
    /// `salt_length` random bytes; `random` also blinds the private operation.
    pub fn sign<R: Random>(
        key: &RSAPrivateKey,
        message: &[u8],
        salt_length: usize,
        random: &mut R,
    ) -> Result<Vec<u8>, CryptoError> {
        RSAPSS::<H, G>::sign_digest(key, H::digest(message).as_ref(), salt_length, random)
    }

    /// The signature of the digest `digest` of the message under `H`.
    pub fn sign_digest<R: Random>(
        key: &RSAPrivateKey,
        digest: &[u8],
        salt_length: usize,
        random: &mut R,
    ) -> Result<Vec<u8>, CryptoError> {
        // A salt that cannot fit the encoding is refused before it is allocated.
        let length = (key.public_key().bits() - 1).div_ceil(8) as usize;
        if salt_length > length.saturating_sub(H::OUTPUT_SIZE + 2) {
            return Err(CryptoError::InvalidParameter);
        }
        let mut salt = alloc::vec![0u8; salt_length];
        random.fill(&mut salt).map_err(|_| CryptoError::RandomFailed)?;
        let result = RSAPSS::<H, G>::sign_digest_with_salt(key, digest, &salt, random);
        salt.zeroize();
        result
    }

    /// The signature of `digest` with the salt `salt`, given rather than
    /// random (an empty salt makes the signature deterministic).
    pub fn sign_digest_with_salt<R: Random>(
        key: &RSAPrivateKey,
        digest: &[u8],
        salt: &[u8],
        random: &mut R,
    ) -> Result<Vec<u8>, CryptoError> {
        let public = key.public_key();
        let encoded = RSAPSS::<H, G>::encode(digest, salt, public.bits() - 1)?;
        let signature = key.apply(&public.integer(&encoded)?, random)?;
        let mut out = alloc::vec![0u8; public.size()];
        signature.write_be_bytes(&mut out).map_err(|_| CryptoError::InvalidKey)?;
        Ok(out)
    }

    /// Succeeds if `signature` is a signature of `message` under `key` with a
    /// salt of `salt_length` bytes (section 8.1.2); fails with
    /// `InvalidSignature` otherwise.
    pub fn verify(key: &RSAPublicKey, message: &[u8], signature: &[u8], salt_length: usize) -> Result<(), CryptoError> {
        RSAPSS::<H, G>::verify_digest(key, H::digest(message).as_ref(), signature, salt_length)
    }

    /// [`RSAPSS::verify`] of the digest `digest` of the message under `H`.
    pub fn verify_digest(
        key: &RSAPublicKey,
        digest: &[u8],
        signature: &[u8],
        salt_length: usize,
    ) -> Result<(), CryptoError> {
        let invalid = |_| CryptoError::InvalidSignature;
        if signature.len() != key.size() || digest.len() != H::OUTPUT_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let message = key.apply(&key.integer(signature).map_err(invalid)?).map_err(invalid)?;
        let bits = key.bits() - 1;
        let length = bits.div_ceil(8) as usize;
        // I2OSP(m, emLen) fails if m does not fit emLen bytes.
        let mut encoded = alloc::vec![0u8; length];
        message.write_be_bytes(&mut encoded).map_err(|_| CryptoError::InvalidSignature)?;
        if message.bit_length() > 8 * length as u32 {
            return Err(CryptoError::InvalidSignature);
        }
        // Section 9.1.2 steps 3 to 13 (a salt length that does not fit, even
        // one whose sum would overflow, cannot be that of the signature).
        let fits = H::OUTPUT_SIZE
            .checked_add(salt_length)
            .and_then(|sum| sum.checked_add(2))
            .is_some_and(|needed| needed <= length);
        if !fits || encoded[length - 1] != 0xBC {
            return Err(CryptoError::InvalidSignature);
        }
        let data_length = length - H::OUTPUT_SIZE - 1;
        let unused = 0xFFu8 << (8 - (8 * length as u32 - bits));
        let unused = if 8 * length as u32 == bits { 0 } else { unused };
        if encoded[0] & unused != 0 {
            return Err(CryptoError::InvalidSignature);
        }
        let (data, rest) = encoded.split_at_mut(data_length);
        let hash = &rest[..H::OUTPUT_SIZE];
        MGF1::<G>::apply(hash, data);
        data[0] &= !unused;
        let padding = data_length - salt_length - 1;
        if data[..padding].iter().any(|byte| *byte != 0) || data[padding] != 0x01 {
            return Err(CryptoError::InvalidSignature);
        }
        let expected = RSAPSS::<H, G>::hash_salted(digest, &data[padding + 1..]);
        if !expected.as_ref().ct_eq(hash).into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }
}
