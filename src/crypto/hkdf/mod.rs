//! HKDF (RFC 5869): the HMAC-based extract-and-expand key derivation function.

use core::fmt;
use core::marker::PhantomData;

use crate::crypto::CryptoError;
use crate::crypto::hmac::HMAC;
use crate::hash::CryptographicDigest;
use crate::secret::Zeroize;

/// HKDF over the hash function `H`: Extract turns input keying material into
/// a pseudorandom key (PRK), Expand turns the PRK and an info string into up
/// to 255 × HashLen bytes of output keying material.
#[derive(Clone)]
pub struct HKDF<H: CryptographicDigest + Default> {
    /// HMAC keyed with the PRK.
    prk: HMAC<H>,
    hash: PhantomData<H>,
}

impl<H: CryptographicDigest + Default> HKDF<H> {
    /// The longest output: 255 × HashLen (section 2.3).
    pub const MAXIMUM_OUTPUT: usize = 255 * H::OUTPUT_SIZE;

    /// HKDF-Extract(salt, IKM) (section 2.2): PRK = HMAC-Hash(salt, IKM). An
    /// empty salt is HashLen zeros, the same HMAC key once padded.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> H::Output {
        HMAC::<H>::mac(salt, ikm)
    }

    /// HKDF with the pseudorandom key `prk` of at least HashLen bytes (section 2.3).
    pub fn new(prk: &[u8]) -> Result<HKDF<H>, CryptoError> {
        if prk.len() < H::OUTPUT_SIZE {
            return Err(CryptoError::KeyLength { length: prk.len(), minimum: H::OUTPUT_SIZE, maximum: usize::MAX });
        }
        Ok(HKDF { prk: HMAC::new(prk), hash: PhantomData })
    }

    /// HKDF with the PRK extracted from `salt` and `ikm`.
    pub fn from_secret(salt: &[u8], ikm: &[u8]) -> HKDF<H> {
        let mut prk = HKDF::<H>::extract(salt, ikm);
        let hkdf = HKDF { prk: HMAC::new(prk.as_ref()), hash: PhantomData };
        prk.as_mut().zeroize();
        hkdf
    }

    /// HKDF-Expand(PRK, info, L) (section 2.3) into `okm`: T(i) = HMAC-Hash(PRK, T(i-1) || info || i).
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), CryptoError> {
        if okm.len() > HKDF::<H>::MAXIMUM_OUTPUT {
            return Err(CryptoError::InputLength { length: okm.len() });
        }
        let mut previous: Option<H::Output> = None;
        for (index, piece) in okm.chunks_mut(H::OUTPUT_SIZE).enumerate() {
            let mut hmac = self.prk.clone();
            if let Some(previous) = &previous {
                hmac.update(previous.as_ref());
            }
            hmac.update(info);
            hmac.update(&[index as u8 + 1]);
            let block = hmac.finalize();
            piece.copy_from_slice(&block.as_ref()[..piece.len()]);
            if let Some(mut old) = previous.replace(block) {
                old.as_mut().zeroize();
            }
        }
        if let Some(mut last) = previous {
            last.as_mut().zeroize();
        }
        Ok(())
    }

    /// Extract and Expand: `okm` from `salt`, `ikm` and `info`.
    pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), CryptoError> {
        HKDF::<H>::from_secret(salt, ikm).expand(info, okm)
    }
}

impl<H: CryptographicDigest + Default> Zeroize for HKDF<H> {
    fn zeroize(&mut self) {
        self.prk.zeroize();
    }
}

impl<H: CryptographicDigest + Default> fmt::Debug for HKDF<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HKDF(..)")
    }
}
