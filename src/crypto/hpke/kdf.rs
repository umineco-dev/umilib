use alloc::vec::Vec;

use crate::crypto::CryptoError;
use crate::crypto::hkdf::HKDF;
use crate::crypto::hmac::HMAC;
use crate::hash::CryptographicDigest;

/// A hash function whose HKDF is a KDF of HPKE (RFC 9180 section 7.2).
pub trait HPKEKDF: CryptographicDigest + Default {
    /// The kdf_id of section 7.2.
    const ID: u16;
}

#[cfg(umilib_feature = "hash-sha-v2")]
impl HPKEKDF for crate::hash::sha::v2::SHA256 {
    const ID: u16 = 0x0001;
}

#[cfg(umilib_feature = "hash-sha-v2")]
impl HPKEKDF for crate::hash::sha::v2::SHA384 {
    const ID: u16 = 0x0002;
}

#[cfg(umilib_feature = "hash-sha-v2")]
impl HPKEKDF for crate::hash::sha::v2::SHA512 {
    const ID: u16 = 0x0003;
}

/// LabeledExtract and LabeledExpand of RFC 9180 section 4 for the suite
/// `suite` (the suite_id of the KEM or of HPKE).
pub struct HPKELabels<'a> {
    suite: &'a [u8],
}

impl<'a> HPKELabels<'a> {
    /// The prefix of every label.
    pub const VERSION: &'static [u8] = b"HPKE-v1";

    pub fn new(suite: &'a [u8]) -> HPKELabels<'a> {
        HPKELabels { suite }
    }

    /// LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm).
    pub fn extract<F: HPKEKDF>(&self, salt: &[u8], label: &[u8], ikm: &[u8]) -> F::Output {
        // An empty salt is Nh zeros (RFC 5869 section 2.2), the same HMAC key once padded.
        let mut hmac = HMAC::<F>::new(salt);
        hmac.update(HPKELabels::VERSION);
        hmac.update(self.suite);
        hmac.update(label);
        hmac.update(ikm);
        hmac.finalize()
    }

    /// LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L, 2) ||
    /// "HPKE-v1" || suite_id || label || info, L) into `out` of L bytes.
    pub fn expand<F: HPKEKDF>(&self, prk: &[u8], label: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let length = u16::try_from(out.len()).map_err(|_| CryptoError::InputLength { length: out.len() })?;
        let mut labeled = Vec::new();
        labeled.extend_from_slice(&length.to_be_bytes());
        labeled.extend_from_slice(HPKELabels::VERSION);
        labeled.extend_from_slice(self.suite);
        labeled.extend_from_slice(label);
        labeled.extend_from_slice(info);
        HKDF::<F>::new(prk)?.expand(&labeled, out)
    }
}
