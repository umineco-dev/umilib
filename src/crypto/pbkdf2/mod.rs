//! PBKDF2 (RFC 8018 section 5.2, NIST SP 800-132): the password-based key
//! derivation function with HMAC as its pseudorandom function.

use core::marker::PhantomData;

use crate::crypto::CryptoError;
use crate::crypto::hmac::HMAC;
use crate::hash::CryptographicDigest;
use crate::secret::Zeroize;

/// PBKDF2 with HMAC over the hash function `H`.
///
/// SP 800-132 recommends a salt of at least 128 bits and an iteration count
/// of at least 1000, as high as the application can afford; those are left
/// to the caller, since protocols fix their own parameters.
pub struct PBKDF2<H: CryptographicDigest + Default> {
    hash: PhantomData<H>,
}

impl<H: CryptographicDigest + Default> PBKDF2<H> {
    /// The longest output: (2^32 - 1) × hLen.
    pub const MAXIMUM_OUTPUT: u64 = ((1u64 << 32) - 1) * H::OUTPUT_SIZE as u64;

    /// DK = T_1 || T_2 || ... with T_i = U_1 ^ ... ^ U_c, U_1 = PRF(P, S || INT(i)) and U_j = PRF(P, U_(j-1)).
    pub fn derive(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> Result<(), CryptoError> {
        if iterations == 0 {
            return Err(CryptoError::InvalidParameter);
        }
        if out.len() as u64 > PBKDF2::<H>::MAXIMUM_OUTPUT {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        let prf = HMAC::<H>::new(password);
        for (index, piece) in out.chunks_mut(H::OUTPUT_SIZE).enumerate() {
            let mut hmac = prf.clone();
            hmac.update(salt);
            hmac.update(&(index as u32 + 1).to_be_bytes());
            let mut u = hmac.finalize();
            let mut t = u;
            for _ in 1..iterations {
                let mut hmac = prf.clone();
                hmac.update(u.as_ref());
                let next = hmac.finalize();
                u.as_mut().zeroize();
                u = next;
                for (byte, value) in t.as_mut().iter_mut().zip(u.as_ref()) {
                    *byte ^= value;
                }
            }
            piece.copy_from_slice(&t.as_ref()[..piece.len()]);
            u.as_mut().zeroize();
            t.as_mut().zeroize();
        }
        Ok(())
    }
}
