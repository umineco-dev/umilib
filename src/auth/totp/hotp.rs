use core::fmt;

use super::{OTPCode, OTPError};
use crate::crypto::hmac::HMAC;
use crate::hash::CryptographicDigest;
use crate::secret::{ConstantTimeEq, Secret, Zeroize};

/// HOTP (RFC 4226): the password of a counter is HMAC of the key over the
/// counter (8 bytes, big-endian), dynamically truncated to 31 bits and
/// reduced to its last digits.
pub struct HOTP<H: CryptographicDigest + Default> {
    mac: Secret<HMAC<H>>,
    digits: u32,
}

impl<H: CryptographicDigest + Default> HOTP<H> {
    /// The shortest key: 128 bits (RFC 4226 R6; 160 are recommended).
    pub const MINIMUM_KEY_SIZE: usize = 16;
    /// The fewest digits of a password (RFC 4226 R4).
    pub const MINIMUM_DIGITS: u32 = 6;
    /// The most digits of a password: the truncated value is below 2^31.
    pub const MAXIMUM_DIGITS: u32 = OTPCode::MAXIMUM_DIGITS as u32;

    /// The fewest bytes of a digest: the dynamic truncation reads 4 bytes at an offset up to 15.
    pub const MINIMUM_DIGEST_SIZE: usize = 19;

    /// The generator of `key` and passwords of `digits` digits.
    pub fn new(key: &[u8], digits: u32) -> Result<HOTP<H>, OTPError> {
        if H::OUTPUT_SIZE < HOTP::<H>::MINIMUM_DIGEST_SIZE {
            return Err(OTPError::Hash);
        }
        if key.len() < HOTP::<H>::MINIMUM_KEY_SIZE {
            return Err(OTPError::KeyTooShort);
        }
        if !(HOTP::<H>::MINIMUM_DIGITS..=HOTP::<H>::MAXIMUM_DIGITS).contains(&digits) {
            return Err(OTPError::Digits);
        }
        Ok(HOTP { mac: Secret::new(HMAC::new(key)), digits })
    }

    pub fn digits(&self) -> u32 {
        self.digits
    }

    /// The dynamic truncation of RFC 4226 §5.3: the 31 bits at the offset
    /// given by the low 4 bits of the last byte of `digest`; `None` if
    /// `digest` is shorter than [`HOTP::MINIMUM_DIGEST_SIZE`].
    pub fn truncate(digest: &[u8]) -> Option<u32> {
        if digest.len() < HOTP::<H>::MINIMUM_DIGEST_SIZE {
            return None;
        }
        let offset = (digest[digest.len() - 1] & 0x0F) as usize;
        let bytes = [digest[offset], digest[offset + 1], digest[offset + 2], digest[offset + 3]];
        Some(u32::from_be_bytes(bytes) & 0x7FFF_FFFF)
    }

    /// The password of `counter`.
    pub fn generate(&self, counter: u64) -> OTPCode {
        let mut mac = self.mac.expose().clone();
        mac.update(&counter.to_be_bytes());
        let mut digest = mac.finalize();
        // `new` refused hash functions of shorter digests.
        let truncated = HOTP::<H>::truncate(digest.as_ref()).unwrap_or(0);
        digest.as_mut().zeroize();
        let value = u64::from(truncated) % 10u64.pow(self.digits);
        OTPCode::new(value as u32, self.digits)
    }

    /// The counter of `counter` to `counter + look_ahead` whose password is
    /// `code` (ASCII digits), if any. Every counter of the window is tried,
    /// and passwords are compared in constant time, so the time taken does
    /// not tell which counter matched.
    pub fn verify(&self, code: &[u8], counter: u64, look_ahead: u64) -> Option<u64> {
        let mut found = None;
        for step in 0..=look_ahead {
            let Some(candidate) = counter.checked_add(step) else { break };
            let expected = self.generate(candidate).to_ascii();
            let length = self.digits as usize;
            let matches = code.len() == length && expected[..length].ct_eq(code).into_bool();
            if matches && found.is_none() {
                found = Some(candidate);
            }
        }
        found
    }
}

impl<H: CryptographicDigest + Default> Clone for HOTP<H> {
    fn clone(&self) -> HOTP<H> {
        HOTP { mac: self.mac.clone(), digits: self.digits }
    }
}

impl<H: CryptographicDigest + Default> fmt::Debug for HOTP<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("HOTP").field("digits", &self.digits).finish_non_exhaustive()
    }
}
