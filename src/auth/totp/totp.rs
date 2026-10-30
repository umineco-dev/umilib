use super::{HOTP, OTPCode, OTPError};
use crate::hash::CryptographicDigest;

/// The parameters of a [`TOTP`]: the digits of a password, the length of
/// a time step in seconds (X) and the origin of the steps (T0, seconds of
/// the Unix epoch). RFC 6238 recommends 30-second steps from the epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TOTPConfig {
    pub digits: u32,
    pub period: u64,
    pub origin: u64,
}

impl Default for TOTPConfig {
    fn default() -> TOTPConfig {
        TOTPConfig { digits: 6, period: 30, origin: 0 }
    }
}

/// TOTP (RFC 6238): HOTP of the count of time steps since the origin.
/// Times are seconds of the Unix epoch, given by the caller.
#[derive(Clone, Debug)]
pub struct TOTP<H: CryptographicDigest + Default> {
    hotp: HOTP<H>,
    period: u64,
    origin: u64,
}

impl<H: CryptographicDigest + Default> TOTP<H> {
    /// The generator of `key` with the parameters `config`.
    pub fn new(key: &[u8], config: &TOTPConfig) -> Result<TOTP<H>, OTPError> {
        if config.period == 0 {
            return Err(OTPError::Period);
        }
        Ok(TOTP { hotp: HOTP::new(key, config.digits)?, period: config.period, origin: config.origin })
    }

    pub fn hotp(&self) -> &HOTP<H> {
        &self.hotp
    }

    pub fn period(&self) -> u64 {
        self.period
    }

    pub fn origin(&self) -> u64 {
        self.origin
    }

    /// The time step of `time`: `(time - origin) / period`.
    pub fn counter(&self, time: u64) -> Result<u64, OTPError> {
        time.checked_sub(self.origin).map(|elapsed| elapsed / self.period).ok_or(OTPError::Time)
    }

    /// The password at `time`.
    pub fn generate(&self, time: u64) -> Result<OTPCode, OTPError> {
        Ok(self.hotp.generate(self.counter(time)?))
    }

    /// The time step, from `behind` steps before that of `time` to `ahead`
    /// steps after it (for clocks out of step and the time the password took
    /// to arrive, RFC 6238 §5.2), whose password is `code`; `None` if none
    /// is. Steps before the origin are not tried.
    pub fn verify(&self, code: &[u8], time: u64, behind: u64, ahead: u64) -> Result<Option<u64>, OTPError> {
        let counter = self.counter(time)?;
        let first = counter.saturating_sub(behind);
        Ok(self.hotp.verify(code, first, (counter - first).saturating_add(ahead)))
    }
}
