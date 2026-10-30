//! One-time passwords: HOTP (RFC 4226), counted by events, and TOTP
//! (RFC 6238), counted by time steps, over HMAC of any hash function
//! (RFC 6238 names SHA-1, SHA-256 and SHA-512).
//!
//! The verifier keeps the counter of the last password it accepted and
//! accepts no password of that counter or an earlier one again (RFC 4226
//! §7.2, RFC 6238 §5.2): `verify` returns the counter that matched for
//! that purpose.

mod code;
mod error;
mod hotp;
#[allow(clippy::module_inception)]
mod totp;

pub use code::OTPCode;
pub use error::OTPError;
pub use hotp::HOTP;
pub use totp::{TOTP, TOTPConfig};
