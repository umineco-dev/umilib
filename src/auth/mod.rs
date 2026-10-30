//! Authentication: the X.509 public-key infrastructure, OAuth, SASL and one-time passwords.

#[cfg(umilib_feature = "auth-cert")]
pub mod cert;
#[cfg(umilib_feature = "auth-oauth")]
pub mod oauth;
#[cfg(umilib_feature = "auth-sasl")]
pub mod sasl;
#[cfg(umilib_feature = "auth-totp")]
pub mod totp;
