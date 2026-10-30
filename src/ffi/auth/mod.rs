//! The C ABI of [`crate::auth`].

#[cfg(umilib_feature = "auth-cert")]
pub mod cert;
#[cfg(umilib_feature = "auth-oauth")]
pub mod oauth;
#[cfg(umilib_feature = "auth-sasl")]
pub mod sasl;
#[cfg(umilib_feature = "auth-totp")]
pub mod totp;

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "auth",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "auth-cert")]
        cert::MODULE,
        #[cfg(umilib_feature = "auth-oauth")]
        oauth::MODULE,
        #[cfg(umilib_feature = "auth-sasl")]
        sasl::MODULE,
        #[cfg(umilib_feature = "auth-totp")]
        totp::MODULE,
    ],
};
