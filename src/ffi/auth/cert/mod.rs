//! The C ABI of [`crate::auth::cert`].

#[cfg(umilib_feature = "auth-cert-csr")]
pub mod csr;
#[cfg(umilib_feature = "auth-cert-key")]
pub mod key;
#[cfg(umilib_feature = "auth-cert-ocsp")]
pub mod ocsp;
#[cfg(umilib_feature = "auth-cert-path")]
pub mod path;
#[cfg(umilib_feature = "auth-cert-x509")]
pub mod x509;

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "cert",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "auth-cert-csr")]
        csr::MODULE,
        #[cfg(umilib_feature = "auth-cert-key")]
        key::MODULE,
        #[cfg(umilib_feature = "auth-cert-ocsp")]
        ocsp::MODULE,
        #[cfg(umilib_feature = "auth-cert-path")]
        path::MODULE,
        #[cfg(umilib_feature = "auth-cert-x509")]
        x509::MODULE,
    ],
};
