//! The C ABI of [`crate::hash::sha`].

#[cfg(umilib_feature = "hash-sha-v1")]
pub mod v1;
#[cfg(umilib_feature = "hash-sha-v2")]
pub mod v2;
#[cfg(umilib_feature = "hash-sha-v3")]
pub mod v3;

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "sha",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "hash-sha-v1")]
        v1::MODULE,
        #[cfg(umilib_feature = "hash-sha-v2")]
        v2::MODULE,
        #[cfg(umilib_feature = "hash-sha-v3")]
        v3::MODULE,
    ],
};
