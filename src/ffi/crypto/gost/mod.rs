//! The C ABI of [`crate::crypto::gost`].

use crate::ffi::Module;

#[cfg(umilib_feature = "crypto-gost-kuznyechik")]
pub mod kuznyechik;
#[cfg(umilib_feature = "crypto-gost-magma")]
pub mod magma;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "gost",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "crypto-gost-kuznyechik")]
        kuznyechik::MODULE,
        #[cfg(umilib_feature = "crypto-gost-magma")]
        magma::MODULE,
    ],
};
