//! The C ABI of [`crate::crypto::gost::magma`].

use crate::ffi::Module;

/// [`Magma`](crate::crypto::gost::magma::Magma).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod magma {
    crate::ffi_block_cipher!(
        crate::crypto::gost::magma::Magma,
        "umilib_crypto_gost_magma_magma",
        "umilib_crypto_gost_magma_Magma",
        "Magma (GOST R 34.12-2015, RFC 8891): a 256-bit key and 64-bit blocks."
    );
}

/// The manifest node of this module.
pub const MODULE: Module =
    Module { name: "magma", definitions: &[magma::DEFINITION], functions: magma::FUNCTIONS, modules: &[] };
