//! The C ABI of [`crate::crypto::sm4`].

use crate::ffi::Module;

/// [`SM4`](crate::crypto::sm4::SM4).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod sm4 {
    crate::ffi_block_cipher!(
        crate::crypto::sm4::SM4,
        "umilib_crypto_sm4_sm4",
        "umilib_crypto_sm4_SM4",
        "SM4 (GB/T 32907-2016): a 128-bit key and 32 rounds."
    );
}

/// The manifest node of this module.
pub const MODULE: Module =
    Module { name: "sm4", definitions: &[sm4::DEFINITION], functions: sm4::FUNCTIONS, modules: &[] };
