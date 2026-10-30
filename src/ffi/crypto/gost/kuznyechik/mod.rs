//! The C ABI of [`crate::crypto::gost::kuznyechik`].

use crate::ffi::Module;

/// [`Kuznyechik`](crate::crypto::gost::kuznyechik::Kuznyechik).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod kuznyechik {
    crate::ffi_block_cipher!(
        crate::crypto::gost::kuznyechik::Kuznyechik,
        "umilib_crypto_gost_kuznyechik_kuznyechik",
        "umilib_crypto_gost_kuznyechik_Kuznyechik",
        "Kuznyechik (GOST R 34.12-2015, RFC 7801): a 256-bit key and 128-bit blocks."
    );
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "kuznyechik",
    definitions: &[kuznyechik::DEFINITION],
    functions: kuznyechik::FUNCTIONS,
    modules: &[],
};
