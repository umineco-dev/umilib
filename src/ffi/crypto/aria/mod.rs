//! The C ABI of [`crate::crypto::aria`].

use crate::ffi::Module;

/// [`ARIA128`](crate::crypto::aria::ARIA128).
pub mod aria128 {
    crate::ffi_block_cipher!(
        crate::crypto::aria::ARIA128,
        "umilib_crypto_aria_aria128",
        "umilib_crypto_aria_ARIA128",
        "ARIA-128 (RFC 5794): a 128-bit key and 12 rounds."
    );
}

/// [`ARIA192`](crate::crypto::aria::ARIA192).
pub mod aria192 {
    crate::ffi_block_cipher!(
        crate::crypto::aria::ARIA192,
        "umilib_crypto_aria_aria192",
        "umilib_crypto_aria_ARIA192",
        "ARIA-192 (RFC 5794): a 192-bit key and 14 rounds."
    );
}

/// [`ARIA256`](crate::crypto::aria::ARIA256).
pub mod aria256 {
    crate::ffi_block_cipher!(
        crate::crypto::aria::ARIA256,
        "umilib_crypto_aria_aria256",
        "umilib_crypto_aria_ARIA256",
        "ARIA-256 (RFC 5794): a 256-bit key and 16 rounds."
    );
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "aria",
    definitions: &[aria128::DEFINITION, aria192::DEFINITION, aria256::DEFINITION],
    functions: &crate::ffi::Function::concat::<
        { aria128::FUNCTIONS.len() + aria192::FUNCTIONS.len() + aria256::FUNCTIONS.len() },
    >(&[aria128::FUNCTIONS, aria192::FUNCTIONS, aria256::FUNCTIONS]),
    modules: &[],
};
