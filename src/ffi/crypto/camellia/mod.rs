//! The C ABI of [`crate::crypto::camellia`].

use crate::ffi::Module;

/// [`Camellia128`](crate::crypto::camellia::Camellia128).
pub mod camellia128 {
    crate::ffi_block_cipher!(
        crate::crypto::camellia::Camellia128,
        "umilib_crypto_camellia_camellia128",
        "umilib_crypto_camellia_Camellia128",
        "Camellia with a 128-bit key (RFC 3713): 18 rounds."
    );
}

/// [`Camellia192`](crate::crypto::camellia::Camellia192).
pub mod camellia192 {
    crate::ffi_block_cipher!(
        crate::crypto::camellia::Camellia192,
        "umilib_crypto_camellia_camellia192",
        "umilib_crypto_camellia_Camellia192",
        "Camellia with a 192-bit key (RFC 3713): 24 rounds."
    );
}

/// [`Camellia256`](crate::crypto::camellia::Camellia256).
pub mod camellia256 {
    crate::ffi_block_cipher!(
        crate::crypto::camellia::Camellia256,
        "umilib_crypto_camellia_camellia256",
        "umilib_crypto_camellia_Camellia256",
        "Camellia with a 256-bit key (RFC 3713): 24 rounds."
    );
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "camellia",
    definitions: &[camellia128::DEFINITION, camellia192::DEFINITION, camellia256::DEFINITION],
    functions: &crate::ffi::Function::concat::<
        { camellia128::FUNCTIONS.len() + camellia192::FUNCTIONS.len() + camellia256::FUNCTIONS.len() },
    >(&[camellia128::FUNCTIONS, camellia192::FUNCTIONS, camellia256::FUNCTIONS]),
    modules: &[],
};
