//! The C ABI of [`crate::hash::streebog`].

use crate::ffi::Module;

/// [`Streebog256`](crate::hash::streebog::Streebog256).
pub mod streebog256 {
    crate::ffi_digest!(default crate::hash::streebog::Streebog256, "umilib_hash_streebog_streebog256", "umilib_hash_streebog_Streebog256", "Streebog with 256 bits of output (GOST R 34.11-2012, RFC 6986).");
}

/// [`Streebog512`](crate::hash::streebog::Streebog512).
pub mod streebog512 {
    crate::ffi_digest!(default crate::hash::streebog::Streebog512, "umilib_hash_streebog_streebog512", "umilib_hash_streebog_Streebog512", "Streebog with 512 bits of output (GOST R 34.11-2012, RFC 6986).");
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "streebog",
    definitions: &[streebog256::DEFINITION, streebog512::DEFINITION],
    functions: &crate::ffi::Function::concat::<{ streebog256::FUNCTIONS.len() + streebog512::FUNCTIONS.len() }>(&[
        streebog256::FUNCTIONS,
        streebog512::FUNCTIONS,
    ]),
    modules: &[],
};
