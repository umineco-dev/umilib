//! The C ABI of [`crate::hash::sha::v1`].

use crate::ffi::Module;

/// [`SHA1`](crate::hash::sha::v1::SHA1).
pub mod sha1 {
    crate::ffi_digest!(default crate::hash::sha::v1::SHA1, "umilib_hash_sha_v1_sha1", "umilib_hash_sha_v1_SHA1", "SHA-1 (FIPS 180-4).");
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v1",
    definitions: &[sha1::DEFINITION],
    functions: &crate::ffi::Function::concat::<{ sha1::FUNCTIONS.len() }>(&[sha1::FUNCTIONS]),
    modules: &[],
};
