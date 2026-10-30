//! The C ABI of [`crate::hash::md::v5`].

use crate::ffi::Module;

/// [`MD5`](crate::hash::md::v5::MD5).
pub mod md5 {
    crate::ffi_digest!(default crate::hash::md::v5::MD5, "umilib_hash_md_v5_md5", "umilib_hash_md_v5_MD5", "MD5 (RFC 1321), broken: for compatibility only.");
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v5",
    definitions: &[md5::DEFINITION],
    functions: &crate::ffi::Function::concat::<{ md5::FUNCTIONS.len() }>(&[md5::FUNCTIONS]),
    modules: &[],
};
