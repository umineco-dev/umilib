//! The C ABI of [`crate::hash::md::v4`].

use crate::ffi::Module;

/// [`MD4`](crate::hash::md::v4::MD4).
pub mod md4 {
    crate::ffi_digest!(default crate::hash::md::v4::MD4, "umilib_hash_md_v4_md4", "umilib_hash_md_v4_MD4", "MD4 (RFC 1320), broken: for compatibility only.");
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v4",
    definitions: &[md4::DEFINITION],
    functions: &crate::ffi::Function::concat::<{ md4::FUNCTIONS.len() }>(&[md4::FUNCTIONS]),
    modules: &[],
};
