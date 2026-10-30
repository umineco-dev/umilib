//! The C ABI of [`crate::hash::adler32`].

use crate::ffi::Module;

/// [`Adler32`](crate::hash::adler32::Adler32).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod adler32 {
    crate::ffi_digest!(
        default crate::hash::adler32::Adler32,
        "umilib_hash_adler32_adler32",
        "umilib_hash_adler32_Adler32",
        "Adler-32 (RFC 1950), the checksum of zlib streams; its digest is the value in big-endian order."
    );
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "adler32",
    definitions: &[adler32::DEFINITION],
    functions: &crate::ffi::Function::concat::<{ adler32::FUNCTIONS.len() }>(&[adler32::FUNCTIONS]),
    modules: &[],
};
