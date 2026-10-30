//! The C ABI of [`crate::hash::sm3`].

use crate::ffi::Module;

/// [`SM3`](crate::hash::sm3::SM3).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod sm3 {
    crate::ffi_digest!(default crate::hash::sm3::SM3, "umilib_hash_sm3_sm3", "umilib_hash_sm3_SM3", "SM3 (GB/T 32905-2016).");
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "sm3",
    definitions: &[sm3::DEFINITION],
    functions: &crate::ffi::Function::concat::<{ sm3::FUNCTIONS.len() }>(&[sm3::FUNCTIONS]),
    modules: &[],
};
