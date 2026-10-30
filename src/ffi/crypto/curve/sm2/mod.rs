//! The C ABI of [`crate::crypto::curve::sm2`].
//!
//! Its points and scalars.

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "sm2", definitions: &[], functions: &[], modules: &[] };
