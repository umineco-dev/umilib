//! The C ABI of [`crate::crypto::curve::gost`].
//!
//! Its points and scalars.

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "gost", definitions: &[], functions: &[], modules: &[] };
