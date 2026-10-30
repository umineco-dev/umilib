//! The C ABI of [`crate::crypto::curve::p384`].
//!
//! Its points and scalars.

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "p384", definitions: &[], functions: &[], modules: &[] };
