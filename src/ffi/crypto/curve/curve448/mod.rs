//! The C ABI of [`crate::crypto::curve::curve448`].
//!
//! Its points and scalars.

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "curve448", definitions: &[], functions: &[], modules: &[] };
