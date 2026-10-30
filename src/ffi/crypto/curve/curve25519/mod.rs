//! The C ABI of [`crate::crypto::curve::curve25519`].
//!
//! Its points and scalars.

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "curve25519", definitions: &[], functions: &[], modules: &[] };
