//! The C ABI of [`crate::crypto::curve::secp256k1`].
//!
//! Its points and scalars.

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "secp256k1", definitions: &[], functions: &[], modules: &[] };
