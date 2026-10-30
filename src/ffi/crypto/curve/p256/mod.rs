//! The C ABI of [`crate::crypto::curve::p256`].
//!
//! Its points and scalars.

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "p256", definitions: &[], functions: &[], modules: &[] };
