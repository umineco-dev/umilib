//! The C ABI of [`crate::math::ec`].
//!
//! The arithmetic of curves is generic over the curve, which C cannot name;
//! the curves of `crypto::curve` export their points.

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "ec", definitions: &[], functions: &[], modules: &[] };
