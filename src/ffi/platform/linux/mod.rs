//! The C ABI of `crate::platform::linux`: none of its own. Its types are
//! those of one operating system, and the C ABI is the same on every
//! system; what C needs of them is in the native layer
//! ([`crate::ffi::platform::native`]).

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "linux", definitions: &[], functions: &[], modules: &[] };
