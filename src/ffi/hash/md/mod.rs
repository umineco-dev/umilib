//! The C ABI of [`crate::hash::md`].

#[cfg(umilib_feature = "hash-md-v4")]
pub mod v4;
#[cfg(umilib_feature = "hash-md-v5")]
pub mod v5;

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "md",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "hash-md-v4")]
        v4::MODULE,
        #[cfg(umilib_feature = "hash-md-v5")]
        v5::MODULE,
    ],
};
