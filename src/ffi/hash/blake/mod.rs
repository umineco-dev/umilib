//! The C ABI of [`crate::hash::blake`].

#[cfg(umilib_feature = "hash-blake-v2")]
pub mod v2;
#[cfg(umilib_feature = "hash-blake-v3")]
pub mod v3;

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "blake",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "hash-blake-v2")]
        v2::MODULE,
        #[cfg(umilib_feature = "hash-blake-v3")]
        v3::MODULE,
    ],
};
