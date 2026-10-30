//! The C ABI of [`crate::protocol::pop`], by version.

#[cfg(umilib_feature = "protocol-pop-v3")]
pub mod v3;

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "pop",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "protocol-pop-v3")]
        v3::MODULE,
    ],
};
