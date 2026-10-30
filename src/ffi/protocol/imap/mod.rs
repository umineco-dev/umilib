//! The C ABI of [`crate::protocol::imap`], by version.

#[cfg(umilib_feature = "protocol-imap-v4")]
pub mod v4;

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "imap",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "protocol-imap-v4")]
        v4::MODULE,
    ],
};
