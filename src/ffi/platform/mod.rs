//! The C ABI of [`crate::platform`].

#[cfg(umilib_feature = "platform-android")]
pub mod android;
#[cfg(umilib_feature = "platform-bench")]
pub mod bench;
#[cfg(umilib_feature = "platform-darwin")]
pub mod darwin;
#[cfg(umilib_feature = "platform-fuzz")]
pub mod fuzz;
#[cfg(umilib_feature = "platform-linux")]
pub mod linux;
#[cfg(umilib_feature = "platform-native")]
pub mod native;
#[cfg(umilib_feature = "platform-runtime")]
pub mod runtime;
#[cfg(umilib_feature = "platform-unix")]
pub mod unix;
#[cfg(umilib_feature = "platform-windows")]
pub mod windows;

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "platform",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "platform-android")]
        android::MODULE,
        #[cfg(umilib_feature = "platform-bench")]
        bench::MODULE,
        #[cfg(umilib_feature = "platform-darwin")]
        darwin::MODULE,
        #[cfg(umilib_feature = "platform-fuzz")]
        fuzz::MODULE,
        #[cfg(umilib_feature = "platform-linux")]
        linux::MODULE,
        #[cfg(umilib_feature = "platform-native")]
        native::MODULE,
        #[cfg(umilib_feature = "platform-runtime")]
        runtime::MODULE,
        #[cfg(umilib_feature = "platform-unix")]
        unix::MODULE,
        #[cfg(umilib_feature = "platform-windows")]
        windows::MODULE,
    ],
};
