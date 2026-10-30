//! The platform-specific part of umilib: everything that needs an operating
//! system. This is the only module tree that uses `std`.
//!
//! The modules of an operating system (`unix`, `linux`, `android`,
//! `darwin`, `windows`) are compiled on that system only (`linux` on Linux
//! and Android, `unix` on all three Unix-like ones); `native` gives the
//! types of the system it is compiled for under one set of names.

#[cfg(all(umilib_feature = "platform-android", target_os = "android"))]
pub mod android;
#[cfg(umilib_feature = "platform-bench")]
pub mod bench;
#[cfg(all(umilib_feature = "platform-darwin", target_vendor = "apple"))]
pub mod darwin;
#[cfg(umilib_feature = "platform-fuzz")]
pub mod fuzz;
#[cfg(all(umilib_feature = "platform-linux", any(target_os = "linux", target_os = "android")))]
pub mod linux;
#[cfg(umilib_feature = "platform-native")]
pub mod native;
#[cfg(all(
    umilib_feature = "platform-runtime",
    any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)
))]
pub mod runtime;
#[cfg(all(umilib_feature = "platform-unix", any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
pub mod unix;
#[cfg(all(umilib_feature = "platform-windows", windows))]
pub mod windows;
