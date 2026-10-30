//! Tests of `umilib::platform`.

#[cfg(umilib_feature = "platform-bench")]
mod bench;
#[cfg(umilib_feature = "platform-fuzz")]
mod fuzz;
#[cfg(all(
    umilib_feature = "platform-native",
    any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)
))]
mod native;
#[cfg(all(
    umilib_feature = "platform-runtime",
    any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)
))]
mod runtime;
#[cfg(all(
    umilib_feature = "platform-native",
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))
))]
mod unsupported;
