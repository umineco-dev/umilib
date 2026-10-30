//! Tests of `umilib::ffi`: the manifest is consistent, `include/` matches it,
//! and the exported functions behave like the Rust API they mirror.
//!
//! Set `UMILIB_BLESS=1` to rewrite `include/` from the manifest.

#![allow(clippy::upper_case_acronyms)]

mod manifest;

#[cfg(all(umilib_feature = "auth-oauth", umilib_feature = "hash-sha-v2"))]
mod auth_oauth;
#[cfg(umilib_feature = "bytes")]
mod bytes;
#[cfg(umilib_feature = "calendar")]
mod calendar;
#[cfg(umilib_all_features)]
mod codec;
#[cfg(all(umilib_feature = "crypto-random", umilib_feature = "hash-sha-v2"))]
mod crypto;
#[cfg(any(
    umilib_feature = "hash-sha-v2",
    umilib_feature = "hash-sha-v3",
    umilib_feature = "hash-blake",
    umilib_feature = "hash-siphash",
    all(
        umilib_feature = "hash-xxhash-xxh32",
        umilib_feature = "hash-xxhash-xxh64",
        umilib_feature = "hash-xxhash-xxh3"
    ),
    umilib_feature = "hash-crc"
))]
mod hash;
#[cfg(umilib_feature = "math-bigint")]
mod math;
#[cfg(any(umilib_feature = "platform-bench", umilib_feature = "platform-fuzz", umilib_feature = "platform-native"))]
mod platform;
#[cfg(umilib_feature = "protocol-tcp")]
mod protocol;
#[cfg(umilib_feature = "runtime")]
mod runtime;
#[cfg(umilib_feature = "secret")]
mod secret;

#[cfg(umilib_all_features)]
#[path = "../common/vectors.rs"]
mod vectors;

use std::ffi::CStr;

use umilib::ffi::Status;

/// Helpers shared by the tests of every module.
struct Check;

impl Check {
    /// Asserts that a fallible function succeeded.
    fn ok(status: *const Status) {
        if let Some(status) = unsafe { status.as_ref() } {
            panic!("unexpected status {:?}/{:?}", status.domain(), status.name());
        }
    }

    /// The bytes of hexadecimal `text`.
    // Used by the tests of some features only.
    #[allow(dead_code)]
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
    }

    /// Asserts that a fallible function failed with `domain` and `name`.
    fn fails(status: *const Status, domain: &str, name: &str) {
        let status = unsafe { status.as_ref() }.expect("the function must fail");
        assert_eq!(status.domain(), CStr::from_bytes_with_nul(format!("{domain}\0").as_bytes()).unwrap());
        assert_eq!(status.name(), CStr::from_bytes_with_nul(format!("{name}\0").as_bytes()).unwrap());
        assert!(!status.message().is_empty());
    }
}
