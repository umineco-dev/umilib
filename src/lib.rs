//! Umineco Library.
//!
//! Every module is selected by a Cargo feature whose name is the module path
//! joined by `-`: the feature `platform-bench` enables `umilib::platform::bench`.
//! A parent module is compiled whenever any of its descendants is enabled.
//!
//! Everything except [`platform`] is `no_std` and depends only on `core` and
//! `alloc`. [`platform`] is the only part that uses `std`.

#![no_std]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::upper_case_acronyms)]

extern crate alloc;
#[cfg(umilib_feature = "platform")]
extern crate std;

/// The version of this library, as written in `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(umilib_feature = "auth")]
pub mod auth;
#[cfg(umilib_feature = "bytes")]
pub mod bytes;
#[cfg(umilib_feature = "calendar")]
pub mod calendar;
#[cfg(umilib_feature = "codec")]
pub mod codec;
#[cfg(umilib_feature = "crypto")]
pub mod crypto;
#[cfg(umilib_feature = "ffi")]
#[allow(unsafe_code)]
pub mod ffi;
#[cfg(any(umilib_feature = "hash", umilib_feature = "crypto-hmac"))]
pub mod hash;
#[cfg(umilib_feature = "math")]
pub mod math;
#[cfg(umilib_feature = "platform")]
#[allow(unsafe_code)]
pub mod platform;
#[cfg(umilib_feature = "protocol")]
pub mod protocol;
#[cfg(umilib_feature = "runtime")]
#[allow(unsafe_code)]
pub mod runtime;
#[cfg(umilib_feature = "secret")]
#[allow(unsafe_code)]
pub mod secret;
#[cfg(umilib_feature = "service")]
pub mod service;
