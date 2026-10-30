//! Tests of `umilib::auth`.

#![allow(clippy::upper_case_acronyms)]

#[cfg(umilib_feature = "auth-cert")]
mod cert;
#[cfg(umilib_feature = "auth-oauth")]
mod oauth;
#[cfg(umilib_feature = "auth-sasl")]
mod sasl;
#[cfg(umilib_feature = "auth-totp")]
mod totp;

#[path = "../common/vectors.rs"]
mod vectors;

pub use vectors::{RFC, Vectors};
