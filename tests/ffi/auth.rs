//! The C ABI of `umilib::auth`.

#[cfg(all(umilib_feature = "auth-oauth", umilib_feature = "hash-sha-v2"))]
mod oauth;
