//! The block ciphers of GOST R 34.12-2015: Magma (64-bit blocks, RFC 8891)
//! and Kuznyechik (128-bit blocks, RFC 7801).

#[cfg(umilib_feature = "crypto-gost-kuznyechik")]
pub mod kuznyechik;
#[cfg(umilib_feature = "crypto-gost-magma")]
pub mod magma;
