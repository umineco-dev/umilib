//! SHA-2 (FIPS 180-4): SHA-224 and SHA-256 on 32-bit words, and SHA-384,
//! SHA-512, SHA-512/224 and SHA-512/256 on 64-bit words.

mod sha256;
mod sha512;

pub use sha256::{SHA224, SHA256};
pub use sha512::{SHA384, SHA512, SHA512_224, SHA512_256};
