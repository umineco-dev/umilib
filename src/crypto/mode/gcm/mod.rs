//! The Galois/Counter Mode (SP 800-38D): [`GCM`] and its hash [`GHASH`].

mod aead;
mod ghash;

pub use aead::GCM;
pub use ghash::GHASH;
