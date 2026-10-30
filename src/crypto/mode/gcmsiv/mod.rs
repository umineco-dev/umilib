//! The nonce misuse-resistant GCM-SIV mode (RFC 8452): [`GCMSIV`] and its
//! hash [`POLYVAL`].

mod aead;
mod polyval;

pub use aead::GCMSIV;
pub use polyval::POLYVAL;
