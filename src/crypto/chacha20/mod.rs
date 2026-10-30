//! The ChaCha20 stream cipher (RFC 8439) and its extended-nonce variant
//! XChaCha20 (draft-irtf-cfrg-xchacha).

mod chacha;
mod xchacha;

pub use chacha::ChaCha20;
pub use xchacha::XChaCha20;
