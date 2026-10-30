//! Cryptography: ciphers, authenticated encryption, message authentication,
//! key derivation and random generation.
//!
//! The interfaces every algorithm of a kind implements are here:
//! [`BlockCipher`] with [`KeyInit`], [`StreamCipher`], [`AEAD`] and [`MAC`],
//! with the errors of [`CryptoError`]. Their implementations are constant
//! time in their secret inputs and zeroize their keys when dropped (see
//! `.docs/constant-time.md`).

mod aead;
mod block_cipher;
mod error;
#[cfg(umilib_feature = "crypto-random")]
mod key_agreement;
#[cfg(umilib_feature = "crypto-random")]
mod key_encapsulation;
mod key_init;
mod mac;
#[cfg(all(umilib_feature = "hash-sha-v2", umilib_feature = "hash-sha-v3"))]
mod pre_hash;
#[cfg(umilib_feature = "crypto-random")]
mod signature_scheme;
mod stream_cipher;

pub use aead::AEAD;
pub use block_cipher::BlockCipher;
pub use error::CryptoError;
#[cfg(umilib_feature = "crypto-random")]
pub use key_agreement::KeyAgreement;
#[cfg(umilib_feature = "crypto-random")]
pub use key_encapsulation::KeyEncapsulation;
pub use key_init::KeyInit;
pub use mac::{MAC, PRF};
#[cfg(all(umilib_feature = "hash-sha-v2", umilib_feature = "hash-sha-v3"))]
pub use pre_hash::PreHash;
#[cfg(umilib_feature = "crypto-random")]
pub use signature_scheme::SignatureScheme;
pub use stream_cipher::StreamCipher;

#[cfg(umilib_feature = "crypto-aegis")]
pub mod aegis;
#[cfg(umilib_feature = "crypto-aes")]
pub mod aes;
#[cfg(umilib_feature = "crypto-argon2")]
pub mod argon2;
#[cfg(umilib_feature = "crypto-aria")]
pub mod aria;
#[cfg(umilib_feature = "crypto-ascon")]
pub mod ascon;
#[cfg(umilib_feature = "crypto-camellia")]
pub mod camellia;
#[cfg(umilib_feature = "crypto-chacha20")]
pub mod chacha20;
#[cfg(umilib_feature = "crypto-chacha20poly1305")]
pub mod chacha20poly1305;
#[cfg(umilib_feature = "crypto-cmac")]
pub mod cmac;
#[cfg(umilib_feature = "crypto-concatkdf")]
pub mod concatkdf;
#[cfg(umilib_feature = "crypto-curve")]
pub mod curve;
#[cfg(umilib_feature = "crypto-des")]
pub mod des;
#[cfg(umilib_feature = "crypto-dh")]
pub mod dh;
#[cfg(umilib_feature = "crypto-dragonfly")]
pub mod dragonfly;
#[cfg(umilib_feature = "crypto-dsa")]
pub mod dsa;
#[cfg(umilib_feature = "crypto-eccsi")]
pub mod eccsi;
#[cfg(umilib_feature = "crypto-ecdh")]
pub mod ecdh;
#[cfg(umilib_feature = "crypto-ecdsa")]
pub mod ecdsa;
#[cfg(umilib_feature = "crypto-eddsa")]
pub mod eddsa;
#[cfg(umilib_feature = "crypto-gost")]
pub mod gost;
#[cfg(umilib_feature = "crypto-gostr3410")]
pub mod gostr3410;
#[cfg(umilib_feature = "crypto-hkdf")]
pub mod hkdf;
#[cfg(umilib_feature = "crypto-hmac")]
pub mod hmac;
#[cfg(umilib_feature = "crypto-hpke")]
pub mod hpke;
#[cfg(umilib_feature = "crypto-hybrid")]
pub mod hybrid;
#[cfg(umilib_feature = "crypto-ibs")]
pub mod ibs;
#[cfg(umilib_feature = "crypto-idea")]
pub mod idea;
#[cfg(umilib_feature = "crypto-kbkdf")]
pub mod kbkdf;
#[cfg(umilib_feature = "crypto-kdftree")]
pub mod kdftree;
#[cfg(umilib_feature = "crypto-mldsa")]
pub mod mldsa;
#[cfg(umilib_feature = "crypto-mlkem")]
pub mod mlkem;
#[cfg(umilib_feature = "crypto-mode")]
pub mod mode;
#[cfg(umilib_feature = "crypto-pbkdf2")]
pub mod pbkdf2;
#[cfg(umilib_feature = "crypto-poly1305")]
pub mod poly1305;
#[cfg(umilib_feature = "crypto-random")]
pub mod random;
#[cfg(umilib_feature = "crypto-rc2")]
pub mod rc2;
#[cfg(umilib_feature = "crypto-rc4")]
pub mod rc4;
#[cfg(umilib_feature = "crypto-rsa")]
pub mod rsa;
#[cfg(umilib_feature = "crypto-scrypt")]
pub mod scrypt;
#[cfg(umilib_feature = "crypto-seed")]
pub mod seed;
#[cfg(umilib_feature = "crypto-slhdsa")]
pub mod slhdsa;
#[cfg(umilib_feature = "crypto-sm2")]
pub mod sm2;
#[cfg(umilib_feature = "crypto-sm4")]
pub mod sm4;
#[cfg(umilib_feature = "crypto-sm9")]
pub mod sm9;
#[cfg(umilib_feature = "crypto-srp")]
pub mod srp;
