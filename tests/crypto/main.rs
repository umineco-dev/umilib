//! Tests of `umilib::crypto` against the test vectors of the specifications.

#![allow(clippy::upper_case_acronyms)]

#[cfg(umilib_feature = "crypto-aegis")]
mod aegis;
#[cfg(umilib_feature = "crypto-aes")]
mod aes;
#[cfg(umilib_feature = "crypto-argon2")]
mod argon2;
#[cfg(all(umilib_feature = "crypto-aria", umilib_feature = "crypto-mode", umilib_feature = "crypto-cmac"))]
mod aria;
#[cfg(umilib_feature = "crypto-ascon")]
mod ascon;
#[cfg(all(umilib_feature = "crypto-camellia", umilib_feature = "crypto-mode", umilib_feature = "crypto-cmac"))]
mod camellia;
#[cfg(all(umilib_feature = "crypto-mode-ccm", umilib_feature = "crypto-aes"))]
mod ccm;
#[cfg(umilib_feature = "crypto-chacha20poly1305")]
mod chacha20;
#[cfg(all(umilib_feature = "crypto-cmac", umilib_feature = "crypto-aes"))]
mod cmac;
#[cfg(all(umilib_feature = "crypto-concatkdf", umilib_feature = "hash-sha-v2", umilib_feature = "hash-sha-v3"))]
mod concatkdf;
#[cfg(umilib_feature = "crypto-curve")]
mod curve;
#[cfg(all(umilib_feature = "crypto-des", umilib_feature = "crypto-mode"))]
mod des;
#[cfg(all(umilib_feature = "crypto-dh", umilib_feature = "hash-sha-v2"))]
mod dh;
#[cfg(all(umilib_feature = "crypto-dragonfly", umilib_feature = "crypto-curve-p256", umilib_feature = "hash-sha-v2"))]
mod dragonfly;
#[cfg(all(umilib_feature = "crypto-dsa", umilib_feature = "hash-sha"))]
mod dsa;
#[cfg(all(umilib_feature = "crypto-eccsi", umilib_feature = "crypto-curve-p256", umilib_feature = "hash-sha-v2"))]
mod eccsi;
#[cfg(all(umilib_feature = "crypto-ecdh", umilib_feature = "hash-sha-v2"))]
mod ecdh;
#[cfg(all(umilib_feature = "crypto-ecdsa", umilib_feature = "hash-sha"))]
mod ecdsa;
#[cfg(all(umilib_feature = "crypto-eddsa", umilib_feature = "crypto-ecdsa", umilib_feature = "hash-sha"))]
mod eddsa;
mod field;
#[cfg(all(umilib_feature = "crypto-mode-gcm", umilib_feature = "crypto-aes"))]
mod gcm;
#[cfg(all(umilib_feature = "crypto-mode-gcmsiv", umilib_feature = "crypto-aes"))]
mod gcmsiv;
#[cfg(umilib_feature = "crypto-gost")]
mod gost;
#[cfg(all(
    umilib_feature = "crypto-gostr3410",
    umilib_feature = "crypto-curve-gost",
    umilib_feature = "crypto-ecdsa",
    umilib_feature = "hash-sha",
    umilib_feature = "hash-streebog"
))]
mod gostr3410;
#[cfg(umilib_feature = "crypto-hmac")]
mod hmac;
#[cfg(all(
    umilib_feature = "crypto-hpke",
    umilib_feature = "crypto-curve-curve25519",
    umilib_feature = "crypto-curve-p256",
    umilib_feature = "crypto-curve-p521",
    umilib_feature = "crypto-mode-gcm",
    umilib_feature = "crypto-aes",
    umilib_feature = "crypto-chacha20poly1305",
    umilib_feature = "hash-sha-v2"
))]
mod hpke;
#[cfg(all(umilib_feature = "crypto-hybrid", umilib_feature = "hash-sha-v2"))]
mod hybrid;
#[cfg(all(umilib_feature = "crypto-ibs", umilib_feature = "hash-sha-v2"))]
mod ibs;
#[cfg(umilib_feature = "crypto-idea")]
mod idea;
#[cfg(all(
    umilib_feature = "crypto-hkdf",
    umilib_feature = "crypto-pbkdf2",
    umilib_feature = "crypto-kbkdf",
    umilib_feature = "crypto-kdftree",
    umilib_feature = "crypto-aes",
    umilib_feature = "crypto-des",
    umilib_feature = "crypto-cmac",
    umilib_feature = "hash-sha"
))]
mod kdf;
#[cfg(all(umilib_feature = "crypto-mode-kw", umilib_feature = "crypto-aes", umilib_feature = "crypto-des"))]
mod kw;
#[cfg(umilib_feature = "crypto-mldsa")]
mod mldsa;
#[cfg(all(umilib_feature = "crypto-mlkem", umilib_feature = "hash-sha-v2"))]
mod mlkem;
#[cfg(all(umilib_feature = "crypto-mode", umilib_feature = "crypto-aes"))]
mod mode;
#[cfg(umilib_feature = "crypto-random")]
mod random;
#[cfg(umilib_feature = "crypto-rc2")]
mod rc2;
#[cfg(umilib_feature = "crypto-rc4")]
mod rc4;
#[cfg(all(umilib_feature = "crypto-rsa", umilib_feature = "hash-sha"))]
mod rsa;
#[cfg(umilib_feature = "crypto-scrypt")]
mod scrypt;
#[cfg(all(umilib_feature = "crypto-seed", umilib_feature = "crypto-mode"))]
mod seed;
#[cfg(all(umilib_feature = "crypto-mode-siv", umilib_feature = "crypto-aes"))]
mod siv;
#[cfg(umilib_feature = "crypto-slhdsa")]
mod slhdsa;
#[cfg(all(umilib_feature = "crypto-sm2", umilib_feature = "crypto-ecdsa", umilib_feature = "hash-sha"))]
mod sm2;
#[cfg(all(umilib_feature = "crypto-sm4", umilib_feature = "crypto-mode"))]
mod sm4;
#[cfg(all(
    umilib_feature = "crypto-sm9",
    umilib_feature = "crypto-sm4",
    umilib_feature = "crypto-mode-cbc",
    umilib_feature = "hash-sm3",
    umilib_feature = "hash-sha-v2"
))]
mod sm9;
#[cfg(all(umilib_feature = "crypto-srp", umilib_feature = "hash-sha-v2"))]
mod srp;
#[cfg(all(
    umilib_feature = "crypto-cmac",
    umilib_feature = "crypto-mode-cbc",
    umilib_feature = "crypto-mode-ccm",
    umilib_feature = "crypto-mode-gcm"
))]
mod suite;
#[cfg(all(umilib_feature = "crypto-mode-xts", umilib_feature = "crypto-aes"))]
mod xts;

#[cfg(umilib_feature = "math-ec")]
#[path = "../common/ec.rs"]
mod ec_checks;
#[path = "../common/vectors.rs"]
mod vectors;

pub use vectors::{GMT, Json, Nessie, RFC, Record, Vectors, Wycheproof};
