//! The C ABI of [`crate::crypto`].
//!
//! The types generic over a hash function `H` are exported once, and C
//! selects `H` by the C type name of its hash type, such as
//! `umilib_hash_sha_v2_SHA256`, among those of
//! [`ffi_digest_algorithms!`](crate::ffi_digest_algorithms) whose features
//! are enabled; with none enabled, their constructors fail with InvalidArgument.
//!
//! The types generic over a block cipher `C` (the modes, CMAC) are exported
//! once for each block size, and C selects `C` by the C type name of its
//! type, such as `umilib_crypto_aes_AES128`, among those of
//! [`ffi_block_ciphers!`](crate::ffi_block_ciphers) whose features are
//! enabled; [`BlockCipher128`] and [`BlockCipher64`] hold the chosen cipher.
//! Fixed-length arguments are checked by [`CryptoInput`].

mod aead;
mod block_cipher;
mod error;
mod input;
#[cfg(umilib_feature = "crypto-random")]
mod key_agreement;
#[cfg(umilib_feature = "crypto-random")]
mod key_encapsulation;
mod mac;
#[cfg(all(umilib_feature = "hash-sha-v2", umilib_feature = "hash-sha-v3"))]
mod pre_hash;
mod prf;
#[cfg(umilib_feature = "crypto-random")]
mod registry;
#[cfg(umilib_feature = "crypto-random")]
mod signature_scheme;
mod stream_cipher;

pub use aead::AEADState;
pub use block_cipher::{BlockCipher64, BlockCipher128, BlockCipherChoice, BlockData};
pub use error::CryptoStatus;
pub use input::CryptoInput;
#[cfg(umilib_feature = "crypto-random")]
pub use key_agreement::{
    KeyAgreementAgree, KeyAgreementCall, KeyAgreementCheckPrivate, KeyAgreementCheckPublic, KeyAgreementGenerate,
    KeyAgreementPublicKey, KeyAgreementSizes,
};
#[cfg(umilib_feature = "crypto-random")]
pub use key_encapsulation::{
    KeyEncapsulationCall, KeyEncapsulationCheckDecapsulation, KeyEncapsulationCheckEncapsulation,
    KeyEncapsulationDecapsulate, KeyEncapsulationEncapsulate, KeyEncapsulationEncapsulationKey,
    KeyEncapsulationGenerate, KeyEncapsulationSizes,
};
pub use mac::MACState;
#[cfg(all(umilib_feature = "hash-sha-v2", umilib_feature = "hash-sha-v3"))]
pub use pre_hash::{PreHashCall, PreHashRegistry};
#[cfg(umilib_feature = "crypto-random")]
pub use signature_scheme::{
    SignatureSchemeCall, SignatureSchemeCheckSigning, SignatureSchemeCheckVerifying, SignatureSchemeGenerate,
    SignatureSchemeSign, SignatureSchemeSizes, SignatureSchemeVerify, SignatureSchemeVerifyingKey,
};

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

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "crypto",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "crypto-aegis")]
        aegis::MODULE,
        #[cfg(umilib_feature = "crypto-aes")]
        aes::MODULE,
        #[cfg(umilib_feature = "crypto-argon2")]
        argon2::MODULE,
        #[cfg(umilib_feature = "crypto-aria")]
        aria::MODULE,
        #[cfg(umilib_feature = "crypto-ascon")]
        ascon::MODULE,
        #[cfg(umilib_feature = "crypto-camellia")]
        camellia::MODULE,
        #[cfg(umilib_feature = "crypto-chacha20")]
        chacha20::MODULE,
        #[cfg(umilib_feature = "crypto-chacha20poly1305")]
        chacha20poly1305::MODULE,
        #[cfg(umilib_feature = "crypto-cmac")]
        cmac::MODULE,
        #[cfg(umilib_feature = "crypto-concatkdf")]
        concatkdf::MODULE,
        #[cfg(umilib_feature = "crypto-curve")]
        curve::MODULE,
        #[cfg(umilib_feature = "crypto-des")]
        des::MODULE,
        #[cfg(umilib_feature = "crypto-dh")]
        dh::MODULE,
        #[cfg(umilib_feature = "crypto-dragonfly")]
        dragonfly::MODULE,
        #[cfg(umilib_feature = "crypto-dsa")]
        dsa::MODULE,
        #[cfg(umilib_feature = "crypto-eccsi")]
        eccsi::MODULE,
        #[cfg(umilib_feature = "crypto-ecdh")]
        ecdh::MODULE,
        #[cfg(umilib_feature = "crypto-ecdsa")]
        ecdsa::MODULE,
        #[cfg(umilib_feature = "crypto-eddsa")]
        eddsa::MODULE,
        #[cfg(umilib_feature = "crypto-gost")]
        gost::MODULE,
        #[cfg(umilib_feature = "crypto-gostr3410")]
        gostr3410::MODULE,
        #[cfg(umilib_feature = "crypto-hkdf")]
        hkdf::MODULE,
        #[cfg(umilib_feature = "crypto-hmac")]
        hmac::MODULE,
        #[cfg(umilib_feature = "crypto-hpke")]
        hpke::MODULE,
        #[cfg(umilib_feature = "crypto-hybrid")]
        hybrid::MODULE,
        #[cfg(umilib_feature = "crypto-ibs")]
        ibs::MODULE,
        #[cfg(umilib_feature = "crypto-idea")]
        idea::MODULE,
        #[cfg(umilib_feature = "crypto-kbkdf")]
        kbkdf::MODULE,
        #[cfg(umilib_feature = "crypto-kdftree")]
        kdftree::MODULE,
        #[cfg(umilib_feature = "crypto-mldsa")]
        mldsa::MODULE,
        #[cfg(umilib_feature = "crypto-mlkem")]
        mlkem::MODULE,
        #[cfg(umilib_feature = "crypto-mode")]
        mode::MODULE,
        #[cfg(umilib_feature = "crypto-pbkdf2")]
        pbkdf2::MODULE,
        #[cfg(umilib_feature = "crypto-poly1305")]
        poly1305::MODULE,
        #[cfg(umilib_feature = "crypto-random")]
        random::MODULE,
        #[cfg(umilib_feature = "crypto-rc2")]
        rc2::MODULE,
        #[cfg(umilib_feature = "crypto-rc4")]
        rc4::MODULE,
        #[cfg(umilib_feature = "crypto-rsa")]
        rsa::MODULE,
        #[cfg(umilib_feature = "crypto-scrypt")]
        scrypt::MODULE,
        #[cfg(umilib_feature = "crypto-seed")]
        seed::MODULE,
        #[cfg(umilib_feature = "crypto-slhdsa")]
        slhdsa::MODULE,
        #[cfg(umilib_feature = "crypto-sm2")]
        sm2::MODULE,
        #[cfg(umilib_feature = "crypto-sm4")]
        sm4::MODULE,
        #[cfg(umilib_feature = "crypto-sm9")]
        sm9::MODULE,
        #[cfg(umilib_feature = "crypto-srp")]
        srp::MODULE,
    ],
};
