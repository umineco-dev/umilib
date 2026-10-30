//! The C ABI of [`crate::crypto::dh`].
//!
//! [`DH<G>`](crate::crypto::dh::DH) is exported once (`umilib_crypto_dh_dh_*`)
//! for every group, named by the C type name of the group type, such as
//! `umilib_crypto_dh_FFDHE2048`. Keys and shared secrets are the encodings
//! of [`KeyAgreement`](crate::crypto::KeyAgreement).

use crate::ffi::Module;

/// [`DH`](crate::crypto::dh::DH).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod dh {
    use crate::crypto::dh::{
        DH, FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192, MODP1536, MODP2048, MODP3072, MODP4096, MODP6144,
        MODP8192,
    };
    use crate::ffi::crypto::KeyAgreementCall;
    use crate::ffi::{Pointer, Status};

    /// Calls `call` with `DH<G>` for the group named `names.0`; `None` if it is unknown.
    pub fn scheme<V: KeyAgreementCall>(names: (&str,), call: V) -> Option<V::Output> {
        Some(match names.0 {
            "umilib_crypto_dh_FFDHE2048" => call.call::<DH<FFDHE2048>>(),
            "umilib_crypto_dh_FFDHE3072" => call.call::<DH<FFDHE3072>>(),
            "umilib_crypto_dh_FFDHE4096" => call.call::<DH<FFDHE4096>>(),
            "umilib_crypto_dh_FFDHE6144" => call.call::<DH<FFDHE6144>>(),
            "umilib_crypto_dh_FFDHE8192" => call.call::<DH<FFDHE8192>>(),
            "umilib_crypto_dh_MODP1536" => call.call::<DH<MODP1536>>(),
            "umilib_crypto_dh_MODP2048" => call.call::<DH<MODP2048>>(),
            "umilib_crypto_dh_MODP3072" => call.call::<DH<MODP3072>>(),
            "umilib_crypto_dh_MODP4096" => call.call::<DH<MODP4096>>(),
            "umilib_crypto_dh_MODP6144" => call.call::<DH<MODP6144>>(),
            "umilib_crypto_dh_MODP8192" => call.call::<DH<MODP8192>>(),
            _ => return None,
        })
    }

    crate::ffi_key_agreement!("umilib_crypto_dh_dh", "DH in the group named by `group`", [group group_length]);
}

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "dh", definitions: &[], functions: dh::FUNCTIONS, modules: &[] };
