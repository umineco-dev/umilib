//! The C ABI of [`crate::crypto::des`].

use crate::crypto::des::DES;
use crate::ffi::{Module, Pointer, Status};

/// [`DES`].
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod des {
    crate::ffi_block_cipher!(
        crate::crypto::des::DES,
        "umilib_crypto_des_des",
        "umilib_crypto_des_DES",
        "DES (SP 800-67r2 section 2): a 64-bit key of 56 bits and 64-bit blocks; broken, for legacy data."
    );
}

/// [`TDES`](crate::crypto::des::TDES).
pub mod tdes {
    crate::ffi_block_cipher!(
        crate::crypto::des::TDES,
        "umilib_crypto_des_tdes",
        "umilib_crypto_des_TDES",
        "Triple DES (SP 800-67r2 section 3): a bundle of three keys (24 bytes) or two (16 bytes, Key3 = Key1); Key1 = Key2 or Key2 = Key3 is refused."
    );
}

crate::ffi_functions! {
    const WEAK;
    /// Writes into `out` whether the 8 bytes at `key` are a weak, semi-weak or possibly weak DES key
    /// (SP 800-67r2 section 3.3.2), ignoring the parity bits; fails with KeyLength for another length.
    pub unsafe extern "C" fn umilib_crypto_des_des_is_weak(key: *const u8, key_length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let key = crate::ffi::crypto::CryptoInput::key::<8>(unsafe { Pointer::slice(key, key_length) }?)?;
            unsafe { Pointer::write(out, DES::is_weak(key)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "des",
    definitions: &[des::DEFINITION, tdes::DEFINITION],
    functions: &crate::ffi::Function::concat::<{ des::FUNCTIONS.len() + tdes::FUNCTIONS.len() + WEAK.len() }>(&[
        des::FUNCTIONS,
        tdes::FUNCTIONS,
        WEAK,
    ]),
    modules: &[],
};
