//! The C ABI of [`crate::crypto::rc2`].

use crate::crypto::rc2::RC2;
use crate::ffi::{Module, Pointer, Status, ToStatus};

/// [`RC2`].
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod rc2 {
    crate::ffi_block_cipher!(
        crate::crypto::rc2::RC2,
        "umilib_crypto_rc2_rc2",
        "umilib_crypto_rc2_RC2",
        "RC2 (RFC 2268): a key of 1 to 128 bytes and 64-bit blocks; _new takes 8 effective bits per key byte."
    );
}

crate::ffi_functions! {
    const EFFECTIVE;
    /// Creates RC2 with the `key_length` bytes at `key` (1 to 128) and `effective_bits` effective key
    /// bits (1 to 1024, RFC 2268 section 2).
    pub unsafe extern "C" fn umilib_crypto_rc2_rc2_new_with_effective_bits(key: *const u8, key_length: usize, effective_bits: usize, out: *mut *mut RC2) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let cipher = RC2::new(key, effective_bits).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, cipher) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "rc2",
    definitions: &[rc2::DEFINITION],
    functions: &crate::ffi::Function::concat::<{ rc2::FUNCTIONS.len() + EFFECTIVE.len() }>(&[
        rc2::FUNCTIONS,
        EFFECTIVE,
    ]),
    modules: &[],
};
