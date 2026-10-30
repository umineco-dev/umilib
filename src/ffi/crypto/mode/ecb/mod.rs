//! The C ABI of [`crate::crypto::mode::ecb`].

use crate::crypto::mode::ecb::ECB;
use crate::ffi::crypto::{BlockCipher64, BlockCipher128, BlockCipherChoice};
use crate::ffi::{Definition, Module, Pointer, Status, ToStatus, Type, Value};

/// [`ECB`] over a block cipher of the registry.
#[derive(Clone, Debug)]
// The enum lives behind a handle: boxing the variants would add an allocation.
#[allow(clippy::large_enum_variant)]
pub enum ECBState {
    Block128(ECB<BlockCipher128>),
    Block64(ECB<BlockCipher64>),
}

impl Value for ECBState {
    const TYPE: Type = Type::Named("umilib_crypto_mode_ecb_ECB");
}

crate::ffi_functions! {
    /// Creates ECB over the cipher whose C type is named by the UTF-8 text at `cipher`, such as
    /// `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key`; fails with InvalidArgument if
    /// that cipher is unknown or not enabled.
    pub unsafe extern "C" fn umilib_crypto_mode_ecb_ecb_new(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, out: *mut *mut ECBState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let state = match BlockCipherChoice::new(cipher, key)? {
                BlockCipherChoice::Block128(cipher) => ECBState::Block128(ECB::new(cipher)),
                BlockCipherChoice::Block64(cipher) => ECBState::Block64(ECB::new(cipher)),
            };
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Releases the state, zeroizing it. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_mode_ecb_ecb_free(state: *mut ECBState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`.
    pub unsafe extern "C" fn umilib_crypto_mode_ecb_ecb_clone(state: *const ECBState, out: *mut *mut ECBState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Encrypts the `length` bytes at `data` in place, a whole number of blocks.
    pub unsafe extern "C" fn umilib_crypto_mode_ecb_ecb_encrypt(state: *const ECBState, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte range.
            let state = unsafe { Pointer::reference(state) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            match state {
                ECBState::Block128(ecb) => ecb.encrypt(data),
                ECBState::Block64(ecb) => ecb.encrypt(data),
            }
            .map_err(|error| error.to_status())
        })())
    }

    /// Decrypts the `length` bytes at `data` in place, a whole number of blocks.
    pub unsafe extern "C" fn umilib_crypto_mode_ecb_ecb_decrypt(state: *const ECBState, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte range.
            let state = unsafe { Pointer::reference(state) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            match state {
                ECBState::Block128(ecb) => ecb.decrypt(data),
                ECBState::Block64(ecb) => ecb.decrypt(data),
            }
            .map_err(|error| error.to_status())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ecb",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_mode_ecb_ECB",
        documentation: " ECB over a block cipher chosen by name; every block is encrypted alone.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
