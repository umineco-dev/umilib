//! The C ABI of [`crate::crypto::mode::cbc`].

use crate::crypto::mode::cbc::CBC;
use crate::ffi::crypto::{BlockCipher64, BlockCipher128, BlockCipherChoice, CryptoInput};
use crate::ffi::{Definition, Module, Pointer, Status, ToStatus, Type, Value};

/// [`CBC`] over a block cipher of the registry.
#[derive(Clone, Debug)]
// The enum lives behind a handle: boxing the variants would add an allocation.
#[allow(clippy::large_enum_variant)]
pub enum CBCState {
    Block128(CBC<BlockCipher128>),
    Block64(CBC<BlockCipher64>),
}

impl Value for CBCState {
    const TYPE: Type = Type::Named("umilib_crypto_mode_cbc_CBC");
}

crate::ffi_functions! {
    /// Creates CBC over the cipher whose C type is named by the UTF-8 text at `cipher`, such as
    /// `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key` and the IV of one block at `iv`;
    /// fails with InvalidArgument if that cipher is unknown or not enabled.
    pub unsafe extern "C" fn umilib_crypto_mode_cbc_cbc_new(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, iv: *const u8, iv_length: usize, out: *mut *mut CBCState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let iv = unsafe { Pointer::slice(iv, iv_length) }?;
            let state = match BlockCipherChoice::new(cipher, key)? {
                BlockCipherChoice::Block128(cipher) => CBCState::Block128(CBC::new(cipher, CryptoInput::nonce(iv)?)),
                BlockCipherChoice::Block64(cipher) => CBCState::Block64(CBC::new(cipher, CryptoInput::nonce(iv)?)),
            };
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Releases the state, zeroizing it. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_mode_cbc_cbc_free(state: *mut CBCState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`; the copy continues from the same point of the data.
    pub unsafe extern "C" fn umilib_crypto_mode_cbc_cbc_clone(state: *const CBCState, out: *mut *mut CBCState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Encrypts the `length` bytes at `data` in place, a whole number of blocks, continuing the chain.
    pub unsafe extern "C" fn umilib_crypto_mode_cbc_cbc_encrypt(state: *mut CBCState, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte range.
            let state = unsafe { Pointer::reference_mut(state) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            match state {
                CBCState::Block128(mode) => mode.encrypt(data),
                CBCState::Block64(mode) => mode.encrypt(data),
            }
            .map_err(|error| error.to_status())
        })())
    }

    /// Decrypts the `length` bytes at `data` in place, a whole number of blocks, continuing the chain.
    pub unsafe extern "C" fn umilib_crypto_mode_cbc_cbc_decrypt(state: *mut CBCState, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte range.
            let state = unsafe { Pointer::reference_mut(state) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            match state {
                CBCState::Block128(mode) => mode.decrypt(data),
                CBCState::Block64(mode) => mode.decrypt(data),
            }
            .map_err(|error| error.to_status())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "cbc",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_mode_cbc_CBC",
        documentation: " CBC over a block cipher chosen by name, chaining across calls.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
