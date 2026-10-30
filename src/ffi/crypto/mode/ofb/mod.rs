//! The C ABI of [`crate::crypto::mode::ofb`].

use crate::crypto::mode::ofb::OFB;
use crate::ffi::crypto::{BlockCipher64, BlockCipher128, BlockCipherChoice, CryptoInput};
use crate::ffi::{Definition, Module, Pointer, Status, Type, Value};

/// [`OFB`] over a block cipher of the registry.
#[derive(Clone, Debug)]
// The enum lives behind a handle: boxing the variants would add an allocation.
#[allow(clippy::large_enum_variant)]
pub enum OFBState {
    Block128(OFB<BlockCipher128>),
    Block64(OFB<BlockCipher64>),
}

impl Value for OFBState {
    const TYPE: Type = Type::Named("umilib_crypto_mode_ofb_OFB");
}

crate::ffi_functions! {
    /// Creates OFB over the cipher whose C type is named by the UTF-8 text at `cipher`, such as
    /// `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key` and the IV of one block at `iv`;
    /// fails with InvalidArgument if that cipher is unknown or not enabled.
    pub unsafe extern "C" fn umilib_crypto_mode_ofb_ofb_new(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, iv: *const u8, iv_length: usize, out: *mut *mut OFBState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let iv = unsafe { Pointer::slice(iv, iv_length) }?;
            let state = match BlockCipherChoice::new(cipher, key)? {
                BlockCipherChoice::Block128(cipher) => OFBState::Block128(OFB::new(cipher, CryptoInput::nonce(iv)?)),
                BlockCipherChoice::Block64(cipher) => OFBState::Block64(OFB::new(cipher, CryptoInput::nonce(iv)?)),
            };
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Releases the state, zeroizing it. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_mode_ofb_ofb_free(state: *mut OFBState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`; the copy continues from the same point of the data.
    pub unsafe extern "C" fn umilib_crypto_mode_ofb_ofb_clone(state: *const OFBState, out: *mut *mut OFBState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Xors the next `length` bytes of the key stream into the bytes at `data`.
    pub unsafe extern "C" fn umilib_crypto_mode_ofb_ofb_apply(state: *mut OFBState, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte range.
            let state = unsafe { Pointer::reference_mut(state) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            match state {
                OFBState::Block128(mode) => mode.apply(data),
                OFBState::Block64(mode) => mode.apply(data),
            }
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ofb",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_mode_ofb_OFB",
        documentation: " OFB over a block cipher chosen by name: a stream cipher.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
