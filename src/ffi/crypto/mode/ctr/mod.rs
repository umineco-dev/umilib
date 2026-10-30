//! The C ABI of [`crate::crypto::mode::ctr`].

use crate::crypto::StreamCipher;
use crate::crypto::mode::ctr::CTR;
use crate::ffi::crypto::{BlockCipher64, BlockCipher128, BlockCipherChoice, CryptoInput};
use crate::ffi::{Definition, Module, Pointer, Status, ToStatus, Type, U128, Value};

/// [`CTR`] over a block cipher of the registry.
#[derive(Clone, Debug)]
// The enum lives behind a handle: boxing the variants would add an allocation.
#[allow(clippy::large_enum_variant)]
pub enum CTRState {
    Block128(CTR<BlockCipher128>),
    Block64(CTR<BlockCipher64>),
}

impl Value for CTRState {
    const TYPE: Type = Type::Named("umilib_crypto_mode_ctr_CTR");
}

crate::ffi_functions! {
    /// Creates CTR over the cipher whose C type is named by the UTF-8 text at `cipher`, such as
    /// `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key` and the initial counter block at `initial`;
    /// fails with InvalidArgument if that cipher is unknown or not enabled.
    pub unsafe extern "C" fn umilib_crypto_mode_ctr_ctr_new(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, initial: *const u8, initial_length: usize, out: *mut *mut CTRState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let initial = unsafe { Pointer::slice(initial, initial_length) }?;
            let state = match BlockCipherChoice::new(cipher, key)? {
                BlockCipherChoice::Block128(cipher) => CTRState::Block128(CTR::new(cipher, CryptoInput::nonce(initial)?)),
                BlockCipherChoice::Block64(cipher) => CTRState::Block64(CTR::new(cipher, CryptoInput::nonce(initial)?)),
            };
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Creates CTR as `umilib_crypto_mode_ctr_ctr_new`, with only the last `counter_bits` bits (1 to 8 × the block size)
    /// of the initial block counting.
    pub unsafe extern "C" fn umilib_crypto_mode_ctr_ctr_with_counter_bits(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, initial: *const u8, initial_length: usize, counter_bits: u32, out: *mut *mut CTRState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let initial = unsafe { Pointer::slice(initial, initial_length) }?;
            let state = match BlockCipherChoice::new(cipher, key)? {
                BlockCipherChoice::Block128(cipher) => CTR::with_counter_bits(cipher, CryptoInput::nonce(initial)?, counter_bits).map(CTRState::Block128),
                BlockCipherChoice::Block64(cipher) => CTR::with_counter_bits(cipher, CryptoInput::nonce(initial)?, counter_bits).map(CTRState::Block64),
            }
            .map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Releases the state, zeroizing it. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_mode_ctr_ctr_free(state: *mut CTRState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`; the copy continues from the same point of the data.
    pub unsafe extern "C" fn umilib_crypto_mode_ctr_ctr_clone(state: *const CTRState, out: *mut *mut CTRState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Xors the next `length` bytes of the key stream into the bytes at `data`; fails with LimitExceeded, changing nothing, if the counter would wrap.
    pub unsafe extern "C" fn umilib_crypto_mode_ctr_ctr_apply_keystream(state: *mut CTRState, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte range.
            let state = unsafe { Pointer::reference_mut(state) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            match state {
                CTRState::Block128(mode) => mode.apply_keystream(data),
                CTRState::Block64(mode) => mode.apply_keystream(data),
            }
            .map_err(|error| error.to_status())
        })())
    }

    /// Writes into `has_value` whether the bytes of key stream left before the counter runs out fit in
    /// 128 bits (not for counters of 124 bits or more with 16-byte blocks) and, if so, that number into
    /// `out` (0 otherwise).
    pub unsafe extern "C" fn umilib_crypto_mode_ctr_ctr_remaining_bytes(state: *const CTRState, has_value: *mut bool, out: *mut U128) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let state = unsafe { Pointer::reference(state) }?;
            if has_value.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let remaining = match state {
                CTRState::Block128(mode) => mode.remaining_bytes(),
                CTRState::Block64(mode) => mode.remaining_bytes(),
            };
            unsafe { Pointer::write(has_value, remaining.is_some()) }?;
            unsafe { Pointer::write(out, U128::from(remaining.unwrap_or(0))) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ctr",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_mode_ctr_CTR",
        documentation: " CTR over a block cipher chosen by name: a stream cipher that refuses to repeat its counter.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
