//! The C ABI of [`crate::crypto::mode::cfb`].

use crate::crypto::mode::cfb::{CFB, CFB1, CFB8};
use crate::ffi::crypto::{BlockCipher64, BlockCipher128, BlockCipherChoice, CryptoInput};
use crate::ffi::{Definition, Module, Pointer, Status, ToStatus, Type, Value};

/// [`CFB`] over a block cipher of the registry.
#[derive(Clone, Debug)]
// The enum lives behind a handle: boxing the variants would add an allocation.
#[allow(clippy::large_enum_variant)]
pub enum CFBState {
    Block128(CFB<BlockCipher128>),
    Block64(CFB<BlockCipher64>),
}

impl Value for CFBState {
    const TYPE: Type = Type::Named("umilib_crypto_mode_cfb_CFB");
}

/// [`CFB8`] over a block cipher of the registry.
#[derive(Clone, Debug)]
// The enum lives behind a handle: boxing the variants would add an allocation.
#[allow(clippy::large_enum_variant)]
pub enum CFB8State {
    Block128(CFB8<BlockCipher128>),
    Block64(CFB8<BlockCipher64>),
}

impl Value for CFB8State {
    const TYPE: Type = Type::Named("umilib_crypto_mode_cfb_CFB8");
}

/// [`CFB1`] over a block cipher of the registry.
#[derive(Clone, Debug)]
// The enum lives behind a handle: boxing the variants would add an allocation.
#[allow(clippy::large_enum_variant)]
pub enum CFB1State {
    Block128(CFB1<BlockCipher128>),
    Block64(CFB1<BlockCipher64>),
}

impl Value for CFB1State {
    const TYPE: Type = Type::Named("umilib_crypto_mode_cfb_CFB1");
}

crate::ffi_functions! {
    /// Creates CFB over the cipher whose C type is named by the UTF-8 text at `cipher`, such as
    /// `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key` and the IV of one block at `iv`;
    /// fails with InvalidArgument if that cipher is unknown or not enabled.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb_new(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, iv: *const u8, iv_length: usize, out: *mut *mut CFBState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let iv = unsafe { Pointer::slice(iv, iv_length) }?;
            let state = match BlockCipherChoice::new(cipher, key)? {
                BlockCipherChoice::Block128(cipher) => CFBState::Block128(CFB::new(cipher, CryptoInput::nonce(iv)?)),
                BlockCipherChoice::Block64(cipher) => CFBState::Block64(CFB::new(cipher, CryptoInput::nonce(iv)?)),
            };
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Releases the state, zeroizing it. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb_free(state: *mut CFBState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`; the copy continues from the same point of the data.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb_clone(state: *const CFBState, out: *mut *mut CFBState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Encrypts the `length` bytes at `data` in place, continuing the stream.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb_encrypt(state: *mut CFBState, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte range.
            let state = unsafe { Pointer::reference_mut(state) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            match state {
                CFBState::Block128(mode) => mode.encrypt(data),
                CFBState::Block64(mode) => mode.encrypt(data),
            }
            Ok(())
        })())
    }

    /// Decrypts the `length` bytes at `data` in place, continuing the stream.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb_decrypt(state: *mut CFBState, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte range.
            let state = unsafe { Pointer::reference_mut(state) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            match state {
                CFBState::Block128(mode) => mode.decrypt(data),
                CFBState::Block64(mode) => mode.decrypt(data),
            }
            Ok(())
        })())
    }

    /// Creates CFB8 over the cipher whose C type is named by the UTF-8 text at `cipher`, such as
    /// `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key` and the IV of one block at `iv`;
    /// fails with InvalidArgument if that cipher is unknown or not enabled.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb8_new(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, iv: *const u8, iv_length: usize, out: *mut *mut CFB8State) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let iv = unsafe { Pointer::slice(iv, iv_length) }?;
            let state = match BlockCipherChoice::new(cipher, key)? {
                BlockCipherChoice::Block128(cipher) => CFB8State::Block128(CFB8::new(cipher, CryptoInput::nonce(iv)?)),
                BlockCipherChoice::Block64(cipher) => CFB8State::Block64(CFB8::new(cipher, CryptoInput::nonce(iv)?)),
            };
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Releases the state, zeroizing it. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb8_free(state: *mut CFB8State) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`; the copy continues from the same point of the data.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb8_clone(state: *const CFB8State, out: *mut *mut CFB8State) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Encrypts the `length` bytes at `data` in place, continuing the stream.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb8_encrypt(state: *mut CFB8State, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte range.
            let state = unsafe { Pointer::reference_mut(state) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            match state {
                CFB8State::Block128(mode) => mode.encrypt(data),
                CFB8State::Block64(mode) => mode.encrypt(data),
            }
            Ok(())
        })())
    }

    /// Decrypts the `length` bytes at `data` in place, continuing the stream.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb8_decrypt(state: *mut CFB8State, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte range.
            let state = unsafe { Pointer::reference_mut(state) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            match state {
                CFB8State::Block128(mode) => mode.decrypt(data),
                CFB8State::Block64(mode) => mode.decrypt(data),
            }
            Ok(())
        })())
    }

    /// Creates CFB1 over the cipher whose C type is named by the UTF-8 text at `cipher`, such as
    /// `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key` and the IV of one block at `iv`;
    /// fails with InvalidArgument if that cipher is unknown or not enabled.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb1_new(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, iv: *const u8, iv_length: usize, out: *mut *mut CFB1State) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let iv = unsafe { Pointer::slice(iv, iv_length) }?;
            let state = match BlockCipherChoice::new(cipher, key)? {
                BlockCipherChoice::Block128(cipher) => CFB1State::Block128(CFB1::new(cipher, CryptoInput::nonce(iv)?)),
                BlockCipherChoice::Block64(cipher) => CFB1State::Block64(CFB1::new(cipher, CryptoInput::nonce(iv)?)),
            };
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Releases the state, zeroizing it. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb1_free(state: *mut CFB1State) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`; the copy continues from the same point of the data.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb1_clone(state: *const CFB1State, out: *mut *mut CFB1State) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Encrypts the first `bits` bits (most significant first) of the `length` bytes at `data` in place.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb1_encrypt_bits(state: *mut CFB1State, data: *mut u8, length: usize, bits: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte range.
            let state = unsafe { Pointer::reference_mut(state) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            match state {
                CFB1State::Block128(mode) => mode.encrypt_bits(data, bits),
                CFB1State::Block64(mode) => mode.encrypt_bits(data, bits),
            }
            .map_err(|error| error.to_status())
        })())
    }

    /// Decrypts the first `bits` bits (most significant first) of the `length` bytes at `data` in place.
    pub unsafe extern "C" fn umilib_crypto_mode_cfb_cfb1_decrypt_bits(state: *mut CFB1State, data: *mut u8, length: usize, bits: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte range.
            let state = unsafe { Pointer::reference_mut(state) }?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            match state {
                CFB1State::Block128(mode) => mode.decrypt_bits(data, bits),
                CFB1State::Block64(mode) => mode.decrypt_bits(data, bits),
            }
            .map_err(|error| error.to_status())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "cfb",
    definitions: &[
        Definition::Opaque {
            name: "umilib_crypto_mode_cfb_CFB",
            documentation: " CFB with segments of a whole block over a block cipher chosen by name.",
        },
        Definition::Opaque {
            name: "umilib_crypto_mode_cfb_CFB8",
            documentation: " CFB with 8-bit segments over a block cipher chosen by name.",
        },
        Definition::Opaque {
            name: "umilib_crypto_mode_cfb_CFB1",
            documentation: " CFB with 1-bit segments over a block cipher chosen by name.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
