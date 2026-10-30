//! The C ABI of [`crate::crypto::chacha20`].

use crate::crypto::chacha20::{ChaCha20, XChaCha20};
use crate::ffi::crypto::CryptoInput;
use crate::ffi::{Module, Pointer, Status, Type, U128, Value};
use crate::secret::Zeroize;

impl Value for ChaCha20 {
    const TYPE: Type = Type::Named("umilib_crypto_chacha20_ChaCha20");
}

impl Value for XChaCha20 {
    const TYPE: Type = Type::Named("umilib_crypto_chacha20_XChaCha20");
}

/// [`ChaCha20`].
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod chacha20 {
    use super::{ChaCha20, CryptoInput, Pointer, Status, U128};

    crate::ffi_functions! {
        const CONSTRUCTORS;
        /// Creates ChaCha20 (RFC 8439) with the 32-byte key at `key`, the 12-byte nonce at `nonce` and the
        /// initial 32-bit block counter `counter`.
        pub unsafe extern "C" fn umilib_crypto_chacha20_chacha20_new(key: *const u8, key_length: usize, nonce: *const u8, nonce_length: usize, counter: u32, out: *mut *mut ChaCha20) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable bytes and a writable pointer.
                let key = CryptoInput::key::<32>(unsafe { Pointer::slice(key, key_length) }?)?;
                let nonce = CryptoInput::nonce::<12>(unsafe { Pointer::slice(nonce, nonce_length) }?)?;
                unsafe { Pointer::write_handle(out, ChaCha20::new(key, nonce, counter)) }
            })())
        }

        /// Creates the original ChaCha20 with the 32-byte key at `key`, the 8-byte nonce at `nonce` and the
        /// initial 64-bit block counter `counter`.
        pub unsafe extern "C" fn umilib_crypto_chacha20_chacha20_with_64_bit_counter(key: *const u8, key_length: usize, nonce: *const u8, nonce_length: usize, counter: u64, out: *mut *mut ChaCha20) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable bytes and a writable pointer.
                let key = CryptoInput::key::<32>(unsafe { Pointer::slice(key, key_length) }?)?;
                let nonce = CryptoInput::nonce::<8>(unsafe { Pointer::slice(nonce, nonce_length) }?)?;
                unsafe { Pointer::write_handle(out, ChaCha20::with_64_bit_counter(key, nonce, counter)) }
            })())
        }
    }

    crate::ffi_stream_cipher!(ChaCha20, "umilib_crypto_chacha20_chacha20", COMMON);

    crate::ffi_functions! {
        const FUNCTIONS_OF_TYPE;
        /// Writes the bytes of key stream left before the counter wraps into `out`.
        pub unsafe extern "C" fn umilib_crypto_chacha20_chacha20_remaining_bytes(cipher: *const ChaCha20, out: *mut U128) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes a valid handle and a writable pointer.
                let cipher = unsafe { Pointer::reference(cipher) }?;
                unsafe { Pointer::write(out, U128::from(cipher.remaining_bytes())) }
            })())
        }

        /// Writes the state of RFC 8439 section 2.3 (constants, key, block counter, nonce) for the
        /// 32-byte key at `key`, `counter` and the 12-byte nonce at `nonce` into the 16 words at `out`.
        pub unsafe extern "C" fn umilib_crypto_chacha20_chacha20_initial_state(key: *const u8, key_length: usize, counter: u32, nonce: *const u8, nonce_length: usize, out: *mut u32) -> *const Status {
            Status::from_result((|| {
                Pointer::check_disjoint(key, key_length, out, 16)?;
                Pointer::check_disjoint(nonce, nonce_length, out, 16)?;
                // SAFETY: the caller passes readable bytes and 16 writable words.
                let key = CryptoInput::key::<32>(unsafe { Pointer::slice(key, key_length) }?)?;
                let nonce = CryptoInput::nonce::<12>(unsafe { Pointer::slice(nonce, nonce_length) }?)?;
                let out: &mut [u32; 16] = unsafe { Pointer::slice_of_mut(out, 16) }?.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
                *out = ChaCha20::initial_state(key, counter, nonce);
                Ok(())
            })())
        }

        /// Applies the quarter round to the words `a`, `b`, `c` and `d` (each below 16) of the 16 words at
        /// `state`; fails with InvalidArgument for another index.
        pub unsafe extern "C" fn umilib_crypto_chacha20_chacha20_quarter_round(state: *mut u32, a: usize, b: usize, c: usize, d: usize) -> *const Status {
            Status::from_result((|| {
                if [a, b, c, d].iter().any(|&index| index >= 16) {
                    return Err(&Status::INVALID_ARGUMENT);
                }
                // SAFETY: the caller passes 16 writable words.
                let state: &mut [u32; 16] = unsafe { Pointer::slice_of_mut(state, 16) }?.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
                ChaCha20::quarter_round(state, a, b, c, d);
                Ok(())
            })())
        }

        /// Applies the 20 rounds to the 16 words at `state`.
        pub unsafe extern "C" fn umilib_crypto_chacha20_chacha20_rounds(state: *mut u32) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes 16 writable words.
                let state: &mut [u32; 16] = unsafe { Pointer::slice_of_mut(state, 16) }?.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
                ChaCha20::rounds(state);
                Ok(())
            })())
        }

        /// Writes the 64-byte block of the 16 words at `state` (the rounds, then the addition of the
        /// input state) into the `out_length` bytes at `out`, which must be 64.
        pub unsafe extern "C" fn umilib_crypto_chacha20_chacha20_block(state: *const u32, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                Pointer::check_disjoint(state, 16, out, out_length)?;
                // SAFETY: the caller passes 16 readable words and a writable byte range.
                let state: &[u32; 16] = unsafe { Pointer::slice_of(state, 16) }?.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
                let out = CryptoInput::output_mut::<64>(unsafe { Pointer::slice_mut(out, out_length) }?)?;
                *out = ChaCha20::block(state);
                Ok(())
            })())
        }
    }

    /// The C type of this module.
    pub const DEFINITION: crate::ffi::Definition = crate::ffi::Definition::Opaque {
        name: "umilib_crypto_chacha20_ChaCha20",
        documentation: " ChaCha20 (RFC 8439): a stream cipher with a 32-byte key; it stops before the block counter wraps.",
    };

    /// The functions exported by this module, in declaration order.
    pub const FUNCTIONS: &[crate::ffi::Function] = &crate::ffi::Function::concat::<
        { CONSTRUCTORS.len() + COMMON.len() + FUNCTIONS_OF_TYPE.len() },
    >(&[CONSTRUCTORS, COMMON, FUNCTIONS_OF_TYPE]);
}

/// [`XChaCha20`].
pub mod xchacha20 {
    use super::{CryptoInput, Pointer, Status, U128, XChaCha20, Zeroize};

    crate::ffi_functions! {
        const CONSTRUCTORS;
        /// Creates XChaCha20 with the 32-byte key at `key`, the 24-byte nonce at `nonce` and the initial
        /// 32-bit block counter `counter`.
        pub unsafe extern "C" fn umilib_crypto_chacha20_xchacha20_new(key: *const u8, key_length: usize, nonce: *const u8, nonce_length: usize, counter: u32, out: *mut *mut XChaCha20) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable bytes and a writable pointer.
                let key = CryptoInput::key::<32>(unsafe { Pointer::slice(key, key_length) }?)?;
                let nonce = CryptoInput::nonce::<24>(unsafe { Pointer::slice(nonce, nonce_length) }?)?;
                unsafe { Pointer::write_handle(out, XChaCha20::new(key, nonce, counter)) }
            })())
        }

        /// Creates XChaCha20 with the 64-bit block counter of the original ChaCha20 (libsodium), with the
        /// 32-byte key at `key`, the 24-byte nonce at `nonce` and the initial counter `counter`.
        pub unsafe extern "C" fn umilib_crypto_chacha20_xchacha20_with_64_bit_counter(key: *const u8, key_length: usize, nonce: *const u8, nonce_length: usize, counter: u64, out: *mut *mut XChaCha20) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable bytes and a writable pointer.
                let key = CryptoInput::key::<32>(unsafe { Pointer::slice(key, key_length) }?)?;
                let nonce = CryptoInput::nonce::<24>(unsafe { Pointer::slice(nonce, nonce_length) }?)?;
                unsafe { Pointer::write_handle(out, XChaCha20::with_64_bit_counter(key, nonce, counter)) }
            })())
        }
    }

    crate::ffi_stream_cipher!(XChaCha20, "umilib_crypto_chacha20_xchacha20", COMMON);

    crate::ffi_functions! {
        const FUNCTIONS_OF_TYPE;
        /// Writes the bytes of key stream left before the counter wraps into `out`.
        pub unsafe extern "C" fn umilib_crypto_chacha20_xchacha20_remaining_bytes(cipher: *const XChaCha20, out: *mut U128) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes a valid handle and a writable pointer.
                let cipher = unsafe { Pointer::reference(cipher) }?;
                unsafe { Pointer::write(out, U128::from(cipher.remaining_bytes())) }
            })())
        }

        /// Writes the subkey (HChaCha20 of the key and the first 16 bytes of the nonce) into the 32 bytes at
        /// `out_key` and the ChaCha20 nonce (4 zero bytes, then the last 8 bytes of the nonce) into the 12
        /// bytes at `out_nonce`, for the 32-byte key at `key` and the 24-byte nonce at `nonce`.
        pub unsafe extern "C" fn umilib_crypto_chacha20_xchacha20_derive(key: *const u8, key_length: usize, nonce: *const u8, nonce_length: usize, out_key: *mut u8, out_key_length: usize, out_nonce: *mut u8, out_nonce_length: usize) -> *const Status {
            Status::from_result((|| {
                Pointer::check_disjoint(out_key, out_key_length, out_nonce, out_nonce_length)?;
                for (input, input_length) in [(key, key_length), (nonce, nonce_length)] {
                    Pointer::check_disjoint(input, input_length, out_key, out_key_length)?;
                    Pointer::check_disjoint(input, input_length, out_nonce, out_nonce_length)?;
                }
                // SAFETY: the caller passes readable bytes and writable byte ranges.
                let key = CryptoInput::key::<32>(unsafe { Pointer::slice(key, key_length) }?)?;
                let nonce = CryptoInput::nonce::<24>(unsafe { Pointer::slice(nonce, nonce_length) }?)?;
                let out_key = CryptoInput::output_mut::<32>(unsafe { Pointer::slice_mut(out_key, out_key_length) }?)?;
                let out_nonce = CryptoInput::output_mut::<12>(unsafe { Pointer::slice_mut(out_nonce, out_nonce_length) }?)?;
                let (mut subkey, chacha_nonce) = XChaCha20::derive(key, nonce);
                *out_key = subkey;
                *out_nonce = chacha_nonce;
                subkey.zeroize();
                Ok(())
            })())
        }

        /// Writes HChaCha20 of the 32-byte key at `key` and the 16-byte nonce at `nonce` into the 32 bytes
        /// at `out`.
        pub unsafe extern "C" fn umilib_crypto_chacha20_xchacha20_hchacha20(key: *const u8, key_length: usize, nonce: *const u8, nonce_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                Pointer::check_disjoint(key, key_length, out, out_length)?;
                Pointer::check_disjoint(nonce, nonce_length, out, out_length)?;
                // SAFETY: the caller passes readable bytes and a writable byte range.
                let key = CryptoInput::key::<32>(unsafe { Pointer::slice(key, key_length) }?)?;
                let nonce = CryptoInput::nonce::<16>(unsafe { Pointer::slice(nonce, nonce_length) }?)?;
                let out = CryptoInput::output_mut::<32>(unsafe { Pointer::slice_mut(out, out_length) }?)?;
                let mut subkey = XChaCha20::hchacha20(key, nonce);
                *out = subkey;
                subkey.zeroize();
                Ok(())
            })())
        }
    }

    /// The C type of this module.
    pub const DEFINITION: crate::ffi::Definition = crate::ffi::Definition::Opaque {
        name: "umilib_crypto_chacha20_XChaCha20",
        documentation: " XChaCha20 (draft-irtf-cfrg-xchacha): ChaCha20 with 24-byte nonces, through HChaCha20.",
    };

    /// The functions exported by this module, in declaration order.
    pub const FUNCTIONS: &[crate::ffi::Function] = &crate::ffi::Function::concat::<
        { CONSTRUCTORS.len() + COMMON.len() + FUNCTIONS_OF_TYPE.len() },
    >(&[CONSTRUCTORS, COMMON, FUNCTIONS_OF_TYPE]);
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "chacha20",
    definitions: &[chacha20::DEFINITION, xchacha20::DEFINITION],
    functions: &crate::ffi::Function::concat::<{ chacha20::FUNCTIONS.len() + xchacha20::FUNCTIONS.len() }>(&[
        chacha20::FUNCTIONS,
        xchacha20::FUNCTIONS,
    ]),
    modules: &[],
};
