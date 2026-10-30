//! The C ABI of [`crate::crypto::mode::kw`].

use alloc::vec::Vec;

use crate::crypto::CryptoError;
use crate::crypto::mode::kw::{KW, KWP, Wrapping};
use crate::ffi::crypto::{BlockCipher64, BlockCipher128, BlockCipherChoice};
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};
use crate::secret::Zeroize;

/// [`KW`] over a block cipher of the registry: KW over one of 128 bits,
/// TKW over one of 64 bits.
#[derive(Clone)]
// The enum lives behind a handle: boxing the variants would add an allocation.
#[allow(clippy::large_enum_variant)]
pub enum KWState {
    Block128(KW<BlockCipher128>),
    Block64(KW<BlockCipher64>),
}

impl KWState {
    pub fn wrap(&self, key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let length = match self {
            KWState::Block128(_) => KW::<BlockCipher128>::wrapped_length(key.len()),
            KWState::Block64(_) => KW::<BlockCipher64>::wrapped_length(key.len()),
        }?;
        let mut out = alloc::vec![0u8; length];
        match self {
            KWState::Block128(mode) => mode.wrap(key, &mut out),
            KWState::Block64(mode) => mode.wrap(key, &mut out),
        }?;
        Ok(out)
    }

    pub fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let semiblock = match self {
            KWState::Block128(_) => Wrapping::<BlockCipher128>::SEMIBLOCK,
            KWState::Block64(_) => Wrapping::<BlockCipher64>::SEMIBLOCK,
        };
        let length = wrapped.len().checked_sub(semiblock).ok_or(CryptoError::InputLength { length: wrapped.len() })?;
        let mut out = alloc::vec![0u8; length];
        let result = match self {
            KWState::Block128(mode) => mode.unwrap(wrapped, &mut out),
            KWState::Block64(mode) => mode.unwrap(wrapped, &mut out),
        };
        result.map(|()| out)
    }
}

impl core::fmt::Debug for KWState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KWState(..)")
    }
}

impl Value for KWState {
    const TYPE: Type = Type::Named("umilib_crypto_mode_kw_KW");
}

/// [`KWP`] over a block cipher of 128 bits of the registry.
#[derive(Clone)]
pub struct KWPState {
    pub mode: KWP<BlockCipher128>,
}

impl core::fmt::Debug for KWPState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KWPState(..)")
    }
}

impl Value for KWPState {
    const TYPE: Type = Type::Named("umilib_crypto_mode_kw_KWP");
}

crate::ffi_functions! {
    /// Creates KW (TKW for a cipher of 64-bit blocks) over the cipher whose C type is named by the UTF-8
    /// text at `cipher`, such as `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key`; fails
    /// with InvalidArgument if that cipher is unknown or not enabled.
    pub unsafe extern "C" fn umilib_crypto_mode_kw_kw_new(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, out: *mut *mut KWState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let state = match BlockCipherChoice::new(cipher, key)? {
                BlockCipherChoice::Block128(cipher) => KWState::Block128(KW::new(cipher).map_err(|error| error.to_status())?),
                BlockCipherChoice::Block64(cipher) => KWState::Block64(KW::new(cipher).map_err(|error| error.to_status())?),
            };
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Releases the state, zeroizing its key. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_mode_kw_kw_free(state: *mut KWState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`.
    pub unsafe extern "C" fn umilib_crypto_mode_kw_kw_clone(state: *const KWState, out: *mut *mut KWState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Writes the wrapping of the `length` bytes at `key` (whole semiblocks, at least two) into `out`,
    /// one semiblock longer.
    pub unsafe extern "C" fn umilib_crypto_mode_kw_kw_wrap(state: *const KWState, key: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable `umilib_ffi_Buffer`.
            let state = unsafe { Pointer::reference(state) }?;
            let key = unsafe { Pointer::slice(key, length) }?;
            let wrapped = state.wrap(key).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(wrapped)) }
        })())
    }

    /// Writes the key the `length` bytes at `wrapped` hold into `out`; fails with AuthenticationFailed if
    /// the integrity check fails.
    pub unsafe extern "C" fn umilib_crypto_mode_kw_kw_unwrap(state: *const KWState, wrapped: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable `umilib_ffi_Buffer`.
            let state = unsafe { Pointer::reference(state) }?;
            let wrapped = unsafe { Pointer::slice(wrapped, length) }?;
            let key = state.unwrap(wrapped).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(key)) }
        })())
    }

    /// Creates KWP over the cipher of 128-bit blocks whose C type is named by the UTF-8 text at `cipher`,
    /// with the `key_length` bytes at `key`; fails with InvalidArgument if that cipher is unknown, not
    /// enabled, or of 64-bit blocks.
    pub unsafe extern "C" fn umilib_crypto_mode_kw_kwp_new(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, out: *mut *mut KWPState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let cipher = BlockCipher128::new(cipher, key)?;
            let mode = KWP::new(cipher).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, KWPState { mode }) }
        })())
    }

    /// Releases the state, zeroizing its key. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_mode_kw_kwp_free(state: *mut KWPState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`.
    pub unsafe extern "C" fn umilib_crypto_mode_kw_kwp_clone(state: *const KWPState, out: *mut *mut KWPState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Writes the wrapping of the `length` bytes at `key` (1 to 2^32 − 1 bytes) into `out`.
    pub unsafe extern "C" fn umilib_crypto_mode_kw_kwp_wrap(state: *const KWPState, key: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable `umilib_ffi_Buffer`.
            let state = unsafe { Pointer::reference(state) }?;
            let key = unsafe { Pointer::slice(key, length) }?;
            let mut wrapped = alloc::vec![0u8; KWP::<BlockCipher128>::wrapped_length(key.len()).map_err(|error| error.to_status())?];
            state.mode.wrap(key, &mut wrapped).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(wrapped)) }
        })())
    }

    /// Writes the key the `length` bytes at `wrapped` hold into `out`; fails with AuthenticationFailed if
    /// the integrity value, the length or the padding is wrong.
    pub unsafe extern "C" fn umilib_crypto_mode_kw_kwp_unwrap(state: *const KWPState, wrapped: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable `umilib_ffi_Buffer`.
            let state = unsafe { Pointer::reference(state) }?;
            let wrapped = unsafe { Pointer::slice(wrapped, length) }?;
            let mut key = alloc::vec![0u8; wrapped.len().saturating_sub(8)];
            let length = match state.mode.unwrap(wrapped, &mut key) {
                Ok(length) => length,
                Err(error) => {
                    key.zeroize();
                    return Err(error.to_status());
                }
            };
            key[length..].zeroize();
            key.truncate(length);
            unsafe { Pointer::write(out, Buffer::from_vec(key)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "kw",
    definitions: &[
        Definition::Opaque {
            name: "umilib_crypto_mode_kw_KW",
            documentation: " AES Key Wrap (SP 800-38F, RFC 3394), TKW over a cipher of 64-bit blocks.",
        },
        Definition::Opaque {
            name: "umilib_crypto_mode_kw_KWP",
            documentation: " AES Key Wrap with Padding (SP 800-38F, RFC 5649).",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
