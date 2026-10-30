//! The C ABI of [`crate::crypto::mode::xts`].

use crate::crypto::mode::xts::XTS;
use crate::ffi::crypto::{BlockCipher128, CryptoInput};
use crate::ffi::{Definition, Module, Pointer, Status, ToStatus, Type, U128, Value};

impl Value for XTS<BlockCipher128> {
    const TYPE: Type = Type::Named("umilib_crypto_mode_xts_XTS");
}

crate::ffi_functions! {
    /// Creates XTS over the 128-bit block cipher whose C type is named by the UTF-8 text at `cipher`,
    /// such as `umilib_crypto_aes_AES128`, with the data key at `data_key` and the tweak key at
    /// `tweak_key`, which must have the same length and differ; fails with InvalidArgument if that
    /// cipher is unknown, not enabled or has another block size.
    pub unsafe extern "C" fn umilib_crypto_mode_xts_xts_new(cipher: *const u8, cipher_length: usize, data_key: *const u8, data_key_length: usize, tweak_key: *const u8, tweak_key_length: usize, out: *mut *mut XTS<BlockCipher128>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let data_key = unsafe { Pointer::slice(data_key, data_key_length) }?;
            let tweak_key = unsafe { Pointer::slice(tweak_key, tweak_key_length) }?;
            XTS::<BlockCipher128>::check_keys(data_key, tweak_key).map_err(|error| error.to_status())?;
            let xts = XTS::new(BlockCipher128::new(cipher, data_key)?, BlockCipher128::new(cipher, tweak_key)?);
            unsafe { Pointer::write_handle(out, xts) }
        })())
    }

    /// Releases the state, zeroizing its keys. Does nothing if `xts` is null.
    pub unsafe extern "C" fn umilib_crypto_mode_xts_xts_free(xts: *mut XTS<BlockCipher128>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(xts) }
    }

    /// Writes a copy of `xts` into `out`.
    pub unsafe extern "C" fn umilib_crypto_mode_xts_xts_clone(xts: *const XTS<BlockCipher128>, out: *mut *mut XTS<BlockCipher128>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let xts = unsafe { Pointer::reference(xts) }?;
            unsafe { Pointer::write_handle(out, xts.clone()) }
        })())
    }

    /// Encrypts the data unit of `length` bytes (16 bytes to 2^20 blocks) at `data` in place under the 16-byte
    /// tweak at `tweak`, which must not overlap it.
    pub unsafe extern "C" fn umilib_crypto_mode_xts_xts_encrypt(xts: *const XTS<BlockCipher128>, tweak: *const u8, tweak_length: usize, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(tweak, tweak_length, data, length)?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable byte range.
            let xts = unsafe { Pointer::reference(xts) }?;
            let tweak = CryptoInput::nonce::<16>(unsafe { Pointer::slice(tweak, tweak_length) }?)?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            xts.encrypt(tweak, data).map_err(|error| error.to_status())
        })())
    }

    /// Decrypts the data unit of `length` bytes (16 bytes to 2^20 blocks) at `data` in place under the 16-byte
    /// tweak at `tweak`, which must not overlap it.
    pub unsafe extern "C" fn umilib_crypto_mode_xts_xts_decrypt(xts: *const XTS<BlockCipher128>, tweak: *const u8, tweak_length: usize, data: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(tweak, tweak_length, data, length)?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable byte range.
            let xts = unsafe { Pointer::reference(xts) }?;
            let tweak = CryptoInput::nonce::<16>(unsafe { Pointer::slice(tweak, tweak_length) }?)?;
            let data = unsafe { Pointer::slice_mut(data, length) }?;
            xts.decrypt(tweak, data).map_err(|error| error.to_status())
        })())
    }

    /// Writes the 16-byte tweak of data unit number `unit` (its little-endian encoding) into the
    /// `length` bytes at `out`, which must be 16.
    pub unsafe extern "C" fn umilib_crypto_mode_xts_xts_tweak_of(unit: U128, out: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a writable byte range.
            let out = CryptoInput::output_mut::<16>(unsafe { Pointer::slice_mut(out, length) }?)?;
            *out = XTS::<BlockCipher128>::tweak_of(u128::from(unit));
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "xts",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_mode_xts_XTS",
        documentation: " XTS over a 128-bit block cipher chosen by name, for data units such as disk sectors.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
