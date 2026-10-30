//! The C ABI of [`crate::crypto::mode`].
//!
//! Every mode is exported once and takes its block cipher by the C type name
//! of the cipher type and a key, as [`BlockCipherChoice`](crate::ffi::crypto::BlockCipherChoice).

use alloc::vec::Vec;

use crate::crypto::CryptoError;
use crate::crypto::mode::PKCS7;
use crate::ffi::{Buffer, Module, Pointer, Status, ToStatus};

#[cfg(umilib_feature = "crypto-mode-cbc")]
pub mod cbc;
#[cfg(umilib_feature = "crypto-mode-ccm")]
pub mod ccm;
#[cfg(umilib_feature = "crypto-mode-cfb")]
pub mod cfb;
#[cfg(umilib_feature = "crypto-mode-ctr")]
pub mod ctr;
#[cfg(umilib_feature = "crypto-mode-ecb")]
pub mod ecb;
#[cfg(umilib_feature = "crypto-mode-gcm")]
pub mod gcm;
#[cfg(umilib_feature = "crypto-mode-gcmsiv")]
pub mod gcmsiv;
#[cfg(umilib_feature = "crypto-mode-kw")]
pub mod kw;
#[cfg(umilib_feature = "crypto-mode-ofb")]
pub mod ofb;
#[cfg(umilib_feature = "crypto-mode-siv")]
pub mod siv;
#[cfg(umilib_feature = "crypto-mode-xts")]
pub mod xts;

crate::ffi_functions! {
    /// Writes the `length` bytes at `data` followed by their PKCS #7 padding for blocks of
    /// `block_size` bytes (1 to 255) into `out`.
    pub unsafe extern "C" fn umilib_crypto_mode_pkcs7_pad(data: *const u8, length: usize, block_size: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable `umilib_ffi_Buffer`.
            let data = unsafe { Pointer::slice(data, length) }?;
            let mut padded = Vec::new();
            padded
                .try_reserve_exact(data.len().saturating_add(block_size))
                .map_err(|_| CryptoError::Allocation.to_status())?;
            padded.extend_from_slice(data);
            PKCS7::pad(&mut padded, block_size).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(padded)) }
        })())
    }

    /// Writes into `out` the length of the `length` bytes at `data` without their PKCS #7 padding for
    /// blocks of `block_size` bytes (1 to 255), checked in constant time; fails with InputLength unless
    /// `data` is a whole number of blocks, at least one, and with InvalidParameter if the padding is not
    /// valid.
    pub unsafe extern "C" fn umilib_crypto_mode_pkcs7_unpad_length(data: *const u8, length: usize, block_size: usize, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let unpadded = PKCS7::unpad_length(data, block_size).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, unpadded) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "mode",
    definitions: &[],
    functions: FUNCTIONS,
    modules: &[
        #[cfg(umilib_feature = "crypto-mode-cbc")]
        cbc::MODULE,
        #[cfg(umilib_feature = "crypto-mode-ccm")]
        ccm::MODULE,
        #[cfg(umilib_feature = "crypto-mode-cfb")]
        cfb::MODULE,
        #[cfg(umilib_feature = "crypto-mode-ctr")]
        ctr::MODULE,
        #[cfg(umilib_feature = "crypto-mode-ecb")]
        ecb::MODULE,
        #[cfg(umilib_feature = "crypto-mode-gcm")]
        gcm::MODULE,
        #[cfg(umilib_feature = "crypto-mode-gcmsiv")]
        gcmsiv::MODULE,
        #[cfg(umilib_feature = "crypto-mode-kw")]
        kw::MODULE,
        #[cfg(umilib_feature = "crypto-mode-ofb")]
        ofb::MODULE,
        #[cfg(umilib_feature = "crypto-mode-siv")]
        siv::MODULE,
        #[cfg(umilib_feature = "crypto-mode-xts")]
        xts::MODULE,
    ],
};
