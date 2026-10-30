//! The C ABI of [`crate::crypto::mode::siv`].

use crate::crypto::mode::siv::SIV;
use crate::ffi::crypto::{BlockCipher128, CryptoInput};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for SIV<BlockCipher128> {
    const TYPE: Type = Type::Named("umilib_crypto_mode_siv_SIV");
}

crate::ffi_functions! {
    const CONSTRUCTORS;
    /// Creates SIV over the 128-bit block cipher whose C type is named by the UTF-8 text at `cipher`,
    /// such as `umilib_crypto_aes_AES128`, with K1 (of S2V) at `mac_key` and K2 (of CTR) at
    /// `cipher_key`; fails with InvalidArgument if that cipher is unknown, not enabled or has another
    /// block size.
    pub unsafe extern "C" fn umilib_crypto_mode_siv_siv_new(cipher: *const u8, cipher_length: usize, mac_key: *const u8, mac_key_length: usize, cipher_key: *const u8, cipher_key_length: usize, out: *mut *mut SIV<BlockCipher128>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let mac_key = unsafe { Pointer::slice(mac_key, mac_key_length) }?;
            let cipher_key = unsafe { Pointer::slice(cipher_key, cipher_key_length) }?;
            let siv = SIV::new(BlockCipher128::new(cipher, mac_key)?, BlockCipher128::new(cipher, cipher_key)?);
            unsafe { Pointer::write_handle(out, siv) }
        })())
    }
}

crate::ffi_aead!(SIV<BlockCipher128>, "umilib_crypto_mode_siv_siv", COMMON);

crate::ffi_functions! {
    const VECTORS;
    /// Encrypts the `length` bytes at `buffer` in place and writes V, which authenticates them and the
    /// `count` components of associated data (the `index`-th at `associated[index]`, of
    /// `associated_lengths[index]` bytes; at most 126), into the `out_length` bytes at `out`, which
    /// must be 16. The components must not overlap `buffer` or `siv`.
    pub unsafe extern "C" fn umilib_crypto_mode_siv_siv_encrypt_vector_in_place(siv: *const SIV<BlockCipher128>, associated: *const *const u8, associated_lengths: *const usize, count: usize, buffer: *mut u8, length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(buffer, length, out, out_length)?;
            // SAFETY: the caller passes a valid handle, readable byte sequences and writable byte ranges.
            let siv = unsafe { Pointer::reference(siv) }?;
            let associated = unsafe { Pointer::slices(associated, associated_lengths, count) }?;
            for component in &associated {
                Pointer::check_disjoint(component.as_ptr(), component.len(), buffer, length)?;
                Pointer::check_disjoint(component.as_ptr(), component.len(), out, out_length)?;
            }
            let buffer = unsafe { Pointer::slice_mut(buffer, length) }?;
            let out = CryptoInput::tag_mut::<16>(unsafe { Pointer::slice_mut(out, out_length) }?)?;
            *out = siv.encrypt_vector_in_place(&associated, buffer).map_err(|error| error.to_status())?;
            Ok(())
        })())
    }

    /// Decrypts the `length` bytes at `buffer` in place if the `v_length` bytes at `v` authenticate
    /// them and the `count` components of associated data; otherwise fails with AuthenticationFailed
    /// and leaves the ciphertext in `buffer`. The other inputs must not overlap `buffer`.
    pub unsafe extern "C" fn umilib_crypto_mode_siv_siv_decrypt_vector_in_place(siv: *const SIV<BlockCipher128>, associated: *const *const u8, associated_lengths: *const usize, count: usize, buffer: *mut u8, length: usize, v: *const u8, v_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(v, v_length, buffer, length)?;
            // SAFETY: the caller passes a valid handle, readable byte sequences and a writable byte range.
            let siv = unsafe { Pointer::reference(siv) }?;
            let associated = unsafe { Pointer::slices(associated, associated_lengths, count) }?;
            for component in &associated {
                Pointer::check_disjoint(component.as_ptr(), component.len(), buffer, length)?;
            }
            let v = unsafe { Pointer::slice(v, v_length) }?;
            let buffer = unsafe { Pointer::slice_mut(buffer, length) }?;
            siv.decrypt_vector_in_place(&associated, buffer, v).map_err(|error| error.to_status())
        })())
    }
}

/// The functions exported by this module, in declaration order.
pub const FUNCTIONS: &[Function] =
    &Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() + VECTORS.len() }>(&[CONSTRUCTORS, COMMON, VECTORS]);

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "siv",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_mode_siv_SIV",
        documentation: " SIV (RFC 5297) over a 128-bit block cipher chosen by name: deterministic authenticated encryption, and an AEAD whose tag is V.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
