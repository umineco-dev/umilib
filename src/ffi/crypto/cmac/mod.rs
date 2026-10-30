//! The C ABI of [`crate::crypto::cmac`].

use crate::crypto::cmac::CMAC;
use crate::ffi::crypto::{BlockCipher64, BlockCipher128, BlockCipherChoice, MACState};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};

crate::ffi_mac_enum! {
    /// [`CMAC`] over a block cipher of the registry.
    CMACState {
        Block128(CMAC<BlockCipher128>),
        Block64(CMAC<BlockCipher64>),
    }
}

impl CMACState {
    /// CMAC over the cipher whose C type is named `cipher`, with `key`; fails
    /// with InvalidArgument if that cipher is unknown or not enabled.
    pub fn new(cipher: &str, key: &[u8]) -> Result<CMACState, &'static Status> {
        Ok(match BlockCipherChoice::new(cipher, key)? {
            BlockCipherChoice::Block128(cipher) => CMACState::Block128(CMAC::new(cipher)),
            BlockCipherChoice::Block64(cipher) => CMACState::Block64(CMAC::new(cipher)),
        })
    }

    /// [`CMAC::verify_truncated_with_minimum`] on a copy of the state.
    pub fn verify_truncated_with_minimum(&self, tag: &[u8], minimum: usize) -> bool {
        match self {
            CMACState::Block128(cmac) => cmac.clone().verify_truncated_with_minimum(tag, minimum),
            CMACState::Block64(cmac) => cmac.clone().verify_truncated_with_minimum(tag, minimum),
        }
    }

    /// [`CMAC::verify_truncated`] on a copy of the state.
    pub fn verify_truncated(&self, tag: &[u8]) -> bool {
        match self {
            CMACState::Block128(cmac) => cmac.clone().verify_truncated(tag),
            CMACState::Block64(cmac) => cmac.clone().verify_truncated(tag),
        }
    }
}

impl Value for CMACState {
    const TYPE: Type = Type::Named("umilib_crypto_cmac_CMAC");
}

crate::ffi_functions! {
    const CONSTRUCTORS;
    /// Creates CMAC over the block cipher whose C type is named by the UTF-8 text at `cipher`, such as
    /// `umilib_crypto_aes_AES128`, with the `key_length` bytes at `key`; fails with InvalidArgument if
    /// that cipher is unknown or not enabled.
    pub unsafe extern "C" fn umilib_crypto_cmac_cmac_new(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, out: *mut *mut CMACState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let state = CMACState::new(cipher, key)?;
            unsafe { Pointer::write_handle(out, state) }
        })())
    }
}

crate::ffi_mac!(CMACState, "umilib_crypto_cmac_cmac", COMMON);

crate::ffi_functions! {
    const TRUNCATED;
    /// Writes into `out` whether the `tag_length` bytes at `tag` are the leftmost bytes (at least 8, or
    /// the whole block if shorter) of the tag of the message, compared in constant time, and releases
    /// the state. On failure the state is not released.
    pub unsafe extern "C" fn umilib_crypto_cmac_cmac_verify_truncated(state: *mut CMACState, tag: *const u8, tag_length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes, a writable pointer and a handle created by this module.
            let tag = unsafe { Pointer::slice(tag, tag_length) }?;
            let valid = unsafe { Pointer::reference(state) }?.verify_truncated(tag);
            unsafe { Pointer::write(out, valid) }?;
            unsafe { Pointer::free(state) };
            Ok(())
        })())
    }

    /// Like `umilib_crypto_cmac_cmac_verify_truncated` with tags of at least `minimum` bytes (and one);
    /// SP 800-38B appendix A.2 allows tags shorter than 8 bytes only where the protocol limits the
    /// failed verifications per key.
    pub unsafe extern "C" fn umilib_crypto_cmac_cmac_verify_truncated_with_minimum(state: *mut CMACState, tag: *const u8, tag_length: usize, minimum: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes, a writable pointer and a handle created by this module.
            let tag = unsafe { Pointer::slice(tag, tag_length) }?;
            let valid = unsafe { Pointer::reference(state) }?.verify_truncated_with_minimum(tag, minimum);
            unsafe { Pointer::write(out, valid) }?;
            unsafe { Pointer::free(state) };
            Ok(())
        })())
    }

    /// Writes the tag of the `length` bytes at `data` with the cipher named by `cipher` and the key into
    /// the `out_length` bytes at `out`, which must be the block size and must not overlap the inputs.
    pub unsafe extern "C" fn umilib_crypto_cmac_cmac_mac(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, data: *const u8, length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(cipher, cipher_length, out, out_length)?;
            Pointer::check_disjoint(key, key_length, out, out_length)?;
            Pointer::check_disjoint(data, length, out, out_length)?;
            // SAFETY: the caller passes readable text and bytes and a writable byte range.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            let mut state = CMACState::new(cipher, key)?;
            let size = state.output_size();
            if out.len() != size {
                return Err(crate::crypto::CryptoError::TagLength { length: out.len(), minimum: size, maximum: size }.to_status());
            }
            state.update(data);
            state.finalize_into(out);
            Ok(())
        })())
    }
}

/// The functions exported by this module, in declaration order.
pub const FUNCTIONS: &[Function] =
    &Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() + TRUNCATED.len() }>(&[CONSTRUCTORS, COMMON, TRUNCATED]);

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "cmac",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_cmac_CMAC",
        documentation: " CMAC (SP 800-38B) over a block cipher chosen by name.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
