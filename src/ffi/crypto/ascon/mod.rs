//! The C ABI of [`crate::crypto::ascon`].

use crate::crypto::CryptoError;
use crate::crypto::ascon::AsconAEAD128;
use crate::ffi::crypto::CryptoInput;
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};

crate::ffi_aead_enum! {
    /// [`AsconAEAD128`] with each tag size (4 to 16 bytes).
    AsconAEAD128State {
        Tag4(AsconAEAD128<4>),
        Tag5(AsconAEAD128<5>),
        Tag6(AsconAEAD128<6>),
        Tag7(AsconAEAD128<7>),
        Tag8(AsconAEAD128<8>),
        Tag9(AsconAEAD128<9>),
        Tag10(AsconAEAD128<10>),
        Tag11(AsconAEAD128<11>),
        Tag12(AsconAEAD128<12>),
        Tag13(AsconAEAD128<13>),
        Tag14(AsconAEAD128<14>),
        Tag15(AsconAEAD128<15>),
        Tag16(AsconAEAD128<16>),
    }
}

impl AsconAEAD128State {
    /// Ascon-AEAD128 with tags of `tag_size` bytes and `key`; fails with TagLength for another size.
    pub fn new(tag_size: usize, key: &[u8; 16]) -> Result<AsconAEAD128State, CryptoError> {
        Ok(match tag_size {
            4 => AsconAEAD128State::Tag4(AsconAEAD128::new(key)),
            5 => AsconAEAD128State::Tag5(AsconAEAD128::new(key)),
            6 => AsconAEAD128State::Tag6(AsconAEAD128::new(key)),
            7 => AsconAEAD128State::Tag7(AsconAEAD128::new(key)),
            8 => AsconAEAD128State::Tag8(AsconAEAD128::new(key)),
            9 => AsconAEAD128State::Tag9(AsconAEAD128::new(key)),
            10 => AsconAEAD128State::Tag10(AsconAEAD128::new(key)),
            11 => AsconAEAD128State::Tag11(AsconAEAD128::new(key)),
            12 => AsconAEAD128State::Tag12(AsconAEAD128::new(key)),
            13 => AsconAEAD128State::Tag13(AsconAEAD128::new(key)),
            14 => AsconAEAD128State::Tag14(AsconAEAD128::new(key)),
            15 => AsconAEAD128State::Tag15(AsconAEAD128::new(key)),
            16 => AsconAEAD128State::Tag16(AsconAEAD128::new(key)),
            _ => return Err(CryptoError::TagLength { length: tag_size, minimum: 4, maximum: 16 }),
        })
    }

    /// [`AsconAEAD128State::new`] with nonce masking (SP 800-232 section 4.2.2).
    pub fn with_nonce_mask(
        tag_size: usize,
        key: &[u8; 16],
        nonce_mask: &[u8; 16],
    ) -> Result<AsconAEAD128State, CryptoError> {
        Ok(match tag_size {
            4 => AsconAEAD128State::Tag4(AsconAEAD128::with_nonce_mask(key, nonce_mask)),
            5 => AsconAEAD128State::Tag5(AsconAEAD128::with_nonce_mask(key, nonce_mask)),
            6 => AsconAEAD128State::Tag6(AsconAEAD128::with_nonce_mask(key, nonce_mask)),
            7 => AsconAEAD128State::Tag7(AsconAEAD128::with_nonce_mask(key, nonce_mask)),
            8 => AsconAEAD128State::Tag8(AsconAEAD128::with_nonce_mask(key, nonce_mask)),
            9 => AsconAEAD128State::Tag9(AsconAEAD128::with_nonce_mask(key, nonce_mask)),
            10 => AsconAEAD128State::Tag10(AsconAEAD128::with_nonce_mask(key, nonce_mask)),
            11 => AsconAEAD128State::Tag11(AsconAEAD128::with_nonce_mask(key, nonce_mask)),
            12 => AsconAEAD128State::Tag12(AsconAEAD128::with_nonce_mask(key, nonce_mask)),
            13 => AsconAEAD128State::Tag13(AsconAEAD128::with_nonce_mask(key, nonce_mask)),
            14 => AsconAEAD128State::Tag14(AsconAEAD128::with_nonce_mask(key, nonce_mask)),
            15 => AsconAEAD128State::Tag15(AsconAEAD128::with_nonce_mask(key, nonce_mask)),
            16 => AsconAEAD128State::Tag16(AsconAEAD128::with_nonce_mask(key, nonce_mask)),
            _ => return Err(CryptoError::TagLength { length: tag_size, minimum: 4, maximum: 16 }),
        })
    }
}

impl Value for AsconAEAD128State {
    const TYPE: Type = Type::Named("umilib_crypto_ascon_AsconAEAD128");
}

crate::ffi_functions! {
    const CONSTRUCTORS;
    /// Creates Ascon-AEAD128 with tags of `tag_size` bytes (4 to 16) and the 16-byte key at `key`; nonces
    /// have 16 bytes.
    pub unsafe extern "C" fn umilib_crypto_ascon_ascon_aead128_new(tag_size: usize, key: *const u8, key_length: usize, out: *mut *mut AsconAEAD128State) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let key = CryptoInput::key::<16>(unsafe { Pointer::slice(key, key_length) }?)?;
            let aead = AsconAEAD128State::new(tag_size, key).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, aead) }
        })())
    }

    /// Creates Ascon-AEAD128 like `umilib_crypto_ascon_ascon_aead128_new`, with the 16-byte nonce mask at
    /// `nonce_mask` (SP 800-232 section 4.2.2): the second half of a 32-byte key.
    pub unsafe extern "C" fn umilib_crypto_ascon_ascon_aead128_with_nonce_mask(tag_size: usize, key: *const u8, key_length: usize, nonce_mask: *const u8, nonce_mask_length: usize, out: *mut *mut AsconAEAD128State) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let key = CryptoInput::key::<16>(unsafe { Pointer::slice(key, key_length) }?)?;
            let nonce_mask = CryptoInput::key::<16>(unsafe { Pointer::slice(nonce_mask, nonce_mask_length) }?)?;
            let aead = AsconAEAD128State::with_nonce_mask(tag_size, key, nonce_mask).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, aead) }
        })())
    }
}

crate::ffi_aead!(AsconAEAD128State, "umilib_crypto_ascon_ascon_aead128", COMMON);

/// The functions exported by this module, in declaration order.
pub const FUNCTIONS: &[Function] = &Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ascon",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_ascon_AsconAEAD128",
        documentation: " Ascon-AEAD128 (SP 800-232): a 16-byte key, 16-byte nonces and tags of 4 to 16 bytes (16 recommended).",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
