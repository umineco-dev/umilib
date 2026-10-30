//! The C ABI of [`crate::crypto::mode::ccm`].

use crate::crypto::CryptoError;
use crate::crypto::mode::ccm::CCM;
use crate::ffi::crypto::BlockCipher128;
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};

crate::ffi_aead_enum! {
    /// [`CCM`] over a 128-bit block cipher of the registry, with each tag size (4, 6, 8, 10, 12, 14, 16 bytes).
    CCMState {
        Tag4(CCM<BlockCipher128, 4>),
        Tag6(CCM<BlockCipher128, 6>),
        Tag8(CCM<BlockCipher128, 8>),
        Tag10(CCM<BlockCipher128, 10>),
        Tag12(CCM<BlockCipher128, 12>),
        Tag14(CCM<BlockCipher128, 14>),
        Tag16(CCM<BlockCipher128, 16>),
    }
}

impl Value for CCMState {
    const TYPE: Type = Type::Named("umilib_crypto_mode_ccm_CCM");
}

crate::ffi_functions! {
    const CONSTRUCTORS;
    /// Creates CCM with tags of `tag_size` bytes (4, 6, 8, 10, 12, 14, 16) over the 128-bit block cipher whose C
    /// type is named by the UTF-8 text at `cipher`, such as `umilib_crypto_aes_AES128`, with the
    /// `key_length` bytes at `key`; fails with InvalidArgument if that cipher is unknown, not enabled or
    /// has another block size.
    pub unsafe extern "C" fn umilib_crypto_mode_ccm_ccm_new(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, tag_size: usize, out: *mut *mut CCMState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let cipher = BlockCipher128::new(cipher, key)?;
            let aead = match tag_size {
                4 => CCMState::Tag4(CCM::new(cipher)),
                6 => CCMState::Tag6(CCM::new(cipher)),
                8 => CCMState::Tag8(CCM::new(cipher)),
                10 => CCMState::Tag10(CCM::new(cipher)),
                12 => CCMState::Tag12(CCM::new(cipher)),
                14 => CCMState::Tag14(CCM::new(cipher)),
                16 => CCMState::Tag16(CCM::new(cipher)),
                _ => return Err(CryptoError::TagLength { length: tag_size, minimum: 4, maximum: 16 }.to_status()),
            };
            unsafe { Pointer::write_handle(out, aead) }
        })())
    }
}

crate::ffi_aead!(CCMState, "umilib_crypto_mode_ccm_ccm", COMMON);

/// The functions exported by this module, in declaration order.
pub const FUNCTIONS: &[Function] = &Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ccm",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_mode_ccm_CCM",
        documentation: " CCM over a 128-bit block cipher chosen by name, with a tag size chosen at creation; nonces have 7 to 13 bytes.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
