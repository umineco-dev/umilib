//! The C ABI of [`crate::crypto::mode::gcm`].

use crate::crypto::CryptoError;
use crate::crypto::mode::gcm::GCM;
use crate::ffi::crypto::BlockCipher128;
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};

crate::ffi_aead_enum! {
    /// [`GCM`] over a 128-bit block cipher of the registry, with each tag size (4, 8, 12, 13, 14, 15, 16 bytes).
    GCMState {
        Tag4(GCM<BlockCipher128, 4>),
        Tag8(GCM<BlockCipher128, 8>),
        Tag12(GCM<BlockCipher128, 12>),
        Tag13(GCM<BlockCipher128, 13>),
        Tag14(GCM<BlockCipher128, 14>),
        Tag15(GCM<BlockCipher128, 15>),
        Tag16(GCM<BlockCipher128, 16>),
    }
}

impl Value for GCMState {
    const TYPE: Type = Type::Named("umilib_crypto_mode_gcm_GCM");
}

crate::ffi_functions! {
    const CONSTRUCTORS;
    /// Creates GCM with tags of `tag_size` bytes (4, 8, 12, 13, 14, 15, 16) over the 128-bit block cipher whose C
    /// type is named by the UTF-8 text at `cipher`, such as `umilib_crypto_aes_AES128`, with the
    /// `key_length` bytes at `key`; fails with InvalidArgument if that cipher is unknown, not enabled or
    /// has another block size.
    pub unsafe extern "C" fn umilib_crypto_mode_gcm_gcm_new(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, tag_size: usize, out: *mut *mut GCMState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let cipher = BlockCipher128::new(cipher, key)?;
            let aead = match tag_size {
                4 => GCMState::Tag4(GCM::new(cipher)),
                8 => GCMState::Tag8(GCM::new(cipher)),
                12 => GCMState::Tag12(GCM::new(cipher)),
                13 => GCMState::Tag13(GCM::new(cipher)),
                14 => GCMState::Tag14(GCM::new(cipher)),
                15 => GCMState::Tag15(GCM::new(cipher)),
                16 => GCMState::Tag16(GCM::new(cipher)),
                _ => return Err(CryptoError::TagLength { length: tag_size, minimum: 4, maximum: 16 }.to_status()),
            };
            unsafe { Pointer::write_handle(out, aead) }
        })())
    }
}

crate::ffi_aead!(GCMState, "umilib_crypto_mode_gcm_gcm", COMMON);

/// The functions exported by this module, in declaration order.
pub const FUNCTIONS: &[Function] = &Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "gcm",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_mode_gcm_GCM",
        documentation: " GCM over a 128-bit block cipher chosen by name, with a tag size chosen at creation; nonces of 12 bytes are recommended.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
