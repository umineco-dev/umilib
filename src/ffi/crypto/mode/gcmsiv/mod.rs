//! The C ABI of [`crate::crypto::mode::gcmsiv`].
//!
//! GCM-SIV derives a cipher from every nonce, so it is exported over the
//! concrete 128-bit ciphers of the registry, not [`BlockCipher128`](crate::ffi::crypto::BlockCipher128).

use crate::ffi::{Definition, Function, Module, Pointer, Status, Type, Value};

/// Defines [`GCMSIVState`] over the 128-bit block ciphers of the registry.
macro_rules! gcmsiv_state {
    ([16] $($feature:literal $variant:ident => $type:path, $name:literal;)* [8] $($rest:tt)*) => {
        crate::ffi_aead_enum! {
            /// [`GCMSIV<C>`](crate::crypto::mode::gcmsiv::GCMSIV) for any 128-bit block cipher `C` of the registry.
            GCMSIVState {
                $(
                    #[cfg(umilib_feature = $feature)]
                    $variant(crate::crypto::mode::gcmsiv::GCMSIV<$type>),
                )*
            }
        }

        impl GCMSIVState {
            /// GCM-SIV with the key-generating key `key` (16 or 32 bytes) over the
            /// cipher whose C type is named `cipher`; fails with InvalidArgument if
            /// that cipher is unknown, not enabled or has another block size.
            pub fn new(cipher: &str, key: &[u8]) -> Result<GCMSIVState, &'static Status> {
                match cipher {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => crate::crypto::KeyInit::new_from_slice(key).map(GCMSIVState::$variant).map_err(|error| crate::ffi::ToStatus::to_status(&error)),
                    )*
                    _ => {
                        let _ = key;
                        Err(&Status::INVALID_ARGUMENT)
                    }
                }
            }
        }
    };
}

crate::ffi_block_ciphers!(gcmsiv_state);

impl Value for GCMSIVState {
    const TYPE: Type = Type::Named("umilib_crypto_mode_gcmsiv_GCMSIV");
}

crate::ffi_functions! {
    const CONSTRUCTORS;
    /// Creates GCM-SIV over the 128-bit block cipher whose C type is named by the UTF-8 text at
    /// `cipher`, such as `umilib_crypto_aes_AES128`, with the key-generating key of `key_length` bytes
    /// (16 or 32, a key length of the cipher) at `key`; fails with InvalidArgument if that cipher is unknown, not enabled or has
    /// another block size.
    pub unsafe extern "C" fn umilib_crypto_mode_gcmsiv_gcmsiv_new(cipher: *const u8, cipher_length: usize, key: *const u8, key_length: usize, out: *mut *mut GCMSIVState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let aead = GCMSIVState::new(cipher, key)?;
            unsafe { Pointer::write_handle(out, aead) }
        })())
    }
}

crate::ffi_aead!(GCMSIVState, "umilib_crypto_mode_gcmsiv_gcmsiv", COMMON);

/// The functions exported by this module, in declaration order.
pub const FUNCTIONS: &[Function] = &Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "gcmsiv",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_mode_gcmsiv_GCMSIV",
        documentation: " AES-GCM-SIV (RFC 8452) over a 128-bit block cipher chosen by name: nonce-misuse-resistant, with 12-byte nonces and 16-byte tags.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
