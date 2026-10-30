//! The C ABI of [`crate::crypto::chacha20poly1305`].

use crate::crypto::chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use crate::ffi::crypto::CryptoInput;
use crate::ffi::{Module, Pointer, Status, Type, Value};

impl Value for ChaCha20Poly1305 {
    const TYPE: Type = Type::Named("umilib_crypto_chacha20poly1305_ChaCha20Poly1305");
}

impl Value for XChaCha20Poly1305 {
    const TYPE: Type = Type::Named("umilib_crypto_chacha20poly1305_XChaCha20Poly1305");
}

/// [`ChaCha20Poly1305`].
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod chacha20poly1305 {
    use super::{ChaCha20Poly1305, CryptoInput, Pointer, Status};

    crate::ffi_functions! {
        const CONSTRUCTORS;
        /// Creates ChaCha20-Poly1305 (RFC 8439) with the 32-byte key at `key`; nonces have 12 bytes.
        pub unsafe extern "C" fn umilib_crypto_chacha20poly1305_chacha20poly1305_new(key: *const u8, key_length: usize, out: *mut *mut ChaCha20Poly1305) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable bytes and a writable pointer.
                let key = CryptoInput::key::<32>(unsafe { Pointer::slice(key, key_length) }?)?;
                unsafe { Pointer::write_handle(out, ChaCha20Poly1305::new(key)) }
            })())
        }
    }

    crate::ffi_aead!(ChaCha20Poly1305, "umilib_crypto_chacha20poly1305_chacha20poly1305", COMMON);

    /// The C type of this module.
    pub const DEFINITION: crate::ffi::Definition = crate::ffi::Definition::Opaque {
        name: "umilib_crypto_chacha20poly1305_ChaCha20Poly1305",
        documentation: " ChaCha20-Poly1305 (RFC 8439): a 32-byte key, 12-byte nonces and 16-byte tags.",
    };

    /// The functions exported by this module, in declaration order.
    pub const FUNCTIONS: &[crate::ffi::Function] =
        &crate::ffi::Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);
}

/// [`XChaCha20Poly1305`].
pub mod xchacha20poly1305 {
    use super::{CryptoInput, Pointer, Status, XChaCha20Poly1305};

    crate::ffi_functions! {
        const CONSTRUCTORS;
        /// Creates XChaCha20-Poly1305 with the 32-byte key at `key`; nonces have 24 bytes, enough to be
        /// chosen at random.
        pub unsafe extern "C" fn umilib_crypto_chacha20poly1305_xchacha20poly1305_new(key: *const u8, key_length: usize, out: *mut *mut XChaCha20Poly1305) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable bytes and a writable pointer.
                let key = CryptoInput::key::<32>(unsafe { Pointer::slice(key, key_length) }?)?;
                unsafe { Pointer::write_handle(out, XChaCha20Poly1305::new(key)) }
            })())
        }
    }

    crate::ffi_aead!(XChaCha20Poly1305, "umilib_crypto_chacha20poly1305_xchacha20poly1305", COMMON);

    /// The C type of this module.
    pub const DEFINITION: crate::ffi::Definition = crate::ffi::Definition::Opaque {
        name: "umilib_crypto_chacha20poly1305_XChaCha20Poly1305",
        documentation: " XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha): a 32-byte key, 24-byte nonces and 16-byte tags.",
    };

    /// The functions exported by this module, in declaration order.
    pub const FUNCTIONS: &[crate::ffi::Function] =
        &crate::ffi::Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "chacha20poly1305",
    definitions: &[chacha20poly1305::DEFINITION, xchacha20poly1305::DEFINITION],
    functions: &crate::ffi::Function::concat::<
        { chacha20poly1305::FUNCTIONS.len() + xchacha20poly1305::FUNCTIONS.len() },
    >(&[chacha20poly1305::FUNCTIONS, xchacha20poly1305::FUNCTIONS]),
    modules: &[],
};
