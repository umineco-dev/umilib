//! The C ABI of [`crate::crypto::rc4`].

use crate::crypto::rc4::RC4;
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for RC4 {
    const TYPE: Type = Type::Named("umilib_crypto_rc4_RC4");
}

crate::ffi_functions! {
    const CONSTRUCTORS;
    /// Creates RC4 with the key of 1 to 256 bytes at `key`.
    pub unsafe extern "C" fn umilib_crypto_rc4_rc4_new(key: *const u8, key_length: usize, out: *mut *mut RC4) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let cipher = RC4::new(key).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, cipher) }
        })())
    }
}

crate::ffi_stream_cipher!(RC4, "umilib_crypto_rc4_rc4", COMMON);

/// The functions exported by this module, in declaration order.
pub const FUNCTIONS: &[Function] = &Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "rc4",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_rc4_RC4",
        documentation: " RC4: a stream cipher with keys of 1 to 256 bytes; broken (RFC 7465), for legacy data.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
