//! The C ABI of [`crate::crypto::poly1305`].

use crate::crypto::poly1305::Poly1305;
use crate::ffi::crypto::CryptoInput;
use crate::ffi::{Definition, Function, Module, Pointer, Status, Type, Value};

impl Value for Poly1305 {
    const TYPE: Type = Type::Named("umilib_crypto_poly1305_Poly1305");
}

crate::ffi_functions! {
    const CONSTRUCTORS;
    /// Creates Poly1305 with the one-time key of 32 bytes (r, then s) at `key`.
    pub unsafe extern "C" fn umilib_crypto_poly1305_poly1305_new(key: *const u8, key_length: usize, out: *mut *mut Poly1305) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let key = CryptoInput::key::<32>(unsafe { Pointer::slice(key, key_length) }?)?;
            unsafe { Pointer::write_handle(out, Poly1305::new(key)) }
        })())
    }
}

crate::ffi_mac!(Poly1305, "umilib_crypto_poly1305_poly1305", COMMON);

crate::ffi_functions! {
    const ONE_SHOT;
    /// Writes the 16-byte tag of the `length` bytes at `data` with the one-time key of 32 bytes at `key`
    /// into the `out_length` bytes at `out`, which must be 16 and must not overlap the inputs.
    pub unsafe extern "C" fn umilib_crypto_poly1305_poly1305_mac(key: *const u8, key_length: usize, data: *const u8, length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(key, key_length, out, out_length)?;
            Pointer::check_disjoint(data, length, out, out_length)?;
            // SAFETY: the caller passes readable bytes and a writable byte range.
            let key = CryptoInput::key::<32>(unsafe { Pointer::slice(key, key_length) }?)?;
            let data = unsafe { Pointer::slice(data, length) }?;
            let out = CryptoInput::tag_mut::<16>(unsafe { Pointer::slice_mut(out, out_length) }?)?;
            *out = Poly1305::mac(key, data);
            Ok(())
        })())
    }
}

/// The functions exported by this module, in declaration order.
pub const FUNCTIONS: &[Function] =
    &Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() + ONE_SHOT.len() }>(&[CONSTRUCTORS, COMMON, ONE_SHOT]);

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "poly1305",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_poly1305_Poly1305",
        documentation: " Poly1305 (RFC 8439 section 2.5): a one-time MAC; a key must authenticate one message only.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
