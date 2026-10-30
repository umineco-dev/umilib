//! The C ABI of [`crate::crypto::argon2`].
//!
//! [`Argon2Type`] crosses as its value y of RFC 9106 section 3.1: `0`
//! (Argon2d), `1` (Argon2i) or `2` (Argon2id).

use crate::crypto::argon2::{Argon2, Argon2Type};
use crate::ffi::{Definition, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for Argon2 {
    const TYPE: Type = Type::Named("umilib_crypto_argon2_Argon2");
}

crate::ffi_functions! {
    /// Creates Argon2 of the type `variant` (0 Argon2d, 1 Argon2i, 2 Argon2id) with `memory` KiB (at
    /// least 8 × `lanes`), `passes` passes (at least 1) and `lanes` lanes (1 to 2^24 - 1); fails with
    /// InvalidArgument for another type and with InvalidParameter for other parameters.
    pub unsafe extern "C" fn umilib_crypto_argon2_argon2_new(variant: u32, memory: u32, passes: u32, lanes: u32, out: *mut *mut Argon2) -> *const Status {
        Status::from_result((|| {
            let variant = match variant {
                0 => Argon2Type::Argon2d,
                1 => Argon2Type::Argon2i,
                2 => Argon2Type::Argon2id,
                _ => return Err(&Status::INVALID_ARGUMENT),
            };
            let argon2 = Argon2::new(variant, memory, passes, lanes).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, argon2) }
        })())
    }

    /// Releases the parameters. Does nothing if `argon2` is null.
    pub unsafe extern "C" fn umilib_crypto_argon2_argon2_free(argon2: *mut Argon2) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(argon2) }
    }

    /// Writes a copy of `argon2` into `out`.
    pub unsafe extern "C" fn umilib_crypto_argon2_argon2_clone(argon2: *const Argon2, out: *mut *mut Argon2) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let argon2 = unsafe { Pointer::reference(argon2) }?;
            unsafe { Pointer::write_handle(out, *argon2) }
        })())
    }

    /// Writes the type (0 Argon2d, 1 Argon2i, 2 Argon2id) into `out`.
    pub unsafe extern "C" fn umilib_crypto_argon2_argon2_variant(argon2: *const Argon2, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let argon2 = unsafe { Pointer::reference(argon2) }?;
            unsafe { Pointer::write(out, argon2.variant() as u32) }
        })())
    }

    /// Writes the number of blocks of memory, m' = 4p × ⌊m / 4p⌋, into `out`.
    pub unsafe extern "C" fn umilib_crypto_argon2_argon2_blocks(argon2: *const Argon2, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let argon2 = unsafe { Pointer::reference(argon2) }?;
            unsafe { Pointer::write(out, argon2.blocks()) }
        })())
    }

    /// Writes the bytes of memory a derivation allocates into `out`.
    pub unsafe extern "C" fn umilib_crypto_argon2_argon2_memory_bytes(argon2: *const Argon2, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let argon2 = unsafe { Pointer::reference(argon2) }?;
            unsafe { Pointer::write(out, argon2.memory_bytes()) }
        })())
    }

    /// Fills the tag of `length` bytes (4 to 2^32 - 1) at `out` from the password, the salt, the optional
    /// secret K and the optional associated data X (RFC 9106 section 3.2), which must not overlap `out`;
    /// fails with Allocation if the memory cannot be allocated.
    pub unsafe extern "C" fn umilib_crypto_argon2_argon2_derive(argon2: *const Argon2, password: *const u8, password_length: usize, salt: *const u8, salt_length: usize, secret: *const u8, secret_length: usize, associated: *const u8, associated_length: usize, out: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            for (input, input_length) in [(password, password_length), (salt, salt_length), (secret, secret_length), (associated, associated_length)] {
                Pointer::check_disjoint(input, input_length, out, length)?;
            }
            // SAFETY: the caller passes a valid handle, readable bytes and a writable byte range.
            let argon2 = unsafe { Pointer::reference(argon2) }?;
            let password = unsafe { Pointer::slice(password, password_length) }?;
            let salt = unsafe { Pointer::slice(salt, salt_length) }?;
            let secret = unsafe { Pointer::slice(secret, secret_length) }?;
            let associated = unsafe { Pointer::slice(associated, associated_length) }?;
            let out = unsafe { Pointer::slice_mut(out, length) }?;
            argon2.derive(password, salt, secret, associated, out).map_err(|error| error.to_status())
        })())
    }

    /// Fills the `length` bytes (at least 1) at `out` with H' (RFC 9106 section 3.3) of the
    /// concatenation of the `count` inputs (the `index`-th at `inputs[index]`, of
    /// `input_lengths[index]` bytes), which must not overlap `out`.
    pub unsafe extern "C" fn umilib_crypto_argon2_argon2_variable_hash(inputs: *const *const u8, input_lengths: *const usize, count: usize, out: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable byte sequences and a writable byte range.
            let inputs = unsafe { Pointer::slices(inputs, input_lengths, count) }?;
            for input in &inputs {
                Pointer::check_disjoint(input.as_ptr(), input.len(), out, length)?;
            }
            let out = unsafe { Pointer::slice_mut(out, length) }?;
            Argon2::variable_hash(&inputs, out).map_err(|error| error.to_status())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "argon2",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_argon2_Argon2",
        documentation: " The type and the parameters m, t and p of Argon2 (RFC 9106), version 0x13, checked when they are created.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
