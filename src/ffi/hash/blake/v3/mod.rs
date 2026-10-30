//! The C ABI of [`crate::hash::blake::v3`].
//!
//! [`BLAKE3`] follows [`ffi_digest!`](crate::ffi_digest) with 32 bytes of
//! output, and `_finalize_xof` gives a [`BLAKE3Reader`] for any length. The
//! building blocks [`BLAKE3Chunk`](crate::hash::blake::v3::BLAKE3Chunk) and
//! [`BLAKE3Output`](crate::hash::blake::v3::BLAKE3Output) are not exported.

use crate::ffi::{Function, Module, Pointer, Status};
use crate::hash::ExtendableOutput;
use crate::hash::blake::v3::{BLAKE3, BLAKE3Reader};

/// [`BLAKE3Reader`].
pub mod blake3_reader {
    crate::ffi_xof_reader!(
        crate::hash::blake::v3::BLAKE3Reader,
        "umilib_hash_blake_v3_blake3_reader",
        "umilib_hash_blake_v3_BLAKE3Reader",
        "The output of BLAKE3, read in order from any position up to 2^64 bytes."
    );
}

/// [`BLAKE3`].
pub mod blake3 {
    crate::ffi_digest!(default crate::hash::blake::v3::BLAKE3, "umilib_hash_blake_v3_blake3", "umilib_hash_blake_v3_BLAKE3", "BLAKE3 in the hash, keyed hash or key derivation mode.");
}

crate::ffi_functions! {
    const METHODS;
    /// Creates the keyed hash mode with the 32-byte key at `key`.
    pub unsafe extern "C" fn umilib_hash_blake_v3_blake3_with_key(key: *const u8, key_length: usize, out: *mut *mut BLAKE3) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let key: &[u8; 32] = key.try_into().map_err(|_| &crate::ffi::hash::HashStatus::KEY_LENGTH)?;
            unsafe { Pointer::write_handle(out, BLAKE3::with_key(key)) }
        })())
    }

    /// Creates the key derivation mode for the context string at `context`; the input is the key
    /// material.
    pub unsafe extern "C" fn umilib_hash_blake_v3_blake3_with_context(context: *const u8, length: usize, out: *mut *mut BLAKE3) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let context = unsafe { Pointer::slice(context, length) }?;
            unsafe { Pointer::write_handle(out, BLAKE3::with_context(context)) }
        })())
    }

    /// Writes the 32-byte keyed hash of the `length` bytes at `data` under the 32-byte key into `out`,
    /// which must not overlap the key or the data.
    pub unsafe extern "C" fn umilib_hash_blake_v3_blake3_keyed_hash(key: *const u8, key_length: usize, data: *const u8, length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(key, key_length, out, out_length)?;
            Pointer::check_disjoint(data, length, out, out_length)?;
            // SAFETY: the caller passes readable and writable byte ranges.
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let key: &[u8; 32] = key.try_into().map_err(|_| &crate::ffi::hash::HashStatus::KEY_LENGTH)?;
            let data = unsafe { Pointer::slice(data, length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            crate::ffi::hash::DigestOutput::check(out, BLAKE3::OUTPUT_SIZE)?;
            out.copy_from_slice(&BLAKE3::keyed_hash(key, data));
            Ok(())
        })())
    }

    /// Writes the 32-byte key derived from the `material_length` bytes at `material` for the context
    /// string into `out`, which must not overlap the context or the material.
    pub unsafe extern "C" fn umilib_hash_blake_v3_blake3_derive_key(context: *const u8, context_length: usize, material: *const u8, material_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(context, context_length, out, out_length)?;
            Pointer::check_disjoint(material, material_length, out, out_length)?;
            // SAFETY: the caller passes readable and writable byte ranges.
            let context = unsafe { Pointer::slice(context, context_length) }?;
            let material = unsafe { Pointer::slice(material, material_length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            crate::ffi::hash::DigestOutput::check(out, BLAKE3::OUTPUT_SIZE)?;
            out.copy_from_slice(&BLAKE3::derive_key(context, material));
            Ok(())
        })())
    }

    /// Writes the reader of the output into `out` and releases the state. On failure the state is
    /// not released.
    pub unsafe extern "C" fn umilib_hash_blake_v3_blake3_finalize_xof(state: *mut BLAKE3, out: *mut *mut BLAKE3Reader) -> *const Status {
        if state.is_null() || out.is_null() {
            return &Status::NULL_POINTER;
        }
        // SAFETY: the caller passes a handle created by this module and does not use it afterwards.
        let state = unsafe { alloc::boxed::Box::from_raw(state) };
        // From the root node, so that dropping the box zeroizes the state where it lives.
        let reader = state.root().reader();
        drop(state);
        // SAFETY: the caller passes a writable pointer, checked to be non-null above.
        Status::from_result(unsafe { Pointer::write_handle(out, reader) })
    }

    /// Writes the first `out_length` output bytes of the hash mode for the `length` bytes at `data`
    /// into `out`, which must not overlap `data`.
    pub unsafe extern "C" fn umilib_hash_blake_v3_blake3_digest_xof(data: *const u8, length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(data, length, out, out_length)?;
            // SAFETY: the caller passes readable and writable byte ranges.
            let data = unsafe { Pointer::slice(data, length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            BLAKE3::digest_xof(data, out);
            Ok(())
        })())
    }

    /// Writes the number of bytes read so far into `out`.
    pub unsafe extern "C" fn umilib_hash_blake_v3_blake3_reader_position(reader: *const BLAKE3Reader, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write(out, reader.position()) }
        })())
    }

    /// Moves the reader to byte `position` of the output.
    pub unsafe extern "C" fn umilib_hash_blake_v3_blake3_reader_set_position(reader: *mut BLAKE3Reader, position: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(reader) }?.set_position(position);
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module =
    Module {
        name: "v3",
        definitions: &[blake3::DEFINITION, blake3_reader::DEFINITION],
        functions: &Function::concat::<{ blake3::FUNCTIONS.len() + METHODS.len() + blake3_reader::FUNCTIONS.len() }>(
            &[blake3::FUNCTIONS, METHODS, blake3_reader::FUNCTIONS],
        ),
        modules: &[],
    };
