//! The C ABI of [`crate::hash::xxhash::xxh32`].

use crate::ffi::{Function, Module, Pointer, Status};
use crate::hash::xxhash::xxh32::XXH32;

/// [`XXH32`].
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod xxh32 {
    crate::ffi_digest!(keyed crate::hash::xxhash::xxh32::XXH32, "umilib_hash_xxhash_xxh32_xxh32", "umilib_hash_xxhash_xxh32_XXH32", "XXH32 with a 32-bit seed.");
    crate::ffi_xxhash_integers!(crate::hash::xxhash::xxh32::XXH32, u32, u32, u32, "umilib_hash_xxhash_xxh32_xxh32");
}

crate::ffi_functions! {
    const CONSTRUCTORS;
    /// Creates XXH32 of the empty input with the seed 0.
    pub unsafe extern "C" fn umilib_hash_xxhash_xxh32_xxh32_new(out: *mut *mut XXH32) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, XXH32::new()) })
    }

    /// Creates XXH32 of the empty input with `seed`.
    pub unsafe extern "C" fn umilib_hash_xxhash_xxh32_xxh32_with_seed(seed: u32, out: *mut *mut XXH32) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, XXH32::with_seed(seed)) })
    }

    /// Writes the hash of the `length` bytes at `data` with the seed 0, in its canonical big-endian
    /// form, into the `out_length` bytes at `out`, which must be 4 and must not overlap `data`.
    pub unsafe extern "C" fn umilib_hash_xxhash_xxh32_xxh32_digest(data: *const u8, length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(data, length, out, out_length)?;
            // SAFETY: the caller passes readable and writable byte ranges.
            let data = unsafe { Pointer::slice(data, length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            crate::ffi::hash::DigestOutput::check(out, <XXH32 as crate::hash::Digest>::OUTPUT_SIZE)?;
            out.copy_from_slice(&<XXH32 as crate::hash::Digest>::digest(data));
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "xxh32",
    definitions: &[xxh32::DEFINITION],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + xxh32::COMMON.len() + xxh32::INTEGERS.len() }>(&[
        CONSTRUCTORS,
        xxh32::COMMON,
        xxh32::INTEGERS,
    ]),
    modules: &[],
};
