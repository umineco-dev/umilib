//! The C ABI of [`crate::hash::xxhash::xxh64`].

use crate::ffi::{Function, Module, Pointer, Status};
use crate::hash::xxhash::xxh64::XXH64;

/// [`XXH64`].
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod xxh64 {
    crate::ffi_digest!(keyed crate::hash::xxhash::xxh64::XXH64, "umilib_hash_xxhash_xxh64_xxh64", "umilib_hash_xxhash_xxh64_XXH64", "XXH64 with a 64-bit seed.");
    crate::ffi_xxhash_integers!(crate::hash::xxhash::xxh64::XXH64, u64, u64, u64, "umilib_hash_xxhash_xxh64_xxh64");
}

crate::ffi_functions! {
    const CONSTRUCTORS;
    /// Creates XXH64 of the empty input with the seed 0.
    pub unsafe extern "C" fn umilib_hash_xxhash_xxh64_xxh64_new(out: *mut *mut XXH64) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, XXH64::new()) })
    }

    /// Creates XXH64 of the empty input with `seed`.
    pub unsafe extern "C" fn umilib_hash_xxhash_xxh64_xxh64_with_seed(seed: u64, out: *mut *mut XXH64) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, XXH64::with_seed(seed)) })
    }

    /// Writes the hash of the `length` bytes at `data` with the seed 0, in its canonical big-endian
    /// form, into the `out_length` bytes at `out`, which must be 8 and must not overlap `data`.
    pub unsafe extern "C" fn umilib_hash_xxhash_xxh64_xxh64_digest(data: *const u8, length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(data, length, out, out_length)?;
            // SAFETY: the caller passes readable and writable byte ranges.
            let data = unsafe { Pointer::slice(data, length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            crate::ffi::hash::DigestOutput::check(out, <XXH64 as crate::hash::Digest>::OUTPUT_SIZE)?;
            out.copy_from_slice(&<XXH64 as crate::hash::Digest>::digest(data));
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "xxh64",
    definitions: &[xxh64::DEFINITION],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + xxh64::COMMON.len() + xxh64::INTEGERS.len() }>(&[
        CONSTRUCTORS,
        xxh64::COMMON,
        xxh64::INTEGERS,
    ]),
    modules: &[],
};
