//! The C ABI of [`crate::hash::xxhash::xxh3`].
//!
//! [`XXH3_64`](crate::hash::xxhash::xxh3::XXH3_64) and
//! [`XXH3_128`](crate::hash::xxhash::xxh3::XXH3_128) are exported; the shared state
//! [`XXH3`](crate::hash::xxhash::xxh3::XXH3) and the key
//! [`XXH3Secret`](crate::hash::xxhash::xxh3::XXH3Secret) are built by their
//! constructors.

use crate::ffi::{Function, Module};

/// Exports the constructors from a seed and from a secret of `$type`.
macro_rules! xxh3_constructors {
    ($type:ty, $prefix:literal) => {
        crate::ffi_exports! {
            const KEYED;
            /// Creates the function of the empty input with `seed`.
            pub unsafe extern "C" fn with_seed = concat!($prefix, "_with_seed"); (seed: u64, out: *mut *mut $type) -> *const crate::ffi::Status {
                // SAFETY: the caller passes a writable pointer.
                crate::ffi::Status::from_result(unsafe { crate::ffi::Pointer::write_handle(out, <$type>::with_seed(seed)) })
            }

            /// Creates the function of the empty input with a copy of the secret at `secret`, of at
            /// least 136 bytes.
            pub unsafe extern "C" fn with_secret = concat!($prefix, "_with_secret"); (secret: *const u8, length: usize, out: *mut *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes readable bytes and a writable pointer.
                    let secret = unsafe { crate::ffi::Pointer::slice(secret, length) }?;
                    let state = <$type>::with_secret(secret).map_err(|error| crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { crate::ffi::Pointer::write_handle(out, state) }
                })())
            }
        }
    };
}

/// [`XXH3_64`](crate::hash::xxhash::xxh3::XXH3_64).
pub mod xxh3_64 {
    crate::ffi_digest!(default crate::hash::xxhash::xxh3::XXH3_64, "umilib_hash_xxhash_xxh3_xxh3_64", "umilib_hash_xxhash_xxh3_XXH3_64", "XXH3 with 64 bits of output, keyed by a seed or a secret.");
    crate::ffi_xxhash_integers!(crate::hash::xxhash::xxh3::XXH3_64, u64, u64, u64, "umilib_hash_xxhash_xxh3_xxh3_64");
    xxh3_constructors!(crate::hash::xxhash::xxh3::XXH3_64, "umilib_hash_xxhash_xxh3_xxh3_64");
}

/// [`XXH3_128`](crate::hash::xxhash::xxh3::XXH3_128).
pub mod xxh3_128 {
    crate::ffi_digest!(default crate::hash::xxhash::xxh3::XXH3_128, "umilib_hash_xxhash_xxh3_xxh3_128", "umilib_hash_xxhash_xxh3_XXH3_128", "XXH3 with 128 bits of output (XXH128), keyed by a seed or a secret.");
    crate::ffi_xxhash_integers!(
        crate::hash::xxhash::xxh3::XXH3_128,
        u64,
        u128,
        crate::ffi::U128,
        "umilib_hash_xxhash_xxh3_xxh3_128"
    );
    xxh3_constructors!(crate::hash::xxhash::xxh3::XXH3_128, "umilib_hash_xxhash_xxh3_xxh3_128");
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "xxh3",
    definitions: &[xxh3_64::DEFINITION, xxh3_128::DEFINITION],
    functions: &Function::concat::<
        {
            xxh3_64::FUNCTIONS.len()
                + xxh3_64::KEYED.len()
                + xxh3_64::INTEGERS.len()
                + xxh3_128::FUNCTIONS.len()
                + xxh3_128::KEYED.len()
                + xxh3_128::INTEGERS.len()
        },
    >(&[
        xxh3_64::FUNCTIONS,
        xxh3_64::KEYED,
        xxh3_64::INTEGERS,
        xxh3_128::FUNCTIONS,
        xxh3_128::KEYED,
        xxh3_128::INTEGERS,
    ]),
    modules: &[],
};
