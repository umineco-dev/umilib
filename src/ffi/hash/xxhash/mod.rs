//! The C ABI of [`crate::hash::xxhash`].
//!
//! Each function also gives its value as an integer (`_value` and `_hash`),
//! the 128-bit one as `umilib_ffi_U128`; the output bytes of `_finalize` are
//! the canonical, big-endian form of that integer.

#[cfg(umilib_feature = "hash-xxhash-xxh3")]
pub mod xxh3;
#[cfg(umilib_feature = "hash-xxhash-xxh32")]
pub mod xxh32;
#[cfg(umilib_feature = "hash-xxhash-xxh64")]
pub mod xxh64;

use crate::ffi::Module;

/// Exports the integer forms of a seeded xxHash function `$type`: the
/// constructor from the seed, `_hash` and `_value`, whose values are `$value`
/// in Rust and `$c_value` in C.
#[macro_export]
macro_rules! ffi_xxhash_integers {
    ($type:ty, $seed:ty, $value:ty, $c_value:ty, $prefix:literal) => {
        $crate::ffi_exports! {
            const INTEGERS;
            /// Writes the hash of the `length` bytes at `data` with `seed` into `out`.
            pub unsafe extern "C" fn hash = concat!($prefix, "_hash"); (seed: $seed, data: *const u8, length: usize, out: *mut $c_value) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes readable bytes and a writable pointer.
                    let data = unsafe { $crate::ffi::Pointer::slice(data, length) }?;
                    unsafe { $crate::ffi::Pointer::write(out, <$c_value>::from(<$type>::hash(seed, data))) }
                })())
            }

            /// Writes the hash of the input so far into `out`, without changing the state.
            pub unsafe extern "C" fn value = concat!($prefix, "_value"); (state: *const $type, out: *mut $c_value) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let state = unsafe { $crate::ffi::Pointer::reference(state) }?;
                    let value: $value = state.value();
                    unsafe { $crate::ffi::Pointer::write(out, <$c_value>::from(value)) }
                })())
            }
        }
    };
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "xxhash",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "hash-xxhash-xxh3")]
        xxh3::MODULE,
        #[cfg(umilib_feature = "hash-xxhash-xxh32")]
        xxh32::MODULE,
        #[cfg(umilib_feature = "hash-xxhash-xxh64")]
        xxh64::MODULE,
    ],
};
