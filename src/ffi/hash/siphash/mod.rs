//! The C ABI of [`crate::hash::siphash`].
//!
//! The functions with their numbers of rounds as const generic parameters
//! are exported for the rounds the Rust aliases name: `SipHash<2, 4>` as
//! `SipHash24`, `HalfSipHash64<1, 3>` as `HalfSipHash64_13` and so on.

use crate::ffi::{Function, Module};

/// Exports a SipHash type `$type` with its constructor from the key.
macro_rules! siphash_functions {
    ($type:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        crate::ffi_digest!(keyed $type, $prefix, $c_type, $documentation);

        crate::ffi_exports! {
            const CONSTRUCTORS;
            /// Creates the function with the key at `key`, which must have the key size.
            pub unsafe extern "C" fn new = concat!($prefix, "_new"); (key: *const u8, key_length: usize, out: *mut *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes readable bytes and a writable pointer.
                    let key = unsafe { crate::ffi::Pointer::slice(key, key_length) }?;
                    let key = key.try_into().map_err(|_| &crate::ffi::hash::HashStatus::KEY_LENGTH)?;
                    unsafe { crate::ffi::Pointer::write_handle(out, <$type>::new(key)) }
                })())
            }

            /// Writes the output for the `length` bytes at `data` under the key into the `out_length`
            /// bytes at `out`, which must be the output size and must not overlap the key or the data.
            pub unsafe extern "C" fn hash = concat!($prefix, "_hash"); (key: *const u8, key_length: usize, data: *const u8, length: usize, out: *mut u8, out_length: usize) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    crate::ffi::Pointer::check_disjoint(key, key_length, out, out_length)?;
                    crate::ffi::Pointer::check_disjoint(data, length, out, out_length)?;
                    // SAFETY: the caller passes readable and writable byte ranges.
                    let key = unsafe { crate::ffi::Pointer::slice(key, key_length) }?;
                    let key = key.try_into().map_err(|_| &crate::ffi::hash::HashStatus::KEY_LENGTH)?;
                    let data = unsafe { crate::ffi::Pointer::slice(data, length) }?;
                    let out = unsafe { crate::ffi::Pointer::slice_mut(out, out_length) }?;
                    crate::ffi::hash::DigestOutput::check(out, <$type as crate::hash::Digest>::OUTPUT_SIZE)?;
                    out.copy_from_slice(&<$type>::hash(key, data));
                    Ok(())
                })())
            }

            /// Returns the key size in bytes.
            pub unsafe extern "C" fn key_size = concat!($prefix, "_key_size"); () -> usize {
                <$type>::KEY_SIZE
            }
        }

        /// The functions exported by this module, in declaration order.
        pub const FUNCTIONS: &[crate::ffi::Function] =
            &crate::ffi::Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);
    };
}

/// [`SipHash24`](crate::hash::siphash::SipHash24).
pub mod sip_hash24 {
    siphash_functions!(
        crate::hash::siphash::SipHash24,
        "umilib_hash_siphash_sip_hash24",
        "umilib_hash_siphash_SipHash24",
        "SipHash-2-4 with 64 bits of output and a 128-bit key."
    );
}

/// [`SipHash13`](crate::hash::siphash::SipHash13).
pub mod sip_hash13 {
    siphash_functions!(
        crate::hash::siphash::SipHash13,
        "umilib_hash_siphash_sip_hash13",
        "umilib_hash_siphash_SipHash13",
        "SipHash-1-3 with 64 bits of output and a 128-bit key."
    );
}

/// [`SipHash128_24`](crate::hash::siphash::SipHash128_24).
pub mod sip_hash128_24 {
    siphash_functions!(
        crate::hash::siphash::SipHash128_24,
        "umilib_hash_siphash_sip_hash128_24",
        "umilib_hash_siphash_SipHash128_24",
        "SipHash-2-4 with 128 bits of output and a 128-bit key."
    );
}

/// [`SipHash128_13`](crate::hash::siphash::SipHash128_13).
pub mod sip_hash128_13 {
    siphash_functions!(
        crate::hash::siphash::SipHash128_13,
        "umilib_hash_siphash_sip_hash128_13",
        "umilib_hash_siphash_SipHash128_13",
        "SipHash-1-3 with 128 bits of output and a 128-bit key."
    );
}

/// [`HalfSipHash24`](crate::hash::siphash::HalfSipHash24).
pub mod half_sip_hash24 {
    siphash_functions!(
        crate::hash::siphash::HalfSipHash24,
        "umilib_hash_siphash_half_sip_hash24",
        "umilib_hash_siphash_HalfSipHash24",
        "HalfSipHash-2-4 with 32 bits of output and a 64-bit key."
    );
}

/// [`HalfSipHash13`](crate::hash::siphash::HalfSipHash13).
pub mod half_sip_hash13 {
    siphash_functions!(
        crate::hash::siphash::HalfSipHash13,
        "umilib_hash_siphash_half_sip_hash13",
        "umilib_hash_siphash_HalfSipHash13",
        "HalfSipHash-1-3 with 32 bits of output and a 64-bit key."
    );
}

/// [`HalfSipHash64_24`](crate::hash::siphash::HalfSipHash64_24).
pub mod half_sip_hash64_24 {
    siphash_functions!(
        crate::hash::siphash::HalfSipHash64_24,
        "umilib_hash_siphash_half_sip_hash64_24",
        "umilib_hash_siphash_HalfSipHash64_24",
        "HalfSipHash-2-4 with 64 bits of output and a 64-bit key."
    );
}

/// [`HalfSipHash64_13`](crate::hash::siphash::HalfSipHash64_13).
pub mod half_sip_hash64_13 {
    siphash_functions!(
        crate::hash::siphash::HalfSipHash64_13,
        "umilib_hash_siphash_half_sip_hash64_13",
        "umilib_hash_siphash_HalfSipHash64_13",
        "HalfSipHash-1-3 with 64 bits of output and a 64-bit key."
    );
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "siphash",
    definitions: &[
        sip_hash24::DEFINITION,
        sip_hash13::DEFINITION,
        sip_hash128_24::DEFINITION,
        sip_hash128_13::DEFINITION,
        half_sip_hash24::DEFINITION,
        half_sip_hash13::DEFINITION,
        half_sip_hash64_24::DEFINITION,
        half_sip_hash64_13::DEFINITION,
    ],
    functions: &Function::concat::<
        {
            sip_hash24::FUNCTIONS.len()
                + sip_hash13::FUNCTIONS.len()
                + sip_hash128_24::FUNCTIONS.len()
                + sip_hash128_13::FUNCTIONS.len()
                + half_sip_hash24::FUNCTIONS.len()
                + half_sip_hash13::FUNCTIONS.len()
                + half_sip_hash64_24::FUNCTIONS.len()
                + half_sip_hash64_13::FUNCTIONS.len()
        },
    >(&[
        sip_hash24::FUNCTIONS,
        sip_hash13::FUNCTIONS,
        sip_hash128_24::FUNCTIONS,
        sip_hash128_13::FUNCTIONS,
        half_sip_hash24::FUNCTIONS,
        half_sip_hash13::FUNCTIONS,
        half_sip_hash64_24::FUNCTIONS,
        half_sip_hash64_13::FUNCTIONS,
    ]),
    modules: &[],
};
