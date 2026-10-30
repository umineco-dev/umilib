//! The C ABI of [`crate::hash::sha::v3`].
//!
//! `Sponge<168>` and `Sponge<136>`, the readers of the functions with the
//! rates of SHAKE128 and SHAKE256, are exported as `Sponge168` and
//! `Sponge136`. [`SP800185`](crate::hash::sha::v3::SP800185), the encodings
//! of SP 800-185, is not exported: C code uses the functions built on it.

use crate::ffi::{Function, Module, Pointer, Status};
use crate::hash::sha::v3::KeccakF1600;

/// [`SHA3_224`](crate::hash::sha::v3::SHA3_224).
pub mod sha3_224 {
    crate::ffi_digest!(default crate::hash::sha::v3::SHA3_224, "umilib_hash_sha_v3_sha3_224", "umilib_hash_sha_v3_SHA3_224", "SHA3-224 (FIPS 202).");
}

/// [`SHA3_256`](crate::hash::sha::v3::SHA3_256).
pub mod sha3_256 {
    crate::ffi_digest!(default crate::hash::sha::v3::SHA3_256, "umilib_hash_sha_v3_sha3_256", "umilib_hash_sha_v3_SHA3_256", "SHA3-256 (FIPS 202).");
}

/// [`SHA3_384`](crate::hash::sha::v3::SHA3_384).
pub mod sha3_384 {
    crate::ffi_digest!(default crate::hash::sha::v3::SHA3_384, "umilib_hash_sha_v3_sha3_384", "umilib_hash_sha_v3_SHA3_384", "SHA3-384 (FIPS 202).");
}

/// [`SHA3_512`](crate::hash::sha::v3::SHA3_512).
pub mod sha3_512 {
    crate::ffi_digest!(default crate::hash::sha::v3::SHA3_512, "umilib_hash_sha_v3_sha3_512", "umilib_hash_sha_v3_SHA3_512", "SHA3-512 (FIPS 202).");
}

/// [`Keccak224`](crate::hash::sha::v3::Keccak224).
pub mod keccak224 {
    crate::ffi_digest!(default crate::hash::sha::v3::Keccak224, "umilib_hash_sha_v3_keccak224", "umilib_hash_sha_v3_Keccak224", "Keccak-224, with the padding of the Keccak submission.");
}

/// [`Keccak256`](crate::hash::sha::v3::Keccak256).
pub mod keccak256 {
    crate::ffi_digest!(default crate::hash::sha::v3::Keccak256, "umilib_hash_sha_v3_keccak256", "umilib_hash_sha_v3_Keccak256", "Keccak-256, with the padding of the Keccak submission.");
}

/// [`Keccak384`](crate::hash::sha::v3::Keccak384).
pub mod keccak384 {
    crate::ffi_digest!(default crate::hash::sha::v3::Keccak384, "umilib_hash_sha_v3_keccak384", "umilib_hash_sha_v3_Keccak384", "Keccak-384, with the padding of the Keccak submission.");
}

/// [`Keccak512`](crate::hash::sha::v3::Keccak512).
pub mod keccak512 {
    crate::ffi_digest!(default crate::hash::sha::v3::Keccak512, "umilib_hash_sha_v3_keccak512", "umilib_hash_sha_v3_Keccak512", "Keccak-512, with the padding of the Keccak submission.");
}

/// `Sponge<168>`, the reader of the functions with the rate of SHAKE128.
pub mod sponge168 {
    crate::ffi_xof_reader!(
        crate::hash::sha::v3::Sponge<168>,
        "umilib_hash_sha_v3_sponge168",
        "umilib_hash_sha_v3_Sponge168",
        "The output of a function with the rate of SHAKE128 (Sponge<168>)."
    );
}

/// `Sponge<136>`, the reader of the functions with the rate of SHAKE256.
pub mod sponge136 {
    crate::ffi_xof_reader!(
        crate::hash::sha::v3::Sponge<136>,
        "umilib_hash_sha_v3_sponge136",
        "umilib_hash_sha_v3_Sponge136",
        "The output of a function with the rate of SHAKE256 (Sponge<136>)."
    );
}

/// [`SHAKE128`](crate::hash::sha::v3::SHAKE128).
pub mod shake128 {
    crate::ffi_extendable_output!(default crate::hash::sha::v3::SHAKE128, "umilib_hash_sha_v3_shake128", "umilib_hash_sha_v3_SHAKE128", "SHAKE128 (FIPS 202).");
}

/// [`SHAKE256`](crate::hash::sha::v3::SHAKE256).
pub mod shake256 {
    crate::ffi_extendable_output!(default crate::hash::sha::v3::SHAKE256, "umilib_hash_sha_v3_shake256", "umilib_hash_sha_v3_SHAKE256", "SHAKE256 (FIPS 202).");
}

/// Exports cSHAKE `$type` with its constructor from a function name and a customization string.
macro_rules! cshake_functions {
    ($type:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        crate::ffi_extendable_output!(keyed $type, $prefix, $c_type, $documentation);

        crate::ffi_exports! {
            const CONSTRUCTORS;
            /// Creates cSHAKE with the function name and the customization string, each a byte range;
            /// with both empty it is SHAKE.
            pub unsafe extern "C" fn new = concat!($prefix, "_new"); (name: *const u8, name_length: usize, customization: *const u8, customization_length: usize, out: *mut *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes readable byte ranges and a writable pointer.
                    let name = unsafe { crate::ffi::Pointer::slice(name, name_length) }?;
                    let customization = unsafe { crate::ffi::Pointer::slice(customization, customization_length) }?;
                    unsafe { crate::ffi::Pointer::write_handle(out, <$type>::new(name, customization)) }
                })())
            }
        }

        /// The functions exported by this module, in declaration order.
        pub const FUNCTIONS: &[crate::ffi::Function] =
            &crate::ffi::Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);
    };
}

/// [`CSHAKE128`](crate::hash::sha::v3::CSHAKE128).
pub mod cshake128 {
    cshake_functions!(
        crate::hash::sha::v3::CSHAKE128,
        "umilib_hash_sha_v3_cshake128",
        "umilib_hash_sha_v3_CSHAKE128",
        "cSHAKE128 (SP 800-185)."
    );
}

/// [`CSHAKE256`](crate::hash::sha::v3::CSHAKE256).
pub mod cshake256 {
    cshake_functions!(
        crate::hash::sha::v3::CSHAKE256,
        "umilib_hash_sha_v3_cshake256",
        "umilib_hash_sha_v3_CSHAKE256",
        "cSHAKE256 (SP 800-185)."
    );
}

/// Exports the functions that TupleHash and ParallelHash share: they absorb
/// differently but end alike, with an output of any length or a reader.
macro_rules! sp800185_functions {
    ($type:ty, $reader:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        impl crate::ffi::Value for $type {
            const TYPE: crate::ffi::Type = crate::ffi::Type::Named($c_type);
        }

        /// The C type of this module.
        pub const DEFINITION: crate::ffi::Definition =
            crate::ffi::Definition::Opaque { name: $c_type, documentation: concat!(" ", $documentation) };

        crate::ffi_exports! {
            const COMMON;
            /// Releases the state, zeroizing it. Does nothing if `state` is null.
            pub unsafe extern "C" fn free = concat!($prefix, "_free"); (state: *mut $type) {
                // SAFETY: the caller passes null or a handle created by this module.
                unsafe { crate::ffi::Pointer::free(state) }
            }

            /// Writes a copy of `state` into `out`.
            pub unsafe extern "C" fn clone = concat!($prefix, "_clone"); (state: *const $type, out: *mut *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let state = unsafe { crate::ffi::Pointer::reference(state) }?;
                    unsafe { crate::ffi::Pointer::write_handle(out, state.clone()) }
                })())
            }

            /// Writes `out_length` bytes of output, a length that is part of the input, into `out` and
            /// releases the state. On failure the state is not released.
            pub unsafe extern "C" fn finalize = concat!($prefix, "_finalize"); (state: *mut $type, out: *mut u8, out_length: usize) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a writable byte range.
                    let out = unsafe { crate::ffi::Pointer::slice_mut(out, out_length) }?;
                    if state.is_null() {
                        return Err(&crate::ffi::Status::NULL_POINTER);
                    }
                    // SAFETY: the caller passes a handle created by this module and does not use it afterwards.
                    let state = unsafe { alloc::boxed::Box::from_raw(state) };
                    // From a copy, so that dropping the box zeroizes the state where it lives.
                    (*state).clone().finalize(out);
                    drop(state);
                    Ok(())
                })())
            }

            /// Writes the reader of the XOF variant into `out` and releases the state. On failure the
            /// state is not released.
            pub unsafe extern "C" fn finalize_xof = concat!($prefix, "_finalize_xof"); (state: *mut $type, out: *mut *mut $reader) -> *const crate::ffi::Status {
                if state.is_null() || out.is_null() {
                    return &crate::ffi::Status::NULL_POINTER;
                }
                // SAFETY: the caller passes a handle created by this module and does not use it afterwards.
                let state = unsafe { alloc::boxed::Box::from_raw(state) };
                // From a copy, so that dropping the box zeroizes the state where it lives.
                let reader = (*state).clone().finalize_xof();
                drop(state);
                // SAFETY: the caller passes a writable pointer, checked to be non-null above.
                crate::ffi::Status::from_result(unsafe { crate::ffi::Pointer::write_handle(out, reader) })
            }
        }
    };
}

/// Exports TupleHash `$type`.
macro_rules! tuple_hash_functions {
    ($type:ty, $reader:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        sp800185_functions!($type, $reader, $prefix, $c_type, $documentation);

        crate::ffi_exports! {
            const METHODS;
            /// Creates TupleHash of the empty tuple with the customization string.
            pub unsafe extern "C" fn new = concat!($prefix, "_new"); (customization: *const u8, customization_length: usize, out: *mut *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a readable byte range and a writable pointer.
                    let customization = unsafe { crate::ffi::Pointer::slice(customization, customization_length) }?;
                    unsafe { crate::ffi::Pointer::write_handle(out, <$type>::new(customization)) }
                })())
            }

            /// Adds the `length` bytes at `element` as the next string of the tuple.
            pub unsafe extern "C" fn push = concat!($prefix, "_push"); (state: *mut $type, element: *const u8, length: usize) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and readable bytes.
                    let state = unsafe { crate::ffi::Pointer::reference_mut(state) }?;
                    state.push(unsafe { crate::ffi::Pointer::slice(element, length) }?);
                    Ok(())
                })())
            }

            /// Returns to the empty tuple.
            pub unsafe extern "C" fn reset = concat!($prefix, "_reset"); (state: *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle.
                    unsafe { crate::ffi::Pointer::reference_mut(state) }?.reset();
                    Ok(())
                })())
            }
        }

        /// The functions exported by this module, in declaration order.
        pub const FUNCTIONS: &[crate::ffi::Function] =
            &crate::ffi::Function::concat::<{ METHODS.len() + COMMON.len() }>(&[METHODS, COMMON]);
    };
}

/// Exports ParallelHash `$type`.
macro_rules! parallel_hash_functions {
    ($type:ty, $reader:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        sp800185_functions!($type, $reader, $prefix, $c_type, $documentation);

        crate::ffi_exports! {
            const METHODS;
            /// Creates ParallelHash with blocks of `block_size` bytes (not 0) and the customization string.
            pub unsafe extern "C" fn new = concat!($prefix, "_new"); (block_size: usize, customization: *const u8, customization_length: usize, out: *mut *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a readable byte range and a writable pointer.
                    let customization = unsafe { crate::ffi::Pointer::slice(customization, customization_length) }?;
                    let state = <$type>::new(block_size, customization).map_err(|error| crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { crate::ffi::Pointer::write_handle(out, state) }
                })())
            }

            /// Writes the block size in bytes into `out`.
            pub unsafe extern "C" fn block_size = concat!($prefix, "_block_size"); (state: *const $type, out: *mut usize) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let state = unsafe { crate::ffi::Pointer::reference(state) }?;
                    unsafe { crate::ffi::Pointer::write(out, state.block_size()) }
                })())
            }

            /// Adds the `length` bytes at `data` to the input.
            pub unsafe extern "C" fn update = concat!($prefix, "_update"); (state: *mut $type, data: *const u8, length: usize) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and readable bytes.
                    let state = unsafe { crate::ffi::Pointer::reference_mut(state) }?;
                    state.update(unsafe { crate::ffi::Pointer::slice(data, length) }?);
                    Ok(())
                })())
            }

            /// Returns to the empty input with the same block size and customization.
            pub unsafe extern "C" fn reset = concat!($prefix, "_reset"); (state: *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle.
                    unsafe { crate::ffi::Pointer::reference_mut(state) }?.reset();
                    Ok(())
                })())
            }
        }

        /// The functions exported by this module, in declaration order.
        pub const FUNCTIONS: &[crate::ffi::Function] =
            &crate::ffi::Function::concat::<{ METHODS.len() + COMMON.len() }>(&[METHODS, COMMON]);
    };
}

/// [`TupleHash128`](crate::hash::sha::v3::TupleHash128).
pub mod tuple_hash128 {
    tuple_hash_functions!(
        crate::hash::sha::v3::TupleHash128,
        crate::hash::sha::v3::Sponge<168>,
        "umilib_hash_sha_v3_tuple_hash128",
        "umilib_hash_sha_v3_TupleHash128",
        "TupleHash128 (SP 800-185)."
    );
}

/// [`TupleHash256`](crate::hash::sha::v3::TupleHash256).
pub mod tuple_hash256 {
    tuple_hash_functions!(
        crate::hash::sha::v3::TupleHash256,
        crate::hash::sha::v3::Sponge<136>,
        "umilib_hash_sha_v3_tuple_hash256",
        "umilib_hash_sha_v3_TupleHash256",
        "TupleHash256 (SP 800-185)."
    );
}

/// [`ParallelHash128`](crate::hash::sha::v3::ParallelHash128).
pub mod parallel_hash128 {
    parallel_hash_functions!(
        crate::hash::sha::v3::ParallelHash128,
        crate::hash::sha::v3::Sponge<168>,
        "umilib_hash_sha_v3_parallel_hash128",
        "umilib_hash_sha_v3_ParallelHash128",
        "ParallelHash128 (SP 800-185)."
    );
}

/// [`ParallelHash256`](crate::hash::sha::v3::ParallelHash256).
pub mod parallel_hash256 {
    parallel_hash_functions!(
        crate::hash::sha::v3::ParallelHash256,
        crate::hash::sha::v3::Sponge<136>,
        "umilib_hash_sha_v3_parallel_hash256",
        "umilib_hash_sha_v3_ParallelHash256",
        "ParallelHash256 (SP 800-185)."
    );
}

crate::ffi_functions! {
    const PERMUTATION;
    /// Applies Keccak-f\[1600\] to the 25 lanes at `state` (lane x + 5y at index x + 5y).
    pub unsafe extern "C" fn umilib_hash_sha_v3_keccak_f1600_permute(state: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes 25 writable lanes.
            let lanes = unsafe { Pointer::slice_of_mut(state, 25) }?;
            let lanes: &mut [u64; 25] = lanes.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            KeccakF1600::permute(lanes);
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v3",
    definitions: &[
        sha3_224::DEFINITION,
        sha3_256::DEFINITION,
        sha3_384::DEFINITION,
        sha3_512::DEFINITION,
        keccak224::DEFINITION,
        keccak256::DEFINITION,
        keccak384::DEFINITION,
        keccak512::DEFINITION,
        sponge168::DEFINITION,
        sponge136::DEFINITION,
        shake128::DEFINITION,
        shake256::DEFINITION,
        cshake128::DEFINITION,
        cshake256::DEFINITION,
        tuple_hash128::DEFINITION,
        tuple_hash256::DEFINITION,
        parallel_hash128::DEFINITION,
        parallel_hash256::DEFINITION,
    ],
    functions: &Function::concat::<
        {
            sha3_224::FUNCTIONS.len()
                + sha3_256::FUNCTIONS.len()
                + sha3_384::FUNCTIONS.len()
                + sha3_512::FUNCTIONS.len()
                + keccak224::FUNCTIONS.len()
                + keccak256::FUNCTIONS.len()
                + keccak384::FUNCTIONS.len()
                + keccak512::FUNCTIONS.len()
                + sponge168::FUNCTIONS.len()
                + sponge136::FUNCTIONS.len()
                + shake128::FUNCTIONS.len()
                + shake256::FUNCTIONS.len()
                + cshake128::FUNCTIONS.len()
                + cshake256::FUNCTIONS.len()
                + tuple_hash128::FUNCTIONS.len()
                + tuple_hash256::FUNCTIONS.len()
                + parallel_hash128::FUNCTIONS.len()
                + parallel_hash256::FUNCTIONS.len()
                + PERMUTATION.len()
        },
    >(&[
        sha3_224::FUNCTIONS,
        sha3_256::FUNCTIONS,
        sha3_384::FUNCTIONS,
        sha3_512::FUNCTIONS,
        keccak224::FUNCTIONS,
        keccak256::FUNCTIONS,
        keccak384::FUNCTIONS,
        keccak512::FUNCTIONS,
        sponge168::FUNCTIONS,
        sponge136::FUNCTIONS,
        shake128::FUNCTIONS,
        shake256::FUNCTIONS,
        cshake128::FUNCTIONS,
        cshake256::FUNCTIONS,
        tuple_hash128::FUNCTIONS,
        tuple_hash256::FUNCTIONS,
        parallel_hash128::FUNCTIONS,
        parallel_hash256::FUNCTIONS,
        PERMUTATION,
    ]),
    modules: &[],
};
