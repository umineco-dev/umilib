//! The C ABI of [`crate::hash::blake::v2`].
//!
//! The parameter blocks are structures with the fields of the Rust types;
//! the engines, the parallel modes and BLAKE2X write outputs of the length
//! they were created with, and the fixed-length types follow
//! [`ffi_digest!`](crate::ffi_digest). The compression function and the
//! counter of the engines are not exported.

use crate::ffi::{Definition, Function, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::hash::blake::v2::{BLAKE2bParameters, BLAKE2sParameters};

impl Value for BLAKE2bParameters {
    const TYPE: Type = Type::Named("umilib_hash_blake_v2_BLAKE2bParameters");
}

impl Value for BLAKE2sParameters {
    const TYPE: Type = Type::Named("umilib_hash_blake_v2_BLAKE2sParameters");
}

/// Exports the functions of a variable-length type that the engines, the
/// parallel modes and BLAKE2X share.
macro_rules! variable_functions {
    ($type:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
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

            /// Adds the `length` bytes at `data` to the input.
            pub unsafe extern "C" fn update = concat!($prefix, "_update"); (state: *mut $type, data: *const u8, length: usize) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and readable bytes.
                    let state = unsafe { crate::ffi::Pointer::reference_mut(state) }?;
                    state.update(unsafe { crate::ffi::Pointer::slice(data, length) }?);
                    Ok(())
                })())
            }

            /// Writes the output into the `out_length` bytes at `out`, which must be the output length,
            /// and returns the state to its start.
            pub unsafe extern "C" fn finalize_into = concat!($prefix, "_finalize_into"); (state: *mut $type, out: *mut u8, out_length: usize) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable byte range.
                    let state = unsafe { crate::ffi::Pointer::reference_mut(state) }?;
                    let out = unsafe { crate::ffi::Pointer::slice_mut(out, out_length) }?;
                    state.finalize_into(out).map_err(|error| crate::ffi::ToStatus::to_status(&error))
                })())
            }

            /// Returns the state to its start, after the parameters and the key.
            pub unsafe extern "C" fn reset = concat!($prefix, "_reset"); (state: *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle.
                    unsafe { crate::ffi::Pointer::reference_mut(state) }?.reset();
                    Ok(())
                })())
            }

            /// Writes the output length in bytes into `out`.
            pub unsafe extern "C" fn output_length = concat!($prefix, "_output_length"); (state: *const $type, out: *mut usize) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let state = unsafe { crate::ffi::Pointer::reference(state) }?;
                    unsafe { crate::ffi::Pointer::write(out, state.output_length() as usize) }
                })())
            }
        }
    };
}

/// Exports the constructors from an output length and a key, of the
/// engines and the parallel modes (`usize` lengths) or BLAKE2X (`$length`).
macro_rules! keyed_constructors {
    ($type:ty, $length:ty, $prefix:literal) => {
        crate::ffi_exports! {
            const CONSTRUCTORS;
            /// Creates the unkeyed function with `output_length` bytes of output.
            pub unsafe extern "C" fn new = concat!($prefix, "_new"); (output_length: $length, out: *mut *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    let state = <$type>::new(output_length).map_err(|error| crate::ffi::ToStatus::to_status(&error))?;
                    // SAFETY: the caller passes a writable pointer.
                    unsafe { crate::ffi::Pointer::write_handle(out, state) }
                })())
            }

            /// Creates the keyed function with the `key_length` bytes at `key` and `output_length` bytes
            /// of output.
            pub unsafe extern "C" fn with_key = concat!($prefix, "_with_key"); (key: *const u8, key_length: usize, output_length: $length, out: *mut *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes readable bytes and a writable pointer.
                    let key = unsafe { crate::ffi::Pointer::slice(key, key_length) }?;
                    let state = <$type>::with_key(key, output_length).map_err(|error| crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { crate::ffi::Pointer::write_handle(out, state) }
                })())
            }
        }
    };
}

/// Exports an engine `$type` with its parameter type `$parameters`.
macro_rules! engine_functions {
    ($type:ty, $parameters:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        variable_functions!($type, $prefix, $c_type, $documentation);
        keyed_constructors!($type, usize, $prefix);

        crate::ffi_exports! {
            const METHODS;
            /// Creates the function with every parameter given; `parameters->key_length` must be the
            /// length of the key.
            pub unsafe extern "C" fn with_parameters = concat!($prefix, "_with_parameters"); (parameters: *const $parameters, key: *const u8, key_length: usize, out: *mut *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a readable structure, readable bytes and a writable pointer.
                    let parameters = unsafe { crate::ffi::Pointer::reference(parameters) }?;
                    let key = unsafe { crate::ffi::Pointer::slice(key, key_length) }?;
                    let state = <$type>::with_parameters(parameters, key).map_err(|error| crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { crate::ffi::Pointer::write_handle(out, state) }
                })())
            }

            /// Creates the function with the parameter block and no key block, as the root of the
            /// parallel modes.
            pub unsafe extern "C" fn without_key_block = concat!($prefix, "_without_key_block"); (parameters: *const $parameters, out: *mut *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a readable structure and a writable pointer.
                    let parameters = unsafe { crate::ffi::Pointer::reference(parameters) }?;
                    let state = <$type>::without_key_block(parameters).map_err(|error| crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { crate::ffi::Pointer::write_handle(out, state) }
                })())
            }

            /// Marks the state as the last node of its tree level, or not.
            pub unsafe extern "C" fn set_last_node = concat!($prefix, "_set_last_node"); (state: *mut $type, last_node: bool) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle.
                    unsafe { crate::ffi::Pointer::reference_mut(state) }?.set_last_node(last_node);
                    Ok(())
                })())
            }
        }

        /// The functions exported by this module, in declaration order.
        pub const FUNCTIONS: &[crate::ffi::Function] = &crate::ffi::Function::concat::<
            { CONSTRUCTORS.len() + METHODS.len() + COMMON.len() },
        >(&[CONSTRUCTORS, METHODS, COMMON]);
    };
}

/// Exports a parallel mode or BLAKE2X `$type`, with output lengths of type `$length`.
macro_rules! mode_functions {
    ($type:ty, $length:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        variable_functions!($type, $prefix, $c_type, $documentation);
        keyed_constructors!($type, $length, $prefix);

        /// The functions exported by this module, in declaration order.
        pub const FUNCTIONS: &[crate::ffi::Function] =
            &crate::ffi::Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);
    };
}

/// Exports BLAKE2X `$type` over the parameters `$parameters`, with its reader `$reader`.
macro_rules! blake2x_functions {
    ($type:ty, $length:ty, $parameters:ty, $reader:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        mode_functions!($type, $length, $prefix, $c_type, $documentation);

        crate::ffi_exports! {
            const EXTENDED;
            /// Creates BLAKE2X with every parameter of the root given; the digest length must be the
            /// node size, `parameters->key_length` the length of the key and `xof_length` not 0.
            pub unsafe extern "C" fn with_parameters = concat!($prefix, "_with_parameters"); (parameters: *const $parameters, key: *const u8, key_length: usize, out: *mut *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a readable structure, readable bytes and a writable pointer.
                    let parameters = unsafe { crate::ffi::Pointer::reference(parameters) }?;
                    let key = unsafe { crate::ffi::Pointer::slice(key, key_length) }?;
                    let state = <$type>::with_parameters(parameters, key).map_err(|error| crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { crate::ffi::Pointer::write_handle(out, state) }
                })())
            }

            /// Writes the reader of the output, which computes each output node when it is read, into
            /// `out` and releases the state. On failure the state is not released.
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

/// Exports a fixed-length type `$type`, which also has a keyed constructor.
macro_rules! fixed_functions {
    ($type:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        crate::ffi_digest!(keyed $type, $prefix, $c_type, $documentation);

        crate::ffi_exports! {
            const CONSTRUCTORS;
            /// Creates the unkeyed function.
            pub unsafe extern "C" fn new = concat!($prefix, "_new"); (out: *mut *mut $type) -> *const crate::ffi::Status {
                // SAFETY: the caller passes a writable pointer.
                crate::ffi::Status::from_result(unsafe { crate::ffi::Pointer::write_handle(out, <$type>::new()) })
            }

            /// Creates the keyed function with the `key_length` bytes at `key`.
            pub unsafe extern "C" fn with_key = concat!($prefix, "_with_key"); (key: *const u8, key_length: usize, out: *mut *mut $type) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes readable bytes and a writable pointer.
                    let key = unsafe { crate::ffi::Pointer::slice(key, key_length) }?;
                    let state = <$type>::with_key(key).map_err(|error| crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { crate::ffi::Pointer::write_handle(out, state) }
                })())
            }

            /// Writes the unkeyed hash of the `length` bytes at `data` into the `out_length` bytes at
            /// `out`, which must be the output size and must not overlap `data`.
            pub unsafe extern "C" fn digest = concat!($prefix, "_digest"); (data: *const u8, length: usize, out: *mut u8, out_length: usize) -> *const crate::ffi::Status {
                crate::ffi::Status::from_result((|| {
                    crate::ffi::Pointer::check_disjoint(data, length, out, out_length)?;
                    // SAFETY: the caller passes readable and writable byte ranges.
                    let data = unsafe { crate::ffi::Pointer::slice(data, length) }?;
                    let out = unsafe { crate::ffi::Pointer::slice_mut(out, out_length) }?;
                    crate::ffi::hash::DigestOutput::check(out, <$type as crate::hash::Digest>::OUTPUT_SIZE)?;
                    out.copy_from_slice(<$type as crate::hash::Digest>::digest(data).as_ref());
                    Ok(())
                })())
            }
        }

        /// The functions exported by this module, in declaration order.
        pub const FUNCTIONS: &[crate::ffi::Function] =
            &crate::ffi::Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);
    };
}

/// [`BLAKE2b`](crate::hash::blake::v2::BLAKE2b).
pub mod blake2b {
    engine_functions!(
        crate::hash::blake::v2::BLAKE2b,
        crate::hash::blake::v2::BLAKE2bParameters,
        "umilib_hash_blake_v2_blake2b",
        "umilib_hash_blake_v2_BLAKE2b",
        "BLAKE2b with any output length of 1 to 64 bytes and any parameters (RFC 7693)."
    );
}

/// [`BLAKE2s`](crate::hash::blake::v2::BLAKE2s).
pub mod blake2s {
    engine_functions!(
        crate::hash::blake::v2::BLAKE2s,
        crate::hash::blake::v2::BLAKE2sParameters,
        "umilib_hash_blake_v2_blake2s",
        "umilib_hash_blake_v2_BLAKE2s",
        "BLAKE2s with any output length of 1 to 32 bytes and any parameters (RFC 7693)."
    );
}

/// [`BLAKE2bp`](crate::hash::blake::v2::BLAKE2bp).
pub mod blake2bp {
    mode_functions!(
        crate::hash::blake::v2::BLAKE2bp,
        usize,
        "umilib_hash_blake_v2_blake2bp",
        "umilib_hash_blake_v2_BLAKE2bp",
        "BLAKE2bp: BLAKE2b over 4 interleaved leaves."
    );
}

/// [`BLAKE2sp`](crate::hash::blake::v2::BLAKE2sp).
pub mod blake2sp {
    mode_functions!(
        crate::hash::blake::v2::BLAKE2sp,
        usize,
        "umilib_hash_blake_v2_blake2sp",
        "umilib_hash_blake_v2_BLAKE2sp",
        "BLAKE2sp: BLAKE2s over 8 interleaved leaves."
    );
}

/// [`BLAKE2Xb`](crate::hash::blake::v2::BLAKE2Xb).
pub mod blake2xb {
    blake2x_functions!(
        crate::hash::blake::v2::BLAKE2Xb,
        u32,
        crate::hash::blake::v2::BLAKE2bParameters,
        crate::hash::blake::v2::BLAKE2XbReader,
        "umilib_hash_blake_v2_blake2xb",
        "umilib_hash_blake_v2_BLAKE2Xb",
        "BLAKE2Xb: outputs of up to 2^32 - 2 bytes over BLAKE2b; the output length 2^32 - 1 leaves it open."
    );
}

/// [`BLAKE2XbReader`](crate::hash::blake::v2::BLAKE2XbReader).
pub mod blake2xb_reader {
    crate::ffi_xof_reader!(
        crate::hash::blake::v2::BLAKE2XbReader,
        "umilib_hash_blake_v2_blake2xb_reader",
        "umilib_hash_blake_v2_BLAKE2XbReader",
        "The output of BLAKE2Xb, computed node by node; reading past its length is an error."
    );
}

/// [`BLAKE2Xs`](crate::hash::blake::v2::BLAKE2Xs).
pub mod blake2xs {
    blake2x_functions!(
        crate::hash::blake::v2::BLAKE2Xs,
        u16,
        crate::hash::blake::v2::BLAKE2sParameters,
        crate::hash::blake::v2::BLAKE2XsReader,
        "umilib_hash_blake_v2_blake2xs",
        "umilib_hash_blake_v2_BLAKE2Xs",
        "BLAKE2Xs: outputs of up to 2^16 - 2 bytes over BLAKE2s; the output length 2^16 - 1 leaves it open."
    );
}

/// [`BLAKE2XsReader`](crate::hash::blake::v2::BLAKE2XsReader).
pub mod blake2xs_reader {
    crate::ffi_xof_reader!(
        crate::hash::blake::v2::BLAKE2XsReader,
        "umilib_hash_blake_v2_blake2xs_reader",
        "umilib_hash_blake_v2_BLAKE2XsReader",
        "The output of BLAKE2Xs, computed node by node; reading past its length is an error."
    );
}

/// [`BLAKE2b160`](crate::hash::blake::v2::BLAKE2b160).
pub mod blake2b160 {
    fixed_functions!(
        crate::hash::blake::v2::BLAKE2b160,
        "umilib_hash_blake_v2_blake2b160",
        "umilib_hash_blake_v2_BLAKE2b160",
        "BLAKE2b with 160 bits of output."
    );
}

/// [`BLAKE2b256`](crate::hash::blake::v2::BLAKE2b256).
pub mod blake2b256 {
    fixed_functions!(
        crate::hash::blake::v2::BLAKE2b256,
        "umilib_hash_blake_v2_blake2b256",
        "umilib_hash_blake_v2_BLAKE2b256",
        "BLAKE2b with 256 bits of output."
    );
}

/// [`BLAKE2b384`](crate::hash::blake::v2::BLAKE2b384).
pub mod blake2b384 {
    fixed_functions!(
        crate::hash::blake::v2::BLAKE2b384,
        "umilib_hash_blake_v2_blake2b384",
        "umilib_hash_blake_v2_BLAKE2b384",
        "BLAKE2b with 384 bits of output."
    );
}

/// [`BLAKE2b512`](crate::hash::blake::v2::BLAKE2b512).
pub mod blake2b512 {
    fixed_functions!(
        crate::hash::blake::v2::BLAKE2b512,
        "umilib_hash_blake_v2_blake2b512",
        "umilib_hash_blake_v2_BLAKE2b512",
        "BLAKE2b with 512 bits of output."
    );
}

/// [`BLAKE2s128`](crate::hash::blake::v2::BLAKE2s128).
pub mod blake2s128 {
    fixed_functions!(
        crate::hash::blake::v2::BLAKE2s128,
        "umilib_hash_blake_v2_blake2s128",
        "umilib_hash_blake_v2_BLAKE2s128",
        "BLAKE2s with 128 bits of output."
    );
}

/// [`BLAKE2s160`](crate::hash::blake::v2::BLAKE2s160).
pub mod blake2s160 {
    fixed_functions!(
        crate::hash::blake::v2::BLAKE2s160,
        "umilib_hash_blake_v2_blake2s160",
        "umilib_hash_blake_v2_BLAKE2s160",
        "BLAKE2s with 160 bits of output."
    );
}

/// [`BLAKE2s224`](crate::hash::blake::v2::BLAKE2s224).
pub mod blake2s224 {
    fixed_functions!(
        crate::hash::blake::v2::BLAKE2s224,
        "umilib_hash_blake_v2_blake2s224",
        "umilib_hash_blake_v2_BLAKE2s224",
        "BLAKE2s with 224 bits of output."
    );
}

/// [`BLAKE2s256`](crate::hash::blake::v2::BLAKE2s256).
pub mod blake2s256 {
    fixed_functions!(
        crate::hash::blake::v2::BLAKE2s256,
        "umilib_hash_blake_v2_blake2s256",
        "umilib_hash_blake_v2_BLAKE2s256",
        "BLAKE2s with 256 bits of output."
    );
}

crate::ffi_functions! {
    const PARAMETERS;
    /// Returns the sequential mode (fanout and depth 1) with `digest_length` bytes of output.
    pub unsafe extern "C" fn umilib_hash_blake_v2_blake2b_parameters_new(digest_length: u8) -> BLAKE2bParameters {
        BLAKE2bParameters::new(digest_length)
    }

    /// Writes the 64-byte parameter block of `parameters` into `out`, which must not overlap them.
    pub unsafe extern "C" fn umilib_hash_blake_v2_blake2b_parameters_to_bytes(parameters: *const BLAKE2bParameters, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(parameters, 1, out, out_length)?;
            // SAFETY: the caller passes a readable structure and a writable byte range.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            if out.len() != 64 {
                return Err(&Status::INVALID_ARGUMENT);
            }
            out.copy_from_slice(&parameters.to_bytes());
            Ok(())
        })())
    }

    /// Writes the parameters of the 64-byte block at `data` into `out`; fails if its reserved bytes
    /// are not zero.
    pub unsafe extern "C" fn umilib_hash_blake_v2_blake2b_parameters_from_bytes(data: *const u8, length: usize, out: *mut BLAKE2bParameters) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(data, length, out, 1)?;
            // SAFETY: the caller passes readable bytes and a writable structure.
            let data = unsafe { Pointer::slice(data, length) }?;
            let block: &[u8; 64] = data.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            let parameters = BLAKE2bParameters::from_bytes(block).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, parameters) }
        })())
    }

    /// Returns the sequential mode (fanout and depth 1) with `digest_length` bytes of output.
    pub unsafe extern "C" fn umilib_hash_blake_v2_blake2s_parameters_new(digest_length: u8) -> BLAKE2sParameters {
        BLAKE2sParameters::new(digest_length)
    }

    /// Writes the 32-byte parameter block of `parameters` into `out`, which must not overlap them.
    pub unsafe extern "C" fn umilib_hash_blake_v2_blake2s_parameters_to_bytes(parameters: *const BLAKE2sParameters, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(parameters, 1, out, out_length)?;
            // SAFETY: the caller passes a readable structure and a writable byte range.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            if out.len() != 32 {
                return Err(&Status::INVALID_ARGUMENT);
            }
            out.copy_from_slice(&parameters.to_bytes());
            Ok(())
        })())
    }

    /// Writes the parameters of the 32-byte block at `data` into `out`.
    pub unsafe extern "C" fn umilib_hash_blake_v2_blake2s_parameters_from_bytes(data: *const u8, length: usize, out: *mut BLAKE2sParameters) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(data, length, out, 1)?;
            // SAFETY: the caller passes readable bytes and a writable structure.
            let data = unsafe { Pointer::slice(data, length) }?;
            let block: &[u8; 32] = data.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, BLAKE2sParameters::from_bytes(block)) }
        })())
    }
}

/// The fields of a parameter structure with salts and personalizations of `N` bytes.
macro_rules! parameter_fields {
    ($node_offset:ty, $xof_length:ty, $salt:ty) => {
        &[
            Parameter { name: "digest_length", value: <u8 as Value>::TYPE },
            Parameter { name: "key_length", value: <u8 as Value>::TYPE },
            Parameter { name: "fanout", value: <u8 as Value>::TYPE },
            Parameter { name: "depth", value: <u8 as Value>::TYPE },
            Parameter { name: "leaf_length", value: <u32 as Value>::TYPE },
            Parameter { name: "node_offset", value: <$node_offset as Value>::TYPE },
            Parameter { name: "xof_length", value: <$xof_length as Value>::TYPE },
            Parameter { name: "node_depth", value: <u8 as Value>::TYPE },
            Parameter { name: "inner_length", value: <u8 as Value>::TYPE },
            Parameter { name: "salt", value: <$salt as Value>::TYPE },
            Parameter { name: "personal", value: <$salt as Value>::TYPE },
        ]
    };
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "v2",
    definitions: &[
        Definition::Structure {
            name: "umilib_hash_blake_v2_BLAKE2bParameters",
            documentation: " The parameters of BLAKE2b (RFC 7693 section 2.8), in the fields of their block.",
            fields: parameter_fields!(u32, u32, [u8; 16]),
        },
        Definition::Structure {
            name: "umilib_hash_blake_v2_BLAKE2sParameters",
            documentation: " The parameters of BLAKE2s (RFC 7693 section 2.8), in the fields of their block.",
            fields: parameter_fields!(u32, u16, [u8; 8]),
        },
        blake2b::DEFINITION,
        blake2s::DEFINITION,
        blake2bp::DEFINITION,
        blake2sp::DEFINITION,
        blake2xb::DEFINITION,
        blake2xs::DEFINITION,
        blake2xb_reader::DEFINITION,
        blake2xs_reader::DEFINITION,
        blake2b160::DEFINITION,
        blake2b256::DEFINITION,
        blake2b384::DEFINITION,
        blake2b512::DEFINITION,
        blake2s128::DEFINITION,
        blake2s160::DEFINITION,
        blake2s224::DEFINITION,
        blake2s256::DEFINITION,
    ],
    functions: &Function::concat::<
        {
            PARAMETERS.len()
                + blake2b::FUNCTIONS.len()
                + blake2s::FUNCTIONS.len()
                + blake2bp::FUNCTIONS.len()
                + blake2sp::FUNCTIONS.len()
                + blake2xb::FUNCTIONS.len()
                + blake2xb::EXTENDED.len()
                + blake2xb_reader::FUNCTIONS.len()
                + blake2xs::FUNCTIONS.len()
                + blake2xs::EXTENDED.len()
                + blake2xs_reader::FUNCTIONS.len()
                + blake2b160::FUNCTIONS.len()
                + blake2b256::FUNCTIONS.len()
                + blake2b384::FUNCTIONS.len()
                + blake2b512::FUNCTIONS.len()
                + blake2s128::FUNCTIONS.len()
                + blake2s160::FUNCTIONS.len()
                + blake2s224::FUNCTIONS.len()
                + blake2s256::FUNCTIONS.len()
        },
    >(&[
        PARAMETERS,
        blake2b::FUNCTIONS,
        blake2s::FUNCTIONS,
        blake2bp::FUNCTIONS,
        blake2sp::FUNCTIONS,
        blake2xb::FUNCTIONS,
        blake2xb::EXTENDED,
        blake2xb_reader::FUNCTIONS,
        blake2xs::FUNCTIONS,
        blake2xs::EXTENDED,
        blake2xs_reader::FUNCTIONS,
        blake2b160::FUNCTIONS,
        blake2b256::FUNCTIONS,
        blake2b384::FUNCTIONS,
        blake2b512::FUNCTIONS,
        blake2s128::FUNCTIONS,
        blake2s160::FUNCTIONS,
        blake2s224::FUNCTIONS,
        blake2s256::FUNCTIONS,
    ]),
    modules: &[],
};
