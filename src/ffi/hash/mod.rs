//! The C ABI of [`crate::hash`].
//!
//! Every hash function type is an opaque handle with the same functions,
//! defined by [`ffi_digest!`](crate::ffi_digest) and
//! [`ffi_extendable_output!`](crate::ffi_extendable_output):
//! `_new` (for unkeyed functions), `_free`, `_clone`, `_update`,
//! `_finalize` (which releases the handle on success, as the Rust method
//! consumes the state), `_finalize_reset`, `_reset`, `_digest` and the sizes.
//! Outputs are written into caller memory of exactly the output size.
//! Generic types are exported for the parameters C can name: `Sponge<168>`
//! as `Sponge168`, `SipHash<2, 4>` as `SipHash24`, and `CRCTable<W>` and
//! `CRC<W>` for every register type at once, with 128-bit values.

#[cfg(umilib_feature = "hash-adler32")]
pub mod adler32;
#[cfg(umilib_feature = "hash-ascon")]
pub mod ascon;
#[cfg(umilib_feature = "hash-blake")]
pub mod blake;
#[cfg(umilib_feature = "hash-crc")]
pub mod crc;
#[cfg(umilib_feature = "hash-md")]
pub mod md;
#[cfg(umilib_feature = "hash-ripemd")]
pub mod ripemd;
#[cfg(umilib_feature = "hash-sha")]
pub mod sha;
#[cfg(umilib_feature = "hash-siphash")]
pub mod siphash;
#[cfg(umilib_feature = "hash-sm3")]
pub mod sm3;
#[cfg(umilib_feature = "hash-streebog")]
pub mod streebog;
#[cfg(umilib_feature = "hash-xxhash")]
pub mod xxhash;

use crate::ffi::{Module, Status, ToStatus};
use crate::hash::HashError;

/// The statuses of [`HashError`], one per variant.
pub struct HashStatus;

impl HashStatus {
    pub const OUTPUT_LENGTH: Status = Status::new(c"hash", c"OutputLength", c"the output length is out of range");
    pub const KEY_LENGTH: Status = Status::new(c"hash", c"KeyLength", c"the key length is out of range");
    pub const INVALID_PARAMETER: Status = Status::new(c"hash", c"InvalidParameter", c"a parameter is invalid");
}

impl ToStatus for HashError {
    fn to_status(&self) -> &'static Status {
        match self {
            HashError::OutputLength { .. } => &HashStatus::OUTPUT_LENGTH,
            HashError::KeyLength { .. } => &HashStatus::KEY_LENGTH,
            HashError::InvalidParameter => &HashStatus::INVALID_PARAMETER,
        }
    }
}

/// Exports a [`Digest`](crate::hash::Digest) type `$type` as the opaque C
/// type `$c_type`, with the functions named `$prefix` followed by the method
/// name, into the current module as `FUNCTIONS` and `DEFINITION`.
///
/// `default` also exports `_new` and `_digest`, for types that implement
/// [`Default`]; `keyed` leaves the constructors to the module.
#[macro_export]
macro_rules! ffi_digest {
    (default $type:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        $crate::ffi_digest!(@common $type, $prefix, $c_type, $documentation, COMMON);

        $crate::ffi_exports! {
            const CONSTRUCTORS;
            /// Creates the state of the empty input.
            pub unsafe extern "C" fn new = concat!($prefix, "_new"); (out: *mut *mut $type) -> *const $crate::ffi::Status {
                // SAFETY: the caller passes a writable pointer.
                $crate::ffi::Status::from_result(unsafe { $crate::ffi::Pointer::write_handle(out, <$type as Default>::default()) })
            }

            /// Writes the hash of the `length` bytes at `data` into the `out_length` bytes at `out`,
            /// which must be the output size and must not overlap `data`.
            pub unsafe extern "C" fn digest = concat!($prefix, "_digest"); (data: *const u8, length: usize, out: *mut u8, out_length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    $crate::ffi::Pointer::check_disjoint(data, length, out, out_length)?;
                    // SAFETY: the caller passes readable and writable byte ranges.
                    let data = unsafe { $crate::ffi::Pointer::slice(data, length) }?;
                    let out = unsafe { $crate::ffi::Pointer::slice_mut(out, out_length) }?;
                    $crate::ffi::hash::DigestOutput::check(out, <$type as $crate::hash::Digest>::OUTPUT_SIZE)?;
                    out.copy_from_slice(<$type as $crate::hash::Digest>::digest(data).as_ref());
                    Ok(())
                })())
            }
        }

        /// The functions exported by this module, in declaration order.
        pub const FUNCTIONS: &[$crate::ffi::Function] =
            &$crate::ffi::Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);
    };
    (keyed $type:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        $crate::ffi_digest!(@common $type, $prefix, $c_type, $documentation, COMMON);
    };
    (@common $type:ty, $prefix:literal, $c_type:literal, $documentation:literal, $constant:ident) => {
        impl $crate::ffi::Value for $type {
            const TYPE: $crate::ffi::Type = $crate::ffi::Type::Named($c_type);
        }

        /// The C type of this module.
        pub const DEFINITION: $crate::ffi::Definition =
            $crate::ffi::Definition::Opaque { name: $c_type, documentation: concat!(" ", $documentation) };

        $crate::ffi_exports! {
            const $constant;
            /// Releases the state, zeroizing it. Does nothing if `state` is null.
            pub unsafe extern "C" fn free = concat!($prefix, "_free"); (state: *mut $type) {
                // SAFETY: the caller passes null or a handle created by this module.
                unsafe { $crate::ffi::Pointer::free(state) }
            }

            /// Writes a copy of `state` into `out`.
            pub unsafe extern "C" fn clone = concat!($prefix, "_clone"); (state: *const $type, out: *mut *mut $type) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let state = unsafe { $crate::ffi::Pointer::reference(state) }?;
                    unsafe { $crate::ffi::Pointer::write_handle(out, state.clone()) }
                })())
            }

            /// Adds the `length` bytes at `data` to the input.
            pub unsafe extern "C" fn update = concat!($prefix, "_update"); (state: *mut $type, data: *const u8, length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and readable bytes.
                    let state = unsafe { $crate::ffi::Pointer::reference_mut(state) }?;
                    let data = unsafe { $crate::ffi::Pointer::slice(data, length) }?;
                    $crate::hash::Digest::update(state, data);
                    Ok(())
                })())
            }

            /// Writes the hash into the `out_length` bytes at `out`, which must be the output size,
            /// and releases the state. On failure the state is not released.
            pub unsafe extern "C" fn finalize = concat!($prefix, "_finalize"); (state: *mut $type, out: *mut u8, out_length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a writable byte range.
                    let out = unsafe { $crate::ffi::Pointer::slice_mut(out, out_length) }?;
                    $crate::ffi::hash::DigestOutput::check(out, <$type as $crate::hash::Digest>::OUTPUT_SIZE)?;
                    if state.is_null() {
                        return Err(&$crate::ffi::Status::NULL_POINTER);
                    }
                    // SAFETY: the caller passes a handle created by this module and does not use it afterwards.
                    let mut state = unsafe { alloc::boxed::Box::from_raw(state) };
                    // Computed in place, so that dropping the box zeroizes the state where it lives.
                    out.copy_from_slice($crate::hash::Digest::finalize_reset(&mut *state).as_ref());
                    drop(state);
                    Ok(())
                })())
            }

            /// Writes the hash into the `out_length` bytes at `out`, which must be the output size,
            /// and returns the state to its start.
            pub unsafe extern "C" fn finalize_reset = concat!($prefix, "_finalize_reset"); (state: *mut $type, out: *mut u8, out_length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable byte range.
                    let state = unsafe { $crate::ffi::Pointer::reference_mut(state) }?;
                    let out = unsafe { $crate::ffi::Pointer::slice_mut(out, out_length) }?;
                    $crate::ffi::hash::DigestOutput::check(out, <$type as $crate::hash::Digest>::OUTPUT_SIZE)?;
                    out.copy_from_slice($crate::hash::Digest::finalize_reset(state).as_ref());
                    Ok(())
                })())
            }

            /// Returns the state to its start.
            pub unsafe extern "C" fn reset = concat!($prefix, "_reset"); (state: *mut $type) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle.
                    $crate::hash::Digest::reset(unsafe { $crate::ffi::Pointer::reference_mut(state) }?);
                    Ok(())
                })())
            }

            /// Returns the output size in bytes.
            pub unsafe extern "C" fn output_size = concat!($prefix, "_output_size"); () -> usize {
                <$type as $crate::hash::Digest>::OUTPUT_SIZE
            }

            /// Returns the block size in bytes.
            pub unsafe extern "C" fn block_size = concat!($prefix, "_block_size"); () -> usize {
                <$type as $crate::hash::Digest>::BLOCK_SIZE
            }
        }
    };
}

/// Exports an [`ExtendableOutput`](crate::hash::ExtendableOutput) type like
/// [`ffi_digest!`], with `_finalize_xof` creating its reader of the C type
/// exported by [`ffi_xof_reader!`](crate::ffi_xof_reader), and `_digest_xof`
/// for `default` types. The output has any length.
#[macro_export]
macro_rules! ffi_extendable_output {
    (default $type:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        $crate::ffi_extendable_output!(@common $type, $prefix, $c_type, $documentation, COMMON);

        $crate::ffi_exports! {
            const CONSTRUCTORS;
            /// Creates the state of the empty input.
            pub unsafe extern "C" fn new = concat!($prefix, "_new"); (out: *mut *mut $type) -> *const $crate::ffi::Status {
                // SAFETY: the caller passes a writable pointer.
                $crate::ffi::Status::from_result(unsafe { $crate::ffi::Pointer::write_handle(out, <$type as Default>::default()) })
            }

            /// Writes the first `out_length` output bytes for the `length` bytes at `data` into `out`,
            /// which must not overlap `data`.
            pub unsafe extern "C" fn digest_xof = concat!($prefix, "_digest_xof"); (data: *const u8, length: usize, out: *mut u8, out_length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    $crate::ffi::Pointer::check_disjoint(data, length, out, out_length)?;
                    // SAFETY: the caller passes readable and writable byte ranges.
                    let data = unsafe { $crate::ffi::Pointer::slice(data, length) }?;
                    let out = unsafe { $crate::ffi::Pointer::slice_mut(out, out_length) }?;
                    <$type as $crate::hash::ExtendableOutput>::digest_xof(data, out);
                    Ok(())
                })())
            }
        }

        /// The functions exported by this module, in declaration order.
        pub const FUNCTIONS: &[$crate::ffi::Function] =
            &$crate::ffi::Function::concat::<{ CONSTRUCTORS.len() + COMMON.len() }>(&[CONSTRUCTORS, COMMON]);
    };
    (keyed $type:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        $crate::ffi_extendable_output!(@common $type, $prefix, $c_type, $documentation, COMMON);
    };
    (@common $type:ty, $prefix:literal, $c_type:literal, $documentation:literal, $constant:ident) => {
        impl $crate::ffi::Value for $type {
            const TYPE: $crate::ffi::Type = $crate::ffi::Type::Named($c_type);
        }

        /// The C type of this module.
        pub const DEFINITION: $crate::ffi::Definition =
            $crate::ffi::Definition::Opaque { name: $c_type, documentation: concat!(" ", $documentation) };

        $crate::ffi_exports! {
            const $constant;
            /// Releases the state, zeroizing it. Does nothing if `state` is null.
            pub unsafe extern "C" fn free = concat!($prefix, "_free"); (state: *mut $type) {
                // SAFETY: the caller passes null or a handle created by this module.
                unsafe { $crate::ffi::Pointer::free(state) }
            }

            /// Writes a copy of `state` into `out`.
            pub unsafe extern "C" fn clone = concat!($prefix, "_clone"); (state: *const $type, out: *mut *mut $type) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let state = unsafe { $crate::ffi::Pointer::reference(state) }?;
                    unsafe { $crate::ffi::Pointer::write_handle(out, state.clone()) }
                })())
            }

            /// Adds the `length` bytes at `data` to the input.
            pub unsafe extern "C" fn update = concat!($prefix, "_update"); (state: *mut $type, data: *const u8, length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and readable bytes.
                    let state = unsafe { $crate::ffi::Pointer::reference_mut(state) }?;
                    let data = unsafe { $crate::ffi::Pointer::slice(data, length) }?;
                    $crate::hash::ExtendableOutput::update(state, data);
                    Ok(())
                })())
            }

            /// Writes the reader of the output into `out` and releases the state. On failure the
            /// state is not released.
            pub unsafe extern "C" fn finalize_xof = concat!($prefix, "_finalize_xof"); (state: *mut $type, out: *mut *mut <$type as $crate::hash::ExtendableOutput>::Reader) -> *const $crate::ffi::Status {
                if state.is_null() || out.is_null() {
                    return &$crate::ffi::Status::NULL_POINTER;
                }
                // SAFETY: the caller passes a handle created by this module and does not use it afterwards.
                let state = unsafe { alloc::boxed::Box::from_raw(state) };
                // From a copy, so that dropping the box zeroizes the state where it lives.
                let reader = $crate::hash::ExtendableOutput::finalize_xof((*state).clone());
                drop(state);
                // SAFETY: the caller passes a writable pointer, checked to be non-null above.
                $crate::ffi::Status::from_result(unsafe { $crate::ffi::Pointer::write_handle(out, reader) })
            }

            /// Returns the state to its start.
            pub unsafe extern "C" fn reset = concat!($prefix, "_reset"); (state: *mut $type) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle.
                    $crate::hash::ExtendableOutput::reset(unsafe { $crate::ffi::Pointer::reference_mut(state) }?);
                    Ok(())
                })())
            }

            /// Returns the block size in bytes.
            pub unsafe extern "C" fn block_size = concat!($prefix, "_block_size"); () -> usize {
                <$type as $crate::hash::ExtendableOutput>::BLOCK_SIZE
            }
        }
    };
}

/// Exports an [`XOFReader`](crate::hash::XOFReader) type `$type` as the
/// opaque C type `$c_type` with `_free`, `_clone` and `_read`.
#[macro_export]
macro_rules! ffi_xof_reader {
    ($type:ty, $prefix:literal, $c_type:literal, $documentation:literal) => {
        impl $crate::ffi::Value for $type {
            const TYPE: $crate::ffi::Type = $crate::ffi::Type::Named($c_type);
        }

        /// The C type of this module.
        pub const DEFINITION: $crate::ffi::Definition =
            $crate::ffi::Definition::Opaque { name: $c_type, documentation: concat!(" ", $documentation) };

        $crate::ffi_exports! {
            const FUNCTIONS;
            /// Releases the reader, zeroizing it. Does nothing if `reader` is null.
            pub unsafe extern "C" fn free = concat!($prefix, "_free"); (reader: *mut $type) {
                // SAFETY: the caller passes null or a handle created by this module.
                unsafe { $crate::ffi::Pointer::free(reader) }
            }

            /// Writes a copy of `reader`, at the same position, into `out`.
            pub unsafe extern "C" fn clone = concat!($prefix, "_clone"); (reader: *const $type, out: *mut *mut $type) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let reader = unsafe { $crate::ffi::Pointer::reference(reader) }?;
                    unsafe { $crate::ffi::Pointer::write_handle(out, reader.clone()) }
                })())
            }

            /// Writes the next `out_length` output bytes into `out`.
            pub unsafe extern "C" fn read = concat!($prefix, "_read"); (reader: *mut $type, out: *mut u8, out_length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable byte range.
                    let reader = unsafe { $crate::ffi::Pointer::reference_mut(reader) }?;
                    let out = unsafe { $crate::ffi::Pointer::slice_mut(out, out_length) }?;
                    $crate::hash::XOFReader::read(reader, out);
                    Ok(())
                })())
            }
        }
    };
}

/// Invokes the macro `$callback` with every cryptographic hash function of
/// fixed output that implements [`Digest`](crate::hash::Digest) and
/// [`Default`], as `"feature" Variant => path::Type, "C type name";` lines,
/// for the C ABI of the types generic over a hash function, which C selects
/// by the C type name of the hash function. The callback must put each
/// line behind the `umilib_feature` cfg of its feature.
#[macro_export]
macro_rules! ffi_digest_algorithms {
    ($callback:ident) => {
        $callback! {
            "hash-sha-v1" SHA1 => $crate::hash::sha::v1::SHA1, "umilib_hash_sha_v1_SHA1";
            "hash-sha-v2" SHA224 => $crate::hash::sha::v2::SHA224, "umilib_hash_sha_v2_SHA224";
            "hash-sha-v2" SHA256 => $crate::hash::sha::v2::SHA256, "umilib_hash_sha_v2_SHA256";
            "hash-sha-v2" SHA384 => $crate::hash::sha::v2::SHA384, "umilib_hash_sha_v2_SHA384";
            "hash-sha-v2" SHA512 => $crate::hash::sha::v2::SHA512, "umilib_hash_sha_v2_SHA512";
            "hash-sha-v2" SHA512_224 => $crate::hash::sha::v2::SHA512_224, "umilib_hash_sha_v2_SHA512_224";
            "hash-sha-v2" SHA512_256 => $crate::hash::sha::v2::SHA512_256, "umilib_hash_sha_v2_SHA512_256";
            "hash-sha-v3" SHA3_224 => $crate::hash::sha::v3::SHA3_224, "umilib_hash_sha_v3_SHA3_224";
            "hash-sha-v3" SHA3_256 => $crate::hash::sha::v3::SHA3_256, "umilib_hash_sha_v3_SHA3_256";
            "hash-sha-v3" SHA3_384 => $crate::hash::sha::v3::SHA3_384, "umilib_hash_sha_v3_SHA3_384";
            "hash-sha-v3" SHA3_512 => $crate::hash::sha::v3::SHA3_512, "umilib_hash_sha_v3_SHA3_512";
            "hash-sha-v3" Keccak224 => $crate::hash::sha::v3::Keccak224, "umilib_hash_sha_v3_Keccak224";
            "hash-sha-v3" Keccak256 => $crate::hash::sha::v3::Keccak256, "umilib_hash_sha_v3_Keccak256";
            "hash-sha-v3" Keccak384 => $crate::hash::sha::v3::Keccak384, "umilib_hash_sha_v3_Keccak384";
            "hash-sha-v3" Keccak512 => $crate::hash::sha::v3::Keccak512, "umilib_hash_sha_v3_Keccak512";
            "hash-md-v4" MD4 => $crate::hash::md::v4::MD4, "umilib_hash_md_v4_MD4";
            "hash-md-v5" MD5 => $crate::hash::md::v5::MD5, "umilib_hash_md_v5_MD5";
            "hash-ripemd" RIPEMD128 => $crate::hash::ripemd::RIPEMD128, "umilib_hash_ripemd_RIPEMD128";
            "hash-ripemd" RIPEMD160 => $crate::hash::ripemd::RIPEMD160, "umilib_hash_ripemd_RIPEMD160";
            "hash-ripemd" RIPEMD256 => $crate::hash::ripemd::RIPEMD256, "umilib_hash_ripemd_RIPEMD256";
            "hash-ripemd" RIPEMD320 => $crate::hash::ripemd::RIPEMD320, "umilib_hash_ripemd_RIPEMD320";
            "hash-sm3" SM3 => $crate::hash::sm3::SM3, "umilib_hash_sm3_SM3";
            "hash-streebog" Streebog256 => $crate::hash::streebog::Streebog256, "umilib_hash_streebog_Streebog256";
            "hash-streebog" Streebog512 => $crate::hash::streebog::Streebog512, "umilib_hash_streebog_Streebog512";
            "hash-blake-v2" BLAKE2b160 => $crate::hash::blake::v2::BLAKE2b160, "umilib_hash_blake_v2_BLAKE2b160";
            "hash-blake-v2" BLAKE2b256 => $crate::hash::blake::v2::BLAKE2b256, "umilib_hash_blake_v2_BLAKE2b256";
            "hash-blake-v2" BLAKE2b384 => $crate::hash::blake::v2::BLAKE2b384, "umilib_hash_blake_v2_BLAKE2b384";
            "hash-blake-v2" BLAKE2b512 => $crate::hash::blake::v2::BLAKE2b512, "umilib_hash_blake_v2_BLAKE2b512";
            "hash-blake-v2" BLAKE2s128 => $crate::hash::blake::v2::BLAKE2s128, "umilib_hash_blake_v2_BLAKE2s128";
            "hash-blake-v2" BLAKE2s160 => $crate::hash::blake::v2::BLAKE2s160, "umilib_hash_blake_v2_BLAKE2s160";
            "hash-blake-v2" BLAKE2s224 => $crate::hash::blake::v2::BLAKE2s224, "umilib_hash_blake_v2_BLAKE2s224";
            "hash-blake-v2" BLAKE2s256 => $crate::hash::blake::v2::BLAKE2s256, "umilib_hash_blake_v2_BLAKE2s256";
            "hash-blake-v3" BLAKE3 => $crate::hash::blake::v3::BLAKE3, "umilib_hash_blake_v3_BLAKE3";
            "hash-ascon" AsconHash256 => $crate::hash::ascon::AsconHash256, "umilib_hash_ascon_AsconHash256";
        }
    };
}

/// The check of output buffers shared by the exported hash functions.
pub struct DigestOutput;

impl DigestOutput {
    /// Fails unless `out` has exactly `size` bytes.
    pub fn check(out: &[u8], size: usize) -> Result<(), &'static Status> {
        if out.len() != size {
            return Err(&HashStatus::OUTPUT_LENGTH);
        }
        Ok(())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "hash",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "hash-adler32")]
        adler32::MODULE,
        #[cfg(umilib_feature = "hash-ascon")]
        ascon::MODULE,
        #[cfg(umilib_feature = "hash-blake")]
        blake::MODULE,
        #[cfg(umilib_feature = "hash-crc")]
        crc::MODULE,
        #[cfg(umilib_feature = "hash-md")]
        md::MODULE,
        #[cfg(umilib_feature = "hash-ripemd")]
        ripemd::MODULE,
        #[cfg(umilib_feature = "hash-sha")]
        sha::MODULE,
        #[cfg(umilib_feature = "hash-siphash")]
        siphash::MODULE,
        #[cfg(umilib_feature = "hash-sm3")]
        sm3::MODULE,
        #[cfg(umilib_feature = "hash-streebog")]
        streebog::MODULE,
        #[cfg(umilib_feature = "hash-xxhash")]
        xxhash::MODULE,
    ],
};

/// The registry of the hash functions of FIPS 180-4 and FIPS 202 that the
/// C ABI offers with signatures and key derivations of public-key schemes
/// (each instantiated for every curve): `$callback!` receives one line per
/// function, as [`ffi_digest_algorithms!`](crate::ffi_digest_algorithms) does.
#[macro_export]
macro_rules! ffi_standard_digests {
    ($callback:ident) => {
        $callback! {
            "hash-sha-v1" SHA1 => $crate::hash::sha::v1::SHA1, "umilib_hash_sha_v1_SHA1";
            "hash-sha-v2" SHA224 => $crate::hash::sha::v2::SHA224, "umilib_hash_sha_v2_SHA224";
            "hash-sha-v2" SHA256 => $crate::hash::sha::v2::SHA256, "umilib_hash_sha_v2_SHA256";
            "hash-sha-v2" SHA384 => $crate::hash::sha::v2::SHA384, "umilib_hash_sha_v2_SHA384";
            "hash-sha-v2" SHA512 => $crate::hash::sha::v2::SHA512, "umilib_hash_sha_v2_SHA512";
            "hash-sha-v2" SHA512_224 => $crate::hash::sha::v2::SHA512_224, "umilib_hash_sha_v2_SHA512_224";
            "hash-sha-v2" SHA512_256 => $crate::hash::sha::v2::SHA512_256, "umilib_hash_sha_v2_SHA512_256";
            "hash-sha-v3" SHA3_224 => $crate::hash::sha::v3::SHA3_224, "umilib_hash_sha_v3_SHA3_224";
            "hash-sha-v3" SHA3_256 => $crate::hash::sha::v3::SHA3_256, "umilib_hash_sha_v3_SHA3_256";
            "hash-sha-v3" SHA3_384 => $crate::hash::sha::v3::SHA3_384, "umilib_hash_sha_v3_SHA3_384";
            "hash-sha-v3" SHA3_512 => $crate::hash::sha::v3::SHA3_512, "umilib_hash_sha_v3_SHA3_512";
        }
    };
}
