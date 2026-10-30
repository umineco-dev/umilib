//! The C ABI of [`crate::crypto::hkdf`].
//!
//! [`HKDF<H>`](crate::crypto::hkdf::HKDF) is exported as one type for every
//! hash function of [`ffi_digest_algorithms!`](crate::ffi_digest_algorithms),
//! chosen by the C type name of the hash type.

use crate::crypto::CryptoError;
use crate::ffi::{Definition, Module, Pointer, Status, ToStatus, Type, Value};

/// Defines [`HKDFState`] over the hash functions of the registry.
macro_rules! hkdf_state {
    ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        /// [`HKDF<H>`](crate::crypto::hkdf::HKDF) for any hash function `H` of the registry.
        #[derive(Clone)]
        // The enum lives behind a handle: boxing the variants would add an allocation.
        #[allow(clippy::large_enum_variant)]
        pub enum HKDFState {
            $(
                #[cfg(umilib_feature = $feature)]
                $variant(crate::crypto::hkdf::HKDF<$type>),
            )*
        }

        // The enum is empty when no algorithm of the registry is enabled, leaving the arguments unused.
        #[allow(unused_variables)]
        impl HKDFState {
            /// HKDF with the pseudorandom key `prk` over the hash function whose C type is named
            /// `hash`; `None` if it is unknown or not enabled.
            pub fn new(hash: &str, prk: &[u8]) -> Option<Result<HKDFState, CryptoError>> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(crate::crypto::hkdf::HKDF::<$type>::new(prk).map(HKDFState::$variant)),
                    )*
                    _ => None,
                }
            }

            /// HKDF with the PRK extracted from `salt` and `ikm`; `None` if the hash function is unknown.
            pub fn from_secret(hash: &str, salt: &[u8], ikm: &[u8]) -> Option<HKDFState> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(HKDFState::$variant(crate::crypto::hkdf::HKDF::<$type>::from_secret(salt, ikm))),
                    )*
                    _ => None,
                }
            }

            /// HKDF-Extract into `out`, which must have the output size of the hash function; `None`
            /// if the hash function is unknown.
            pub fn extract(hash: &str, salt: &[u8], ikm: &[u8], out: &mut [u8]) -> Option<Result<(), &'static Status>> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some((|| {
                            crate::ffi::hash::DigestOutput::check(out, <$type as crate::hash::Digest>::OUTPUT_SIZE)?;
                            let mut prk = crate::crypto::hkdf::HKDF::<$type>::extract(salt, ikm);
                            out.copy_from_slice(prk.as_ref());
                            crate::secret::Zeroize::zeroize(prk.as_mut());
                            Ok(())
                        })()),
                    )*
                    _ => None,
                }
            }

            pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), CryptoError> {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        HKDFState::$variant(ref hkdf) => hkdf.expand(info, okm),
                    )*
                }
            }

            /// The longest output: 255 × HashLen.
            pub fn maximum_output(&self) -> usize {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        HKDFState::$variant(_) => crate::crypto::hkdf::HKDF::<$type>::MAXIMUM_OUTPUT,
                    )*
                }
            }
        }
    };
}

crate::ffi_digest_algorithms!(hkdf_state);

impl core::fmt::Debug for HKDFState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("HKDFState(..)")
    }
}

impl Value for HKDFState {
    const TYPE: Type = Type::Named("umilib_crypto_hkdf_HKDF");
}

crate::ffi_functions! {
    /// Creates HKDF with the pseudorandom key of at least HashLen bytes at `prk` over the hash function
    /// whose C type is named by the UTF-8 text at `hash`, such as `umilib_hash_sha_v2_SHA256`; fails with
    /// InvalidArgument if that hash function is unknown or not enabled.
    pub unsafe extern "C" fn umilib_crypto_hkdf_hkdf_new(hash: *const u8, hash_length: usize, prk: *const u8, prk_length: usize, out: *mut *mut HKDFState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let prk = unsafe { Pointer::slice(prk, prk_length) }?;
            let state = HKDFState::new(hash, prk).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Creates HKDF with the PRK extracted from the salt and the input keying material (an empty salt is
    /// HashLen zeros) over the hash function named by `hash`.
    pub unsafe extern "C" fn umilib_crypto_hkdf_hkdf_from_secret(hash: *const u8, hash_length: usize, salt: *const u8, salt_length: usize, ikm: *const u8, ikm_length: usize, out: *mut *mut HKDFState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let salt = unsafe { Pointer::slice(salt, salt_length) }?;
            let ikm = unsafe { Pointer::slice(ikm, ikm_length) }?;
            let state = HKDFState::from_secret(hash, salt, ikm).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Releases the state, zeroizing its key. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_hkdf_hkdf_free(state: *mut HKDFState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`.
    pub unsafe extern "C" fn umilib_crypto_hkdf_hkdf_clone(state: *const HKDFState, out: *mut *mut HKDFState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// HKDF-Expand: fills the `length` bytes at `okm` (at most 255 × HashLen) from the PRK and the info
    /// string, which must not overlap `okm`.
    pub unsafe extern "C" fn umilib_crypto_hkdf_hkdf_expand(state: *const HKDFState, info: *const u8, info_length: usize, okm: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(info, info_length, okm, length)?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable byte range.
            let state = unsafe { Pointer::reference(state) }?;
            let info = unsafe { Pointer::slice(info, info_length) }?;
            let okm = unsafe { Pointer::slice_mut(okm, length) }?;
            state.expand(info, okm).map_err(|error| error.to_status())
        })())
    }

    /// Writes the longest output, 255 × HashLen bytes, into `out`.
    pub unsafe extern "C" fn umilib_crypto_hkdf_hkdf_maximum_output(state: *const HKDFState, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write(out, state.maximum_output()) }
        })())
    }

    /// HKDF-Extract: writes the PRK of the salt and the input keying material into the `out_length`
    /// bytes at `out`, which must be the output size of the hash function named by `hash` and must not
    /// overlap the inputs.
    pub unsafe extern "C" fn umilib_crypto_hkdf_hkdf_extract(hash: *const u8, hash_length: usize, salt: *const u8, salt_length: usize, ikm: *const u8, ikm_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            for (input, input_length) in [(hash, hash_length), (salt, salt_length), (ikm, ikm_length)] {
                Pointer::check_disjoint(input, input_length, out, out_length)?;
            }
            // SAFETY: the caller passes readable text and bytes and a writable byte range.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let salt = unsafe { Pointer::slice(salt, salt_length) }?;
            let ikm = unsafe { Pointer::slice(ikm, ikm_length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            HKDFState::extract(hash, salt, ikm, out).ok_or(&Status::INVALID_ARGUMENT)?
        })())
    }

    /// Extract and Expand: fills the `length` bytes at `okm` from the salt, the input keying material
    /// and the info string with the hash function named by `hash`; the inputs must not overlap `okm`.
    pub unsafe extern "C" fn umilib_crypto_hkdf_hkdf_derive(hash: *const u8, hash_length: usize, salt: *const u8, salt_length: usize, ikm: *const u8, ikm_length: usize, info: *const u8, info_length: usize, okm: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            for (input, input_length) in [(hash, hash_length), (salt, salt_length), (ikm, ikm_length), (info, info_length)] {
                Pointer::check_disjoint(input, input_length, okm, length)?;
            }
            // SAFETY: the caller passes readable text and bytes and a writable byte range.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let salt = unsafe { Pointer::slice(salt, salt_length) }?;
            let ikm = unsafe { Pointer::slice(ikm, ikm_length) }?;
            let info = unsafe { Pointer::slice(info, info_length) }?;
            let okm = unsafe { Pointer::slice_mut(okm, length) }?;
            let state = HKDFState::from_secret(hash, salt, ikm).ok_or(&Status::INVALID_ARGUMENT)?;
            state.expand(info, okm).map_err(|error| error.to_status())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "hkdf",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_hkdf_HKDF",
        documentation: " HKDF (RFC 5869) over a hash function chosen by name, keyed with a pseudorandom key.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
