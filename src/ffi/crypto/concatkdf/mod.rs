//! The C ABI of [`crate::crypto::concatkdf`].
//!
//! [`ConcatKDF<F>`](crate::crypto::concatkdf::ConcatKDF) is exported as one
//! type whose auxiliary function is chosen when it is created: a hash
//! function of [`ffi_digest_algorithms!`](crate::ffi_digest_algorithms)
//! (`umilib_crypto_concatkdf_HashFunction`, SP 800-56C Rev. 2 option 1) or
//! HMAC over one, keyed with a salt (`umilib_crypto_hmac_HMAC`, option 2).

use crate::crypto::CryptoError;
use crate::ffi::{Definition, Module, Pointer, Status, ToStatus, Type, Value};

/// Defines [`ConcatKDFState`] over the hash functions of the registry.
macro_rules! concatkdf_state {
    ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        /// [`ConcatKDF`](crate::crypto::concatkdf::ConcatKDF) over a hash function of the registry.
        #[derive(Clone)]
        // The enum lives behind a handle: boxing the variants would add an allocation.
        #[allow(clippy::large_enum_variant)]
        pub enum ConcatKDFHashState {
            $(
                #[cfg(umilib_feature = $feature)]
                $variant(crate::crypto::concatkdf::ConcatKDF<crate::crypto::concatkdf::HashFunction<$type>>),
            )*
        }

        /// [`ConcatKDF`](crate::crypto::concatkdf::ConcatKDF) over HMAC over a hash function of the registry.
        #[derive(Clone)]
        // The enum lives behind a handle: boxing the variants would add an allocation.
        #[allow(clippy::large_enum_variant)]
        pub enum ConcatKDFHMACState {
            $(
                #[cfg(umilib_feature = $feature)]
                $variant(crate::crypto::concatkdf::ConcatKDF<crate::crypto::hmac::HMAC<$type>>),
            )*
        }

        // The enums are empty when no algorithm of the registry is enabled, leaving the arguments unused.
        #[allow(unused_variables)]
        impl ConcatKDFState {
            /// The KDF over the auxiliary function whose C type is named `function`, over the hash
            /// function whose C type is named `hash`; HMAC is keyed with `salt`, which a hash function
            /// takes empty. `None` if either is unknown or not enabled.
            pub fn new(function: &str, hash: &str, salt: &[u8]) -> Option<ConcatKDFState> {
                match function {
                    ConcatKDFState::HASH_FUNCTION_NAME if salt.is_empty() => match hash {
                        $(
                            #[cfg(umilib_feature = $feature)]
                            $name => Some(ConcatKDFState::Hash(ConcatKDFHashState::$variant(
                                crate::crypto::concatkdf::ConcatKDF::<crate::crypto::concatkdf::HashFunction<$type>>::hash(),
                            ))),
                        )*
                        _ => None,
                    },
                    ConcatKDFState::HMAC_NAME => match hash {
                        $(
                            #[cfg(umilib_feature = $feature)]
                            $name => Some(ConcatKDFState::HMAC(ConcatKDFHMACState::$variant(
                                crate::crypto::concatkdf::ConcatKDF::new(crate::crypto::hmac::HMAC::<$type>::new(salt)),
                            ))),
                        )*
                        _ => None,
                    },
                    _ => None,
                }
            }

        }

        // The enum is empty when no algorithm of the registry is enabled, leaving the arguments unused.
        #[allow(unused_variables)]
        impl ConcatKDFHashState {
            pub fn derive(&self, z: &[u8], fixed_info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        ConcatKDFHashState::$variant(ref kdf) => kdf.derive(z, fixed_info, out),
                    )*
                }
            }
        }

        // The enum is empty when no algorithm of the registry is enabled, leaving the arguments unused.
        #[allow(unused_variables)]
        impl ConcatKDFHMACState {
            pub fn derive(&self, z: &[u8], fixed_info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        ConcatKDFHMACState::$variant(ref kdf) => kdf.derive(z, fixed_info, out),
                    )*
                }
            }
        }
    };
}

/// [`ConcatKDF`](crate::crypto::concatkdf::ConcatKDF) over a hash function or HMAC.
#[derive(Clone)]
// The enum lives behind a handle: boxing the variants would add an allocation.
#[allow(clippy::large_enum_variant)]
pub enum ConcatKDFState {
    Hash(ConcatKDFHashState),
    HMAC(ConcatKDFHMACState),
}

impl ConcatKDFState {
    /// The C type names of the auxiliary functions.
    pub const HASH_FUNCTION_NAME: &'static str = "umilib_crypto_concatkdf_HashFunction";
    pub const HMAC_NAME: &'static str = "umilib_crypto_hmac_HMAC";

    pub fn derive(&self, z: &[u8], fixed_info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            ConcatKDFState::Hash(state) => state.derive(z, fixed_info, out),
            ConcatKDFState::HMAC(state) => state.derive(z, fixed_info, out),
        }
    }
}

crate::ffi_digest_algorithms!(concatkdf_state);

impl core::fmt::Debug for ConcatKDFState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ConcatKDFState(..)")
    }
}

impl Value for ConcatKDFState {
    const TYPE: Type = Type::Named("umilib_crypto_concatkdf_ConcatKDF");
}

crate::ffi_functions! {
    /// Creates the one-step KDF over the auxiliary function whose C type is named by the UTF-8 text at
    /// `function` (`umilib_crypto_concatkdf_HashFunction` or `umilib_crypto_hmac_HMAC`), over the hash
    /// function whose C type is named by the UTF-8 text at `hash`, such as `umilib_hash_sha_v2_SHA256`;
    /// HMAC is keyed with the `salt_length` bytes at `salt`, which must be empty for a hash function.
    /// Fails with InvalidArgument if the function or the hash function is unknown or not enabled.
    pub unsafe extern "C" fn umilib_crypto_concatkdf_concat_kdf_new(function: *const u8, function_length: usize, hash: *const u8, hash_length: usize, salt: *const u8, salt_length: usize, out: *mut *mut ConcatKDFState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let function = unsafe { Pointer::text(function, function_length) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let salt = unsafe { Pointer::slice(salt, salt_length) }?;
            let state = ConcatKDFState::new(function, hash, salt).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Releases the state, zeroizing its key. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_concatkdf_concat_kdf_free(state: *mut ConcatKDFState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`.
    pub unsafe extern "C" fn umilib_crypto_concatkdf_concat_kdf_clone(state: *const ConcatKDFState, out: *mut *mut ConcatKDFState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Fills the `length` bytes at `out` with K(1) || K(2) || ..., K(i) = H(\[i\]_32 || Z || FixedInfo),
    /// from the shared secret at `z` and the fixed information at `fixed_info`, which must not overlap
    /// `out`.
    pub unsafe extern "C" fn umilib_crypto_concatkdf_concat_kdf_derive(state: *const ConcatKDFState, z: *const u8, z_length: usize, fixed_info: *const u8, fixed_info_length: usize, out: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            for (input, input_length) in [(z, z_length), (fixed_info, fixed_info_length)] {
                Pointer::check_disjoint(input, input_length, out, length)?;
            }
            // SAFETY: the caller passes a valid handle, readable bytes and a writable byte range.
            let state = unsafe { Pointer::reference(state) }?;
            let z = unsafe { Pointer::slice(z, z_length) }?;
            let fixed_info = unsafe { Pointer::slice(fixed_info, fixed_info_length) }?;
            let out = unsafe { Pointer::slice_mut(out, length) }?;
            state.derive(z, fixed_info, out).map_err(|error| error.to_status())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "concatkdf",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_concatkdf_ConcatKDF",
        documentation: " The one-step KDF of SP 800-56C Rev. 2 over a hash function or HMAC.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
