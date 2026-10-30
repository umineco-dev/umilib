//! The C ABI of [`crate::crypto::pbkdf2`].

use crate::crypto::CryptoError;
use crate::ffi::{Module, Pointer, Status, ToStatus};

/// Defines [`PBKDF2Dispatch`] over the hash functions of the registry.
macro_rules! pbkdf2_dispatch {
    ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        /// [`PBKDF2<H>`](crate::crypto::pbkdf2::PBKDF2) for the hash function `H` of the
        /// registry named by the C type name of its hash type.
        pub struct PBKDF2Dispatch;

        // With no algorithm of the registry enabled the arguments are unused.
        #[allow(unused_variables)]
        impl PBKDF2Dispatch {
            /// [`PBKDF2::derive`](crate::crypto::pbkdf2::PBKDF2::derive) with HMAC over the hash
            /// function named `hash`; `None` if it is unknown or not enabled.
            pub fn derive(hash: &str, password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> Option<Result<(), CryptoError>> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(crate::crypto::pbkdf2::PBKDF2::<$type>::derive(password, salt, iterations, out)),
                    )*
                    _ => None,
                }
            }

            /// The longest output, (2^32 - 1) × HashLen bytes; `None` if the hash function is unknown.
            pub fn maximum_output(hash: &str) -> Option<u64> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(crate::crypto::pbkdf2::PBKDF2::<$type>::MAXIMUM_OUTPUT),
                    )*
                    _ => None,
                }
            }
        }
    };
}

crate::ffi_digest_algorithms!(pbkdf2_dispatch);

crate::ffi_functions! {
    /// Fills the `length` bytes at `out` with PBKDF2 (RFC 8018 section 5.2) of the password and the salt
    /// with `iterations` (at least 1) iterations of HMAC over the hash function whose C type is named by
    /// the UTF-8 text at `hash`, such as `umilib_hash_sha_v2_SHA256`; fails with InvalidArgument if that
    /// hash function is unknown or not enabled. The inputs must not overlap `out`.
    pub unsafe extern "C" fn umilib_crypto_pbkdf2_pbkdf2_derive(hash: *const u8, hash_length: usize, password: *const u8, password_length: usize, salt: *const u8, salt_length: usize, iterations: u32, out: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            for (input, input_length) in [(hash, hash_length), (password, password_length), (salt, salt_length)] {
                Pointer::check_disjoint(input, input_length, out, length)?;
            }
            // SAFETY: the caller passes readable text and bytes and a writable byte range.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let password = unsafe { Pointer::slice(password, password_length) }?;
            let salt = unsafe { Pointer::slice(salt, salt_length) }?;
            let out = unsafe { Pointer::slice_mut(out, length) }?;
            PBKDF2Dispatch::derive(hash, password, salt, iterations, out).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
        })())
    }

    /// Writes the longest output with the hash function named by `hash`, (2^32 - 1) × HashLen bytes,
    /// into `out`.
    pub unsafe extern "C" fn umilib_crypto_pbkdf2_pbkdf2_maximum_output(hash: *const u8, hash_length: usize, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let maximum = PBKDF2Dispatch::maximum_output(hash).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, maximum) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "pbkdf2", definitions: &[], functions: FUNCTIONS, modules: &[] };
