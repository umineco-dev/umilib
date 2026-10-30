//! The C ABI of [`crate::crypto::hmac`].
//!
//! [`HMAC<H>`](crate::crypto::hmac::HMAC) is exported as one type for every
//! hash function of [`ffi_digest_algorithms!`](crate::ffi_digest_algorithms),
//! chosen by the C type name of the hash type when it is created.

use crate::ffi::{Definition, Module, Pointer, Status, Type, Value};

/// Defines [`HMACState`] over the hash functions of the registry.
macro_rules! hmac_state {
    ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        /// [`HMAC<H>`](crate::crypto::hmac::HMAC) for any hash function `H` of the registry.
        #[derive(Clone, Debug)]
        // The enum lives behind a handle: boxing the variants would add an allocation.
        #[allow(clippy::large_enum_variant)]
        pub enum HMACState {
            $(
                #[cfg(umilib_feature = $feature)]
                $variant(crate::crypto::hmac::HMAC<$type>),
            )*
        }

        // The enum is empty when no algorithm of the registry is enabled, leaving the arguments unused.
        #[allow(unused_variables)]
        impl HMACState {
            /// HMAC with `key` over the hash function whose C type is named `hash`, if it is enabled.
            pub fn new(hash: &str, key: &[u8]) -> Option<HMACState> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(HMACState::$variant(crate::crypto::hmac::HMAC::new(key))),
                    )*
                    _ => None,
                }
            }

            pub fn update(&mut self, data: &[u8]) {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        HMACState::$variant(ref mut state) => state.update(data),
                    )*
                }
            }

            /// Writes the tag into `out`, which must have the output size.
            pub fn finalize_into(self, out: &mut [u8]) -> Result<(), &'static Status> {
                match self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        HMACState::$variant(state) => {
                            let tag = state.finalize();
                            crate::ffi::hash::DigestOutput::check(out, tag.as_ref().len())?;
                            out.copy_from_slice(tag.as_ref());
                            Ok(())
                        }
                    )*
                }
            }

            pub fn reset(&mut self) {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        HMACState::$variant(ref mut state) => state.reset(),
                    )*
                }
            }

            /// Writes the tag into `out`, which must have the output size, and returns to the key.
            pub fn finalize_reset(&mut self, out: &mut [u8]) -> Result<(), &'static Status> {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        HMACState::$variant(ref mut state) => {
                            crate::ffi::hash::DigestOutput::check(out, <$type as crate::hash::Digest>::OUTPUT_SIZE)?;
                            out.copy_from_slice(state.clone().finalize().as_ref());
                            state.reset();
                            Ok(())
                        }
                    )*
                }
            }

            /// Whether `tag` is the tag of the message, compared in constant time, from a copy of the state.
            pub fn verify(&self, tag: &[u8]) -> bool {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        HMACState::$variant(ref state) => state.clone().verify(tag),
                    )*
                }
            }

            /// [`HMACState::verify`] for a tag truncated to its leftmost bytes.
            pub fn verify_truncated(&self, tag: &[u8]) -> bool {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        HMACState::$variant(ref state) => state.clone().verify_truncated(tag),
                    )*
                }
            }

            /// The output size of the hash function.
            pub fn output_size(&self) -> usize {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        HMACState::$variant(_) => <$type as crate::hash::Digest>::OUTPUT_SIZE,
                    )*
                }
            }

            /// The shortest tag [`HMACState::verify_truncated`] accepts.
            pub fn minimum_truncated_length(&self) -> usize {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        HMACState::$variant(_) => crate::crypto::hmac::HMAC::<$type>::MINIMUM_TRUNCATED_LENGTH,
                    )*
                }
            }
        }
    };
}

crate::ffi_digest_algorithms!(hmac_state);

impl Value for HMACState {
    const TYPE: Type = Type::Named("umilib_crypto_hmac_HMAC");
}

crate::ffi_functions! {
    /// Creates HMAC with the `key_length` bytes at `key` over the hash function whose C type is named
    /// by the UTF-8 text at `hash`, such as `umilib_hash_sha_v2_SHA256`; fails with InvalidArgument
    /// if that hash function is unknown or not enabled.
    pub unsafe extern "C" fn umilib_crypto_hmac_hmac_new(hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, out: *mut *mut HMACState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let state = HMACState::new(hash, key).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Writes the tag of the `length` bytes at `data` under the key into the `out_length` bytes at
    /// `out`, which must be the output size of the hash function named as in `umilib_crypto_hmac_hmac_new`
    /// and must not overlap the other arguments.
    pub unsafe extern "C" fn umilib_crypto_hmac_hmac_mac(hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, data: *const u8, length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(hash, hash_length, out, out_length)?;
            Pointer::check_disjoint(key, key_length, out, out_length)?;
            Pointer::check_disjoint(data, length, out, out_length)?;
            // SAFETY: the caller passes readable text and bytes and a writable byte range.
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            let mut state = HMACState::new(hash, key).ok_or(&Status::INVALID_ARGUMENT)?;
            state.update(data);
            state.finalize_into(out)
        })())
    }

    /// Releases the state, zeroizing it. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_hmac_hmac_free(state: *mut HMACState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`.
    pub unsafe extern "C" fn umilib_crypto_hmac_hmac_clone(state: *const HMACState, out: *mut *mut HMACState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Adds the `length` bytes at `data` to the message.
    pub unsafe extern "C" fn umilib_crypto_hmac_hmac_update(state: *mut HMACState, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let state = unsafe { Pointer::reference_mut(state) }?;
            state.update(unsafe { Pointer::slice(data, length) }?);
            Ok(())
        })())
    }

    /// Writes the tag into the `out_length` bytes at `out`, which must be the output size, and releases
    /// the state. On failure the state is not released.
    pub unsafe extern "C" fn umilib_crypto_hmac_hmac_finalize(state: *mut HMACState, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a writable byte range.
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            let size = unsafe { Pointer::reference(state) }?.output_size();
            crate::ffi::hash::DigestOutput::check(out, size)?;
            // SAFETY: the caller passes a handle created by this module and does not use it afterwards.
            let state = unsafe { alloc::boxed::Box::from_raw(state) };
            // From a copy, so that dropping the box zeroizes the state where it lives.
            let result = (*state).clone().finalize_into(out);
            drop(state);
            result
        })())
    }

    /// Writes the tag into the `out_length` bytes at `out`, which must be the output size, and returns
    /// the state to the key.
    pub unsafe extern "C" fn umilib_crypto_hmac_hmac_finalize_reset(state: *mut HMACState, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable byte range.
            let state = unsafe { Pointer::reference_mut(state) }?;
            let out = unsafe { Pointer::slice_mut(out, out_length) }?;
            state.finalize_reset(out)
        })())
    }

    /// Returns the state to the key.
    pub unsafe extern "C" fn umilib_crypto_hmac_hmac_reset(state: *mut HMACState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(state) }?.reset();
            Ok(())
        })())
    }

    /// Writes into `out` whether the `length` bytes at `tag` are the tag of the message, compared in
    /// constant time, and releases the state.
    pub unsafe extern "C" fn umilib_crypto_hmac_hmac_verify(state: *mut HMACState, tag: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let tag = unsafe { Pointer::slice(tag, length) }?;
            if state.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a handle created by this module and does not use it afterwards.
            let state = unsafe { alloc::boxed::Box::from_raw(state) };
            let valid = state.verify(tag);
            drop(state);
            unsafe { Pointer::write(out, valid) }
        })())
    }

    /// Like `umilib_crypto_hmac_hmac_verify` for a tag truncated to its leftmost bytes, of at least the
    /// minimum truncated length.
    pub unsafe extern "C" fn umilib_crypto_hmac_hmac_verify_truncated(state: *mut HMACState, tag: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let tag = unsafe { Pointer::slice(tag, length) }?;
            if state.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller passes a handle created by this module and does not use it afterwards.
            let state = unsafe { alloc::boxed::Box::from_raw(state) };
            let valid = state.verify_truncated(tag);
            drop(state);
            unsafe { Pointer::write(out, valid) }
        })())
    }

    /// Writes the output size of the hash function into `out`.
    pub unsafe extern "C" fn umilib_crypto_hmac_hmac_output_size(state: *const HMACState, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write(out, state.output_size()) }
        })())
    }

    /// Writes the shortest truncated tag that verification accepts (half of the output and at least
    /// 80 bits) into `out`.
    pub unsafe extern "C" fn umilib_crypto_hmac_hmac_minimum_truncated_length(state: *const HMACState, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write(out, state.minimum_truncated_length()) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "hmac",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_hmac_HMAC",
        documentation: " HMAC (RFC 2104) over a hash function chosen when it is created.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
