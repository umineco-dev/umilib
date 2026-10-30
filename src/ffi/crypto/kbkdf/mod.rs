//! The C ABI of [`crate::crypto::kbkdf`].
//!
//! [`KBKDF<P>`](crate::crypto::kbkdf::KBKDF) is exported as one type whose
//! PRF is chosen when it is created, as [`ffi_prf_enum!`](crate::ffi_prf_enum)
//! describes. [`KBKDFCounter`] crosses as `0` (Absent), `1`
//! (BeforeIteration), `2` (AfterIteration) or `3` (AfterFixed).

use crate::crypto::CryptoError;
// The wrapper appears only in the variants, which no PRF may enable.
#[allow(unused_imports)]
use crate::crypto::kbkdf::KBKDF;
use crate::crypto::kbkdf::KBKDFCounter;
use crate::ffi::{Definition, Module, Pointer, Status, ToStatus, Type, Value};

macro_rules! kbkdf_state {
    ($($line:tt)*) => {
        crate::ffi_prf_enum!(@build KBKDFState, KBKDF, u32 {
            /// The counter mode (section 4.1): K(i) = PRF(before || \[i\] || after).
            fn counter(&self, before: &[u8], after: &[u8], out: &mut [u8]) -> Result<(), CryptoError>;
            /// The feedback mode (section 4.2) from the initial value `iv`.
            fn feedback(&self, iv: &[u8], fixed: &[u8], location: KBKDFCounter, out: &mut [u8]) -> Result<(), CryptoError>;
            /// The double-pipeline mode (section 4.3).
            fn double_pipeline(&self, fixed: &[u8], location: KBKDFCounter, out: &mut [u8]) -> Result<(), CryptoError>;
        } { $($line)* });
    };
}

// HMAC is the PRF over the hash functions; without it no hash function is a choice.
#[cfg(umilib_feature = "crypto-hmac")]
crate::ffi_digest_algorithms!(kbkdf_state);
#[cfg(not(umilib_feature = "crypto-hmac"))]
kbkdf_state!();

impl Value for KBKDFState {
    const TYPE: Type = Type::Named("umilib_crypto_kbkdf_KBKDF");
}

impl KBKDFState {
    /// The counter location of its C value; fails with InvalidArgument for another value.
    pub fn location(value: u32) -> Result<KBKDFCounter, &'static Status> {
        match value {
            0 => Ok(KBKDFCounter::Absent),
            1 => Ok(KBKDFCounter::BeforeIteration),
            2 => Ok(KBKDFCounter::AfterIteration),
            3 => Ok(KBKDFCounter::AfterFixed),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

crate::ffi_functions! {
    /// Creates KBKDF (SP 800-108r1) over the PRF whose C type is named by the UTF-8 text at `prf`
    /// (`umilib_crypto_hmac_HMAC` or `umilib_crypto_cmac_CMAC`), over the hash function or block cipher
    /// whose C type is named by the UTF-8 text at `primitive`, keyed with K_IN at `key`, with a counter of
    /// `counter_bits` bits (8, 16, 24 or 32); fails with InvalidArgument if the PRF or the primitive is
    /// unknown or not enabled, and with InvalidParameter for another counter size.
    pub unsafe extern "C" fn umilib_crypto_kbkdf_kbkdf_new(prf: *const u8, prf_length: usize, primitive: *const u8, primitive_length: usize, key: *const u8, key_length: usize, counter_bits: u32, out: *mut *mut KBKDFState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let prf = unsafe { Pointer::text(prf, prf_length) }?;
            let primitive = unsafe { Pointer::text(primitive, primitive_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let state = KBKDFState::new(prf, primitive, key, counter_bits)?;
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Releases the state, zeroizing its key. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_kbkdf_kbkdf_free(state: *mut KBKDFState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`.
    pub unsafe extern "C" fn umilib_crypto_kbkdf_kbkdf_clone(state: *const KBKDFState, out: *mut *mut KBKDFState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Fills the `length` bytes at `out` in the counter mode (section 4.1), with the fixed input data
    /// split around the counter: K(i) = PRF(before || \[i\] || after). The inputs must not overlap `out`.
    pub unsafe extern "C" fn umilib_crypto_kbkdf_kbkdf_counter(state: *const KBKDFState, before: *const u8, before_length: usize, after: *const u8, after_length: usize, out: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(before, before_length, out, length)?;
            Pointer::check_disjoint(after, after_length, out, length)?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable byte range.
            let state = unsafe { Pointer::reference(state) }?;
            let before = unsafe { Pointer::slice(before, before_length) }?;
            let after = unsafe { Pointer::slice(after, after_length) }?;
            let out = unsafe { Pointer::slice_mut(out, length) }?;
            state.counter(before, after, out).map_err(|error| error.to_status())
        })())
    }

    /// Fills the `length` bytes at `out` in the feedback mode (section 4.2) from the initial value `iv`
    /// and the fixed input data, with the counter at `location` (0 to 3). The inputs must not overlap
    /// `out`.
    pub unsafe extern "C" fn umilib_crypto_kbkdf_kbkdf_feedback(state: *const KBKDFState, iv: *const u8, iv_length: usize, fixed: *const u8, fixed_length: usize, location: u32, out: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(iv, iv_length, out, length)?;
            Pointer::check_disjoint(fixed, fixed_length, out, length)?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable byte range.
            let state = unsafe { Pointer::reference(state) }?;
            let iv = unsafe { Pointer::slice(iv, iv_length) }?;
            let fixed = unsafe { Pointer::slice(fixed, fixed_length) }?;
            let location = KBKDFState::location(location)?;
            let out = unsafe { Pointer::slice_mut(out, length) }?;
            state.feedback(iv, fixed, location, out).map_err(|error| error.to_status())
        })())
    }

    /// Fills the `length` bytes at `out` in the double-pipeline mode (section 4.3) from the fixed input
    /// data, with the counter at `location` (0 to 3), which must not overlap `out`.
    pub unsafe extern "C" fn umilib_crypto_kbkdf_kbkdf_double_pipeline(state: *const KBKDFState, fixed: *const u8, fixed_length: usize, location: u32, out: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(fixed, fixed_length, out, length)?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable byte range.
            let state = unsafe { Pointer::reference(state) }?;
            let fixed = unsafe { Pointer::slice(fixed, fixed_length) }?;
            let location = KBKDFState::location(location)?;
            let out = unsafe { Pointer::slice_mut(out, length) }?;
            state.double_pipeline(fixed, location, out).map_err(|error| error.to_status())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "kbkdf",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_kbkdf_KBKDF",
        documentation: " KBKDF (SP 800-108r1) over HMAC or CMAC chosen by name, with its counter size.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
