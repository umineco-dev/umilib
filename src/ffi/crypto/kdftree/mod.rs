//! The C ABI of [`crate::crypto::kdftree`].
//!
//! [`KDFTree<P>`](crate::crypto::kdftree::KDFTree) is exported as one type
//! whose PRF is chosen when it is created, as
//! [`ffi_prf_enum!`](crate::ffi_prf_enum) describes.

use crate::crypto::CryptoError;
// The wrapper appears only in the variants, which no PRF may enable.
#[allow(unused_imports)]
use crate::crypto::kdftree::KDFTree;
use crate::ffi::{Definition, Module, Pointer, Status, ToStatus, Type, Value};

macro_rules! kdftree_state {
    ($($line:tt)*) => {
        crate::ffi_prf_enum!(@build KDFTreeState, KDFTree, usize {
            /// K(i) = PRF(K_in, \[i\]_b || label || 0x00 || seed || \[L\]_b) into `out`.
            fn derive(&self, label: &[u8], seed: &[u8], out: &mut [u8]) -> Result<(), CryptoError>;
        } { $($line)* });
    };
}

// HMAC is the PRF over the hash functions; without it no hash function is a choice.
#[cfg(umilib_feature = "crypto-hmac")]
crate::ffi_digest_algorithms!(kdftree_state);
#[cfg(not(umilib_feature = "crypto-hmac"))]
kdftree_state!();

impl Value for KDFTreeState {
    const TYPE: Type = Type::Named("umilib_crypto_kdftree_KDFTree");
}

crate::ffi_functions! {
    /// Creates KDF_TREE (RFC 7836 section 4.4) over the PRF whose C type is named by the UTF-8 text at
    /// `prf` (`umilib_crypto_hmac_HMAC` or `umilib_crypto_cmac_CMAC`), over the hash function or block
    /// cipher whose C type is named by the UTF-8 text at `primitive` (Streebog-256 in RFC 7836), keyed with
    /// K_in at `key`, with a counter of `counter_bytes` bytes (1 to 4); fails with InvalidArgument if the
    /// PRF or the primitive is unknown or not enabled, and with InvalidParameter for another counter size.
    pub unsafe extern "C" fn umilib_crypto_kdftree_kdftree_new(prf: *const u8, prf_length: usize, primitive: *const u8, primitive_length: usize, key: *const u8, key_length: usize, counter_bytes: usize, out: *mut *mut KDFTreeState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes and a writable pointer.
            let prf = unsafe { Pointer::text(prf, prf_length) }?;
            let primitive = unsafe { Pointer::text(primitive, primitive_length) }?;
            let key = unsafe { Pointer::slice(key, key_length) }?;
            let state = KDFTreeState::new(prf, primitive, key, counter_bytes)?;
            unsafe { Pointer::write_handle(out, state) }
        })())
    }

    /// Releases the state, zeroizing its key. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_crypto_kdftree_kdftree_free(state: *mut KDFTreeState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state` into `out`.
    pub unsafe extern "C" fn umilib_crypto_kdftree_kdftree_clone(state: *const KDFTreeState, out: *mut *mut KDFTreeState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Fills the `length` bytes (L = 8 × `length` bits) at `out` with the keying material of the label and
    /// the seed, which must not overlap `out`.
    pub unsafe extern "C" fn umilib_crypto_kdftree_kdftree_derive(state: *const KDFTreeState, label: *const u8, label_length: usize, seed: *const u8, seed_length: usize, out: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_disjoint(label, label_length, out, length)?;
            Pointer::check_disjoint(seed, seed_length, out, length)?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable byte range.
            let state = unsafe { Pointer::reference(state) }?;
            let label = unsafe { Pointer::slice(label, label_length) }?;
            let seed = unsafe { Pointer::slice(seed, seed_length) }?;
            let out = unsafe { Pointer::slice_mut(out, length) }?;
            state.derive(label, seed, out).map_err(|error| error.to_status())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "kdftree",
    definitions: &[Definition::Opaque {
        name: "umilib_crypto_kdftree_KDFTree",
        documentation: " KDF_TREE (RFC 7836 section 4.4) over HMAC or CMAC chosen by name, with its counter size.",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
