//! The C ABI of [`crate::crypto::eddsa`].
//!
//! [`EdDSA<C>`](crate::crypto::eddsa::EdDSA) is exported once
//! (`umilib_crypto_eddsa_eddsa_*`) for `umilib_crypto_curve_curve25519_Edwards25519`
//! (Ed25519) and `umilib_crypto_curve_curve448_Edwards448` (Ed448), named by
//! the C type name of the curve. The functions of
//! [`SignatureScheme`](crate::crypto::SignatureScheme) give the pure
//! variants; `_sign_with_context`/`_verify_with_context` give Ed25519ctx and
//! Ed448 with a context, `_sign_prehashed`/`_verify_prehashed` Ed25519ph
//! and Ed448ph.

use crate::ffi::Module;

/// [`EdDSA`](crate::crypto::eddsa::EdDSA).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod eddsa {
    use crate::crypto::eddsa::{EdDSA, EdDSACurve};
    use crate::crypto::{CryptoError, SignatureScheme};
    use crate::ffi::crypto::SignatureSchemeCall;
    use crate::ffi::{Pointer, Status, ToStatus};

    /// Calls `call` with `EdDSA<C>` for the curve named `names.0`; `None` if it is unknown.
    pub fn scheme<V: SignatureSchemeCall>(names: (&str,), call: V) -> Option<V::Output> {
        match names.0 {
            "umilib_crypto_curve_curve25519_Edwards25519" => Some(call.call::<crate::crypto::eddsa::Ed25519>()),
            "umilib_crypto_curve_curve448_Edwards448" => Some(call.call::<crate::crypto::eddsa::Ed448>()),
            _ => None,
        }
    }

    /// A variant of EdDSA beyond the pure one.
    #[derive(Clone, Copy)]
    pub enum Variant {
        /// Ed25519ctx or Ed448 with a context.
        Context,
        /// Ed25519ph or Ed448ph.
        Prehashed,
    }

    impl Variant {
        /// Signs `message` with `context` under the encoded `key` in this variant.
        pub fn sign<C: EdDSACurve>(
            self,
            key: &[u8],
            context: &[u8],
            message: &[u8],
            out: &mut [u8],
        ) -> Result<(), CryptoError> {
            let key = EdDSA::<C>::signing_key_from_bytes(key)?;
            match self {
                Variant::Context => EdDSA::<C>::sign_with_context(&key, context, message, out),
                Variant::Prehashed => EdDSA::<C>::sign_prehashed(&key, context, message, out),
            }
        }

        /// Verifies `signature` of `message` with `context` under the encoded `key` in this variant.
        pub fn verify<C: EdDSACurve>(
            self,
            key: &[u8],
            context: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), CryptoError> {
            let key = EdDSA::<C>::verifying_key_from_bytes(key)?;
            match self {
                Variant::Context => EdDSA::<C>::verify_with_context(&key, context, message, signature),
                Variant::Prehashed => EdDSA::<C>::verify_prehashed(&key, context, message, signature),
            }
        }

        /// [`Variant::sign`] for the curve named `curve`; fails with InvalidArgument if it is unknown.
        pub fn sign_named(
            self,
            curve: &str,
            key: &[u8],
            context: &[u8],
            message: &[u8],
            out: &mut [u8],
        ) -> Result<(), &'static Status> {
            let result = match curve {
                "umilib_crypto_curve_curve25519_Edwards25519" => {
                    self.sign::<crate::crypto::curve::curve25519::Edwards25519>(key, context, message, out)
                }
                "umilib_crypto_curve_curve448_Edwards448" => {
                    self.sign::<crate::crypto::curve::curve448::Edwards448>(key, context, message, out)
                }
                _ => return Err(&Status::INVALID_ARGUMENT),
            };
            result.map_err(|error| error.to_status())
        }

        /// [`Variant::verify`] for the curve named `curve`; fails with InvalidArgument if it is unknown.
        pub fn verify_named(
            self,
            curve: &str,
            key: &[u8],
            context: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), &'static Status> {
            let result = match curve {
                "umilib_crypto_curve_curve25519_Edwards25519" => {
                    self.verify::<crate::crypto::curve::curve25519::Edwards25519>(key, context, message, signature)
                }
                "umilib_crypto_curve_curve448_Edwards448" => {
                    self.verify::<crate::crypto::curve::curve448::Edwards448>(key, context, message, signature)
                }
                _ => return Err(&Status::INVALID_ARGUMENT),
            };
            result.map_err(|error| error.to_status())
        }

        /// The body of the signing functions of the variants.
        ///
        /// # Safety
        ///
        /// The pointers must be readable (and `out` writable) for their lengths.
        #[allow(clippy::too_many_arguments)]
        pub unsafe fn sign_with_pointers(
            self,
            curve: *const u8,
            curve_length: usize,
            key: *const u8,
            key_length: usize,
            context: *const u8,
            context_length: usize,
            message: *const u8,
            message_length: usize,
            out: *mut u8,
            out_length: usize,
        ) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes and writable bytes.
                let inputs =
                    [(curve, curve_length), (key, key_length), (context, context_length), (message, message_length)];
                Pointer::check_ranges(&inputs, &[(out, out_length)])?;
                let curve = unsafe { Pointer::text(curve, curve_length) }?;
                let key = unsafe { Pointer::slice(key, key_length) }?;
                let context = unsafe { Pointer::slice(context, context_length) }?;
                let message = unsafe { Pointer::slice(message, message_length) }?;
                let out = unsafe { Pointer::slice_mut(out, out_length) }?;
                self.sign_named(curve, key, context, message, out)
            })())
        }

        /// The body of the verification functions of the variants.
        ///
        /// # Safety
        ///
        /// The pointers must be readable for their lengths.
        #[allow(clippy::too_many_arguments)]
        pub unsafe fn verify_with_pointers(
            self,
            curve: *const u8,
            curve_length: usize,
            key: *const u8,
            key_length: usize,
            context: *const u8,
            context_length: usize,
            message: *const u8,
            message_length: usize,
            signature: *const u8,
            signature_length: usize,
        ) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes.
                let curve = unsafe { Pointer::text(curve, curve_length) }?;
                let key = unsafe { Pointer::slice(key, key_length) }?;
                let context = unsafe { Pointer::slice(context, context_length) }?;
                let message = unsafe { Pointer::slice(message, message_length) }?;
                let signature = unsafe { Pointer::slice(signature, signature_length) }?;
                self.verify_named(curve, key, context, message, signature)
            })())
        }
    }

    crate::ffi_signature_scheme!("umilib_crypto_eddsa_eddsa", "EdDSA on the curve named by `curve`", [curve curve_length]);

    crate::ffi_exports! {
        const VARIANTS;
        /// Writes the signature of Ed25519ctx or of Ed448 with the context of at most 255 bytes into `out`
        /// of the size of a signature; fails with InvalidParameter for a longer context.
        pub unsafe extern "C" fn sign_with_context = "umilib_crypto_eddsa_eddsa_sign_with_context"; (curve: *const u8, curve_length: usize, key: *const u8, key_length: usize, context: *const u8, context_length: usize, message: *const u8, message_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            // SAFETY: forwarded with the same contract.
            unsafe { Variant::Context.sign_with_pointers( curve, curve_length, key, key_length, context, context_length, message, message_length, out, out_length) }
        }

        /// Succeeds if the signature is one of Ed25519ctx or Ed448 with the context; fails with InvalidSignature otherwise.
        pub unsafe extern "C" fn verify_with_context = "umilib_crypto_eddsa_eddsa_verify_with_context"; (curve: *const u8, curve_length: usize, key: *const u8, key_length: usize, context: *const u8, context_length: usize, message: *const u8, message_length: usize, signature: *const u8, signature_length: usize) -> *const Status {
            // SAFETY: forwarded with the same contract.
            unsafe { Variant::Context.verify_with_pointers( curve, curve_length, key, key_length, context, context_length, message, message_length, signature, signature_length) }
        }

        /// Writes the signature of Ed25519ph or Ed448ph of the message (hashed by the function) with the
        /// context into `out` of the size of a signature.
        pub unsafe extern "C" fn sign_prehashed = "umilib_crypto_eddsa_eddsa_sign_prehashed"; (curve: *const u8, curve_length: usize, key: *const u8, key_length: usize, context: *const u8, context_length: usize, message: *const u8, message_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            // SAFETY: forwarded with the same contract.
            unsafe { Variant::Prehashed.sign_with_pointers( curve, curve_length, key, key_length, context, context_length, message, message_length, out, out_length) }
        }

        /// Succeeds if the signature is one of Ed25519ph or Ed448ph with the context; fails with InvalidSignature otherwise.
        pub unsafe extern "C" fn verify_prehashed = "umilib_crypto_eddsa_eddsa_verify_prehashed"; (curve: *const u8, curve_length: usize, key: *const u8, key_length: usize, context: *const u8, context_length: usize, message: *const u8, message_length: usize, signature: *const u8, signature_length: usize) -> *const Status {
            // SAFETY: forwarded with the same contract.
            unsafe { Variant::Prehashed.verify_with_pointers( curve, curve_length, key, key_length, context, context_length, message, message_length, signature, signature_length) }
        }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "eddsa",
    definitions: &[],
    functions: &crate::ffi::Function::concat::<{ eddsa::FUNCTIONS.len() + eddsa::VARIANTS.len() }>(&[
        eddsa::FUNCTIONS,
        eddsa::VARIANTS,
    ]),
    modules: &[],
};
