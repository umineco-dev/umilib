//! The C ABI of [`crate::crypto::mldsa`].
//!
//! [`MLDSA<P>`](crate::crypto::mldsa::MLDSA) is exported once
//! (`umilib_crypto_mldsa_mldsa_*`) for the parameter sets named by the C type
//! names `umilib_crypto_mldsa_MLDSA44`, `umilib_crypto_mldsa_MLDSA65` and
//! `umilib_crypto_mldsa_MLDSA87`: the functions of
//! [`SignatureScheme`](crate::crypto::SignatureScheme) (deterministic, empty
//! context) on the encodings of FIPS 204; `_signing_key_from_seed` (the
//! private key of the seed ξ); `_sign_with_context` (hedged, rnd from a generator) or
//! `_sign_deterministic_with_context` and `_verify_with_context`; and their
//! HashML-DSA forms `_sign_pre_hash`, `_sign_pre_hash_deterministic` and
//! `_verify_pre_hash`, with the hash function named by the C type name of
//! its type (SHA-2, SHA-3, SHAKE128 and SHAKE256).

use crate::ffi::Module;

/// [`MLDSA`](crate::crypto::mldsa::MLDSA).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod mldsa {
    use core::marker::PhantomData;

    use crate::crypto::mldsa::{MLDSA, MLDSA44, MLDSA65, MLDSA87, MLDSAParameters};
    use crate::crypto::{CryptoError, PreHash, SignatureScheme};
    use crate::ffi::crypto::random::RandomSource;
    use crate::ffi::crypto::{PreHashCall, PreHashRegistry, SignatureSchemeCall};
    use crate::ffi::{Pointer, Status, ToStatus};

    /// An operation on a parameter set of ML-DSA chosen at run time.
    pub trait MLDSACall {
        type Output;

        fn call<P: MLDSAParameters>(self) -> Self::Output;
    }

    /// Calls `call` with the parameter set named `name`; `None` if it is unknown.
    pub fn parameters<V: MLDSACall>(name: &str, call: V) -> Option<V::Output> {
        match name {
            "umilib_crypto_mldsa_MLDSA44" => Some(call.call::<MLDSA44>()),
            "umilib_crypto_mldsa_MLDSA65" => Some(call.call::<MLDSA65>()),
            "umilib_crypto_mldsa_MLDSA87" => Some(call.call::<MLDSA87>()),
            _ => None,
        }
    }

    /// The step of [`scheme`] from the parameter set to `MLDSA<P>`.
    pub struct MLDSAScheme<V> {
        call: V,
    }

    impl<V: SignatureSchemeCall> MLDSACall for MLDSAScheme<V> {
        type Output = V::Output;

        fn call<P: MLDSAParameters>(self) -> V::Output {
            self.call.call::<MLDSA<P>>()
        }
    }

    /// Calls `call` with `MLDSA<P>` for the parameter set named `names.0`; `None` if it is unknown.
    pub fn scheme<V: SignatureSchemeCall>(names: (&str,), call: V) -> Option<V::Output> {
        parameters(names.0, MLDSAScheme { call })
    }

    crate::ffi_signature_scheme!("umilib_crypto_mldsa_mldsa", "ML-DSA with the parameter set named by `parameters`", [parameters parameters_length]);

    /// An operation of ML-DSA beyond [`SignatureScheme`], on encoded keys.
    pub enum MLDSAOperation<'a> {
        /// Writes the private key of the seed ξ.
        ExpandSeed { seed: &'a [u8], out: &'a mut [u8] },
        /// Signs with a context: hedged with rnd from `random`, deterministic without it.
        Sign {
            key: &'a [u8],
            message: &'a [u8],
            context: &'a [u8],
            random: Option<RandomSource<'a>>,
            out: &'a mut [u8],
        },
        /// Verifies with a context.
        Verify { key: &'a [u8], message: &'a [u8], context: &'a [u8], signature: &'a [u8] },
    }

    impl MLDSACall for MLDSAOperation<'_> {
        type Output = Result<(), CryptoError>;

        fn call<P: MLDSAParameters>(self) -> Result<(), CryptoError> {
            match self {
                MLDSAOperation::ExpandSeed { seed, out } => {
                    MLDSA::<P>::write_signing_key(&MLDSA::<P>::signing_key_from_seed(seed)?, out)
                }
                MLDSAOperation::Sign { key, message, context, random, out } => {
                    let key = MLDSA::<P>::signing_key_from_bytes(key)?;
                    match random {
                        Some(mut random) => MLDSA::<P>::sign_with_context(&key, message, context, &mut random, out),
                        None => MLDSA::<P>::sign_deterministic_with_context(&key, message, context, out),
                    }
                }
                MLDSAOperation::Verify { key, message, context, signature } => MLDSA::<P>::verify_with_context(
                    &MLDSA::<P>::verifying_key_from_bytes(key)?,
                    message,
                    context,
                    signature,
                ),
            }
        }
    }

    /// An operation of HashML-DSA with the pre-hash named `hash`.
    pub struct MLDSAPreHash<'a> {
        pub hash: &'a str,
        pub operation: MLDSAOperation<'a>,
    }

    impl MLDSACall for MLDSAPreHash<'_> {
        type Output = Option<Result<(), CryptoError>>;

        fn call<P: MLDSAParameters>(self) -> Self::Output {
            PreHashRegistry::hash(
                self.hash,
                MLDSAPreHashWith::<P> { operation: self.operation, parameters: PhantomData },
            )
        }
    }

    /// The step of [`MLDSAPreHash`] with the parameter set `P` chosen.
    pub struct MLDSAPreHashWith<'a, P> {
        operation: MLDSAOperation<'a>,
        parameters: PhantomData<P>,
    }

    impl<P: MLDSAParameters> PreHashCall for MLDSAPreHashWith<'_, P> {
        type Output = Result<(), CryptoError>;

        fn call<H: PreHash>(self) -> Result<(), CryptoError> {
            match self.operation {
                MLDSAOperation::Sign { key, message, context, random, out } => {
                    let key = MLDSA::<P>::signing_key_from_bytes(key)?;
                    match random {
                        Some(mut random) => MLDSA::<P>::sign_pre_hash::<H, _>(&key, message, context, &mut random, out),
                        None => MLDSA::<P>::sign_pre_hash_deterministic::<H>(&key, message, context, out),
                    }
                }
                MLDSAOperation::Verify { key, message, context, signature } => {
                    let key = MLDSA::<P>::verifying_key_from_bytes(key)?;
                    MLDSA::<P>::verify_pre_hash::<H>(&key, message, context, signature)
                }
                MLDSAOperation::ExpandSeed { .. } => Err(CryptoError::InvalidParameter),
            }
        }
    }

    crate::ffi_exports! {
        const VARIANTS;
        /// Writes the private key of the seed ξ (32 bytes) into `out` of the size of a signing key.
        pub unsafe extern "C" fn signing_key_from_seed = "umilib_crypto_mldsa_mldsa_signing_key_from_seed"; (parameters: *const u8, parameters_length: usize, seed: *const u8, seed_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes and writable bytes.
                Pointer::check_ranges(&[(parameters, parameters_length), (seed, seed_length)], &[(out, out_length)])?;
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = MLDSAOperation::ExpandSeed { seed: unsafe { Pointer::slice(seed, seed_length) }?, out: unsafe { Pointer::slice_mut(out, out_length) }? };
                self::parameters(name, operation).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }

        /// ML-DSA.Sign (FIPS 204 algorithm 2) of the message with the context (at most 255 bytes) and rnd from the
        /// generator handle `random`, into `out` of the size of a signature.
        pub unsafe extern "C" fn sign_with_context = "umilib_crypto_mldsa_mldsa_sign_with_context"; (parameters: *const u8, parameters_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, context: *const u8, context_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes, a live generator of the named type and writable bytes.
                let inputs = [(parameters, parameters_length), (key, key_length), (message, message_length), (context, context_length), (random_type, random_type_length)];
                Pointer::check_ranges(&inputs, &[(out, out_length)])?;
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = MLDSAOperation::Sign {
                    key: unsafe { Pointer::slice(key, key_length) }?,
                    message: unsafe { Pointer::slice(message, message_length) }?,
                    context: unsafe { Pointer::slice(context, context_length) }?,
                    random: Some(unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?),
                    out: unsafe { Pointer::slice_mut(out, out_length) }?,
                };
                self::parameters(name, operation).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }

        /// The deterministic variant of ML-DSA.Sign (rnd = 0^32) with the context.
        pub unsafe extern "C" fn sign_deterministic_with_context = "umilib_crypto_mldsa_mldsa_sign_deterministic_with_context"; (parameters: *const u8, parameters_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, context: *const u8, context_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes and writable bytes.
                let inputs = [(parameters, parameters_length), (key, key_length), (message, message_length), (context, context_length)];
                Pointer::check_ranges(&inputs, &[(out, out_length)])?;
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = MLDSAOperation::Sign {
                    key: unsafe { Pointer::slice(key, key_length) }?,
                    message: unsafe { Pointer::slice(message, message_length) }?,
                    context: unsafe { Pointer::slice(context, context_length) }?,
                    random: None,
                    out: unsafe { Pointer::slice_mut(out, out_length) }?,
                };
                self::parameters(name, operation).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }

        /// ML-DSA.Verify (FIPS 204 algorithm 3) with the context; fails with InvalidSignature otherwise.
        pub unsafe extern "C" fn verify_with_context = "umilib_crypto_mldsa_mldsa_verify_with_context"; (parameters: *const u8, parameters_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, context: *const u8, context_length: usize, signature: *const u8, signature_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes.
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = MLDSAOperation::Verify {
                    key: unsafe { Pointer::slice(key, key_length) }?,
                    message: unsafe { Pointer::slice(message, message_length) }?,
                    context: unsafe { Pointer::slice(context, context_length) }?,
                    signature: unsafe { Pointer::slice(signature, signature_length) }?,
                };
                self::parameters(name, operation).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }

        /// HashML-DSA.Sign (FIPS 204 algorithm 4) with the pre-hash named by `hash`, the context and rnd from the
        /// generator handle `random`.
        pub unsafe extern "C" fn sign_pre_hash = "umilib_crypto_mldsa_mldsa_sign_pre_hash"; (parameters: *const u8, parameters_length: usize, hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, context: *const u8, context_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes, a live generator of the named type and writable bytes.
                let inputs = [(parameters, parameters_length), (hash, hash_length), (key, key_length), (message, message_length), (context, context_length), (random_type, random_type_length)];
                Pointer::check_ranges(&inputs, &[(out, out_length)])?;
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = MLDSAOperation::Sign {
                    key: unsafe { Pointer::slice(key, key_length) }?,
                    message: unsafe { Pointer::slice(message, message_length) }?,
                    context: unsafe { Pointer::slice(context, context_length) }?,
                    random: Some(unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?),
                    out: unsafe { Pointer::slice_mut(out, out_length) }?,
                };
                let call = MLDSAPreHash { hash: unsafe { Pointer::text(hash, hash_length) }?, operation };
                self::parameters(name, call).flatten().ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }

        /// The deterministic variant of HashML-DSA.Sign (rnd = 0^32).
        pub unsafe extern "C" fn sign_pre_hash_deterministic = "umilib_crypto_mldsa_mldsa_sign_pre_hash_deterministic"; (parameters: *const u8, parameters_length: usize, hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, context: *const u8, context_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes and writable bytes.
                let inputs = [(parameters, parameters_length), (hash, hash_length), (key, key_length), (message, message_length), (context, context_length)];
                Pointer::check_ranges(&inputs, &[(out, out_length)])?;
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = MLDSAOperation::Sign {
                    key: unsafe { Pointer::slice(key, key_length) }?,
                    message: unsafe { Pointer::slice(message, message_length) }?,
                    context: unsafe { Pointer::slice(context, context_length) }?,
                    random: None,
                    out: unsafe { Pointer::slice_mut(out, out_length) }?,
                };
                let call = MLDSAPreHash { hash: unsafe { Pointer::text(hash, hash_length) }?, operation };
                self::parameters(name, call).flatten().ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }

        /// HashML-DSA.Verify (FIPS 204 algorithm 5) with the pre-hash named by `hash` and the context.
        pub unsafe extern "C" fn verify_pre_hash = "umilib_crypto_mldsa_mldsa_verify_pre_hash"; (parameters: *const u8, parameters_length: usize, hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, context: *const u8, context_length: usize, signature: *const u8, signature_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes.
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = MLDSAOperation::Verify {
                    key: unsafe { Pointer::slice(key, key_length) }?,
                    message: unsafe { Pointer::slice(message, message_length) }?,
                    context: unsafe { Pointer::slice(context, context_length) }?,
                    signature: unsafe { Pointer::slice(signature, signature_length) }?,
                };
                let call = MLDSAPreHash { hash: unsafe { Pointer::text(hash, hash_length) }?, operation };
                self::parameters(name, call).flatten().ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "mldsa",
    definitions: &[],
    functions: &crate::ffi::Function::concat::<{ mldsa::FUNCTIONS.len() + mldsa::VARIANTS.len() }>(&[
        mldsa::FUNCTIONS,
        mldsa::VARIANTS,
    ]),
    modules: &[],
};
