//! The C ABI of [`crate::crypto::slhdsa`].
//!
//! [`SLHDSA<P>`](crate::crypto::slhdsa::SLHDSA) is exported once
//! (`umilib_crypto_slhdsa_slhdsa_*`) for the twelve parameter sets named by
//! the C type names `umilib_crypto_slhdsa_SLHDSA_SHA2_128s` to
//! `umilib_crypto_slhdsa_SLHDSA_SHAKE_256f`: the functions of
//! [`SignatureScheme`](crate::crypto::SignatureScheme) (deterministic, empty
//! context) on the encodings of FIPS 205; `_key_gen_internal` (the private
//! key of SK.seed, SK.prf and PK.seed); `_sign_with_context` (hedged, addrnd from a
//! generator) or `_sign_deterministic_with_context` and
//! `_verify_with_context`; and their HashSLH-DSA forms `_sign_pre_hash`,
//! `_sign_pre_hash_deterministic` and `_verify_pre_hash`, with the hash
//! function named by the C type name of its type (SHA-2, SHA-3, SHAKE128
//! and SHAKE256).

use crate::ffi::Module;

/// [`SLHDSA`](crate::crypto::slhdsa::SLHDSA).
// Every exported type has a module named after it, here the name of its parent too.
#[allow(clippy::module_inception)]
pub mod slhdsa {
    use core::marker::PhantomData;

    use crate::crypto::slhdsa::{
        SLHDSA, SLHDSA_SHA2_128f, SLHDSA_SHA2_128s, SLHDSA_SHA2_192f, SLHDSA_SHA2_192s, SLHDSA_SHA2_256f,
        SLHDSA_SHA2_256s, SLHDSA_SHAKE_128f, SLHDSA_SHAKE_128s, SLHDSA_SHAKE_192f, SLHDSA_SHAKE_192s,
        SLHDSA_SHAKE_256f, SLHDSA_SHAKE_256s, SLHDSAParameters,
    };
    use crate::crypto::{CryptoError, PreHash, SignatureScheme};
    use crate::ffi::crypto::random::RandomSource;
    use crate::ffi::crypto::{PreHashCall, PreHashRegistry, SignatureSchemeCall};
    use crate::ffi::{Pointer, Status, ToStatus};

    /// An operation on a parameter set of SLH-DSA chosen at run time.
    pub trait SLHDSACall {
        type Output;

        fn call<P: SLHDSAParameters>(self) -> Self::Output;
    }

    /// Calls `call` with the parameter set named `name`; `None` if it is unknown.
    pub fn parameters<V: SLHDSACall>(name: &str, call: V) -> Option<V::Output> {
        match name {
            "umilib_crypto_slhdsa_SLHDSA_SHA2_128s" => Some(call.call::<SLHDSA_SHA2_128s>()),
            "umilib_crypto_slhdsa_SLHDSA_SHAKE_128s" => Some(call.call::<SLHDSA_SHAKE_128s>()),
            "umilib_crypto_slhdsa_SLHDSA_SHA2_128f" => Some(call.call::<SLHDSA_SHA2_128f>()),
            "umilib_crypto_slhdsa_SLHDSA_SHAKE_128f" => Some(call.call::<SLHDSA_SHAKE_128f>()),
            "umilib_crypto_slhdsa_SLHDSA_SHA2_192s" => Some(call.call::<SLHDSA_SHA2_192s>()),
            "umilib_crypto_slhdsa_SLHDSA_SHAKE_192s" => Some(call.call::<SLHDSA_SHAKE_192s>()),
            "umilib_crypto_slhdsa_SLHDSA_SHA2_192f" => Some(call.call::<SLHDSA_SHA2_192f>()),
            "umilib_crypto_slhdsa_SLHDSA_SHAKE_192f" => Some(call.call::<SLHDSA_SHAKE_192f>()),
            "umilib_crypto_slhdsa_SLHDSA_SHA2_256s" => Some(call.call::<SLHDSA_SHA2_256s>()),
            "umilib_crypto_slhdsa_SLHDSA_SHAKE_256s" => Some(call.call::<SLHDSA_SHAKE_256s>()),
            "umilib_crypto_slhdsa_SLHDSA_SHA2_256f" => Some(call.call::<SLHDSA_SHA2_256f>()),
            "umilib_crypto_slhdsa_SLHDSA_SHAKE_256f" => Some(call.call::<SLHDSA_SHAKE_256f>()),
            _ => None,
        }
    }

    /// The step of [`scheme`] from the parameter set to `SLHDSA<P>`.
    pub struct SLHDSAScheme<V> {
        call: V,
    }

    impl<V: SignatureSchemeCall> SLHDSACall for SLHDSAScheme<V> {
        type Output = V::Output;

        fn call<P: SLHDSAParameters>(self) -> V::Output {
            self.call.call::<SLHDSA<P>>()
        }
    }

    /// Calls `call` with `SLHDSA<P>` for the parameter set named `names.0`; `None` if it is unknown.
    pub fn scheme<V: SignatureSchemeCall>(names: (&str,), call: V) -> Option<V::Output> {
        parameters(names.0, SLHDSAScheme { call })
    }

    crate::ffi_signature_scheme!("umilib_crypto_slhdsa_slhdsa", "SLH-DSA with the parameter set named by `parameters`", [parameters parameters_length]);

    /// An operation of SLH-DSA beyond [`SignatureScheme`], on encoded keys.
    pub enum SLHDSAOperation<'a> {
        /// Writes the private key of SK.seed, SK.prf and PK.seed.
        KeyGen { sk_seed: &'a [u8], sk_prf: &'a [u8], pk_seed: &'a [u8], out: &'a mut [u8] },
        /// Signs with a context: hedged with addrnd from `random`, deterministic without it.
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

    impl SLHDSACall for SLHDSAOperation<'_> {
        type Output = Result<(), CryptoError>;

        fn call<P: SLHDSAParameters>(self) -> Result<(), CryptoError> {
            match self {
                SLHDSAOperation::KeyGen { sk_seed, sk_prf, pk_seed, out } => {
                    SLHDSA::<P>::write_signing_key(&SLHDSA::<P>::key_gen_internal(sk_seed, sk_prf, pk_seed)?, out)
                }
                SLHDSAOperation::Sign { key, message, context, random, out } => {
                    let key = SLHDSA::<P>::signing_key_from_bytes(key)?;
                    match random {
                        Some(mut random) => SLHDSA::<P>::sign_with_context(&key, message, context, &mut random, out),
                        None => SLHDSA::<P>::sign_deterministic_with_context(&key, message, context, out),
                    }
                }
                SLHDSAOperation::Verify { key, message, context, signature } => SLHDSA::<P>::verify_with_context(
                    &SLHDSA::<P>::verifying_key_from_bytes(key)?,
                    message,
                    context,
                    signature,
                ),
            }
        }
    }

    /// An operation of HashSLH-DSA with the pre-hash named `hash`.
    pub struct SLHDSAPreHash<'a> {
        pub hash: &'a str,
        pub operation: SLHDSAOperation<'a>,
    }

    impl SLHDSACall for SLHDSAPreHash<'_> {
        type Output = Option<Result<(), CryptoError>>;

        fn call<P: SLHDSAParameters>(self) -> Self::Output {
            PreHashRegistry::hash(
                self.hash,
                SLHDSAPreHashWith::<P> { operation: self.operation, parameters: PhantomData },
            )
        }
    }

    /// The step of [`SLHDSAPreHash`] with the parameter set `P` chosen.
    pub struct SLHDSAPreHashWith<'a, P> {
        operation: SLHDSAOperation<'a>,
        parameters: PhantomData<P>,
    }

    impl<P: SLHDSAParameters> PreHashCall for SLHDSAPreHashWith<'_, P> {
        type Output = Result<(), CryptoError>;

        fn call<H: PreHash>(self) -> Result<(), CryptoError> {
            match self.operation {
                SLHDSAOperation::Sign { key, message, context, random, out } => {
                    let key = SLHDSA::<P>::signing_key_from_bytes(key)?;
                    match random {
                        Some(mut random) => {
                            SLHDSA::<P>::sign_pre_hash::<H, _>(&key, message, context, &mut random, out)
                        }
                        None => SLHDSA::<P>::sign_pre_hash_deterministic::<H>(&key, message, context, out),
                    }
                }
                SLHDSAOperation::Verify { key, message, context, signature } => {
                    let key = SLHDSA::<P>::verifying_key_from_bytes(key)?;
                    SLHDSA::<P>::verify_pre_hash::<H>(&key, message, context, signature)
                }
                SLHDSAOperation::KeyGen { .. } => Err(CryptoError::InvalidParameter),
            }
        }
    }

    crate::ffi_exports! {
        const VARIANTS;
        /// slh_keygen_internal (FIPS 205 algorithm 18) of SK.seed, SK.prf and PK.seed (n bytes each): writes
        /// the private key into `out` of the size of a signing key.
        pub unsafe extern "C" fn key_gen_internal = "umilib_crypto_slhdsa_slhdsa_key_gen_internal"; (parameters: *const u8, parameters_length: usize, sk_seed: *const u8, sk_seed_length: usize, sk_prf: *const u8, sk_prf_length: usize, pk_seed: *const u8, pk_seed_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes and writable bytes.
                let inputs = [(parameters, parameters_length), (sk_seed, sk_seed_length), (sk_prf, sk_prf_length), (pk_seed, pk_seed_length)];
                Pointer::check_ranges(&inputs, &[(out, out_length)])?;
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = SLHDSAOperation::KeyGen {
                    sk_seed: unsafe { Pointer::slice(sk_seed, sk_seed_length) }?,
                    sk_prf: unsafe { Pointer::slice(sk_prf, sk_prf_length) }?,
                    pk_seed: unsafe { Pointer::slice(pk_seed, pk_seed_length) }?,
                    out: unsafe { Pointer::slice_mut(out, out_length) }?,
                };
                self::parameters(name, operation).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }

        /// slh_sign (FIPS 205 algorithm 22) of the message with the context (at most 255 bytes) and addrnd from
        /// the generator handle `random`, into `out` of the size of a signature.
        pub unsafe extern "C" fn sign_with_context = "umilib_crypto_slhdsa_slhdsa_sign_with_context"; (parameters: *const u8, parameters_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, context: *const u8, context_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes, a live generator of the named type and writable bytes.
                let inputs = [(parameters, parameters_length), (key, key_length), (message, message_length), (context, context_length), (random_type, random_type_length)];
                Pointer::check_ranges(&inputs, &[(out, out_length)])?;
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = SLHDSAOperation::Sign {
                    key: unsafe { Pointer::slice(key, key_length) }?,
                    message: unsafe { Pointer::slice(message, message_length) }?,
                    context: unsafe { Pointer::slice(context, context_length) }?,
                    random: Some(unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?),
                    out: unsafe { Pointer::slice_mut(out, out_length) }?,
                };
                self::parameters(name, operation).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }

        /// The deterministic variant of slh_sign (opt_rand = PK.seed) with the context.
        pub unsafe extern "C" fn sign_deterministic_with_context = "umilib_crypto_slhdsa_slhdsa_sign_deterministic_with_context"; (parameters: *const u8, parameters_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, context: *const u8, context_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes and writable bytes.
                let inputs = [(parameters, parameters_length), (key, key_length), (message, message_length), (context, context_length)];
                Pointer::check_ranges(&inputs, &[(out, out_length)])?;
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = SLHDSAOperation::Sign {
                    key: unsafe { Pointer::slice(key, key_length) }?,
                    message: unsafe { Pointer::slice(message, message_length) }?,
                    context: unsafe { Pointer::slice(context, context_length) }?,
                    random: None,
                    out: unsafe { Pointer::slice_mut(out, out_length) }?,
                };
                self::parameters(name, operation).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }

        /// slh_verify (FIPS 205 algorithm 24) with the context; fails with InvalidSignature otherwise.
        pub unsafe extern "C" fn verify_with_context = "umilib_crypto_slhdsa_slhdsa_verify_with_context"; (parameters: *const u8, parameters_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, context: *const u8, context_length: usize, signature: *const u8, signature_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes.
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = SLHDSAOperation::Verify {
                    key: unsafe { Pointer::slice(key, key_length) }?,
                    message: unsafe { Pointer::slice(message, message_length) }?,
                    context: unsafe { Pointer::slice(context, context_length) }?,
                    signature: unsafe { Pointer::slice(signature, signature_length) }?,
                };
                self::parameters(name, operation).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }

        /// hash_slh_sign (FIPS 205 algorithm 23) with the pre-hash named by `hash`, the context and addrnd from
        /// the generator handle `random`.
        pub unsafe extern "C" fn sign_pre_hash = "umilib_crypto_slhdsa_slhdsa_sign_pre_hash"; (parameters: *const u8, parameters_length: usize, hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, context: *const u8, context_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes, a live generator of the named type and writable bytes.
                let inputs = [(parameters, parameters_length), (hash, hash_length), (key, key_length), (message, message_length), (context, context_length), (random_type, random_type_length)];
                Pointer::check_ranges(&inputs, &[(out, out_length)])?;
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = SLHDSAOperation::Sign {
                    key: unsafe { Pointer::slice(key, key_length) }?,
                    message: unsafe { Pointer::slice(message, message_length) }?,
                    context: unsafe { Pointer::slice(context, context_length) }?,
                    random: Some(unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?),
                    out: unsafe { Pointer::slice_mut(out, out_length) }?,
                };
                let call = SLHDSAPreHash { hash: unsafe { Pointer::text(hash, hash_length) }?, operation };
                self::parameters(name, call).flatten().ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }

        /// The deterministic variant of hash_slh_sign (opt_rand = PK.seed).
        pub unsafe extern "C" fn sign_pre_hash_deterministic = "umilib_crypto_slhdsa_slhdsa_sign_pre_hash_deterministic"; (parameters: *const u8, parameters_length: usize, hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, context: *const u8, context_length: usize, out: *mut u8, out_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes and writable bytes.
                let inputs = [(parameters, parameters_length), (hash, hash_length), (key, key_length), (message, message_length), (context, context_length)];
                Pointer::check_ranges(&inputs, &[(out, out_length)])?;
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = SLHDSAOperation::Sign {
                    key: unsafe { Pointer::slice(key, key_length) }?,
                    message: unsafe { Pointer::slice(message, message_length) }?,
                    context: unsafe { Pointer::slice(context, context_length) }?,
                    random: None,
                    out: unsafe { Pointer::slice_mut(out, out_length) }?,
                };
                let call = SLHDSAPreHash { hash: unsafe { Pointer::text(hash, hash_length) }?, operation };
                self::parameters(name, call).flatten().ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }

        /// hash_slh_verify (FIPS 205 algorithm 25) with the pre-hash named by `hash` and the context.
        pub unsafe extern "C" fn verify_pre_hash = "umilib_crypto_slhdsa_slhdsa_verify_pre_hash"; (parameters: *const u8, parameters_length: usize, hash: *const u8, hash_length: usize, key: *const u8, key_length: usize, message: *const u8, message_length: usize, context: *const u8, context_length: usize, signature: *const u8, signature_length: usize) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text and bytes.
                let name = unsafe { Pointer::text(parameters, parameters_length) }?;
                let operation = SLHDSAOperation::Verify {
                    key: unsafe { Pointer::slice(key, key_length) }?,
                    message: unsafe { Pointer::slice(message, message_length) }?,
                    context: unsafe { Pointer::slice(context, context_length) }?,
                    signature: unsafe { Pointer::slice(signature, signature_length) }?,
                };
                let call = SLHDSAPreHash { hash: unsafe { Pointer::text(hash, hash_length) }?, operation };
                self::parameters(name, call).flatten().ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| error.to_status())
            })())
        }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "slhdsa",
    definitions: &[],
    functions: &crate::ffi::Function::concat::<{ slhdsa::FUNCTIONS.len() + slhdsa::VARIANTS.len() }>(&[
        slhdsa::FUNCTIONS,
        slhdsa::VARIANTS,
    ]),
    modules: &[],
};
