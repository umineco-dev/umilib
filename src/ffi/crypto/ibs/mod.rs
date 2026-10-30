//! The C ABI of [`crate::crypto::ibs`].
//!
//! Each scheme exports its functions on the pairing-friendly curves of
//! [`ffi_pairing_curves!`](crate::ffi_pairing_curves) with the hash
//! functions of [`ffi_standard_digests!`](crate::ffi_standard_digests), named
//! by their C type names (see [`ffi_identity_based_signature!`](crate::ffi_identity_based_signature)).
//! A master key ([`IBSMasterKey`]) and the user keys it extracts
//! ([`IBSUserKey`]) are the handles `umilib_crypto_ibs_IBSMasterKey` and
//! `umilib_crypto_ibs_IBSUserKey`, which keep their scheme. The master
//! secret is big-endian of the bytes of r, the master public key the
//! encoding of its scheme
//! ([`IdentityBasedSignature::master_public_key_to_bytes`]), and signatures
//! the encodings of [`IBSSignature`].

#[cfg(umilib_feature = "crypto-ibs-chacheon")]
pub mod chacheon;
#[cfg(umilib_feature = "crypto-ibs-hess")]
pub mod hess;
#[cfg(umilib_feature = "crypto-ibs-sm9")]
pub mod sm9;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::crypto::CryptoError;
use crate::crypto::ibs::{IBSMasterKey, IBSSignature, IBSUserKey, IdentityBasedSignature};
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};
use crate::math::ec::{FieldElement, PrimeField};
use crate::math::pairing::PairingCurve;
use crate::secret::Zeroize;

/// A master key of any scheme: [`IBSMasterKey`] with the scheme chosen at run time.
pub trait IBSMasterState {
    /// The encoding of the master public key.
    fn public_key(&self) -> Vec<u8>;

    /// The encoding of the master secret.
    fn secret(&self) -> Vec<u8>;

    /// The key of `identity` (Extract) of the scheme.
    fn extract(&self, identity: &[u8]) -> Result<Box<dyn IBSUserState>, CryptoError>;
}

/// A user key of any scheme: [`IBSUserKey`] with the scheme chosen at run time.
pub trait IBSUserState {
    fn identity(&self) -> &[u8];

    /// The encoded signature of `message` by the owner of the key.
    fn sign(&self, message: &[u8], random: &mut RandomSource<'_>) -> Result<Vec<u8>, CryptoError>;
}

/// The master key of the scheme `S`.
pub struct IBSMaster<S: IdentityBasedSignature> {
    pub key: IBSMasterKey<S::Curve>,
    pub scheme: PhantomData<S>,
}

/// A user key of the scheme `S`.
pub struct IBSUser<S: IdentityBasedSignature> {
    pub key: IBSUserKey<S::Curve>,
    pub scheme: PhantomData<S>,
}

impl<S: IdentityBasedSignature + 'static> IBSMasterState for IBSMaster<S> {
    fn public_key(&self) -> Vec<u8> {
        S::master_public_key_to_bytes(self.key.public_key())
    }

    fn secret(&self) -> Vec<u8> {
        let mut out = vec![0u8; <<S::Curve as PairingCurve>::Scalar as PrimeField>::BYTES];
        // The buffer has the bytes of the scalars.
        let _ = self.key.secret().write_be_bytes(&mut out);
        out
    }

    fn extract(&self, identity: &[u8]) -> Result<Box<dyn IBSUserState>, CryptoError> {
        let key = S::extract(&self.key, identity)?;
        Ok(Box::new(IBSUser::<S> { key, scheme: PhantomData }))
    }
}

impl<S: IdentityBasedSignature> IBSUserState for IBSUser<S> {
    fn identity(&self) -> &[u8] {
        self.key.identity()
    }

    fn sign(&self, message: &[u8], random: &mut RandomSource<'_>) -> Result<Vec<u8>, CryptoError> {
        Ok(S::sign(&self.key, message, random)?.to_bytes())
    }
}

impl Value for Box<dyn IBSMasterState> {
    const TYPE: Type = Type::Named("umilib_crypto_ibs_IBSMasterKey");
}

impl Value for Box<dyn IBSUserState> {
    const TYPE: Type = Type::Named("umilib_crypto_ibs_IBSUserKey");
}

/// An operation on a scheme chosen at run time: the registry of a scheme's
/// module calls `call` with the scheme its names choose.
pub trait IBSCall {
    type Output;

    fn call<S: IdentityBasedSignature + 'static>(self) -> Self::Output;
}

/// The sizes in bytes of a master secret, a master public key and a signature.
pub struct IBSSizes;

impl IBSCall for IBSSizes {
    type Output = [usize; 3];

    fn call<S: IdentityBasedSignature + 'static>(self) -> [usize; 3] {
        [
            <<S::Curve as PairingCurve>::Scalar as PrimeField>::BYTES,
            S::master_public_key_size(),
            S::Signature::encoded_length(),
        ]
    }
}

/// The master key from a generator (Setup), or of a given secret.
pub enum IBSMasterNew<'a> {
    Random(RandomSource<'a>),
    Secret(&'a [u8]),
}

impl IBSCall for IBSMasterNew<'_> {
    type Output = Result<Box<dyn IBSMasterState>, CryptoError>;

    fn call<S: IdentityBasedSignature + 'static>(self) -> Self::Output {
        let key = match self {
            IBSMasterNew::Random(mut random) => S::setup(&mut random)?,
            IBSMasterNew::Secret(bytes) => {
                let mut secret = FieldElement::from_be_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
                let key = IBSMasterKey::new(secret);
                secret.zeroize();
                key?
            }
        };
        Ok(Box::new(IBSMaster::<S> { key, scheme: PhantomData }))
    }
}

/// Verifies a signature under the encoded master public key.
pub struct IBSVerify<'a> {
    pub master: &'a [u8],
    pub identity: &'a [u8],
    pub message: &'a [u8],
    pub signature: &'a [u8],
}

impl IBSCall for IBSVerify<'_> {
    type Output = Result<(), CryptoError>;

    fn call<S: IdentityBasedSignature + 'static>(self) -> Result<(), CryptoError> {
        let master = S::master_public_key_from_bytes(self.master)?;
        let signature = S::Signature::from_bytes(self.signature)?;
        S::verify(&master, self.identity, self.message, &signature)
    }
}

/// Exports the functions of an identity-based signature scheme chosen by
/// the C type names of its pairing-friendly curve and hash function, whose
/// registry the module defines as `fn scheme<V: IBSCall>(names, call)`.
#[macro_export]
macro_rules! ffi_identity_based_signature {
    ($prefix:literal, $what:literal) => {
        $crate::ffi_exports! {
            const FUNCTIONS;
            #[doc = concat!(" Writes the sizes in bytes of a master secret, a master public key and a signature of ", $what, " on")]
            /// the curve named by `curve` with the hash function named by `hash` into `sizes` (three elements).
            pub unsafe extern "C" fn sizes = concat!($prefix, "_sizes"); (curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, sizes: *mut usize) -> *const Status {
                Status::from_result((|| {
                    Pointer::check_ranges(&[(curve, curve_length), (hash, hash_length)], &[(sizes.cast_const().cast(), 3 * core::mem::size_of::<usize>())])?;
                    // SAFETY: the caller passes readable text and three writable elements.
                    let names = (unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?);
                    let values = scheme(names, $crate::ffi::crypto::ibs::IBSSizes).ok_or(&Status::INVALID_ARGUMENT)?;
                    let out = unsafe { Pointer::slice_of_mut(sizes, 3) }?;
                    out.copy_from_slice(&values);
                    Ok(())
                })())
            }

            /// Creates the master key of a new private key generator (Setup) from the generator handle `random`,
            /// whose C type is named by `random_type`.
            pub unsafe extern "C" fn setup = concat!($prefix, "_setup"); (curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut alloc::boxed::Box<dyn $crate::ffi::crypto::ibs::IBSMasterState>) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text, a live generator of the named type and a writable
                    // pointer.
                    let names = (unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?);
                    let random = unsafe { $crate::ffi::crypto::random::RandomSource::from_handle(random, random_type, random_type_length) }?;
                    let call = $crate::ffi::crypto::ibs::IBSMasterNew::Random(random);
                    let key = scheme(names, call).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| $crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { Pointer::write_handle(out, key) }
                })())
            }

            /// Creates the master key of the master secret (big-endian, 1 ≤ s < r); fails with InvalidKey
            /// otherwise.
            pub unsafe extern "C" fn master_key_new = concat!($prefix, "_master_key_new"); (curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, secret: *const u8, secret_length: usize, out: *mut *mut alloc::boxed::Box<dyn $crate::ffi::crypto::ibs::IBSMasterState>) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes and a writable pointer.
                    let names = (unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?);
                    let call = $crate::ffi::crypto::ibs::IBSMasterNew::Secret(unsafe { Pointer::slice(secret, secret_length) }?);
                    let key = scheme(names, call).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| $crate::ffi::ToStatus::to_status(&error))?;
                    unsafe { Pointer::write_handle(out, key) }
                })())
            }

            /// Succeeds if `signature` is a signature of `message` by `identity` under the encoded master public
            /// key `master`; fails with InvalidSignature otherwise and InvalidKey for a master key that is not a
            /// point of G_2.
            pub unsafe extern "C" fn verify = concat!($prefix, "_verify"); (curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, master: *const u8, master_length: usize, identity: *const u8, identity_length: usize, message: *const u8, message_length: usize, signature: *const u8, signature_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text and bytes.
                    let names = (unsafe { Pointer::text(curve, curve_length) }?, unsafe { Pointer::text(hash, hash_length) }?);
                    let call = $crate::ffi::crypto::ibs::IBSVerify {
                        master: unsafe { Pointer::slice(master, master_length) }?,
                        identity: unsafe { Pointer::slice(identity, identity_length) }?,
                        message: unsafe { Pointer::slice(message, message_length) }?,
                        signature: unsafe { Pointer::slice(signature, signature_length) }?,
                    };
                    scheme(names, call).ok_or(&Status::INVALID_ARGUMENT)?.map_err(|error| $crate::ffi::ToStatus::to_status(&error))
                })())
            }
        }
    };
}

crate::ffi_functions! {
    /// Releases the master key, zeroizing its secret. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_ibs_ibs_master_key_free(key: *mut Box<dyn IBSMasterState>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(key) }
    }

    /// Writes the encoded master public key P_pub into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_ibs_ibs_master_key_public_key(key: *const Box<dyn IBSMasterState>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(key.public_key())) }
        })())
    }

    /// Writes the master secret s into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_ibs_ibs_master_key_secret(key: *const Box<dyn IBSMasterState>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(key.secret())) }
        })())
    }

    /// Creates the user key of `identity` (Extract) of the scheme of the master key.
    pub unsafe extern "C" fn umilib_crypto_ibs_ibs_master_key_extract(key: *const Box<dyn IBSMasterState>, identity: *const u8, identity_length: usize, out: *mut *mut Box<dyn IBSUserState>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let key = unsafe { Pointer::reference(key) }?;
            let identity = unsafe { Pointer::slice(identity, identity_length) }?;
            let user = key.extract(identity).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, user) }
        })())
    }

    /// Releases the user key, zeroizing it. Does nothing if it is null.
    pub unsafe extern "C" fn umilib_crypto_ibs_ibs_user_key_free(key: *mut Box<dyn IBSUserState>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(key) }
    }

    /// Writes the identity of the key into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_ibs_ibs_user_key_identity(key: *const Box<dyn IBSUserState>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(key.identity().to_vec())) }
        })())
    }

    /// Writes the encoded signature of `message` by the owner of the key, with random values from the
    /// generator handle `random` of the type named by `random_type`, into a new buffer.
    pub unsafe extern "C" fn umilib_crypto_ibs_ibs_user_key_sign(key: *const Box<dyn IBSUserState>, message: *const u8, message_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes, a live generator of the named type and a
            // writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let message = unsafe { Pointer::slice(message, message_length) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let signature = key.sign(message, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(signature)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ibs",
    definitions: &[
        Definition::Opaque {
            name: "umilib_crypto_ibs_IBSMasterKey",
            documentation: " The master key of a private key generator of an identity-based signature scheme, which keeps its scheme.",
        },
        Definition::Opaque {
            name: "umilib_crypto_ibs_IBSUserKey",
            documentation: " The key of a user of an identity-based signature scheme, which keeps its scheme.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[
        #[cfg(umilib_feature = "crypto-ibs-chacheon")]
        chacheon::MODULE,
        #[cfg(umilib_feature = "crypto-ibs-hess")]
        hess::MODULE,
        #[cfg(umilib_feature = "crypto-ibs-sm9")]
        sm9::MODULE,
    ],
};
