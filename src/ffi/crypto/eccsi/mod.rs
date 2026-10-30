//! The C ABI of [`crate::crypto::eccsi`].
//!
//! [`ECCSI<C, H>`](crate::crypto::eccsi::ECCSI) is exported once
//! (`umilib_crypto_eccsi_eccsi_*`) for every curve of
//! [`ffi_weierstrass_curves!`](crate::ffi_weierstrass_curves) and hash
//! function of [`ffi_standard_digests!`](crate::ffi_standard_digests), named
//! by their C type names; a pair other than those of RFC 6507 section 4.1
//! (a = -3 and a hash of the bytes of the field) fails with
//! InvalidParameter. Secrets (KSAK, SSK and the ephemerals) are big-endian
//! integers of the bytes of the order; points (KPAK and PVT) are
//! uncompressed, the canonical form of RFC 6509 section 3.2.

use crate::crypto::CryptoError;
use crate::crypto::eccsi::{ECCSI, ECCSIKMS, ECCSIUserKey};
use crate::ffi::crypto::random::RandomSource;
use crate::ffi::{Module, Pointer, Status};
use crate::hash::CryptographicDigest;
use crate::math::ec::{AffinePoint, FieldElement, PrimeField, WeierstrassCurve};
use crate::secret::Zeroize;

/// The encodings of the C ABI.
pub struct ECCSIEncoding;

impl ECCSIEncoding {
    /// The sizes in bytes of a secret, a point and a signature.
    pub fn sizes<C: WeierstrassCurve, H: CryptographicDigest + Default>() -> [usize; 3] {
        [<C::Scalar as PrimeField>::BYTES, AffinePoint::<C>::encoded_length(false), ECCSI::<C, H>::SIGNATURE_SIZE]
    }

    /// The secret of `bytes`, 1 ≤ secret < q; fails with InvalidKey otherwise.
    pub fn secret<C: WeierstrassCurve>(bytes: &[u8]) -> Result<FieldElement<C::Scalar>, CryptoError> {
        let secret = FieldElement::from_be_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
        if secret.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(secret)
    }

    /// The point of `bytes`, on the curve; fails with InvalidKey otherwise.
    pub fn point<C: WeierstrassCurve>(bytes: &[u8]) -> Result<AffinePoint<C>, CryptoError> {
        AffinePoint::from_encoded(bytes).map_err(|_| CryptoError::InvalidKey)
    }

    /// Writes the secret into `out` of its bytes.
    pub fn write_secret<C: WeierstrassCurve>(
        secret: &FieldElement<C::Scalar>,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if out.len() != <C::Scalar as PrimeField>::BYTES {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        secret.write_be_bytes(out).map_err(|_| CryptoError::InvalidKey)
    }

    /// Writes the point uncompressed into `out` of its bytes.
    pub fn write_point<C: WeierstrassCurve>(point: &AffinePoint<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != AffinePoint::<C>::encoded_length(false) {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        point.write_encoded(out, false).map_err(|_| CryptoError::InvalidKey)
    }

    /// Writes the (SSK, PVT) pair of `key`.
    pub fn write_user_key<C: WeierstrassCurve, H: CryptographicDigest + Default>(
        key: &ECCSIUserKey<C, H>,
        secret: &mut [u8],
        token: &mut [u8],
    ) -> Result<(), CryptoError> {
        ECCSIEncoding::write_point(key.token(), token)?;
        ECCSIEncoding::write_secret::<C>(key.secret(), secret)
    }

    /// Copies `signature` into `out` of its length.
    pub fn write_signature(signature: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != signature.len() {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        out.copy_from_slice(signature);
        Ok(())
    }
}

/// The key of a user: KPAK, the identity and the (SSK, PVT) pair.
pub struct ECCSIUserKeyBytes<'a> {
    pub authority: &'a [u8],
    pub identity: &'a [u8],
    pub secret: &'a [u8],
    pub token: &'a [u8],
}

impl ECCSIUserKeyBytes<'_> {
    /// The validated key (section 5.1.2); fails with InvalidKey or InvalidParameter.
    pub fn key<C: WeierstrassCurve, H: CryptographicDigest + Default>(
        &self,
    ) -> Result<ECCSIUserKey<C, H>, CryptoError> {
        let authority = ECCSIEncoding::point::<C>(self.authority)?;
        let token = ECCSIEncoding::point::<C>(self.token)?;
        let mut secret = ECCSIEncoding::secret::<C>(self.secret)?;
        let key = ECCSIUserKey::new(&authority, self.identity, secret, token);
        secret.zeroize();
        key
    }
}

/// An operation of the KMS, generic over the curve.
pub enum ECCSIKMSCall<'a> {
    /// Writes the sizes in bytes of a secret and a point.
    Sizes { out: &'a mut [usize; 2] },
    /// A random KSAK and its KPAK.
    Generate { random: RandomSource<'a>, secret: &'a mut [u8], public_key: &'a mut [u8] },
    /// The KPAK of the KSAK.
    PublicKey { secret: &'a [u8], public_key: &'a mut [u8] },
}

impl ECCSIKMSCall<'_> {
    pub fn call<C: WeierstrassCurve>(self) -> Result<(), CryptoError> {
        match self {
            ECCSIKMSCall::Sizes { out } => {
                *out = [<C::Scalar as PrimeField>::BYTES, AffinePoint::<C>::encoded_length(false)];
                Ok(())
            }
            ECCSIKMSCall::Generate { mut random, secret, public_key } => {
                let kms = ECCSIKMS::<C>::generate(&mut random)?;
                ECCSIEncoding::write_point(kms.public_key(), public_key)?;
                ECCSIEncoding::write_secret::<C>(kms.secret(), secret)
            }
            ECCSIKMSCall::PublicKey { secret, public_key } => {
                let mut value = ECCSIEncoding::secret::<C>(secret)?;
                let kms = ECCSIKMS::<C>::new(value);
                value.zeroize();
                let kms = kms?;
                ECCSIEncoding::write_point(kms.public_key(), public_key)
            }
        }
    }
}

/// An operation of users and verifiers, generic over the curve and the hash function.
pub enum ECCSICall<'a> {
    /// Writes the sizes in bytes of a secret, a point and a signature.
    Sizes {
        out: &'a mut [usize; 3],
    },
    /// The (SSK, PVT) pair of `identity` from the KSAK, with v random or given.
    Issue {
        kms: &'a [u8],
        identity: &'a [u8],
        ephemeral: ECCSIEphemeral<'a>,
        secret: &'a mut [u8],
        token: &'a mut [u8],
    },
    /// Validates the key of a user.
    Check {
        key: ECCSIUserKeyBytes<'a>,
    },
    /// The signature of `message`, with j random or given.
    Sign {
        key: ECCSIUserKeyBytes<'a>,
        message: &'a [u8],
        ephemeral: ECCSIEphemeral<'a>,
        out: &'a mut [u8],
    },
    Verify {
        authority: &'a [u8],
        identity: &'a [u8],
        message: &'a [u8],
        signature: &'a [u8],
    },
}

/// The ephemeral secret of an operation: from a generator, or given.
pub enum ECCSIEphemeral<'a> {
    Random(RandomSource<'a>),
    Given(&'a [u8]),
}

impl ECCSICall<'_> {
    pub fn call<C: WeierstrassCurve, H: CryptographicDigest + Default>(self) -> Result<(), CryptoError> {
        ECCSIUserKey::<C, H>::check_parameters()?;
        match self {
            ECCSICall::Sizes { out } => {
                *out = ECCSIEncoding::sizes::<C, H>();
                Ok(())
            }
            ECCSICall::Issue { kms, identity, ephemeral, secret, token } => {
                let mut value = ECCSIEncoding::secret::<C>(kms)?;
                let kms = ECCSIKMS::<C>::new(value);
                value.zeroize();
                let kms = kms?;
                let key = match ephemeral {
                    ECCSIEphemeral::Random(mut random) => kms.issue::<H, _>(identity, &mut random)?,
                    ECCSIEphemeral::Given(bytes) => {
                        let mut v = ECCSIEncoding::secret::<C>(bytes)?;
                        let key = kms.issue_with_ephemeral::<H>(identity, &v);
                        v.zeroize();
                        key?
                    }
                };
                ECCSIEncoding::write_user_key(&key, secret, token)
            }
            ECCSICall::Check { key } => key.key::<C, H>().map(|_| ()),
            ECCSICall::Sign { key, message, ephemeral, out } => {
                let key = key.key::<C, H>()?;
                let signature = match ephemeral {
                    ECCSIEphemeral::Random(mut random) => ECCSI::<C, H>::sign(&key, message, &mut random)?,
                    ECCSIEphemeral::Given(bytes) => {
                        let mut j = ECCSIEncoding::secret::<C>(bytes)?;
                        let signature = ECCSI::<C, H>::sign_with_ephemeral(&key, message, &j);
                        j.zeroize();
                        signature?
                    }
                };
                ECCSIEncoding::write_signature(&signature, out)
            }
            ECCSICall::Verify { authority, identity, message, signature } => {
                let authority = ECCSIEncoding::point::<C>(authority)?;
                ECCSI::<C, H>::verify(&authority, identity, message, signature)
            }
        }
    }
}

/// Defines the dispatch of [`ECCSIKMSCall`] and [`ECCSICall`] over the curves of the registry.
macro_rules! eccsi_curves {
    ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        // The registry may enable no curve, leaving the arguments unused.
        #[allow(unused_variables)]
        impl ECCSIKMSCall<'_> {
            /// The operation on the curve named `curve`; fails with InvalidArgument if it is unknown.
            pub fn dispatch(self, curve: &str) -> Result<(), &'static Status> {
                match curve {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => self.call::<$type>().map_err(|error| crate::ffi::ToStatus::to_status(&error)),
                    )*
                    _ => Err(&Status::INVALID_ARGUMENT),
                }
            }
        }

        // The registry may enable no curve, leaving the arguments unused.
        #[allow(unused_variables)]
        impl ECCSICall<'_> {
            /// The operation on the curve named `curve` with the hash function named `hash`; fails with
            /// InvalidArgument if either is unknown.
            pub fn dispatch(self, curve: &str, hash: &str) -> Result<(), &'static Status> {
                match curve {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => self.with_curve::<$type>(hash),
                    )*
                    _ => Err(&Status::INVALID_ARGUMENT),
                }
            }
        }
    };
}

/// Defines [`ECCSICall::with_curve`] over the hash functions of the registry.
macro_rules! eccsi_hashes {
    ($($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        // The registry may enable no hash function, leaving the arguments unused.
        #[allow(unused_variables, dead_code)]
        impl ECCSICall<'_> {
            /// The operation on `C` with the hash function named `hash`; fails with InvalidArgument if it is
            /// unknown.
            pub fn with_curve<C: WeierstrassCurve>(self, hash: &str) -> Result<(), &'static Status> {
                match hash {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => self.call::<C, $type>().map_err(|error| crate::ffi::ToStatus::to_status(&error)),
                    )*
                    _ => Err(&Status::INVALID_ARGUMENT),
                }
            }
        }
    };
}

crate::ffi_weierstrass_curves!(eccsi_curves);
crate::ffi_standard_digests!(eccsi_hashes);

crate::ffi_functions! {
    /// Writes the sizes in bytes of a secret, a point and a signature of ECCSI on the curve named by `curve`
    /// with the hash function named by `hash` into `sizes` (three elements); fails with InvalidParameter for a
    /// pair other than those of section 4.1.
    pub unsafe extern "C" fn umilib_crypto_eccsi_eccsi_sizes(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, sizes: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(curve, curve_length), (hash, hash_length)], &[(sizes.cast_const().cast(), 3 * core::mem::size_of::<usize>())])?;
            // SAFETY: the caller passes readable text and three writable elements.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let out = unsafe { Pointer::slice_of_mut(sizes, 3) }?;
            let out = out.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            ECCSICall::Sizes { out }.dispatch(curve, hash)
        })())
    }

    /// Writes the sizes in bytes of a secret and a point on the curve named by `curve` into `sizes` (two
    /// elements).
    pub unsafe extern "C" fn umilib_crypto_eccsi_eccsi_kms_sizes(curve: *const u8, curve_length: usize, sizes: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(curve, curve_length)], &[(sizes.cast_const().cast(), 2 * core::mem::size_of::<usize>())])?;
            // SAFETY: the caller passes readable text and two writable elements.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let out = unsafe { Pointer::slice_of_mut(sizes, 2) }?;
            let out = out.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            ECCSIKMSCall::Sizes { out }.dispatch(curve)
        })())
    }

    /// Generates a KMS on the curve named by `curve` from the generator handle `random` of the type named by
    /// `random_type`: writes its KSAK into `secret` and its KPAK into `public_key`.
    pub unsafe extern "C" fn umilib_crypto_eccsi_eccsi_kms_generate(curve: *const u8, curve_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, secret: *mut u8, secret_length: usize, public_key: *mut u8, public_key_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(curve, curve_length), (random_type, random_type_length)], &[(secret.cast_const(), secret_length), (public_key.cast_const(), public_key_length)])?;
            // SAFETY: the caller passes readable text, a live generator of the named type and writable bytes.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let secret = unsafe { Pointer::slice_mut(secret, secret_length) }?;
            let public_key = unsafe { Pointer::slice_mut(public_key, public_key_length) }?;
            ECCSIKMSCall::Generate { random, secret, public_key }.dispatch(curve)
        })())
    }

    /// Writes the KPAK of the KSAK `secret` on the curve named by `curve` into `out`.
    pub unsafe extern "C" fn umilib_crypto_eccsi_eccsi_kms_public_key(curve: *const u8, curve_length: usize, secret: *const u8, secret_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(curve, curve_length), (secret, secret_length)], &[(out.cast_const(), out_length)])?;
            // SAFETY: the caller passes readable text and bytes and writable bytes.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let secret = unsafe { Pointer::slice(secret, secret_length) }?;
            let public_key = unsafe { Pointer::slice_mut(out, out_length) }?;
            ECCSIKMSCall::PublicKey { secret, public_key }.dispatch(curve)
        })())
    }

    /// Issues the (SSK, PVT) pair of `identity` from the KSAK `kms` (section 5.1.1) with v drawn from the
    /// generator handle `random` of the type named by `random_type`.
    pub unsafe extern "C" fn umilib_crypto_eccsi_eccsi_kms_issue(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, kms: *const u8, kms_length: usize, identity: *const u8, identity_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, secret: *mut u8, secret_length: usize, token: *mut u8, token_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(curve, curve_length), (hash, hash_length), (kms, kms_length), (identity, identity_length), (random_type, random_type_length)], &[(secret.cast_const(), secret_length), (token.cast_const(), token_length)])?;
            // SAFETY: the caller passes readable text and bytes, a live generator of the named type and
            // writable bytes.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let call = ECCSICall::Issue {
                kms: unsafe { Pointer::slice(kms, kms_length) }?,
                identity: unsafe { Pointer::slice(identity, identity_length) }?,
                ephemeral: ECCSIEphemeral::Random(random),
                secret: unsafe { Pointer::slice_mut(secret, secret_length) }?,
                token: unsafe { Pointer::slice_mut(token, token_length) }?,
            };
            call.dispatch(curve, hash)
        })())
    }

    /// [`umilib_crypto_eccsi_eccsi_kms_issue`] with v given (section 5.1.1 steps 2 to 6). v must be secret,
    /// random and used once; fails with InvalidParameter when another v is needed.
    pub unsafe extern "C" fn umilib_crypto_eccsi_eccsi_kms_issue_with_ephemeral(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, kms: *const u8, kms_length: usize, identity: *const u8, identity_length: usize, ephemeral: *const u8, ephemeral_length: usize, secret: *mut u8, secret_length: usize, token: *mut u8, token_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(curve, curve_length), (hash, hash_length), (kms, kms_length), (identity, identity_length), (ephemeral, ephemeral_length)], &[(secret.cast_const(), secret_length), (token.cast_const(), token_length)])?;
            // SAFETY: the caller passes readable text and bytes and writable bytes.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let call = ECCSICall::Issue {
                kms: unsafe { Pointer::slice(kms, kms_length) }?,
                identity: unsafe { Pointer::slice(identity, identity_length) }?,
                ephemeral: ECCSIEphemeral::Given(unsafe { Pointer::slice(ephemeral, ephemeral_length) }?),
                secret: unsafe { Pointer::slice_mut(secret, secret_length) }?,
                token: unsafe { Pointer::slice_mut(token, token_length) }?,
            };
            call.dispatch(curve, hash)
        })())
    }

    /// Succeeds if (SSK, PVT) is a valid key of `identity` under the KPAK `authority` (section 5.1.2); fails
    /// with InvalidKey otherwise.
    pub unsafe extern "C" fn umilib_crypto_eccsi_eccsi_user_key_check(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, authority: *const u8, authority_length: usize, identity: *const u8, identity_length: usize, secret: *const u8, secret_length: usize, token: *const u8, token_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let key = ECCSIUserKeyBytes {
                authority: unsafe { Pointer::slice(authority, authority_length) }?,
                identity: unsafe { Pointer::slice(identity, identity_length) }?,
                secret: unsafe { Pointer::slice(secret, secret_length) }?,
                token: unsafe { Pointer::slice(token, token_length) }?,
            };
            ECCSICall::Check { key }.dispatch(curve, hash)
        })())
    }

    /// Writes the signature r || s || PVT of `message` by the key (SSK, PVT) of `identity` under the KPAK
    /// `authority` (section 5.2.1) into `out` of the size of a signature, with j derived from the key, the
    /// message and the generator handle `random` of the type named by `random_type`.
    pub unsafe extern "C" fn umilib_crypto_eccsi_eccsi_sign(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, authority: *const u8, authority_length: usize, identity: *const u8, identity_length: usize, secret: *const u8, secret_length: usize, token: *const u8, token_length: usize, message: *const u8, message_length: usize, random: *mut core::ffi::c_void, random_type: *const u8, random_type_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(curve, curve_length), (hash, hash_length), (authority, authority_length), (identity, identity_length), (secret, secret_length), (token, token_length), (message, message_length), (random_type, random_type_length)], &[(out.cast_const(), out_length)])?;
            // SAFETY: the caller passes readable text and bytes, a live generator of the named type and
            // writable bytes.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let call = ECCSICall::Sign {
                key: ECCSIUserKeyBytes {
                    authority: unsafe { Pointer::slice(authority, authority_length) }?,
                    identity: unsafe { Pointer::slice(identity, identity_length) }?,
                    secret: unsafe { Pointer::slice(secret, secret_length) }?,
                    token: unsafe { Pointer::slice(token, token_length) }?,
                },
                message: unsafe { Pointer::slice(message, message_length) }?,
                ephemeral: ECCSIEphemeral::Random(random),
                out: unsafe { Pointer::slice_mut(out, out_length) }?,
            };
            call.dispatch(curve, hash)
        })())
    }

    /// [`umilib_crypto_eccsi_eccsi_sign`] with j given (section 5.2.1 steps 2 to 7). j must be secret, random
    /// and used once; fails with InvalidParameter when another j is needed.
    pub unsafe extern "C" fn umilib_crypto_eccsi_eccsi_sign_with_ephemeral(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, authority: *const u8, authority_length: usize, identity: *const u8, identity_length: usize, secret: *const u8, secret_length: usize, token: *const u8, token_length: usize, message: *const u8, message_length: usize, ephemeral: *const u8, ephemeral_length: usize, out: *mut u8, out_length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[(curve, curve_length), (hash, hash_length), (authority, authority_length), (identity, identity_length), (secret, secret_length), (token, token_length), (message, message_length), (ephemeral, ephemeral_length)], &[(out.cast_const(), out_length)])?;
            // SAFETY: the caller passes readable text and bytes and writable bytes.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let call = ECCSICall::Sign {
                key: ECCSIUserKeyBytes {
                    authority: unsafe { Pointer::slice(authority, authority_length) }?,
                    identity: unsafe { Pointer::slice(identity, identity_length) }?,
                    secret: unsafe { Pointer::slice(secret, secret_length) }?,
                    token: unsafe { Pointer::slice(token, token_length) }?,
                },
                message: unsafe { Pointer::slice(message, message_length) }?,
                ephemeral: ECCSIEphemeral::Given(unsafe { Pointer::slice(ephemeral, ephemeral_length) }?),
                out: unsafe { Pointer::slice_mut(out, out_length) }?,
            };
            call.dispatch(curve, hash)
        })())
    }

    /// Succeeds if `signature` is a signature of `message` by `identity` under the KPAK `authority` (section
    /// 5.2.2); fails with InvalidSignature otherwise.
    pub unsafe extern "C" fn umilib_crypto_eccsi_eccsi_verify(curve: *const u8, curve_length: usize, hash: *const u8, hash_length: usize, authority: *const u8, authority_length: usize, identity: *const u8, identity_length: usize, message: *const u8, message_length: usize, signature: *const u8, signature_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and bytes.
            let curve = unsafe { Pointer::text(curve, curve_length) }?;
            let hash = unsafe { Pointer::text(hash, hash_length) }?;
            let call = ECCSICall::Verify {
                authority: unsafe { Pointer::slice(authority, authority_length) }?,
                identity: unsafe { Pointer::slice(identity, identity_length) }?,
                message: unsafe { Pointer::slice(message, message_length) }?,
                signature: unsafe { Pointer::slice(signature, signature_length) }?,
            };
            call.dispatch(curve, hash)
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module { name: "eccsi", definitions: &[], functions: FUNCTIONS, modules: &[] };
