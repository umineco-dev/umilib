use alloc::vec;
use core::fmt;
use core::marker::PhantomData;

use super::ECDSASignature;
use crate::crypto::random::{DRBGConfig, HMACDRBG, Random};
use crate::crypto::{CryptoError, SignatureScheme};
use crate::hash::CryptographicDigest;
use crate::math::bigint::UnsignedInteger;
use crate::math::ec::{AffinePoint, FieldElement, FieldValue, PrimeField, ProjectivePoint, WeierstrassCurve};
use crate::math::modular::ModularArithmetic;
use crate::secret::Zeroize;

/// ECDSA on the curve `C` with the hash function `H`.
pub struct ECDSA<C: WeierstrassCurve, H: CryptographicDigest + Default> {
    types: PhantomData<(C, H)>,
}

/// A signing key of [`ECDSA`]: a scalar d with 1 ≤ d < n, zeroized when dropped.
pub struct ECDSASigningKey<C: WeierstrassCurve> {
    scalar: FieldElement<C::Scalar>,
}

impl<C: WeierstrassCurve> ECDSASigningKey<C> {
    /// The key of the scalar `scalar`; fails with `InvalidKey` for zero.
    pub fn new(scalar: FieldElement<C::Scalar>) -> Result<ECDSASigningKey<C>, CryptoError> {
        if scalar.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(ECDSASigningKey { scalar })
    }

    pub fn scalar(&self) -> &FieldElement<C::Scalar> {
        &self.scalar
    }
}

impl<C: WeierstrassCurve> Clone for ECDSASigningKey<C> {
    fn clone(&self) -> ECDSASigningKey<C> {
        ECDSASigningKey { scalar: self.scalar }
    }
}

impl<C: WeierstrassCurve> Zeroize for ECDSASigningKey<C> {
    fn zeroize(&mut self) {
        self.scalar.zeroize();
    }
}

impl<C: WeierstrassCurve> Drop for ECDSASigningKey<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the curve, not the key.
impl<C: WeierstrassCurve> fmt::Debug for ECDSASigningKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = core::any::type_name::<C>();
        write!(formatter, "ECDSASigningKey<{}>(..)", name.rsplit("::").next().unwrap_or(name))
    }
}

/// A verifying key of [`ECDSA`]: a point of the subgroup of `C` other than the identity.
pub struct ECDSAVerifyingKey<C: WeierstrassCurve> {
    point: AffinePoint<C>,
}

impl<C: WeierstrassCurve> Clone for ECDSAVerifyingKey<C> {
    fn clone(&self) -> ECDSAVerifyingKey<C> {
        *self
    }
}

impl<C: WeierstrassCurve> Copy for ECDSAVerifyingKey<C> {}

impl<C: WeierstrassCurve> PartialEq for ECDSAVerifyingKey<C> {
    fn eq(&self, other: &ECDSAVerifyingKey<C>) -> bool {
        self.point == other.point
    }
}

impl<C: WeierstrassCurve> Eq for ECDSAVerifyingKey<C> {}

impl<C: WeierstrassCurve> fmt::Debug for ECDSAVerifyingKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ECDSAVerifyingKey({:?})", self.point)
    }
}

impl<C: WeierstrassCurve> ECDSAVerifyingKey<C> {
    /// The key of `point`, validated as SEC 1 section 3.2.2.1 requires: not
    /// the identity, on the curve and in the subgroup of the generator.
    /// Fails with `InvalidKey` otherwise.
    pub fn new(point: AffinePoint<C>) -> Result<ECDSAVerifyingKey<C>, CryptoError> {
        if (point.is_identity() | !point.is_in_subgroup()).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(ECDSAVerifyingKey { point })
    }

    pub fn point(&self) -> &AffinePoint<C> {
        &self.point
    }

    /// The key of the SEC 1 encoding `bytes`, compressed or not; fails with
    /// `InvalidKey` for anything else.
    pub fn from_encoded(bytes: &[u8]) -> Result<ECDSAVerifyingKey<C>, CryptoError> {
        ECDSAVerifyingKey::new(AffinePoint::from_encoded(bytes).map_err(|_| CryptoError::InvalidKey)?)
    }

    /// Writes the SEC 1 encoding into `out` of its length,
    /// `AffinePoint::<C>::encoded_length(compressed)`.
    pub fn write_encoded(&self, out: &mut [u8], compressed: bool) -> Result<(), CryptoError> {
        let length = out.len();
        self.point.write_encoded(out, compressed).map_err(|_| CryptoError::InputLength { length })
    }
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> ECDSA<C, H> {
    /// The integer of a digest, bits2int of RFC 6979 section 2.3.2 (its
    /// leftmost bits, as many as the order has) reduced modulo the order:
    /// the e of SEC 1 section 4.1.3 step 5.
    pub fn digest_scalar(digest: &[u8]) -> FieldElement<C::Scalar> {
        let order_bits = <C::Scalar as PrimeField>::MODULUS.value().bit_length();
        let taken = &digest[..digest.len().min(<C::Scalar as PrimeField>::BYTES)];
        // At most the bytes of the order always fit.
        let value = FieldValue::<C::Scalar>::from_be_bytes(taken).unwrap_or(FieldValue::<C::Scalar>::ZERO);
        let excess = (8 * taken.len() as u32).saturating_sub(order_bits);
        FieldElement::from_value_reduced(&value.shr(excess))
    }

    /// The signature of the digest `digest` (computed with `H` or any other
    /// hash, as FIPS 186-5 allows) with the nonce of RFC 6979 section 3.2.
    pub fn sign_digest(key: &ECDSASigningKey<C>, digest: &[u8]) -> Result<ECDSASignature<C>, CryptoError> {
        ECDSA::<C, H>::sign_digest_with_additional(key, digest, &[])
    }

    /// [`ECDSA::sign_digest`] with random bytes of `random`, as many as the
    /// order has, appended to the seed of the nonce (RFC 6979 section 3.6):
    /// the signature depends on them, and stays safe if they are not random.
    pub fn sign_digest_hedged<R: Random>(
        key: &ECDSASigningKey<C>,
        digest: &[u8],
        random: &mut R,
    ) -> Result<ECDSASignature<C>, CryptoError> {
        let mut additional = vec![0u8; <C::Scalar as PrimeField>::BYTES];
        random.fill(&mut additional).map_err(|_| CryptoError::RandomFailed)?;
        let result = ECDSA::<C, H>::sign_digest_with_additional(key, digest, &additional);
        additional.zeroize();
        result
    }

    /// The signature of SEC 1 section 4.1.3 with the nonce k of RFC 6979
    /// section 3.2, whose HMAC_DRBG is seeded with int2octets(d),
    /// bits2octets(digest) and `additional` (the k' of section 3.6).
    pub fn sign_digest_with_additional(
        key: &ECDSASigningKey<C>,
        digest: &[u8],
        additional: &[u8],
    ) -> Result<ECDSASignature<C>, CryptoError> {
        let bytes = <C::Scalar as PrimeField>::BYTES;
        let order = *<C::Scalar as PrimeField>::MODULUS.value();
        let excess = 8 * bytes as u32 - order.bit_length();
        let e = ECDSA::<C, H>::digest_scalar(digest);
        let failed = |_| CryptoError::InvalidKey;
        let mut seed = vec![0u8; 2 * bytes];
        key.scalar.write_be_bytes(&mut seed[..bytes]).map_err(failed)?;
        e.write_be_bytes(&mut seed[bytes..]).map_err(failed)?;
        let mut generator = HMACDRBG::<H>::with_seed(DRBGConfig::default(), &[&seed, additional]);
        seed.zeroize();
        let mut candidate = vec![0u8; bytes];
        let mut x = vec![0u8; <C::Field as PrimeField>::BYTES];
        let result = loop {
            // Section 3.2 step h: T of the bits of the order, then k = bits2int(T) in 1..n.
            if generator.fill(&mut candidate).is_err() {
                break Err(CryptoError::RandomFailed);
            }
            let mut value =
                FieldValue::<C::Scalar>::from_be_bytes(&candidate).unwrap_or(FieldValue::<C::Scalar>::ZERO).shr(excess);
            let valid = !value.is_zero() & value.ct_lt(&order);
            let mut k = FieldElement::<C::Scalar>::from_value_reduced(&value);
            value.zeroize();
            if !valid.into_bool() {
                continue;
            }
            let mut point = ProjectivePoint::<C>::generator().mul(&k).to_affine();
            let written = point.x().write_be_bytes(&mut x);
            point.zeroize();
            if written.is_err() {
                break Err(CryptoError::InvalidKey);
            }
            let r = FieldElement::<C::Scalar>::from_be_bytes_reduced(&x);
            // k is not zero, so it has an inverse.
            let mut inverse = k.invert().unwrap_or(FieldElement::zero());
            let s = inverse.mul(&e.add(&r.mul(&key.scalar)));
            k.zeroize();
            inverse.zeroize();
            if let Ok(signature) = ECDSASignature::new(r, s) {
                break Ok(signature);
            }
        };
        candidate.zeroize();
        x.zeroize();
        result
    }

    /// Succeeds if `signature` is a signature of the digest `digest` under
    /// `key` (SEC 1 section 4.1.4); fails with `InvalidSignature` otherwise.
    pub fn verify_digest(
        key: &ECDSAVerifyingKey<C>,
        digest: &[u8],
        signature: &ECDSASignature<C>,
    ) -> Result<(), CryptoError> {
        let e = ECDSA::<C, H>::digest_scalar(digest);
        // s is not zero, so it has an inverse.
        let w = signature.s().invert().map_err(|_| CryptoError::InvalidSignature)?;
        let (u1, u2) = (e.mul(&w), signature.r().mul(&w));
        let point = ProjectivePoint::<C>::generator().mul_add_vartime(&u1, &key.point.to_projective(), &u2);
        if point.is_identity().into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        let mut x = vec![0u8; <C::Field as PrimeField>::BYTES];
        point.to_affine().x().write_be_bytes(&mut x).map_err(|_| CryptoError::InvalidSignature)?;
        if FieldElement::<C::Scalar>::from_be_bytes_reduced(&x) != *signature.r() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> SignatureScheme for ECDSA<C, H> {
    type SigningKey = ECDSASigningKey<C>;
    type VerifyingKey = ECDSAVerifyingKey<C>;
    const SIGNING_KEY_SIZE: usize = <C::Scalar as PrimeField>::BYTES;
    /// The uncompressed SEC 1 encoding.
    const VERIFYING_KEY_SIZE: usize = AffinePoint::<C>::encoded_length(false);
    /// r then s.
    const SIGNATURE_SIZE: usize = ECDSASignature::<C>::BYTES;

    /// A scalar of FIPS 186-5 appendix A.2.2, by rejection sampling.
    fn generate<R: Random>(random: &mut R) -> Result<ECDSASigningKey<C>, CryptoError> {
        let scalar = FieldElement::random_nonzero(|bytes| random.fill(bytes)).map_err(|_| CryptoError::RandomFailed)?;
        Ok(ECDSASigningKey { scalar })
    }

    /// The scalar of [`ECDSA::SIGNING_KEY_SIZE`] big-endian bytes, in 1..n.
    fn signing_key_from_bytes(bytes: &[u8]) -> Result<ECDSASigningKey<C>, CryptoError> {
        ECDSASigningKey::new(FieldElement::from_be_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?)
    }

    fn write_signing_key(key: &ECDSASigningKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != <ECDSA<C, H> as SignatureScheme>::SIGNING_KEY_SIZE {
            return Err(CryptoError::InputLength { length });
        }
        key.scalar.write_be_bytes(out).map_err(|_| CryptoError::InputLength { length })
    }

    fn verifying_key(key: &ECDSASigningKey<C>) -> ECDSAVerifyingKey<C> {
        ECDSAVerifyingKey { point: ProjectivePoint::generator().mul(&key.scalar).to_affine() }
    }

    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<ECDSAVerifyingKey<C>, CryptoError> {
        ECDSAVerifyingKey::from_encoded(bytes)
    }

    fn write_verifying_key(key: &ECDSAVerifyingKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        key.write_encoded(out, false)
    }

    /// The deterministic signature of the digest of `message` under `H`.
    fn sign(key: &ECDSASigningKey<C>, message: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != <ECDSA<C, H> as SignatureScheme>::SIGNATURE_SIZE {
            return Err(CryptoError::InputLength { length });
        }
        let digest = H::digest(message);
        ECDSA::<C, H>::sign_digest(key, digest.as_ref())?.write_bytes(out)
    }

    fn verify(key: &ECDSAVerifyingKey<C>, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let signature = ECDSASignature::from_bytes(signature)?;
        let digest = H::digest(message);
        ECDSA::<C, H>::verify_digest(key, digest.as_ref(), &signature)
    }
}
