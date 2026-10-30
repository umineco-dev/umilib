use alloc::vec;
use core::marker::PhantomData;

use super::{GOSTR3410Signature, GOSTR3410SigningKey, GOSTR3410VerifyingKey};
use crate::crypto::random::{DRBGConfig, HMACDRBG, Random};
use crate::crypto::{CryptoError, SignatureScheme};
use crate::hash::CryptographicDigest;
use crate::math::bigint::UnsignedInteger;
use crate::math::ec::{FieldElement, FieldValue, PrimeField, ProjectivePoint, WeierstrassCurve};
use crate::math::modular::ModularArithmetic;
use crate::secret::{ConditionallySelectable, ConstantTimeEq, Zeroize};

/// The signature of GOST R 34.10-2012 on the curve `C` with the hash
/// function `H`.
pub struct GOSTR3410<C: WeierstrassCurve, H: CryptographicDigest + Default> {
    types: PhantomData<(C, H)>,
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> GOSTR3410<C, H> {
    /// e = alpha mod q, or 1 if that is 0, with alpha the integer of the
    /// little-endian digest (steps 2 of algorithms I and II).
    pub fn digest_scalar(digest: &[u8]) -> FieldElement<C::Scalar> {
        let e = FieldElement::<C::Scalar>::from_le_bytes_reduced(digest);
        FieldElement::select(&e, &FieldElement::one(), e.is_zero())
    }

    /// The signature of `message` (algorithm I).
    pub fn sign(key: &GOSTR3410SigningKey<C>, message: &[u8]) -> Result<GOSTR3410Signature<C>, CryptoError> {
        GOSTR3410::<C, H>::sign_scalar(key, &GOSTR3410::<C, H>::digest_scalar(H::digest(message).as_ref()), &[])
    }

    /// [`GOSTR3410::sign`] with random bytes of `random`, as many as q has,
    /// added to the seed of the nonce.
    pub fn sign_hedged<R: Random>(
        key: &GOSTR3410SigningKey<C>,
        message: &[u8],
        random: &mut R,
    ) -> Result<GOSTR3410Signature<C>, CryptoError> {
        let e = GOSTR3410::<C, H>::digest_scalar(H::digest(message).as_ref());
        let mut additional = vec![0u8; <C::Scalar as PrimeField>::BYTES];
        random.fill(&mut additional).map_err(|_| CryptoError::RandomFailed)?;
        let result = GOSTR3410::<C, H>::sign_scalar(key, &e, &additional);
        additional.zeroize();
        result
    }

    /// Steps 3 to 5 of algorithm I for e: r = x_C mod q with C = k P and
    /// s = (r d + k e) mod q, repeated while r or s is 0; k comes from
    /// HMAC_DRBG seeded with d, e and `additional`.
    pub fn sign_scalar(
        key: &GOSTR3410SigningKey<C>,
        e: &FieldElement<C::Scalar>,
        additional: &[u8],
    ) -> Result<GOSTR3410Signature<C>, CryptoError> {
        let bytes = <C::Scalar as PrimeField>::BYTES;
        let order = *<C::Scalar as PrimeField>::MODULUS.value();
        let excess = 8 * bytes as u32 - order.bit_length();
        let failed = |_| CryptoError::InvalidKey;
        let mut seed = vec![0u8; 2 * bytes];
        key.scalar().write_be_bytes(&mut seed[..bytes]).map_err(failed)?;
        e.write_be_bytes(&mut seed[bytes..]).map_err(failed)?;
        let mut generator = HMACDRBG::<H>::with_seed(DRBGConfig::default(), &[&seed, additional]);
        seed.zeroize();
        let mut candidate = vec![0u8; bytes];
        let mut x = vec![0u8; <C::Field as PrimeField>::BYTES];
        let result = loop {
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
            let s = r.mul(key.scalar()).add(&k.mul(e));
            k.zeroize();
            if let Ok(signature) = GOSTR3410Signature::new(r, s) {
                break Ok(signature);
            }
        };
        candidate.zeroize();
        x.zeroize();
        result
    }

    /// Succeeds if `signature` is a signature of `message` under `key`
    /// (algorithm II); fails with `InvalidSignature` otherwise.
    pub fn verify(
        key: &GOSTR3410VerifyingKey<C>,
        message: &[u8],
        signature: &GOSTR3410Signature<C>,
    ) -> Result<(), CryptoError> {
        let e = GOSTR3410::<C, H>::digest_scalar(H::digest(message).as_ref());
        GOSTR3410::<C, H>::verify_scalar(key, &e, signature)
    }

    /// Steps 4 to 7 of algorithm II for e: v = e^-1, z1 = s v, z2 = -r v,
    /// C = z1 P + z2 Q, and x_C mod q must equal r.
    pub fn verify_scalar(
        key: &GOSTR3410VerifyingKey<C>,
        e: &FieldElement<C::Scalar>,
        signature: &GOSTR3410Signature<C>,
    ) -> Result<(), CryptoError> {
        let v = e.invert().map_err(|_| CryptoError::InvalidSignature)?;
        let (z1, z2) = (signature.s().mul(&v), signature.r().neg().mul(&v));
        let point = ProjectivePoint::<C>::generator().mul_add_vartime(&z1, &key.point().to_projective(), &z2);
        if point.is_identity().into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        let mut x = vec![0u8; <C::Field as PrimeField>::BYTES];
        point.to_affine().x().write_be_bytes(&mut x).map_err(|_| CryptoError::InvalidSignature)?;
        if !FieldElement::<C::Scalar>::from_be_bytes_reduced(&x).ct_eq(signature.r()).into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> SignatureScheme for GOSTR3410<C, H> {
    type SigningKey = GOSTR3410SigningKey<C>;
    type VerifyingKey = GOSTR3410VerifyingKey<C>;
    /// d little-endian.
    const SIGNING_KEY_SIZE: usize = <C::Scalar as PrimeField>::BYTES;
    /// x then y, each little-endian.
    const VERIFYING_KEY_SIZE: usize = 2 * <C::Field as PrimeField>::BYTES;
    /// s then r, each big-endian.
    const SIGNATURE_SIZE: usize = GOSTR3410Signature::<C>::BYTES;

    fn generate<R: Random>(random: &mut R) -> Result<GOSTR3410SigningKey<C>, CryptoError> {
        GOSTR3410SigningKey::generate(random)
    }

    fn signing_key_from_bytes(bytes: &[u8]) -> Result<GOSTR3410SigningKey<C>, CryptoError> {
        GOSTR3410SigningKey::from_bytes(bytes)
    }

    fn write_signing_key(key: &GOSTR3410SigningKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        key.write_bytes(out)
    }

    fn verifying_key(key: &GOSTR3410SigningKey<C>) -> GOSTR3410VerifyingKey<C> {
        *key.verifying_key()
    }

    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<GOSTR3410VerifyingKey<C>, CryptoError> {
        GOSTR3410VerifyingKey::from_bytes(bytes)
    }

    fn write_verifying_key(key: &GOSTR3410VerifyingKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        key.write_bytes(out)
    }

    fn sign(key: &GOSTR3410SigningKey<C>, message: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != GOSTR3410Signature::<C>::BYTES {
            return Err(CryptoError::InputLength { length });
        }
        GOSTR3410::<C, H>::sign(key, message)?.write_bytes(out)
    }

    fn verify(key: &GOSTR3410VerifyingKey<C>, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        GOSTR3410::<C, H>::verify(key, message, &GOSTR3410Signature::from_bytes(signature)?)
    }
}
