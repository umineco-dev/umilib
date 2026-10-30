use alloc::vec;
use core::marker::PhantomData;

use super::{SM2PrivateKey, SM2PublicKey, SM2Signature};
use crate::crypto::curve::sm2::SM2;
use crate::crypto::random::{DRBGConfig, HMACDRBG, Random};
use crate::crypto::{CryptoError, SignatureScheme};
use crate::hash::CryptographicDigest;
use crate::hash::sm3::SM3;
use crate::math::bigint::UnsignedInteger;
use crate::math::ec::{AffinePoint, FieldElement, FieldValue, PrimeField, ProjectivePoint, WeierstrassCurve};
use crate::math::modular::ModularArithmetic;
use crate::secret::{ConstantTimeEq, Zeroize};

/// The digital signature algorithm of GB/T 32918.2 on the curve `C` with
/// the hash function `H`.
///
/// The standard draws the nonce k at random; here it is derived as RFC 6979
/// section 3.2 derives it (HMAC_DRBG over `H` seeded with the key and the
/// digest), so that signatures are deterministic, and
/// [`SM2DSA::sign_hedged`] adds random bytes to the seed.
pub struct SM2DSA<C: WeierstrassCurve = SM2, H: CryptographicDigest + Default = SM3> {
    types: PhantomData<(C, H)>,
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> SM2DSA<C, H> {
    /// The identity of GM/T 0009-2012 section 10 used when none is agreed
    /// (as by RFC 8998).
    pub const DEFAULT_IDENTITY: &'static [u8] = b"1234567812345678";

    /// e = H(Z || M) as an integer modulo n (GB/T 32918.2 section 6.1 steps
    /// A1 and A2), with Z the identity hash of `key` and `identity`.
    pub fn digest_scalar(
        key: &SM2PublicKey<C>,
        identity: &[u8],
        message: &[u8],
    ) -> Result<FieldElement<C::Scalar>, CryptoError> {
        let z = key.identity_hash::<H>(identity)?;
        let mut hash = H::default();
        hash.update(z.as_ref());
        hash.update(message);
        Ok(FieldElement::from_be_bytes_reduced(hash.finalize().as_ref()))
    }

    /// The signature of `message` by the user of `key` with the identity `identity`.
    pub fn sign(key: &SM2PrivateKey<C>, identity: &[u8], message: &[u8]) -> Result<SM2Signature<C>, CryptoError> {
        let e = SM2DSA::<C, H>::digest_scalar(key.public_key(), identity, message)?;
        SM2DSA::<C, H>::sign_scalar(key, &e, &[])
    }

    /// [`SM2DSA::sign`] with random bytes of `random`, as many as the order
    /// has, added to the seed of the nonce.
    pub fn sign_hedged<R: Random>(
        key: &SM2PrivateKey<C>,
        identity: &[u8],
        message: &[u8],
        random: &mut R,
    ) -> Result<SM2Signature<C>, CryptoError> {
        let e = SM2DSA::<C, H>::digest_scalar(key.public_key(), identity, message)?;
        let mut additional = vec![0u8; <C::Scalar as PrimeField>::BYTES];
        random.fill(&mut additional).map_err(|_| CryptoError::RandomFailed)?;
        let result = SM2DSA::<C, H>::sign_scalar(key, &e, &additional);
        additional.zeroize();
        result
    }

    /// Steps A3 to A7 of GB/T 32918.2 section 6.1 for e: r = (e + x1) mod n
    /// with (x1, y1) = \[k\]G, s = (1 + d)^-1 (k - r d) mod n, repeated while
    /// r = 0, r + k = n or s = 0; k comes from HMAC_DRBG seeded with d, e
    /// and `additional`.
    pub fn sign_scalar(
        key: &SM2PrivateKey<C>,
        e: &FieldElement<C::Scalar>,
        additional: &[u8],
    ) -> Result<SM2Signature<C>, CryptoError> {
        let bytes = <C::Scalar as PrimeField>::BYTES;
        let order = *<C::Scalar as PrimeField>::MODULUS.value();
        let excess = 8 * bytes as u32 - order.bit_length();
        let failed = |_| CryptoError::InvalidKey;
        let mut seed = vec![0u8; 2 * bytes];
        key.scalar().write_be_bytes(&mut seed[..bytes]).map_err(failed)?;
        e.write_be_bytes(&mut seed[bytes..]).map_err(failed)?;
        let mut generator = HMACDRBG::<H>::with_seed(DRBGConfig::default(), &[&seed, additional]);
        seed.zeroize();
        let one = FieldElement::<C::Scalar>::one();
        // (1 + d) is invertible: d ≠ n - 1.
        let mut inverse = key.scalar().add(&one).invert().map_err(failed)?;
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
            let r = e.add(&FieldElement::from_be_bytes_reduced(&x));
            let degenerate = r.is_zero() | r.add(&k).is_zero();
            let s = inverse.mul(&k.sub(&r.mul(key.scalar())));
            k.zeroize();
            if degenerate.into_bool() {
                continue;
            }
            if let Ok(signature) = SM2Signature::new(r, s) {
                break Ok(signature);
            }
        };
        inverse.zeroize();
        candidate.zeroize();
        x.zeroize();
        result
    }

    /// Succeeds if `signature` is the signature of `message` by the user of
    /// `key` with the identity `identity` (GB/T 32918.2 section 7.1); fails
    /// with `InvalidSignature` otherwise.
    pub fn verify(
        key: &SM2PublicKey<C>,
        identity: &[u8],
        message: &[u8],
        signature: &SM2Signature<C>,
    ) -> Result<(), CryptoError> {
        let e = SM2DSA::<C, H>::digest_scalar(key, identity, message)?;
        SM2DSA::<C, H>::verify_scalar(key, &e, signature)
    }

    /// Steps B5 to B7 of GB/T 32918.2 section 7.1 for e: t = (r + s) mod n
    /// must not be 0, and R = (e + x1) mod n with (x1, y1) = \[s\]G + \[t\]P
    /// must equal r.
    pub fn verify_scalar(
        key: &SM2PublicKey<C>,
        e: &FieldElement<C::Scalar>,
        signature: &SM2Signature<C>,
    ) -> Result<(), CryptoError> {
        let t = signature.r().add(signature.s());
        if t.is_zero().into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        let point = ProjectivePoint::<C>::generator().mul_add_vartime(signature.s(), &key.point().to_projective(), &t);
        if point.is_identity().into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        let mut x = vec![0u8; <C::Field as PrimeField>::BYTES];
        point.to_affine().x().write_be_bytes(&mut x).map_err(|_| CryptoError::InvalidSignature)?;
        let expected = e.add(&FieldElement::from_be_bytes_reduced(&x));
        if !expected.ct_eq(signature.r()).into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }
}

/// The signatures of [`SM2DSA::DEFAULT_IDENTITY`].
impl<C: WeierstrassCurve, H: CryptographicDigest + Default> SignatureScheme for SM2DSA<C, H> {
    type SigningKey = SM2PrivateKey<C>;
    type VerifyingKey = SM2PublicKey<C>;
    const SIGNING_KEY_SIZE: usize = <C::Scalar as PrimeField>::BYTES;
    /// The uncompressed encoding.
    const VERIFYING_KEY_SIZE: usize = AffinePoint::<C>::encoded_length(false);
    /// r then s.
    const SIGNATURE_SIZE: usize = SM2Signature::<C>::BYTES;

    fn generate<R: Random>(random: &mut R) -> Result<SM2PrivateKey<C>, CryptoError> {
        SM2PrivateKey::generate(random)
    }

    fn signing_key_from_bytes(bytes: &[u8]) -> Result<SM2PrivateKey<C>, CryptoError> {
        SM2PrivateKey::from_bytes(bytes)
    }

    fn write_signing_key(key: &SM2PrivateKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        key.write_bytes(out)
    }

    fn verifying_key(key: &SM2PrivateKey<C>) -> SM2PublicKey<C> {
        *key.public_key()
    }

    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<SM2PublicKey<C>, CryptoError> {
        SM2PublicKey::from_encoded(bytes)
    }

    fn write_verifying_key(key: &SM2PublicKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        key.point().write_encoded(out, false).map_err(|_| CryptoError::InputLength { length })
    }

    fn sign(key: &SM2PrivateKey<C>, message: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != SM2Signature::<C>::BYTES {
            return Err(CryptoError::InputLength { length });
        }
        SM2DSA::<C, H>::sign(key, SM2DSA::<C, H>::DEFAULT_IDENTITY, message)?.write_bytes(out)
    }

    fn verify(key: &SM2PublicKey<C>, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let signature = SM2Signature::from_bytes(signature)?;
        SM2DSA::<C, H>::verify(key, SM2DSA::<C, H>::DEFAULT_IDENTITY, message, &signature)
    }
}
