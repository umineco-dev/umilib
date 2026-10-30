use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::ECCSIUserKey;
use crate::crypto::CryptoError;
use crate::crypto::random::{DRBGConfig, HMACDRBG, Random};
use crate::hash::CryptographicDigest;
use crate::math::bigint::UnsignedInteger;
use crate::math::ec::{AffinePoint, FieldElement, FieldValue, PrimeField, ProjectivePoint, WeierstrassCurve};
use crate::math::modular::ModularArithmetic;
use crate::secret::{ConstantTimeEq, Zeroize};

/// The signatures of ECCSI on the curve `C` with the hash function `H`.
pub struct ECCSI<C: WeierstrassCurve, H: CryptographicDigest + Default> {
    types: PhantomData<(C, H)>,
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> ECCSI<C, H> {
    /// The bytes of a signature: r and s of N bytes, then the canonical PVT.
    pub const SIGNATURE_SIZE: usize = 2 * <C::Field as PrimeField>::BYTES + AffinePoint::<C>::encoded_length(false);

    /// The signature of `message` (section 5.2.1), with j derived from the
    /// key, the message and random bytes of `random`.
    pub fn sign<R: Random>(key: &ECCSIUserKey<C, H>, message: &[u8], random: &mut R) -> Result<Vec<u8>, CryptoError> {
        let bytes = <C::Scalar as PrimeField>::BYTES;
        let mut seed = vec![0u8; 3 * bytes];
        let failed = |_| CryptoError::InvalidKey;
        key.secret().write_be_bytes(&mut seed[..bytes]).map_err(failed)?;
        key.hash().write_be_bytes(&mut seed[bytes..2 * bytes]).map_err(failed)?;
        random.fill(&mut seed[2 * bytes..]).map_err(|_| CryptoError::RandomFailed)?;
        let mut generator = HMACDRBG::<H>::with_seed(DRBGConfig::default(), &[&seed, message]);
        seed.zeroize();
        let order = *<C::Scalar as PrimeField>::MODULUS.value();
        let excess = 8 * bytes as u32 - order.bit_length();
        let mut candidate = vec![0u8; bytes];
        loop {
            generator.fill(&mut candidate).map_err(|_| CryptoError::RandomFailed)?;
            let mut value =
                FieldValue::<C::Scalar>::from_be_bytes(&candidate).unwrap_or(FieldValue::<C::Scalar>::ZERO).shr(excess);
            let valid = !value.is_zero() & value.ct_lt(&order);
            let mut ephemeral = FieldElement::<C::Scalar>::from_value_reduced(&value);
            value.zeroize();
            if !valid.into_bool() {
                continue;
            }
            let signature = ECCSI::<C, H>::sign_with_ephemeral(key, message, &ephemeral);
            ephemeral.zeroize();
            match signature {
                Err(CryptoError::InvalidParameter) => continue,
                signature => {
                    candidate.zeroize();
                    return signature;
                }
            }
        }
    }

    /// Steps 2 to 7 of section 5.2.1 with the ephemeral j given: J = \[j\]G,
    /// r = Jx, HE = hash(HS || r || M), s' = ((HE + r SSK)^-1 j) mod q, s = s'
    /// or q - s' if s' does not fit N bytes. j must be secret, random and
    /// used once; fails with `InvalidParameter` if HE + r SSK is zero, when
    /// another j is needed.
    pub fn sign_with_ephemeral(
        key: &ECCSIUserKey<C, H>,
        message: &[u8],
        ephemeral: &FieldElement<C::Scalar>,
    ) -> Result<Vec<u8>, CryptoError> {
        let size = <C::Field as PrimeField>::BYTES;
        let mut signature = vec![0u8; ECCSI::<C, H>::SIGNATURE_SIZE];
        let failed = |_| CryptoError::InvalidKey;
        let mut point = ProjectivePoint::<C>::generator().mul(ephemeral).to_affine();
        point.x().write_be_bytes(&mut signature[..size]).map_err(failed)?;
        point.zeroize();
        let r = FieldElement::<C::Scalar>::from_be_bytes_reduced(&signature[..size]);
        let he = ECCSI::<C, H>::message_hash(key.hash(), &signature[..size], message)?;
        let sum = he.add(&r.mul(key.secret()));
        let mut inverse = sum.invert().map_err(|_| CryptoError::InvalidParameter)?;
        let s = inverse.mul(ephemeral);
        inverse.zeroize();
        // s' fits N bytes unless q > 2^(8N); then q - s' does (step 6).
        let value = s.value();
        let fits = value.bit_length() <= 8 * size as u32;
        let s = if fits { s } else { s.neg() };
        // s fits N bytes; the scalars may have more, in which it is padded.
        let mut wide = vec![0u8; <C::Scalar as PrimeField>::BYTES.max(size)];
        s.write_be_bytes(&mut wide).map_err(failed)?;
        signature[size..2 * size].copy_from_slice(&wide[wide.len() - size..]);
        let token = ECCSIUserKey::<C, H>::canonical(key.token())?;
        signature[2 * size..].copy_from_slice(&token);
        Ok(signature)
    }

    /// HE = hash(HS || r || M) as an integer modulo q.
    pub fn message_hash(
        identity_hash: &FieldElement<C::Scalar>,
        r: &[u8],
        message: &[u8],
    ) -> Result<FieldElement<C::Scalar>, CryptoError> {
        let mut hs = vec![0u8; H::OUTPUT_SIZE];
        identity_hash.write_be_bytes(&mut hs).map_err(|_| CryptoError::InvalidParameter)?;
        let mut hash = H::default();
        hash.update(&hs);
        hash.update(r);
        hash.update(message);
        Ok(FieldElement::from_be_bytes_reduced(hash.finalize().as_ref()))
    }

    /// Succeeds if `signature` (r || s || PVT) is a signature of `message`
    /// by `identity` in the community of KPAK `authority` (section 5.2.2):
    /// PVT on the curve, HS, HE, Y = \[HS\]PVT + KPAK, J = \[s\](\[HE\]G + \[r\]Y),
    /// Jx = r mod p and Jx ≠ 0. Fails with `InvalidSignature` otherwise.
    pub fn verify(
        authority: &AffinePoint<C>,
        identity: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let size = <C::Field as PrimeField>::BYTES;
        if signature.len() != ECCSI::<C, H>::SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let invalid = |_| CryptoError::InvalidSignature;
        let (r, rest) = signature.split_at(size);
        let (s, token) = rest.split_at(size);
        let token = AffinePoint::<C>::from_encoded(token).map_err(invalid)?;
        if token.is_identity().into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        let hs = ECCSIUserKey::<C, H>::identity_hash(authority, identity, &token)
            .map_err(|_| CryptoError::InvalidSignature)?;
        let he = ECCSI::<C, H>::message_hash(&hs, r, message).map_err(|_| CryptoError::InvalidSignature)?;
        let y = token.to_projective().mul_vartime(&hs).add(&authority.to_projective());
        let r_scalar = FieldElement::<C::Scalar>::from_be_bytes_reduced(r);
        let s_scalar = FieldElement::<C::Scalar>::from_be_bytes_reduced(s);
        let j = ProjectivePoint::<C>::generator().mul_add_vartime(&he, &y, &r_scalar).mul_vartime(&s_scalar);
        let x = *j.to_affine().x();
        let r_field = FieldElement::<C::Field>::from_be_bytes_reduced(r);
        if j.is_identity().into_bool() || x.is_zero().into_bool() || !x.ct_eq(&r_field).into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }
}
