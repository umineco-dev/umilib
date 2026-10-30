//! The identity-based signature of F. Hess, "Efficient Identity Based
//! Signature Schemes Based on Pairings" (SAC 2002), scheme 1, in the
//! asymmetric setting: with P the generator of G_2 and P1 that of G_1,
//! r = e(P1, P)^k, v = H2(m, r), u = v S_ID + k P1, and the verifier
//! checks v = H2(m, e(u, P) e(Q_ID, -P_pub)^v).

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{IBSHash, IBSMasterKey, IBSSignature, IBSUserKey, IdentityBasedSignature};
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::math::ec::{AffinePoint, FieldElement, PrimeField, ProjectivePoint};
use crate::math::pairing::{G2Affine, GT, Pairing, PairingCurve};
use crate::secret::{ConstantTimeEq, Zeroize};

/// Hess's signature on the curve `C` with the hash function `H`.
pub struct Hess<C: PairingCurve, H: CryptographicDigest + Default> {
    types: PhantomData<(C, H)>,
}

/// A signature (u, v) of [`Hess`]: u in G_1 and v a scalar.
pub struct HessSignature<C: PairingCurve> {
    u: AffinePoint<C::G1>,
    v: FieldElement<C::Scalar>,
}

impl<C: PairingCurve> HessSignature<C> {
    pub fn u(&self) -> &AffinePoint<C::G1> {
        &self.u
    }

    pub fn v(&self) -> &FieldElement<C::Scalar> {
        &self.v
    }
}

impl<C: PairingCurve> IBSSignature for HessSignature<C> {
    /// The bytes of the encoding: u compressed (SEC 1), then v big-endian.
    fn encoded_length() -> usize {
        AffinePoint::<C::G1>::encoded_length(true) + <C::Scalar as PrimeField>::BYTES
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = alloc::vec![0u8; HessSignature::<C>::encoded_length()];
        let point = AffinePoint::<C::G1>::encoded_length(true);
        // u is never the identity in a signature that verifies; its buffer has the length of the encoding.
        let _ = self.u.write_encoded(&mut out[..point], true);
        let _ = self.v.write_be_bytes(&mut out[point..]);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<HessSignature<C>, CryptoError> {
        if bytes.len() != HessSignature::<C>::encoded_length() {
            return Err(CryptoError::InvalidSignature);
        }
        let point = AffinePoint::<C::G1>::encoded_length(true);
        let u = AffinePoint::from_encoded(&bytes[..point]).map_err(|_| CryptoError::InvalidSignature)?;
        let v = FieldElement::from_be_bytes(&bytes[point..]).map_err(|_| CryptoError::InvalidSignature)?;
        Ok(HessSignature { u, v })
    }
}

impl<C: PairingCurve, H: CryptographicDigest + Default> Hess<C, H> {
    /// The domain tag of H1.
    pub const IDENTITY_TAG: &'static [u8] = b"umilib Hess IBS H1";
    /// The domain tag of H2.
    pub const MESSAGE_TAG: &'static [u8] = b"umilib Hess IBS H2";

    /// v = H2(m, r), with r encoded as in [`GT::write_bytes`].
    pub fn challenge(message: &[u8], commitment: &GT<C>) -> Result<FieldElement<C::Scalar>, CryptoError> {
        let mut bytes = alloc::vec![0u8; GT::<C>::encoded_length()];
        commitment.write_bytes(&mut bytes).map_err(|_| CryptoError::InvalidParameter)?;
        Ok(IBSHash::<C, H>::hash_to_scalar(Hess::<C, H>::MESSAGE_TAG, &[message, &bytes]))
    }
}

impl<C: PairingCurve, H: CryptographicDigest + Default> IdentityBasedSignature for Hess<C, H> {
    type Curve = C;
    type Signature = HessSignature<C>;

    fn extract(master: &IBSMasterKey<C>, identity: &[u8]) -> Result<IBSUserKey<C>, CryptoError> {
        master.extract::<H>(Hess::<C, H>::IDENTITY_TAG, identity)
    }

    fn sign<R: Random>(key: &IBSUserKey<C>, message: &[u8], random: &mut R) -> Result<HessSignature<C>, CryptoError> {
        let generator = AffinePoint::<C::G1>::generator();
        let base =
            Pairing::<C>::pairing(&generator, &G2Affine::generator()).map_err(|_| CryptoError::InvalidParameter)?;
        let mut k = FieldElement::<C::Scalar>::random_nonzero(|bytes| random.fill(bytes))
            .map_err(|_| CryptoError::RandomFailed)?;
        let mut commitment = base.pow(&k);
        let v = Hess::<C, H>::challenge(message, &commitment)?;
        commitment.zeroize();
        let u = key.key().to_projective().mul(&v).add(&ProjectivePoint::generator().mul(&k)).to_affine();
        k.zeroize();
        Ok(HessSignature { u, v })
    }

    fn verify(
        master: &G2Affine<C>,
        identity: &[u8],
        message: &[u8],
        signature: &HessSignature<C>,
    ) -> Result<(), CryptoError> {
        let invalid = |_| CryptoError::InvalidSignature;
        if !master.is_in_subgroup().into_bool() || master.is_identity().into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        let point = IBSHash::<C, H>::hash_to_g1(Hess::<C, H>::IDENTITY_TAG, identity)
            .map_err(|_| CryptoError::InvalidSignature)?;
        let left = Pairing::<C>::pairing(&signature.u, &G2Affine::generator()).map_err(invalid)?;
        let right = Pairing::<C>::pairing(&point, &master.neg()).map_err(invalid)?;
        let commitment = left.mul(&right.pow(&signature.v));
        let expected = Hess::<C, H>::challenge(message, &commitment)?;
        if !expected.ct_eq(&signature.v).into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }
}
