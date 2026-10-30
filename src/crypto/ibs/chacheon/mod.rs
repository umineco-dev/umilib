//! The identity-based signature of J. C. Cha and J. H. Cheon, "An
//! Identity-Based Signature from Gap Diffie-Hellman Groups" (PKC 2003), in
//! the asymmetric setting: U = r Q_ID, h = H2(m, U), V = (r + h) D_ID, and
//! the verifier checks e(V, P) = e(U + h Q_ID, P_pub).

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{IBSHash, IBSMasterKey, IBSSignature, IBSUserKey, IdentityBasedSignature};
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::math::ec::{AffinePoint, FieldElement};
use crate::math::pairing::{G2Affine, Pairing, PairingCurve};
use crate::secret::Zeroize;

/// Cha and Cheon's signature on the curve `C` with the hash function `H`.
pub struct ChaCheon<C: PairingCurve, H: CryptographicDigest + Default> {
    types: PhantomData<(C, H)>,
}

/// A signature (U, V) of [`ChaCheon`], two points of G_1.
pub struct ChaCheonSignature<C: PairingCurve> {
    u: AffinePoint<C::G1>,
    v: AffinePoint<C::G1>,
}

impl<C: PairingCurve> ChaCheonSignature<C> {
    pub fn u(&self) -> &AffinePoint<C::G1> {
        &self.u
    }

    pub fn v(&self) -> &AffinePoint<C::G1> {
        &self.v
    }
}

impl<C: PairingCurve> IBSSignature for ChaCheonSignature<C> {
    /// The bytes of the encoding: U then V, compressed (SEC 1).
    fn encoded_length() -> usize {
        2 * AffinePoint::<C::G1>::encoded_length(true)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let point = AffinePoint::<C::G1>::encoded_length(true);
        let mut out = alloc::vec![0u8; 2 * point];
        // Neither point is the identity in a signature that verifies; the buffers have the length of the encoding.
        let _ = self.u.write_encoded(&mut out[..point], true);
        let _ = self.v.write_encoded(&mut out[point..], true);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<ChaCheonSignature<C>, CryptoError> {
        let point = AffinePoint::<C::G1>::encoded_length(true);
        if bytes.len() != 2 * point {
            return Err(CryptoError::InvalidSignature);
        }
        let read = |bytes: &[u8]| AffinePoint::<C::G1>::from_encoded(bytes).map_err(|_| CryptoError::InvalidSignature);
        Ok(ChaCheonSignature { u: read(&bytes[..point])?, v: read(&bytes[point..])? })
    }
}

impl<C: PairingCurve, H: CryptographicDigest + Default> ChaCheon<C, H> {
    /// The domain tag of H1.
    pub const IDENTITY_TAG: &'static [u8] = b"umilib Cha-Cheon IBS H1";
    /// The domain tag of H2.
    pub const MESSAGE_TAG: &'static [u8] = b"umilib Cha-Cheon IBS H2";

    /// h = H2(m, U).
    pub fn challenge(message: &[u8], u: &AffinePoint<C::G1>) -> FieldElement<C::Scalar> {
        IBSHash::<C, H>::hash_to_scalar(ChaCheon::<C, H>::MESSAGE_TAG, &[message, &IBSHash::<C, H>::encode_g1(u)])
    }
}

impl<C: PairingCurve, H: CryptographicDigest + Default> IdentityBasedSignature for ChaCheon<C, H> {
    type Curve = C;
    type Signature = ChaCheonSignature<C>;

    fn extract(master: &IBSMasterKey<C>, identity: &[u8]) -> Result<IBSUserKey<C>, CryptoError> {
        master.extract::<H>(ChaCheon::<C, H>::IDENTITY_TAG, identity)
    }

    fn sign<R: Random>(
        key: &IBSUserKey<C>,
        message: &[u8],
        random: &mut R,
    ) -> Result<ChaCheonSignature<C>, CryptoError> {
        // Q_ID = H1(ID), public and derived from the identity of the key.
        let point = IBSHash::<C, H>::hash_to_g1(ChaCheon::<C, H>::IDENTITY_TAG, key.identity())?;
        let mut r = FieldElement::<C::Scalar>::random_nonzero(|bytes| random.fill(bytes))
            .map_err(|_| CryptoError::RandomFailed)?;
        let u = point.to_projective().mul(&r).to_affine();
        let h = ChaCheon::<C, H>::challenge(message, &u);
        let mut sum = r.add(&h);
        let v = key.key().to_projective().mul(&sum).to_affine();
        r.zeroize();
        sum.zeroize();
        Ok(ChaCheonSignature { u, v })
    }

    fn verify(
        master: &G2Affine<C>,
        identity: &[u8],
        message: &[u8],
        signature: &ChaCheonSignature<C>,
    ) -> Result<(), CryptoError> {
        let invalid = |_| CryptoError::InvalidSignature;
        if !master.is_in_subgroup().into_bool() || master.is_identity().into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        for point in [&signature.u, &signature.v] {
            if (point.is_identity() | !point.is_in_subgroup()).into_bool() {
                return Err(CryptoError::InvalidSignature);
            }
        }
        let point = IBSHash::<C, H>::hash_to_g1(ChaCheon::<C, H>::IDENTITY_TAG, identity)
            .map_err(|_| CryptoError::InvalidSignature)?;
        let h = ChaCheon::<C, H>::challenge(message, &signature.u);
        let left = Pairing::<C>::pairing(&signature.v, &G2Affine::generator()).map_err(invalid)?;
        let combined = signature.u.to_projective().add(&point.to_projective().mul_vartime(&h)).to_affine();
        let right = Pairing::<C>::pairing(&combined, master).map_err(invalid)?;
        if left != right {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }
}
