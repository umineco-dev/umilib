//! The identity-based digital signature algorithm of SM9 (GM/T 0044.2-2016),
//! on the curve of GM/T 0044.5-2016 section 3.1 ([`SM9BN256`](crate::math::pairing::SM9BN256))
//! with SM3 as the standard specifies, or on another curve and hash function.
//!
//! The KGC's master key is ks with Ppub-s = \[ks\]P2 ([`IBSMasterKey`]); the
//! key of an identity is dsA = \[ks / (H1(IDA || hid, N) + ks)\]P1 (section
//! 5.3); a signature (h, S) of M is h = H2(M || g^r, N) with g = e(P1,
//! Ppub-s) and S = \[r - h\]dsA (section 6.1). The identifier hid of the key
//! generating function is 0x01 ([`SM9::SIGNATURE_IDENTIFIER`]), as in
//! GM/T 0044.5-2016 annex A, unless given (the `_with_identifier` functions).

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{IBSMasterKey, IBSSignature, IBSUserKey, IdentityBasedSignature};
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::crypto::sm9::{SM9Encoding, SM9Hash};
use crate::hash::CryptographicDigest;
use crate::math::ec::{AffinePoint, FieldElement, PrimeField, ProjectivePoint};
use crate::math::pairing::{G2Affine, G2Projective, Pairing, PairingCurve};
use crate::secret::{ConstantTimeEq, Zeroize};

/// The signatures of SM9 on the curve `C` with the hash function `H` (Hv).
pub struct SM9<C: PairingCurve, H: CryptographicDigest + Default> {
    types: PhantomData<(C, H)>,
}

/// A signature (h, S) of [`SM9`]: h in \[1, N - 1\] and S in G_1.
pub struct SM9Signature<C: PairingCurve> {
    h: FieldElement<C::Scalar>,
    s: AffinePoint<C::G1>,
}

impl<C: PairingCurve> SM9Signature<C> {
    pub fn h(&self) -> &FieldElement<C::Scalar> {
        &self.h
    }

    pub fn s(&self) -> &AffinePoint<C::G1> {
        &self.s
    }
}

impl<C: PairingCurve> IBSSignature for SM9Signature<C> {
    /// The bytes of the encoding of section 6.1 step A7: h of the bytes of
    /// N, then S uncompressed (04 || x || y, GM/T 0044.1-2016 section 7.2.8).
    fn encoded_length() -> usize {
        <C::Scalar as PrimeField>::BYTES + AffinePoint::<C::G1>::encoded_length(false)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let size = <C::Scalar as PrimeField>::BYTES;
        let mut out = vec![0u8; SM9Signature::<C>::encoded_length()];
        // h is below N and S is a point of G_1 other than the identity: the buffers have their lengths.
        let _ = self.h.write_be_bytes(&mut out[..size]);
        let _ = self.s.write_encoded(&mut out[size..], false);
        out
    }

    /// Steps B1 and B2 of section 7.1: h in \[1, N - 1\] and S a point of
    /// G_1 other than the identity, uncompressed.
    fn from_bytes(bytes: &[u8]) -> Result<SM9Signature<C>, CryptoError> {
        if bytes.len() != SM9Signature::<C>::encoded_length() {
            return Err(CryptoError::InvalidSignature);
        }
        let size = <C::Scalar as PrimeField>::BYTES;
        let h = FieldElement::from_be_bytes(&bytes[..size]).map_err(|_| CryptoError::InvalidSignature)?;
        let s = AffinePoint::<C::G1>::from_encoded(&bytes[size..]).map_err(|_| CryptoError::InvalidSignature)?;
        if (h.is_zero() | s.is_identity() | !s.is_in_subgroup()).into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(SM9Signature { h, s })
    }
}

impl<C: PairingCurve, H: CryptographicDigest + Default> SM9<C, H> {
    /// hid of the signature keys in GM/T 0044.5-2016 annex A.
    pub const SIGNATURE_IDENTIFIER: u8 = 0x01;

    /// The key of `identity` with the identifier `hid` (section 5.3): t1 =
    /// H1(ID || hid, N) + ks, t2 = ks t1^-1, dsA = \[t2\]P1. Fails with
    /// `InvalidParameter` if t1 = 0, when the master key must be
    /// generated again.
    pub fn extract_with_identifier(
        master: &IBSMasterKey<C>,
        identity: &[u8],
        hid: u8,
    ) -> Result<IBSUserKey<C>, CryptoError> {
        let h1 = SM9Hash::<C, H>::hash(SM9Hash::<C, H>::H1, &[identity, &[hid]])?;
        let mut t1 = h1.add(master.secret());
        let inverse = t1.invert();
        t1.zeroize();
        let mut inverse = inverse.map_err(|_| CryptoError::InvalidParameter)?;
        let mut t2 = master.secret().mul(&inverse);
        inverse.zeroize();
        let key = ProjectivePoint::<C::G1>::generator().mul(&t2).to_affine();
        t2.zeroize();
        Ok(IBSUserKey::new(identity, key, *master.public_key()))
    }

    /// Steps A1 to A7 of section 6.1 with the random r given: w = g^r, h =
    /// H2(M || w, N), l = (r - h) mod N, S = \[l\]dsA. r must be secret,
    /// random and used once; fails with `InvalidParameter` if l = 0, when
    /// another r is needed.
    pub fn sign_with_ephemeral(
        key: &IBSUserKey<C>,
        message: &[u8],
        ephemeral: &FieldElement<C::Scalar>,
    ) -> Result<SM9Signature<C>, CryptoError> {
        let g = Pairing::<C>::pairing(&AffinePoint::generator(), key.master()).map_err(|_| CryptoError::InvalidKey)?;
        let w = g.pow(ephemeral);
        let mut encoded = SM9Encoding::<C>::gt(&w);
        let h = SM9Hash::<C, H>::hash(SM9Hash::<C, H>::H2, &[message, &encoded]);
        encoded.zeroize();
        let h = h?;
        let mut l = ephemeral.sub(&h);
        if l.is_zero().into_bool() {
            return Err(CryptoError::InvalidParameter);
        }
        let s = key.key().to_projective().mul(&l).to_affine();
        l.zeroize();
        Ok(SM9Signature { h, s })
    }

    /// Steps B3 to B9 of section 7.1 for the identifier `hid` (B1 and B2 are
    /// those of [`SM9Signature`]'s decoding): g = e(P1, Ppub-s), t = g^h,
    /// h1 = H1(ID || hid, N), P = \[h1\]P2 + Ppub-s, u = e(S, P) and h2 =
    /// H2(M || u t, N) = h. Fails with `InvalidSignature` otherwise.
    pub fn verify_with_identifier(
        master: &G2Affine<C>,
        identity: &[u8],
        hid: u8,
        message: &[u8],
        signature: &SM9Signature<C>,
    ) -> Result<(), CryptoError> {
        let invalid = |_| CryptoError::InvalidSignature;
        if (master.is_identity() | !master.is_in_subgroup()).into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        let g = Pairing::<C>::pairing(&AffinePoint::generator(), master).map_err(invalid)?;
        let t = g.pow(&signature.h);
        let h1 = SM9Hash::<C, H>::hash(SM9Hash::<C, H>::H1, &[identity, &[hid]])
            .map_err(|_| CryptoError::InvalidSignature)?;
        let point =
            G2Projective::<C>::generator().mul_value_vartime(&h1.value()).add(&master.to_projective()).to_affine();
        let u = Pairing::<C>::pairing(&signature.s, &point).map_err(invalid)?;
        let encoded = SM9Encoding::<C>::gt(&u.mul(&t));
        let h2 = SM9Hash::<C, H>::hash(SM9Hash::<C, H>::H2, &[message, &encoded])
            .map_err(|_| CryptoError::InvalidSignature)?;
        if !h2.ct_eq(&signature.h).into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }
}

impl<C: PairingCurve, H: CryptographicDigest + Default> IdentityBasedSignature for SM9<C, H> {
    type Curve = C;
    type Signature = SM9Signature<C>;

    /// The key of `identity` with hid = [`SM9::SIGNATURE_IDENTIFIER`].
    fn extract(master: &IBSMasterKey<C>, identity: &[u8]) -> Result<IBSUserKey<C>, CryptoError> {
        SM9::<C, H>::extract_with_identifier(master, identity, SM9::<C, H>::SIGNATURE_IDENTIFIER)
    }

    /// Section 6.1 with r drawn from `random`, drawn again when l = 0.
    fn sign<R: Random>(key: &IBSUserKey<C>, message: &[u8], random: &mut R) -> Result<SM9Signature<C>, CryptoError> {
        loop {
            let mut r = FieldElement::<C::Scalar>::random_nonzero(|bytes| random.fill(bytes))
                .map_err(|_| CryptoError::RandomFailed)?;
            let signature = SM9::<C, H>::sign_with_ephemeral(key, message, &r);
            r.zeroize();
            match signature {
                Err(CryptoError::InvalidParameter) => continue,
                signature => return signature,
            }
        }
    }

    fn master_public_key_size() -> usize {
        SM9Encoding::<C>::g2_length()
    }

    /// Ppub-s uncompressed (GM/T 0044.1-2016 section 7.2.8), as
    /// [`SM9Encoding::g2`] writes it: 04 || x || y.
    fn master_public_key_to_bytes(key: &G2Affine<C>) -> Vec<u8> {
        // Ppub-s = [ks]P2 with ks in [1, N - 1] is never the identity, which
        // would be zeros of the same length, rejected by the decoding.
        SM9Encoding::<C>::g2(key).unwrap_or_else(|_| vec![0u8; SM9Encoding::<C>::g2_length()])
    }

    fn master_public_key_from_bytes(bytes: &[u8]) -> Result<G2Affine<C>, CryptoError> {
        SM9Encoding::<C>::g2_from_bytes(bytes)
    }

    /// The verification with hid = [`SM9::SIGNATURE_IDENTIFIER`].
    fn verify(
        master: &G2Affine<C>,
        identity: &[u8],
        message: &[u8],
        signature: &SM9Signature<C>,
    ) -> Result<(), CryptoError> {
        SM9::<C, H>::verify_with_identifier(master, identity, SM9::<C, H>::SIGNATURE_IDENTIFIER, message, signature)
    }
}
