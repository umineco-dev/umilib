use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::crypto::CryptoError;
use crate::math::ec::{AffinePoint, FieldElement, PrimeField};
use crate::math::pairing::{Fp2, G2Affine, GT, PairingCurve};

/// The conversions of GM/T 0044.1-2016 clause 7 that SM9 uses on the curve
/// `C`: elements of GF(p^2) and of G_T as byte strings (7.2.6, 7.2.7) in
/// the tower of GM/T 0044.5-2016 section 3.2, and points of G_1 and G_2 as
/// byte strings (7.2.8, 7.2.9): x || y directly (case 1, in the inputs of
/// the hash functions and in the ciphertexts of part 4) or with the byte
/// PC = 04 before them (case 2, uncompressed).
pub struct SM9Encoding<C: PairingCurve> {
    curve: PhantomData<C>,
}

impl<C: PairingCurve> SM9Encoding<C> {
    /// The bytes of a point of G_1 without PC: x || y.
    pub fn g1_length() -> usize {
        2 * <C::Field as PrimeField>::BYTES
    }

    /// The bytes of a point of G_2 with PC = 04: 04 || x || y.
    pub fn g2_length() -> usize {
        1 + 4 * <C::Field as PrimeField>::BYTES
    }

    /// The bytes of an element of G_T: twelve elements of GF(p).
    pub fn gt_length() -> usize {
        12 * <C::Field as PrimeField>::BYTES
    }

    /// x || y of a point of G_1 other than the identity (case 1).
    pub fn g1(point: &AffinePoint<C::G1>) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0u8; 1 + SM9Encoding::<C>::g1_length()];
        point.write_encoded(&mut out, false).map_err(|_| CryptoError::InvalidKey)?;
        out.remove(0);
        Ok(out)
    }

    /// The point of G_1 of x || y (case 1): on the curve, in G_1 and not the
    /// identity; fails with `InvalidKey` otherwise.
    pub fn g1_from_bytes(bytes: &[u8]) -> Result<AffinePoint<C::G1>, CryptoError> {
        if bytes.len() != SM9Encoding::<C>::g1_length() {
            return Err(CryptoError::InvalidKey);
        }
        let mut encoded = vec![0x04];
        encoded.extend_from_slice(bytes);
        let point = AffinePoint::<C::G1>::from_encoded(&encoded).map_err(|_| CryptoError::InvalidKey)?;
        if (point.is_identity() | !point.is_in_subgroup()).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(point)
    }

    /// The bytes of an element of GF(p^2) (7.2.6): its u-coefficient, then its constant.
    pub fn fp2(value: &Fp2<C::Field>, out: &mut [u8]) -> Result<(), CryptoError> {
        let size = <C::Field as PrimeField>::BYTES;
        if out.len() != 2 * size {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        let failed = |_| CryptoError::InvalidKey;
        value.c1().write_be_bytes(&mut out[..size]).map_err(failed)?;
        value.c0().write_be_bytes(&mut out[size..]).map_err(failed)
    }

    /// The element of GF(p^2) of the bytes of [`SM9Encoding::fp2`] (7.2.7);
    /// fails with `InvalidKey` for values not below p.
    pub fn fp2_from_bytes(bytes: &[u8]) -> Result<Fp2<C::Field>, CryptoError> {
        let size = <C::Field as PrimeField>::BYTES;
        if bytes.len() != 2 * size {
            return Err(CryptoError::InvalidKey);
        }
        let invalid = |_| CryptoError::InvalidKey;
        let c1 = FieldElement::from_be_bytes(&bytes[..size]).map_err(invalid)?;
        let c0 = FieldElement::from_be_bytes(&bytes[size..]).map_err(invalid)?;
        Ok(Fp2::new(c0, c1))
    }

    /// 04 || x || y of a point of G_2 other than the identity (case 2), each
    /// coordinate as [`SM9Encoding::fp2`] writes it.
    pub fn g2(point: &G2Affine<C>) -> Result<Vec<u8>, CryptoError> {
        if point.is_identity().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let size = 2 * <C::Field as PrimeField>::BYTES;
        let mut out = vec![0u8; SM9Encoding::<C>::g2_length()];
        out[0] = 0x04;
        SM9Encoding::<C>::fp2(point.x(), &mut out[1..1 + size])?;
        SM9Encoding::<C>::fp2(point.y(), &mut out[1 + size..])?;
        Ok(out)
    }

    /// The point of G_2 of the bytes of [`SM9Encoding::g2`]: on the curve, in
    /// G_2 and not the identity; fails with `InvalidKey` otherwise.
    pub fn g2_from_bytes(bytes: &[u8]) -> Result<G2Affine<C>, CryptoError> {
        let size = 2 * <C::Field as PrimeField>::BYTES;
        if bytes.len() != SM9Encoding::<C>::g2_length() || bytes[0] != 0x04 {
            return Err(CryptoError::InvalidKey);
        }
        let x = SM9Encoding::<C>::fp2_from_bytes(&bytes[1..1 + size])?;
        let y = SM9Encoding::<C>::fp2_from_bytes(&bytes[1 + size..])?;
        let point = G2Affine::new(x, y).map_err(|_| CryptoError::InvalidKey)?;
        if (point.is_identity() | !point.is_in_subgroup()).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(point)
    }

    /// The bytes of an element of G_T (7.2.6) in the tower of GM/T
    /// 0044.5-2016 section 3.2, f = a w^2 + b w + c over GF(p^4) =
    /// GF(p^2)\[v\]/(v^2 - ξ) with w^3 = v: the coefficients of w^5, w^2,
    /// w^4, w, w^3 and 1 over GF(p^2), each of its u-coefficient then its
    /// constant, big-endian of the bytes of p.
    pub fn gt(value: &GT<C>) -> Vec<u8> {
        let size = <C::Field as PrimeField>::BYTES;
        let coefficients = value.element().coefficients();
        let mut out = vec![0u8; SM9Encoding::<C>::gt_length()];
        // The pairs of [`Fp12::coefficients`](crate::math::pairing::Fp12::coefficients) of w^5, w^2, w^4, w, w^3, 1.
        for (position, index) in [10, 2, 4, 6, 8, 0].into_iter().enumerate() {
            let at = 2 * position * size;
            // The coefficients are below p: the buffers have their lengths.
            let _ = coefficients[index + 1].write_be_bytes(&mut out[at..at + size]);
            let _ = coefficients[index].write_be_bytes(&mut out[at + size..at + 2 * size]);
        }
        out
    }
}
