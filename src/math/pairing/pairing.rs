use alloc::vec;
use core::fmt;
use core::marker::PhantomData;

use super::{Fp2, Fp6, Fp12, G2Affine, PairingCurve, PairingFamily, TwistType};
use crate::math::bigint::{BoxedUint, MathError, UnsignedInteger};
use crate::math::ec::{AffinePoint, FieldElement, PrimeField};
use crate::math::modular::ModularArithmetic;
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// The optimal ate pairing e: G_1 × G_2 → G_T of the curve `C`
/// (draft-irtf-cfrg-pairing-friendly-curves appendix A): the Miller loop
/// with the lines of its points on the twist evaluated at the point of
/// G_1, then the final exponentiation by (p^12 - 1) / r.
///
/// The lines are computed in affine coordinates. The inversions are those
/// of the fields, constant time like the rest of their arithmetic, and the
/// branches depend only on the loop parameter and on cases that points of
/// the subgroups never reach (the identity, a vertical line): the time of a
/// pairing of points of G_1 and G_2 does not depend on them, so either may
/// be secret, as the encryption keys of SM9 are.
pub struct Pairing<C: PairingCurve> {
    curve: PhantomData<C>,
}

impl<C: PairingCurve> Pairing<C> {
    /// p as an integer of its precision.
    pub fn prime() -> BoxedUint {
        Pairing::<C>::integer(<C::Field as PrimeField>::MODULUS.value())
    }

    /// r as an integer of its precision.
    pub fn order() -> BoxedUint {
        Pairing::<C>::integer(<C::Scalar as PrimeField>::MODULUS.value())
    }

    /// An integer of a fixed precision as a [`BoxedUint`].
    pub fn integer<V: UnsignedInteger>(value: &V) -> BoxedUint {
        let mut bytes = vec![0u8; V::BYTES];
        // The buffer has the bytes of the precision.
        let _ = value.write_be_bytes(&mut bytes);
        BoxedUint::from_be_bytes(&bytes, V::BITS).unwrap_or_else(|_| BoxedUint::with_limbs(1))
    }

    /// The integer c of the Miller loop and its sign: 6t + 2 for BN curves, t for BLS12.
    pub fn loop_parameter() -> (u128, bool) {
        match C::FAMILY {
            PairingFamily::BN => {
                let six = 6 * C::PARAMETER;
                if C::PARAMETER_NEGATIVE { (six - 2, true) } else { (six + 2, false) }
            }
            PairingFamily::BLS12 => (C::PARAMETER, C::PARAMETER_NEGATIVE),
        }
    }

    /// The line through the points t and q of the twist (the tangent when
    /// they are equal) evaluated at p, untwisted into GF(p^12): the
    /// Line_function of appendix A, up to a factor of GF(p^2), which the
    /// final exponentiation removes.
    pub fn line(t: &G2Affine<C>, q: &G2Affine<C>, p: &AffinePoint<C::G1>) -> Result<Fp12<C>, MathError> {
        let (xp, yp) = (Fp2::from_base(*p.x()), Fp2::from_base(*p.y()));
        let (xt, yt) = (*t.x(), *t.y());
        let vertical = (t.x().ct_eq(q.x()) & !t.y().ct_eq(q.y())).into_bool();
        if vertical {
            // x - x_t: with x_t = x' w^2 = x' v (D) or x' w^-2 = x' v^2 / ξ (M, times ξ).
            let c0 = match C::TWIST {
                TwistType::D => Fp6::new(xp, xt.neg(), Fp2::zero()),
                TwistType::M => Fp6::new(xp.mul(&C::XI), Fp2::zero(), xt.neg()),
            };
            return Ok(Fp12::new(c0, Fp6::zero()));
        }
        let slope = Pairing::<C>::slope(t, q)?;
        let constant = yt.sub(&slope.mul(&xt));
        // λ (x - x_t) + y_t - y with λ = λ' w (D) or λ' w^-1 (M, times ξ).
        Ok(match C::TWIST {
            TwistType::D => {
                Fp12::new(Fp6::new(yp.neg(), Fp2::zero(), Fp2::zero()), Fp6::new(slope.mul(&xp), constant, Fp2::zero()))
            }
            TwistType::M => Fp12::new(
                Fp6::new(yp.neg().mul(&C::XI), Fp2::zero(), Fp2::zero()),
                Fp6::new(Fp2::zero(), constant, slope.mul(&xp)),
            ),
        })
    }

    /// The slope λ' on the twist of the line through t and q (the tangent
    /// when they are equal).
    pub fn slope(t: &G2Affine<C>, q: &G2Affine<C>) -> Result<Fp2<C::Field>, MathError> {
        if t.x().ct_eq(q.x()).into_bool() {
            let numerator = t.x().square().mul(&Fp2::from_base(FieldElement::one().double().add(&FieldElement::one())));
            Ok(numerator.mul(&t.y().double().invert()?))
        } else {
            Ok(q.y().sub(t.y()).mul(&q.x().sub(t.x()).invert()?))
        }
    }

    /// t + q on the twist in affine coordinates, for points that are not
    /// each other's negation.
    pub fn add(t: &G2Affine<C>, q: &G2Affine<C>) -> Result<G2Affine<C>, MathError> {
        let slope = Pairing::<C>::slope(t, q)?;
        let x = slope.square().sub(t.x()).sub(q.x());
        let y = slope.mul(&t.x().sub(&x)).sub(t.y());
        Ok(G2Affine::new(x, y).unwrap_or(G2Affine::identity()))
    }

    /// The p-power Frobenius map of the curve E carried to the twist:
    /// (conj(x) ξ^((p-1)/3), conj(y) ξ^((p-1)/2)) for a D-type twist, and
    /// the same with the inverses of these powers for an M-type twist.
    pub fn frobenius(q: &G2Affine<C>) -> Result<G2Affine<C>, MathError> {
        let p_minus_1 = Pairing::<C>::prime().wrapping_sub(&BoxedUint::one(64)?);
        let (third, _) = p_minus_1.div_rem(&BoxedUint::from_u64(3, 64)?)?;
        let half = p_minus_1.shr(1);
        let (mut gamma_x, mut gamma_y) = (C::XI.pow_vartime(&third), C::XI.pow_vartime(&half));
        if C::TWIST == TwistType::M {
            gamma_x = gamma_x.invert()?;
            gamma_y = gamma_y.invert()?;
        }
        Ok(G2Affine::new(q.x().conjugate().mul(&gamma_x), q.y().conjugate().mul(&gamma_y))
            .unwrap_or(G2Affine::identity()))
    }

    /// The Miller loop of appendix A.1 (BN) or A.2 (BLS12) for P and Q,
    /// before the final exponentiation; 1 if either is the identity.
    pub fn miller_loop(p: &AffinePoint<C::G1>, q: &G2Affine<C>) -> Result<Fp12<C>, MathError> {
        if (p.is_identity() | q.is_identity()).into_bool() {
            return Ok(Fp12::one());
        }
        let (parameter, negative) = Pairing::<C>::loop_parameter();
        let step = if negative { q.neg() } else { *q };
        let mut t = step;
        let mut f = Fp12::<C>::one();
        let top = 127 - parameter.leading_zeros();
        for index in (0..top).rev() {
            f = f.square().mul(&Pairing::<C>::line(&t, &t, p)?);
            t = Pairing::<C>::add(&t, &t)?;
            if (parameter >> index) & 1 == 1 {
                f = f.mul(&Pairing::<C>::line(&t, &step, p)?);
                t = Pairing::<C>::add(&t, &step)?;
            }
        }
        if C::FAMILY == PairingFamily::BN {
            let q1 = Pairing::<C>::frobenius(q)?;
            let q2 = Pairing::<C>::frobenius(&q1)?;
            f = f.mul(&Pairing::<C>::line(&t, &q1, p)?);
            t = Pairing::<C>::add(&t, &q1)?;
            f = f.mul(&Pairing::<C>::line(&t, &q2.neg(), p)?);
        }
        Ok(f)
    }

    /// f^((p^12 - 1) / r) = (f^(p^6 - 1))^(p^2 + 1) to the power (p^4 - p^2 + 1) / r.
    pub fn final_exponentiation(f: &Fp12<C>) -> Result<Fp12<C>, MathError> {
        let easy = f.conjugate().mul(&f.invert()?);
        let p = Pairing::<C>::prime();
        let p2 = p.mul_wide(&p);
        let easy = easy.pow_vartime(&p2).mul(&easy);
        let p4 = p2.mul_wide(&p2);
        let one = BoxedUint::one(64)?;
        let numerator = p4.wrapping_sub(&p2.resize(p4.precision())?).wrapping_add(&one.resize(p4.precision())?);
        let (hard, remainder) = numerator.div_rem(&Pairing::<C>::order())?;
        if !remainder.is_zero().into_bool() {
            return Err(MathError::InvalidModulus);
        }
        Ok(easy.pow_vartime(&hard))
    }

    /// e(P, Q); fails with `NotInvertible` only for points not of the
    /// groups (a line that is not defined).
    pub fn pairing(p: &AffinePoint<C::G1>, q: &G2Affine<C>) -> Result<GT<C>, MathError> {
        Ok(GT { element: Pairing::<C>::final_exponentiation(&Pairing::<C>::miller_loop(p, q)?)? })
    }
}

/// An element of G_T, the subgroup of order r of GF(p^12)* where the
/// pairing takes its values.
pub struct GT<C: PairingCurve> {
    element: Fp12<C>,
}

impl<C: PairingCurve> GT<C> {
    /// The identity 1.
    pub fn one() -> GT<C> {
        GT { element: Fp12::one() }
    }

    /// The element of G_T of `element`, which must be of order r.
    pub fn from_element(element: Fp12<C>) -> GT<C> {
        GT { element }
    }

    pub fn element(&self) -> &Fp12<C> {
        &self.element
    }

    pub fn mul(&self, other: &GT<C>) -> GT<C> {
        GT { element: self.element.mul(&other.element) }
    }

    /// The inverse: the conjugate, as G_T lies in the elements of norm 1.
    pub fn invert(&self) -> GT<C> {
        GT { element: self.element.conjugate() }
    }

    /// `self^scalar` in constant time over the bits of the precision of the scalars.
    pub fn pow(&self, scalar: &FieldElement<C::Scalar>) -> GT<C> {
        let mut value = scalar.value();
        let mut exponent = Pairing::<C>::integer(&value);
        value.zeroize();
        let result = GT { element: self.element.pow(&exponent) };
        exponent.zeroize();
        result
    }

    pub fn is_one(&self) -> Choice {
        self.element.is_one()
    }

    /// The bytes of the encoding: the twelve coefficients of
    /// [`Fp12::coefficients`], each big-endian of the bytes of p.
    pub fn encoded_length() -> usize {
        12 * <C::Field as PrimeField>::BYTES
    }

    /// Writes the encoding into `out` of [`GT::encoded_length`] bytes.
    pub fn write_bytes(&self, out: &mut [u8]) -> Result<(), MathError> {
        let size = <C::Field as PrimeField>::BYTES;
        if out.len() != 12 * size {
            return Err(MathError::SizeMismatch);
        }
        for (chunk, coefficient) in out.chunks_mut(size).zip(self.element.coefficients()) {
            coefficient.write_be_bytes(chunk)?;
        }
        Ok(())
    }
}

impl<C: PairingCurve> Clone for GT<C> {
    fn clone(&self) -> GT<C> {
        *self
    }
}

impl<C: PairingCurve> Copy for GT<C> {}

impl<C: PairingCurve> ConstantTimeEq for GT<C> {
    fn ct_eq(&self, other: &GT<C>) -> Choice {
        self.element.ct_eq(&other.element)
    }
}

impl<C: PairingCurve> PartialEq for GT<C> {
    fn eq(&self, other: &GT<C>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<C: PairingCurve> Eq for GT<C> {}

impl<C: PairingCurve> ConditionallySelectable for GT<C> {
    fn select(a: &GT<C>, b: &GT<C>, choice: Choice) -> GT<C> {
        GT { element: Fp12::select(&a.element, &b.element, choice) }
    }
}

impl<C: PairingCurve> Zeroize for GT<C> {
    fn zeroize(&mut self) {
        self.element.zeroize();
    }
}

impl<C: PairingCurve> fmt::Debug for GT<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GT({:?})", self.element)
    }
}
