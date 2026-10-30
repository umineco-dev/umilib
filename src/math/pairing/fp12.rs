use core::fmt;

use super::{Fp2, Fp6, PairingCurve};
use crate::math::bigint::{BoxedUint, MathError};
use crate::math::ec::FieldElement;
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// An element c0 + c1 w of GF(p^12) = GF(p^6)\[w\] / (w^2 - v) of the curve
/// `C`, in constant time.
pub struct Fp12<C: PairingCurve> {
    c0: Fp6<C>,
    c1: Fp6<C>,
}

impl<C: PairingCurve> Fp12<C> {
    pub fn new(c0: Fp6<C>, c1: Fp6<C>) -> Fp12<C> {
        Fp12 { c0, c1 }
    }

    pub fn zero() -> Fp12<C> {
        Fp12 { c0: Fp6::zero(), c1: Fp6::zero() }
    }

    pub fn one() -> Fp12<C> {
        Fp12 { c0: Fp6::one(), c1: Fp6::zero() }
    }

    pub fn c0(&self) -> &Fp6<C> {
        &self.c0
    }

    pub fn c1(&self) -> &Fp6<C> {
        &self.c1
    }

    /// The twelve coefficients over GF(p) in the order of the basis 1, u,
    /// v, uv, v^2, uv^2, w, uw, vw, uvw, v^2w, uv^2w.
    pub fn coefficients(&self) -> [FieldElement<C::Field>; 12] {
        let mut out = [FieldElement::zero(); 12];
        for (half, part) in [&self.c0, &self.c1].iter().enumerate() {
            for (index, element) in part.coefficients().iter().enumerate() {
                out[6 * half + 2 * index] = *element.c0();
                out[6 * half + 2 * index + 1] = *element.c1();
            }
        }
        out
    }

    /// The element of twelve coefficients in the order of [`Fp12::coefficients`].
    pub fn from_coefficients(coefficients: &[FieldElement<C::Field>; 12]) -> Fp12<C> {
        let fp2 = |index: usize| Fp2::new(coefficients[index], coefficients[index + 1]);
        Fp12 { c0: Fp6::new(fp2(0), fp2(2), fp2(4)), c1: Fp6::new(fp2(6), fp2(8), fp2(10)) }
    }

    pub fn add(&self, other: &Fp12<C>) -> Fp12<C> {
        Fp12 { c0: self.c0.add(&other.c0), c1: self.c1.add(&other.c1) }
    }

    pub fn sub(&self, other: &Fp12<C>) -> Fp12<C> {
        Fp12 { c0: self.c0.sub(&other.c0), c1: self.c1.sub(&other.c1) }
    }

    /// (a0 + a1 w)(b0 + b1 w) = (a0 b0 + a1 b1 v) + (a0 b1 + a1 b0) w.
    pub fn mul(&self, other: &Fp12<C>) -> Fp12<C> {
        let (a, b) = (self.c0.mul(&other.c0), self.c1.mul(&other.c1));
        let cross = self.c0.add(&self.c1).mul(&other.c0.add(&other.c1)).sub(&a).sub(&b);
        Fp12 { c0: a.add(&b.mul_by_v()), c1: cross }
    }

    pub fn square(&self) -> Fp12<C> {
        self.mul(self)
    }

    /// The conjugate c0 - c1 w, the map x^(p^6).
    pub fn conjugate(&self) -> Fp12<C> {
        Fp12 { c0: self.c0, c1: self.c1.neg() }
    }

    /// The inverse (c0 - c1 w) / (c0^2 - c1^2 v); fails with `NotInvertible` for zero.
    pub fn invert(&self) -> Result<Fp12<C>, MathError> {
        let norm = self.c0.square().sub(&self.c1.square().mul_by_v()).invert()?;
        Ok(Fp12 { c0: self.c0.mul(&norm), c1: self.c1.neg().mul(&norm) })
    }

    /// `self^exponent` over every bit of the precision of the exponent, in
    /// time that depends on that precision alone.
    pub fn pow(&self, exponent: &BoxedUint) -> Fp12<C> {
        let mut result = Fp12::one();
        for index in (0..exponent.precision()).rev() {
            result = result.square();
            let product = result.mul(self);
            result = Fp12::select(&result, &product, exponent.bit(index));
        }
        result
    }

    /// `self^exponent`, in time that depends on the exponent, which must be public.
    pub fn pow_vartime(&self, exponent: &BoxedUint) -> Fp12<C> {
        let mut result = Fp12::one();
        for index in (0..exponent.bit_length()).rev() {
            result = result.square();
            if exponent.bit(index).into_bool() {
                result = result.mul(self);
            }
        }
        result
    }

    pub fn is_one(&self) -> Choice {
        self.ct_eq(&Fp12::one())
    }
}

impl<C: PairingCurve> Clone for Fp12<C> {
    fn clone(&self) -> Fp12<C> {
        *self
    }
}

impl<C: PairingCurve> Copy for Fp12<C> {}

impl<C: PairingCurve> ConstantTimeEq for Fp12<C> {
    fn ct_eq(&self, other: &Fp12<C>) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1)
    }
}

impl<C: PairingCurve> PartialEq for Fp12<C> {
    fn eq(&self, other: &Fp12<C>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<C: PairingCurve> Eq for Fp12<C> {}

impl<C: PairingCurve> ConditionallySelectable for Fp12<C> {
    fn select(a: &Fp12<C>, b: &Fp12<C>, choice: Choice) -> Fp12<C> {
        Fp12 { c0: Fp6::select(&a.c0, &b.c0, choice), c1: Fp6::select(&a.c1, &b.c1, choice) }
    }
}

impl<C: PairingCurve> Zeroize for Fp12<C> {
    fn zeroize(&mut self) {
        self.c0.zeroize();
        self.c1.zeroize();
    }
}

impl<C: PairingCurve> fmt::Debug for Fp12<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Fp12({:?}, {:?})", self.c0, self.c1)
    }
}
