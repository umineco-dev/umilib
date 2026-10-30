use core::fmt;

use super::{Fp2, PairingCurve};
use crate::math::bigint::MathError;
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// An element c0 + c1 v + c2 v^2 of GF(p^6) = GF(p^2)\[v\] / (v^3 - ξ) of
/// the curve `C`, in constant time.
pub struct Fp6<C: PairingCurve> {
    c0: Fp2<C::Field>,
    c1: Fp2<C::Field>,
    c2: Fp2<C::Field>,
}

impl<C: PairingCurve> Fp6<C> {
    pub fn new(c0: Fp2<C::Field>, c1: Fp2<C::Field>, c2: Fp2<C::Field>) -> Fp6<C> {
        Fp6 { c0, c1, c2 }
    }

    pub fn zero() -> Fp6<C> {
        Fp6 { c0: Fp2::zero(), c1: Fp2::zero(), c2: Fp2::zero() }
    }

    pub fn one() -> Fp6<C> {
        Fp6 { c0: Fp2::one(), c1: Fp2::zero(), c2: Fp2::zero() }
    }

    pub fn coefficients(&self) -> [&Fp2<C::Field>; 3] {
        [&self.c0, &self.c1, &self.c2]
    }

    pub fn add(&self, other: &Fp6<C>) -> Fp6<C> {
        Fp6 { c0: self.c0.add(&other.c0), c1: self.c1.add(&other.c1), c2: self.c2.add(&other.c2) }
    }

    pub fn sub(&self, other: &Fp6<C>) -> Fp6<C> {
        Fp6 { c0: self.c0.sub(&other.c0), c1: self.c1.sub(&other.c1), c2: self.c2.sub(&other.c2) }
    }

    pub fn neg(&self) -> Fp6<C> {
        Fp6 { c0: self.c0.neg(), c1: self.c1.neg(), c2: self.c2.neg() }
    }

    /// The product, reduced by v^3 = ξ.
    pub fn mul(&self, other: &Fp6<C>) -> Fp6<C> {
        let (a, b) = (self.coefficients(), other.coefficients());
        let products = |i: usize, j: usize| a[i].mul(b[j]);
        // Coefficients of v^0 .. v^4 of the product, then v^3 = ξ and v^4 = ξ v.
        let d0 = products(0, 0);
        let d1 = products(0, 1).add(&products(1, 0));
        let d2 = products(0, 2).add(&products(1, 1)).add(&products(2, 0));
        let d3 = products(1, 2).add(&products(2, 1));
        let d4 = products(2, 2);
        Fp6 { c0: d0.add(&d3.mul(&C::XI)), c1: d1.add(&d4.mul(&C::XI)), c2: d2 }
    }

    pub fn square(&self) -> Fp6<C> {
        self.mul(self)
    }

    /// The product with an element of GF(p^2).
    pub fn mul_fp2(&self, other: &Fp2<C::Field>) -> Fp6<C> {
        Fp6 { c0: self.c0.mul(other), c1: self.c1.mul(other), c2: self.c2.mul(other) }
    }

    /// The product with v: (c0, c1, c2) v = (ξ c2, c0, c1).
    pub fn mul_by_v(&self) -> Fp6<C> {
        Fp6 { c0: self.c2.mul(&C::XI), c1: self.c0, c2: self.c1 }
    }

    /// The inverse by the norm to GF(p^2); fails with `NotInvertible` for zero.
    pub fn invert(&self) -> Result<Fp6<C>, MathError> {
        // t0 = c0^2 - ξ c1 c2, t1 = ξ c2^2 - c0 c1, t2 = c1^2 - c0 c2,
        // and the norm c0 t0 + ξ (c2 t1 + c1 t2).
        let t0 = self.c0.square().sub(&self.c1.mul(&self.c2).mul(&C::XI));
        let t1 = self.c2.square().mul(&C::XI).sub(&self.c0.mul(&self.c1));
        let t2 = self.c1.square().sub(&self.c0.mul(&self.c2));
        let norm = self.c0.mul(&t0).add(&self.c2.mul(&t1).add(&self.c1.mul(&t2)).mul(&C::XI));
        let inverse = norm.invert()?;
        Ok(Fp6 { c0: t0.mul(&inverse), c1: t1.mul(&inverse), c2: t2.mul(&inverse) })
    }

    pub fn is_zero(&self) -> Choice {
        self.c0.is_zero() & self.c1.is_zero() & self.c2.is_zero()
    }
}

impl<C: PairingCurve> Clone for Fp6<C> {
    fn clone(&self) -> Fp6<C> {
        *self
    }
}

impl<C: PairingCurve> Copy for Fp6<C> {}

impl<C: PairingCurve> ConstantTimeEq for Fp6<C> {
    fn ct_eq(&self, other: &Fp6<C>) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1) & self.c2.ct_eq(&other.c2)
    }
}

impl<C: PairingCurve> PartialEq for Fp6<C> {
    fn eq(&self, other: &Fp6<C>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<C: PairingCurve> Eq for Fp6<C> {}

impl<C: PairingCurve> ConditionallySelectable for Fp6<C> {
    fn select(a: &Fp6<C>, b: &Fp6<C>, choice: Choice) -> Fp6<C> {
        Fp6 {
            c0: Fp2::select(&a.c0, &b.c0, choice),
            c1: Fp2::select(&a.c1, &b.c1, choice),
            c2: Fp2::select(&a.c2, &b.c2, choice),
        }
    }
}

impl<C: PairingCurve> Zeroize for Fp6<C> {
    fn zeroize(&mut self) {
        self.c0.zeroize();
        self.c1.zeroize();
        self.c2.zeroize();
    }
}

impl<C: PairingCurve> fmt::Debug for Fp6<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Fp6({:?}, {:?}, {:?})", self.c0, self.c1, self.c2)
    }
}
