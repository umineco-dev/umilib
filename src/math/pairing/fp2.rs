use core::fmt;

use crate::math::bigint::{BoxedUint, MathError};
use crate::math::ec::{FieldElement, PrimeField};

use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// The base field GF(p) of a pairing-friendly curve, with the non-square β
/// of its quadratic extension GF(p^2) = GF(p)\[u\] / (u^2 - β).
pub trait PairingField: PrimeField {
    /// β, a non-square of GF(p): -1 when p ≡ 3 mod 4, -2 for SM9.
    const NON_RESIDUE: FieldElement<Self>;

    /// β `value`; fields whose β allows it multiply faster than by a multiplication (-1: a negation).
    fn mul_by_non_residue(value: &FieldElement<Self>) -> FieldElement<Self> {
        value.mul(&Self::NON_RESIDUE)
    }
}

/// An element c0 + c1 u of the quadratic extension GF(p^2) = GF(p)\[u\] /
/// (u^2 - β) of the prime field `F` with its non-square β
/// ([`PairingField::NON_RESIDUE`]), in constant time.
pub struct Fp2<F: PairingField> {
    c0: FieldElement<F>,
    c1: FieldElement<F>,
}

impl<F: PairingField> Fp2<F> {
    pub const fn new(c0: FieldElement<F>, c1: FieldElement<F>) -> Fp2<F> {
        Fp2 { c0, c1 }
    }

    pub fn zero() -> Fp2<F> {
        Fp2 { c0: FieldElement::zero(), c1: FieldElement::zero() }
    }

    pub fn one() -> Fp2<F> {
        Fp2 { c0: FieldElement::one(), c1: FieldElement::zero() }
    }

    /// The element of GF(p) `c0` in GF(p^2).
    pub fn from_base(c0: FieldElement<F>) -> Fp2<F> {
        Fp2 { c0, c1: FieldElement::zero() }
    }

    pub fn c0(&self) -> &FieldElement<F> {
        &self.c0
    }

    pub fn c1(&self) -> &FieldElement<F> {
        &self.c1
    }

    pub fn add(&self, other: &Fp2<F>) -> Fp2<F> {
        Fp2 { c0: self.c0.add(&other.c0), c1: self.c1.add(&other.c1) }
    }

    pub fn sub(&self, other: &Fp2<F>) -> Fp2<F> {
        Fp2 { c0: self.c0.sub(&other.c0), c1: self.c1.sub(&other.c1) }
    }

    pub fn neg(&self) -> Fp2<F> {
        Fp2 { c0: self.c0.neg(), c1: self.c1.neg() }
    }

    pub fn double(&self) -> Fp2<F> {
        self.add(self)
    }

    /// (a0 + a1 u)(b0 + b1 u) = (a0 b0 + β a1 b1) + ((a0 + a1)(b0 + b1) - a0 b0 - a1 b1) u.
    pub fn mul(&self, other: &Fp2<F>) -> Fp2<F> {
        let (a, b) = (self.c0.mul(&other.c0), self.c1.mul(&other.c1));
        let cross = self.c0.add(&self.c1).mul(&other.c0.add(&other.c1)).sub(&a).sub(&b);
        Fp2 { c0: a.add(&F::mul_by_non_residue(&b)), c1: cross }
    }

    /// (a0 + a1 u)^2 = ((a0 + a1)(a0 + β a1) - (1 + β) a0 a1) + 2 a0 a1 u.
    pub fn square(&self) -> Fp2<F> {
        let product = self.c0.mul(&self.c1);
        let mixed = self.c0.add(&self.c1).mul(&self.c0.add(&F::mul_by_non_residue(&self.c1)));
        Fp2 { c0: mixed.sub(&product).sub(&F::mul_by_non_residue(&product)), c1: product.double() }
    }

    /// The product with an element of GF(p).
    pub fn mul_base(&self, other: &FieldElement<F>) -> Fp2<F> {
        Fp2 { c0: self.c0.mul(other), c1: self.c1.mul(other) }
    }

    /// The conjugate c0 - c1 u, which is also the Frobenius map x^p: u^p = β^((p-1)/2) u = -u for the non-square β.
    pub fn conjugate(&self) -> Fp2<F> {
        Fp2 { c0: self.c0, c1: self.c1.neg() }
    }

    /// The inverse (c0 - c1 u) / (c0^2 - β c1^2); fails with `NotInvertible` for zero.
    pub fn invert(&self) -> Result<Fp2<F>, MathError> {
        let norm = self.c0.square().sub(&F::mul_by_non_residue(&self.c1.square())).invert()?;
        Ok(Fp2 { c0: self.c0.mul(&norm), c1: self.c1.neg().mul(&norm) })
    }

    /// `self^exponent`, in time that depends on the exponent, which must be public.
    pub fn pow_vartime(&self, exponent: &BoxedUint) -> Fp2<F> {
        let mut result = Fp2::one();
        for index in (0..exponent.bit_length()).rev() {
            result = result.square();
            if exponent.bit(index).into_bool() {
                result = result.mul(self);
            }
        }
        result
    }

    pub fn is_zero(&self) -> Choice {
        self.c0.is_zero() & self.c1.is_zero()
    }
}

impl<F: PairingField> Clone for Fp2<F> {
    fn clone(&self) -> Fp2<F> {
        *self
    }
}

impl<F: PairingField> Copy for Fp2<F> {}

impl<F: PairingField> Default for Fp2<F> {
    fn default() -> Fp2<F> {
        Fp2::zero()
    }
}

impl<F: PairingField> ConstantTimeEq for Fp2<F> {
    fn ct_eq(&self, other: &Fp2<F>) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1)
    }
}

impl<F: PairingField> PartialEq for Fp2<F> {
    fn eq(&self, other: &Fp2<F>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<F: PairingField> Eq for Fp2<F> {}

impl<F: PairingField> ConditionallySelectable for Fp2<F> {
    fn select(a: &Fp2<F>, b: &Fp2<F>, choice: Choice) -> Fp2<F> {
        Fp2 { c0: FieldElement::select(&a.c0, &b.c0, choice), c1: FieldElement::select(&a.c1, &b.c1, choice) }
    }
}

impl<F: PairingField> Zeroize for Fp2<F> {
    fn zeroize(&mut self) {
        self.c0.zeroize();
        self.c1.zeroize();
    }
}

impl<F: PairingField> fmt::Debug for Fp2<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Fp2({:?}, {:?})", self.c0, self.c1)
    }
}
