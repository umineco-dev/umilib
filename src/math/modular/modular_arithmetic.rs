use core::fmt;

use super::{Modulus, Residue};
use crate::math::bigint::{MathError, Uint, UnsignedInteger};
use crate::secret::{ConditionallySelectable, ConstantTimeEq, Zeroize};

/// A modulus with its residues, for code generic over the precision (the
/// fields of elliptic curves): the operations of [`Modulus`], with the same
/// meaning and the same timing guarantees.
pub trait ModularArithmetic: Copy + fmt::Debug + 'static {
    /// The integers of the precision.
    type Value: UnsignedInteger;
    /// The residues, in the Montgomery form.
    type Residue: Copy + Default + Eq + ConstantTimeEq + ConditionallySelectable + Zeroize + fmt::Debug + 'static;

    fn value(&self) -> &Self::Value;
    fn zero(&self) -> Self::Residue;
    fn one(&self) -> Self::Residue;
    /// `x mod modulus`; `x` may be any value of the precision.
    fn residue(&self, x: &Self::Value) -> Self::Residue;
    /// The value of `residue`, below the modulus.
    fn retrieve(&self, residue: &Self::Residue) -> Self::Value;
    fn add(&self, a: &Self::Residue, b: &Self::Residue) -> Self::Residue;
    fn sub(&self, a: &Self::Residue, b: &Self::Residue) -> Self::Residue;
    fn neg(&self, a: &Self::Residue) -> Self::Residue;
    fn mul(&self, a: &Self::Residue, b: &Self::Residue) -> Self::Residue;
    fn square(&self, a: &Self::Residue) -> Self::Residue;
    /// `base^exponent` in constant time.
    fn pow(&self, base: &Self::Residue, exponent: &Self::Value) -> Self::Residue;
    /// `base^exponent` in time that depends on the public exponent.
    fn pow_vartime(&self, base: &Self::Residue, exponent: &Self::Value) -> Self::Residue;
    /// `a^-1`; fails with `NotInvertible`, which is the one fact the time reveals.
    fn invert(&self, a: &Self::Residue) -> Result<Self::Residue, MathError>;
}

impl<const N: usize> ModularArithmetic for Modulus<N> {
    type Value = Uint<N>;
    type Residue = Residue<N>;

    fn value(&self) -> &Uint<N> {
        Modulus::value(self)
    }

    fn zero(&self) -> Residue<N> {
        Modulus::zero(self)
    }

    fn one(&self) -> Residue<N> {
        Modulus::one(self)
    }

    fn residue(&self, x: &Uint<N>) -> Residue<N> {
        Modulus::residue(self, x)
    }

    fn retrieve(&self, residue: &Residue<N>) -> Uint<N> {
        Modulus::retrieve(self, residue)
    }

    fn add(&self, a: &Residue<N>, b: &Residue<N>) -> Residue<N> {
        Modulus::add(self, a, b)
    }

    fn sub(&self, a: &Residue<N>, b: &Residue<N>) -> Residue<N> {
        Modulus::sub(self, a, b)
    }

    fn neg(&self, a: &Residue<N>) -> Residue<N> {
        Modulus::neg(self, a)
    }

    fn mul(&self, a: &Residue<N>, b: &Residue<N>) -> Residue<N> {
        Modulus::mul(self, a, b)
    }

    fn square(&self, a: &Residue<N>) -> Residue<N> {
        Modulus::square(self, a)
    }

    fn pow(&self, base: &Residue<N>, exponent: &Uint<N>) -> Residue<N> {
        Modulus::pow(self, base, exponent)
    }

    fn pow_vartime(&self, base: &Residue<N>, exponent: &Uint<N>) -> Residue<N> {
        Modulus::pow_vartime(self, base, exponent)
    }

    fn invert(&self, a: &Residue<N>) -> Result<Residue<N>, MathError> {
        Modulus::invert(self, a)
    }
}
