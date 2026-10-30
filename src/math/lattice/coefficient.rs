use core::fmt;

use crate::secret::{ConstantTimeEq, Zeroize};

/// The integer type that stores the coefficients of a [`Polynomial`](super::Polynomial):
/// `u16` for moduli below 2^16 (as ML-KEM's 3329), `u32` for the others.
pub trait LatticeCoefficient: Copy + Default + Eq + ConstantTimeEq + Zeroize + fmt::Debug + 'static {
    /// The value `value`, which must fit the type (it is below the modulus).
    fn from_u32(value: u32) -> Self;

    fn to_u32(self) -> u32;
}

impl LatticeCoefficient for u16 {
    fn from_u32(value: u32) -> u16 {
        value as u16
    }

    fn to_u32(self) -> u32 {
        self as u32
    }
}

impl LatticeCoefficient for u32 {
    fn from_u32(value: u32) -> u32 {
        value
    }

    fn to_u32(self) -> u32 {
        self
    }
}

/// The array of the coefficients of a polynomial: `[C; N]` for the degree N
/// of the ring.
pub trait CoefficientArray<C: LatticeCoefficient>: Copy + Eq + fmt::Debug + 'static {
    /// The array of zeros.
    fn zero() -> Self;

    fn as_slice(&self) -> &[C];

    fn as_mut_slice(&mut self) -> &mut [C];
}

impl<C: LatticeCoefficient, const N: usize> CoefficientArray<C> for [C; N] {
    fn zero() -> [C; N] {
        [C::default(); N]
    }

    fn as_slice(&self) -> &[C] {
        self
    }

    fn as_mut_slice(&mut self) -> &mut [C] {
        self
    }
}
