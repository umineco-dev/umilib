use core::fmt;

use crate::math::bigint::Uint;
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// A value modulo a [`Modulus`](super::Modulus), in the Montgomery form.
///
/// `==` compares in constant time and reveals only the result.
#[derive(Clone, Copy)]
pub struct Residue<const N: usize> {
    montgomery: Uint<N>,
}

impl<const N: usize> Residue<N> {
    /// The residue whose Montgomery form is `montgomery`, which must be below
    /// the modulus; [`Modulus::from_montgomery`](super::Modulus::from_montgomery) checks it.
    pub const fn from_montgomery_unchecked(montgomery: Uint<N>) -> Residue<N> {
        Residue { montgomery }
    }

    /// The Montgomery form `x * R mod modulus` of the value `x`.
    pub const fn as_montgomery(&self) -> &Uint<N> {
        &self.montgomery
    }
}

/// Zero, whose Montgomery form is zero for every modulus.
impl<const N: usize> Default for Residue<N> {
    fn default() -> Residue<N> {
        Residue::from_montgomery_unchecked(Uint::ZERO)
    }
}

impl<const N: usize> ConstantTimeEq for Residue<N> {
    fn ct_eq(&self, other: &Residue<N>) -> Choice {
        self.montgomery.ct_eq(&other.montgomery)
    }
}

impl<const N: usize> PartialEq for Residue<N> {
    fn eq(&self, other: &Residue<N>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<const N: usize> Eq for Residue<N> {}

impl<const N: usize> ConditionallySelectable for Residue<N> {
    fn select(a: &Residue<N>, b: &Residue<N>, choice: Choice) -> Residue<N> {
        Residue { montgomery: Uint::select(&a.montgomery, &b.montgomery, choice) }
    }
}

impl<const N: usize> Zeroize for Residue<N> {
    fn zeroize(&mut self) {
        self.montgomery.zeroize();
    }
}

impl<const N: usize> fmt::Debug for Residue<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Residue(montgomery: 0x{:x})", self.montgomery)
    }
}
