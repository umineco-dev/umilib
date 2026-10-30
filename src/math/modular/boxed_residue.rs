use core::fmt;

use crate::math::bigint::{BoxedUint, MathError};
use crate::secret::{Choice, ConstantTimeEq, Zeroize};

/// A value modulo a [`BoxedModulus`](super::BoxedModulus), in the Montgomery
/// form and the precision of the modulus. Its limbs are zeroed when dropped.
///
/// `==` compares in constant time and reveals only the result.
#[derive(Clone)]
pub struct BoxedResidue {
    montgomery: BoxedUint,
}

impl BoxedResidue {
    /// The residue whose Montgomery form is `montgomery`, which must be below
    /// the modulus and of its precision;
    /// [`BoxedModulus::from_montgomery`](super::BoxedModulus::from_montgomery) checks both.
    pub const fn from_montgomery_unchecked(montgomery: BoxedUint) -> BoxedResidue {
        BoxedResidue { montgomery }
    }

    /// The Montgomery form `x * R mod modulus` of the value `x`.
    pub const fn as_montgomery(&self) -> &BoxedUint {
        &self.montgomery
    }

    /// The precision in bits, that of the modulus.
    pub fn precision(&self) -> u32 {
        self.montgomery.precision()
    }

    /// `self = other` if `choice`; both must have the same precision.
    pub fn conditional_assign(&mut self, other: &BoxedResidue, choice: Choice) -> Result<(), MathError> {
        self.montgomery.conditional_assign(&other.montgomery, choice)
    }

    /// Swaps `a` and `b` if `choice`; both must have the same precision.
    pub fn conditional_swap(a: &mut BoxedResidue, b: &mut BoxedResidue, choice: Choice) -> Result<(), MathError> {
        BoxedUint::conditional_swap(&mut a.montgomery, &mut b.montgomery, choice)
    }
}

impl ConstantTimeEq for BoxedResidue {
    fn ct_eq(&self, other: &BoxedResidue) -> Choice {
        self.montgomery.ct_eq(&other.montgomery)
    }
}

impl PartialEq for BoxedResidue {
    fn eq(&self, other: &BoxedResidue) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl Eq for BoxedResidue {}

impl Zeroize for BoxedResidue {
    fn zeroize(&mut self) {
        self.montgomery.zeroize();
    }
}

impl fmt::Debug for BoxedResidue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BoxedResidue(montgomery: 0x{:x})", self.montgomery)
    }
}
