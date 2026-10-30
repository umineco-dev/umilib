use core::fmt;

use super::{ECError, FieldElement, FieldValue, PrimeField};
use crate::math::bigint::UnsignedInteger;
use crate::math::modular::ModularArithmetic;
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// A Montgomery curve By^2 = x^3 + Ax^2 + x over the prime field `Field`,
/// used through the coordinate u = x alone (RFC 7748).
pub trait MontgomeryCurve: Copy + fmt::Debug + 'static {
    type Field: PrimeField;
    /// a24 = (A - 2) / 4, the constant of the ladder of RFC 7748 section 5.
    const A24: FieldElement<Self::Field>;
    /// The coordinate u of the base point.
    const BASE_U: FieldElement<Self::Field>;
    /// The bits of the scalars the ladder processes (255 for X25519, 448 for X448).
    const SCALAR_BITS: u32;
    /// The number of points divided by the order of the base point (8 for
    /// curve25519, 4 for curve448).
    const COFACTOR: u32;
}

/// A point of the Montgomery curve `C`, as its coordinate u.
pub struct MontgomeryPoint<C: MontgomeryCurve> {
    u: FieldElement<C::Field>,
}

impl<C: MontgomeryCurve> MontgomeryPoint<C> {
    pub fn new(u: FieldElement<C::Field>) -> MontgomeryPoint<C> {
        MontgomeryPoint { u }
    }

    pub fn base() -> MontgomeryPoint<C> {
        MontgomeryPoint { u: C::BASE_U }
    }

    pub fn u(&self) -> &FieldElement<C::Field> {
        &self.u
    }

    /// The point of the little-endian coordinate `bytes` of
    /// [`PrimeField::BYTES`] bytes, as decodeUCoordinate of RFC 7748 section 5
    /// reads it: bits beyond the length of the prime are ignored and values
    /// not below it are reduced. Fails with `InvalidEncoding` for another length.
    pub fn from_bytes(bytes: &[u8]) -> Result<MontgomeryPoint<C>, ECError> {
        if bytes.len() != <C::Field as PrimeField>::BYTES {
            return Err(ECError::InvalidEncoding);
        }
        let value = FieldValue::<C::Field>::from_le_bytes(bytes).map_err(|_| ECError::InvalidEncoding)?;
        // Clear the bits above the length of the prime by shifting them out.
        let unused =
            <FieldValue<C::Field> as UnsignedInteger>::BITS - <C::Field as PrimeField>::MODULUS.value().bit_length();
        let value = value.shl(unused).shr(unused);
        Ok(MontgomeryPoint { u: FieldElement::from_value_reduced(&value) })
    }

    /// Writes the canonical coordinate into `out` little-endian (encodeUCoordinate).
    pub fn write_bytes(&self, out: &mut [u8]) -> Result<(), ECError> {
        if out.len() != <C::Field as PrimeField>::BYTES {
            return Err(ECError::InvalidEncoding);
        }
        self.u.write_le_bytes(out).map_err(|_| ECError::InvalidEncoding)
    }

    /// The ladder of RFC 7748 section 5: `value × self` over the bits
    /// [`MontgomeryCurve::SCALAR_BITS`] - 1 down to 0 of `value` (a scalar
    /// already decoded, as by decodeScalar25519), in constant time.
    pub fn mul_value(&self, value: &FieldValue<C::Field>) -> MontgomeryPoint<C> {
        let x1 = self.u;
        let (mut x2, mut z2) = (FieldElement::<C::Field>::one(), FieldElement::<C::Field>::zero());
        let (mut x3, mut z3) = (self.u, FieldElement::<C::Field>::one());
        let mut swap = Choice::FALSE;
        for index in (0..C::SCALAR_BITS).rev() {
            let bit = value.bit(index);
            swap ^= bit;
            FieldElement::conditional_swap(&mut x2, &mut x3, swap);
            FieldElement::conditional_swap(&mut z2, &mut z3, swap);
            swap = bit;
            let a = x2.add(&z2);
            let aa = a.square();
            let b = x2.sub(&z2);
            let bb = b.square();
            let e = aa.sub(&bb);
            let c = x3.add(&z3);
            let d = x3.sub(&z3);
            let da = d.mul(&a);
            let cb = c.mul(&b);
            x3 = da.add(&cb).square();
            z3 = x1.mul(&da.sub(&cb).square());
            x2 = aa.mul(&bb);
            z2 = e.mul(&aa.add(&C::A24.mul(&e)));
        }
        FieldElement::conditional_swap(&mut x2, &mut x3, swap);
        FieldElement::conditional_swap(&mut z2, &mut z3, swap);
        // x2 / z2 = x2 × z2^(p-2), which is zero for z2 = 0.
        let p = *<C::Field as PrimeField>::MODULUS.value();
        let u = x2.mul(&z2.pow(&p.wrapping_sub(&FieldValue::<C::Field>::ONE.shl(1))));
        for value in [&mut x2, &mut z2, &mut x3, &mut z3] {
            value.zeroize();
        }
        MontgomeryPoint { u }
    }
}

impl<C: MontgomeryCurve> Clone for MontgomeryPoint<C> {
    fn clone(&self) -> MontgomeryPoint<C> {
        *self
    }
}

impl<C: MontgomeryCurve> Copy for MontgomeryPoint<C> {}

impl<C: MontgomeryCurve> ConstantTimeEq for MontgomeryPoint<C> {
    fn ct_eq(&self, other: &MontgomeryPoint<C>) -> Choice {
        self.u.ct_eq(&other.u)
    }
}

impl<C: MontgomeryCurve> PartialEq for MontgomeryPoint<C> {
    fn eq(&self, other: &MontgomeryPoint<C>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<C: MontgomeryCurve> Eq for MontgomeryPoint<C> {}

impl<C: MontgomeryCurve> ConditionallySelectable for MontgomeryPoint<C> {
    fn select(a: &MontgomeryPoint<C>, b: &MontgomeryPoint<C>, choice: Choice) -> MontgomeryPoint<C> {
        MontgomeryPoint { u: FieldElement::select(&a.u, &b.u, choice) }
    }
}

impl<C: MontgomeryCurve> Zeroize for MontgomeryPoint<C> {
    fn zeroize(&mut self) {
        self.u.zeroize();
    }
}

/// Prints the coordinate: keep secret points out of formatted output.
impl<C: MontgomeryCurve> fmt::Debug for MontgomeryPoint<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = core::any::type_name::<C>();
        let name = name.rsplit("::").next().unwrap_or(name);
        write!(formatter, "MontgomeryPoint<{name}>({:?})", self.u)
    }
}
