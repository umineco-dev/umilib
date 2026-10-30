use core::fmt;

use super::{ECError, FieldElement, FieldValue, PrimeField, Window};
use crate::math::bigint::UnsignedInteger;
use crate::math::modular::ModularArithmetic;
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// A twisted Edwards curve ax^2 + y^2 = 1 + dx^2y^2 over the prime field
/// `Field`, with a generator of prime order whose scalars are `Scalar`.
///
/// The unified addition (Hisil, Wong, Carter and Dawson, 2008) is complete
/// when a is a square and d is not, as for edwards25519 and edwards448: it
/// gives the right result for every pair of points without branches.
pub trait EdwardsCurve: Copy + fmt::Debug + 'static {
    type Field: PrimeField;
    type Scalar: PrimeField;
    const A: FieldElement<Self::Field>;
    const D: FieldElement<Self::Field>;
    const GENERATOR_X: FieldElement<Self::Field>;
    const GENERATOR_Y: FieldElement<Self::Field>;
    /// The number of points divided by the order of the generator.
    const COFACTOR: u32;
    /// The bytes of the encoding of RFC 8032 section 5: 32 for edwards25519,
    /// 57 for edwards448.
    const ENCODED_BYTES: usize;
}

/// A point of the twisted Edwards curve `C` in extended coordinates
/// (X : Y : Z : T), the point (X/Z, Y/Z) with XY = ZT.
pub struct EdwardsPoint<C: EdwardsCurve> {
    x: FieldElement<C::Field>,
    y: FieldElement<C::Field>,
    z: FieldElement<C::Field>,
    t: FieldElement<C::Field>,
}

impl<C: EdwardsCurve> EdwardsPoint<C> {
    /// The identity (0, 1).
    pub fn identity() -> EdwardsPoint<C> {
        EdwardsPoint {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one(),
            t: FieldElement::zero(),
        }
    }

    pub fn generator() -> EdwardsPoint<C> {
        EdwardsPoint::from_affine_unchecked(&C::GENERATOR_X, &C::GENERATOR_Y)
    }

    /// The point (x, y); fails with `NotOnCurve` unless it satisfies the equation.
    pub fn from_affine(x: &FieldElement<C::Field>, y: &FieldElement<C::Field>) -> Result<EdwardsPoint<C>, ECError> {
        if !EdwardsPoint::<C>::is_on_curve(x, y).into_bool() {
            return Err(ECError::NotOnCurve);
        }
        Ok(EdwardsPoint::from_affine_unchecked(x, y))
    }

    /// The point (x, y), which must be on the curve.
    pub fn from_affine_unchecked(x: &FieldElement<C::Field>, y: &FieldElement<C::Field>) -> EdwardsPoint<C> {
        EdwardsPoint { x: *x, y: *y, z: FieldElement::one(), t: x.mul(y) }
    }

    /// Whether ax^2 + y^2 = 1 + dx^2y^2.
    pub fn is_on_curve(x: &FieldElement<C::Field>, y: &FieldElement<C::Field>) -> Choice {
        let (xx, yy) = (x.square(), y.square());
        C::A.mul(&xx).add(&yy).ct_eq(&FieldElement::one().add(&C::D.mul(&xx).mul(&yy)))
    }

    /// The affine coordinates (x, y), with one inversion in constant time.
    pub fn to_affine(&self) -> (FieldElement<C::Field>, FieldElement<C::Field>) {
        // Z is never zero on a complete curve.
        let p = *<C::Field as PrimeField>::MODULUS.value();
        let inverse = self.z.pow(&p.wrapping_sub(&FieldValue::<C::Field>::ONE.shl(1)));
        (self.x.mul(&inverse), self.y.mul(&inverse))
    }

    pub fn is_identity(&self) -> Choice {
        self.x.is_zero() & self.y.ct_eq(&self.z)
    }

    pub fn neg(&self) -> EdwardsPoint<C> {
        EdwardsPoint { x: self.x.neg(), y: self.y, z: self.z, t: self.t.neg() }
    }

    /// `self + other` by the unified formulas (add-2008-hwcd).
    pub fn add(&self, other: &EdwardsPoint<C>) -> EdwardsPoint<C> {
        let a = self.x.mul(&other.x);
        let b = self.y.mul(&other.y);
        let c = self.t.mul(&C::D).mul(&other.t);
        let d = self.z.mul(&other.z);
        let e = self.x.add(&self.y).mul(&other.x.add(&other.y)).sub(&a).sub(&b);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.sub(&C::A.mul(&a));
        EdwardsPoint { x: e.mul(&f), y: g.mul(&h), z: f.mul(&g), t: e.mul(&h) }
    }

    /// `2 × self`, by the unified addition.
    pub fn double(&self) -> EdwardsPoint<C> {
        self.add(self)
    }

    pub fn sub(&self, other: &EdwardsPoint<C>) -> EdwardsPoint<C> {
        self.add(&other.neg())
    }

    /// `COFACTOR × self`.
    pub fn mul_by_cofactor(&self) -> EdwardsPoint<C> {
        let mut result = EdwardsPoint::identity();
        for index in (0..u32::BITS - C::COFACTOR.leading_zeros()).rev() {
            result = result.double();
            if (C::COFACTOR >> index) & 1 == 1 {
                result = result.add(self);
            }
        }
        result
    }

    /// Whether `order × self` is the identity, where `order` is the order of
    /// the generator. The time depends only on the curve.
    pub fn is_in_subgroup(&self) -> Choice {
        let order = *<C::Scalar as PrimeField>::MODULUS.value();
        self.mul_value_vartime(&order).is_identity()
    }

    /// `scalar × self` in constant time (see [`EdwardsPoint::mul_value`]).
    pub fn mul(&self, scalar: &FieldElement<C::Scalar>) -> EdwardsPoint<C> {
        let mut value = scalar.value();
        let result = self.mul_value(&value);
        value.zeroize();
        result
    }

    /// `value × self` in constant time for any integer of the precision of
    /// the scalars: windows of [`Window::BITS`] bits over every bit of
    /// the precision, each adding an entry of a table read in full.
    pub fn mul_value(&self, value: &FieldValue<C::Scalar>) -> EdwardsPoint<C> {
        let mut table = [EdwardsPoint::identity(); Window::ENTRIES];
        for index in 1..table.len() {
            table[index] = table[index - 1].add(self);
        }
        let mut result = EdwardsPoint::identity();
        for window in (0..Window::count::<FieldValue<C::Scalar>>()).rev() {
            for _ in 0..Window::BITS {
                result = result.double();
            }
            let mut digit = Window::digit(value, window);
            let mut entry = EdwardsPoint::identity();
            for (index, candidate) in table.iter().enumerate() {
                entry.conditional_assign(candidate, (index as u8).ct_eq(&digit));
            }
            result = result.add(&entry);
            Window::erase(&mut digit);
        }
        table.iter_mut().for_each(|entry| entry.zeroize());
        result
    }

    /// `value × self` in time that depends on the public value.
    pub fn mul_value_vartime(&self, value: &FieldValue<C::Scalar>) -> EdwardsPoint<C> {
        let mut result = EdwardsPoint::identity();
        for index in (0..value.bit_length()).rev() {
            result = result.double();
            if value.bit(index).into_bool() {
                result = result.add(self);
            }
        }
        result
    }

    /// `scalar × self` in time that depends on the public scalar.
    pub fn mul_vartime(&self, scalar: &FieldElement<C::Scalar>) -> EdwardsPoint<C> {
        self.mul_value_vartime(&scalar.value())
    }

    /// `a × self + b × other` (Shamir's trick), in time that depends on the public scalars.
    pub fn mul_add_vartime(
        &self,
        a: &FieldElement<C::Scalar>,
        other: &EdwardsPoint<C>,
        b: &FieldElement<C::Scalar>,
    ) -> EdwardsPoint<C> {
        let (a, b) = (a.value(), b.value());
        let sum = self.add(other);
        let mut result = EdwardsPoint::identity();
        for index in (0..a.bit_length().max(b.bit_length())).rev() {
            result = result.double();
            match (a.bit(index).into_bool(), b.bit(index).into_bool()) {
                (true, true) => result = result.add(&sum),
                (true, false) => result = result.add(self),
                (false, true) => result = result.add(other),
                (false, false) => {}
            }
        }
        result
    }

    /// Writes the encoding of RFC 8032 section 5.1.2 or 5.2.2 into `out` of
    /// [`EdwardsCurve::ENCODED_BYTES`]: y little-endian, with the least
    /// significant bit of x in the most significant bit of the last byte.
    pub fn write_encoded(&self, out: &mut [u8]) -> Result<(), ECError> {
        if out.len() != C::ENCODED_BYTES {
            return Err(ECError::InvalidEncoding);
        }
        let (x, y) = self.to_affine();
        y.write_le_bytes(out).map_err(|_| ECError::InvalidEncoding)?;
        out[C::ENCODED_BYTES - 1] |= x.is_odd().bit() << 7;
        Ok(())
    }

    /// The point of the encoding `bytes` (RFC 8032 section 5.1.3 or 5.2.3):
    /// y must be below the prime and x is recovered from the equation, with
    /// the sign of the last bit. Fails with `InvalidEncoding` (another length,
    /// y not below the prime, x = 0 with the sign 1) or `NotOnCurve` (no x);
    /// the time reveals which, not the point.
    pub fn from_encoded(bytes: &[u8]) -> Result<EdwardsPoint<C>, ECError> {
        if bytes.len() != C::ENCODED_BYTES {
            return Err(ECError::InvalidEncoding);
        }
        let last = bytes[C::ENCODED_BYTES - 1];
        let sign = Choice::from_bit(last >> 7);
        // y is the encoding without its last bit: read it, then clear that bit by shifting.
        let value = if C::ENCODED_BYTES <= <FieldValue<C::Field> as UnsignedInteger>::BYTES {
            let unused = <FieldValue<C::Field> as UnsignedInteger>::BITS - (8 * C::ENCODED_BYTES as u32 - 1);
            FieldValue::<C::Field>::from_le_bytes(bytes).map_err(|_| ECError::InvalidEncoding)?.shl(unused).shr(unused)
        } else {
            // The encoding is longer than the precision (edwards448): its last byte holds the sign alone.
            if last & 0x7F != 0 {
                return Err(ECError::InvalidEncoding);
            }
            FieldValue::<C::Field>::from_le_bytes(&bytes[..C::ENCODED_BYTES - 1])
                .map_err(|_| ECError::InvalidEncoding)?
        };
        let y = FieldElement::from_value(&value).map_err(|_| ECError::InvalidEncoding)?;
        // x^2 = (y^2 - 1) / (dy^2 - a); dy^2 - a is not zero on a complete curve.
        let yy = y.square();
        let numerator = yy.sub(&FieldElement::one());
        let denominator = C::D.mul(&yy).sub(&C::A);
        let quotient = numerator.mul(&denominator.invert().map_err(|_| ECError::NotOnCurve)?);
        let (x, is_square) = quotient.sqrt();
        if !is_square.into_bool() {
            return Err(ECError::NotOnCurve);
        }
        if (x.is_zero() & sign).into_bool() {
            return Err(ECError::InvalidEncoding);
        }
        let x = FieldElement::select(&x, &x.neg(), x.is_odd() ^ sign);
        Ok(EdwardsPoint::from_affine_unchecked(&x, &y))
    }
}

impl<C: EdwardsCurve> Clone for EdwardsPoint<C> {
    fn clone(&self) -> EdwardsPoint<C> {
        *self
    }
}

impl<C: EdwardsCurve> Copy for EdwardsPoint<C> {}

/// Equality of the points, whatever their coordinates: X1 Z2 = X2 Z1 and Y1 Z2 = Y2 Z1.
impl<C: EdwardsCurve> ConstantTimeEq for EdwardsPoint<C> {
    fn ct_eq(&self, other: &EdwardsPoint<C>) -> Choice {
        self.x.mul(&other.z).ct_eq(&other.x.mul(&self.z)) & self.y.mul(&other.z).ct_eq(&other.y.mul(&self.z))
    }
}

impl<C: EdwardsCurve> PartialEq for EdwardsPoint<C> {
    fn eq(&self, other: &EdwardsPoint<C>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<C: EdwardsCurve> Eq for EdwardsPoint<C> {}

impl<C: EdwardsCurve> ConditionallySelectable for EdwardsPoint<C> {
    fn select(a: &EdwardsPoint<C>, b: &EdwardsPoint<C>, choice: Choice) -> EdwardsPoint<C> {
        EdwardsPoint {
            x: FieldElement::select(&a.x, &b.x, choice),
            y: FieldElement::select(&a.y, &b.y, choice),
            z: FieldElement::select(&a.z, &b.z, choice),
            t: FieldElement::select(&a.t, &b.t, choice),
        }
    }
}

impl<C: EdwardsCurve> Zeroize for EdwardsPoint<C> {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
        self.t.zeroize();
    }
}

/// Prints the affine coordinates: keep secret points out of formatted output.
impl<C: EdwardsCurve> fmt::Debug for EdwardsPoint<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = core::any::type_name::<C>();
        let name = name.rsplit("::").next().unwrap_or(name);
        let (x, y) = self.to_affine();
        write!(formatter, "EdwardsPoint<{name}>({x:?}, {y:?})")
    }
}
