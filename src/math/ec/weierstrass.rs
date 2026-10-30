use core::fmt;

use super::{ECError, FieldElement, FieldValue, PrimeField, Window};
use crate::math::bigint::UnsignedInteger;
use crate::math::modular::ModularArithmetic;
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// The coefficient a of a short Weierstrass curve, which chooses the
/// formulas of point addition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoefficientA {
    /// a = -3 (the NIST and SM2 curves).
    MinusThree,
    /// a = 0 (secp256k1, the curves of pairings).
    Zero,
    /// Any other a (the Brainpool curves).
    General,
}

/// A short Weierstrass curve y^2 = x^3 + ax + b over the prime field
/// `Field`, with a generator of prime order whose scalars are `Scalar`.
///
/// The addition formulas are complete for curves of odd order (Renes,
/// Costello and Batina, 2016): they give the right result for every pair of
/// points, the identity included, without branches. A curve with a cofactor
/// above 1 must keep its points in the subgroup of prime order, which
/// [`AffinePoint::is_in_subgroup`] checks.
pub trait WeierstrassCurve: Copy + fmt::Debug + 'static {
    type Field: PrimeField;
    type Scalar: PrimeField;
    const A: FieldElement<Self::Field>;
    const B: FieldElement<Self::Field>;
    /// Which formulas `A` allows; it must match `A`.
    const SHAPE: CoefficientA;
    const GENERATOR_X: FieldElement<Self::Field>;
    const GENERATOR_Y: FieldElement<Self::Field>;
    /// The number of points divided by the order of the generator.
    const COFACTOR: u128;
}

/// A point of the curve `C` in affine coordinates, or the identity.
pub struct AffinePoint<C: WeierstrassCurve> {
    x: FieldElement<C::Field>,
    y: FieldElement<C::Field>,
    identity: Choice,
}

impl<C: WeierstrassCurve> AffinePoint<C> {
    pub fn identity() -> AffinePoint<C> {
        AffinePoint { x: FieldElement::zero(), y: FieldElement::zero(), identity: Choice::TRUE }
    }

    pub fn generator() -> AffinePoint<C> {
        AffinePoint { x: C::GENERATOR_X, y: C::GENERATOR_Y, identity: Choice::FALSE }
    }

    /// The point (x, y); fails with `NotOnCurve` unless it satisfies the equation.
    pub fn new(x: FieldElement<C::Field>, y: FieldElement<C::Field>) -> Result<AffinePoint<C>, ECError> {
        let point = AffinePoint { x, y, identity: Choice::FALSE };
        if !point.is_on_curve().into_bool() {
            return Err(ECError::NotOnCurve);
        }
        Ok(point)
    }

    /// The coordinate x (zero for the identity).
    pub fn x(&self) -> &FieldElement<C::Field> {
        &self.x
    }

    /// The coordinate y (zero for the identity).
    pub fn y(&self) -> &FieldElement<C::Field> {
        &self.y
    }

    pub fn is_identity(&self) -> Choice {
        self.identity
    }

    /// Whether the point satisfies y^2 = x^3 + ax + b (the identity does).
    pub fn is_on_curve(&self) -> Choice {
        let right = self.x.square().add(&C::A).mul(&self.x).add(&C::B);
        self.y.square().ct_eq(&right) | self.identity
    }

    /// Whether `order × point` is the identity, where `order` is the order of
    /// the generator; always true on a curve of cofactor 1 for a point on it.
    /// The time depends only on the curve.
    pub fn is_in_subgroup(&self) -> Choice {
        if C::COFACTOR == 1 {
            return Choice::TRUE;
        }
        let order = *<C::Scalar as PrimeField>::MODULUS.value();
        ProjectivePoint::from_affine(self).mul_value_vartime(&order).is_identity()
    }

    pub fn neg(&self) -> AffinePoint<C> {
        AffinePoint { x: self.x, y: self.y.neg(), identity: self.identity }
    }

    pub fn to_projective(&self) -> ProjectivePoint<C> {
        ProjectivePoint::from_affine(self)
    }

    /// The length of the SEC1 encoding (SEC 1 section 2.3.3) of a point other
    /// than the identity, compressed or not.
    pub const fn encoded_length(compressed: bool) -> usize {
        if compressed { 1 + <C::Field as PrimeField>::BYTES } else { 1 + 2 * <C::Field as PrimeField>::BYTES }
    }

    /// Writes the SEC1 encoding into `out`, which must have its length: the
    /// byte 0 for the identity, 02 or 03 and x when compressed, 04, x and y
    /// otherwise. Fails with `InvalidEncoding` for another length.
    pub fn write_encoded(&self, out: &mut [u8], compressed: bool) -> Result<(), ECError> {
        let bytes = <C::Field as PrimeField>::BYTES;
        if self.identity.into_bool() {
            if out.len() != 1 {
                return Err(ECError::InvalidEncoding);
            }
            out[0] = 0;
            return Ok(());
        }
        if out.len() != AffinePoint::<C>::encoded_length(compressed) {
            return Err(ECError::InvalidEncoding);
        }
        let failed = |_| ECError::InvalidEncoding;
        self.x.write_be_bytes(&mut out[1..1 + bytes]).map_err(failed)?;
        if compressed {
            out[0] = 2 | self.y.is_odd().bit();
        } else {
            out[0] = 4;
            self.y.write_be_bytes(&mut out[1 + bytes..]).map_err(failed)?;
        }
        Ok(())
    }

    /// The point of the SEC1 encoding `bytes` (SEC 1 section 2.3.4): the
    /// identity, a compressed or an uncompressed point, whose coordinates must
    /// be below the prime and satisfy the equation. Fails with
    /// `InvalidEncoding` or `NotOnCurve`; the time reveals which, not the
    /// coordinates.
    pub fn from_encoded(bytes: &[u8]) -> Result<AffinePoint<C>, ECError> {
        let length = <C::Field as PrimeField>::BYTES;
        match (bytes.first(), bytes.len()) {
            (Some(0), 1) => Ok(AffinePoint::identity()),
            (Some(2 | 3), size) if size == 1 + length => {
                let x = FieldElement::from_be_bytes(&bytes[1..]).map_err(|_| ECError::InvalidEncoding)?;
                let (y, is_square) = x.square().add(&C::A).mul(&x).add(&C::B).sqrt();
                if !is_square.into_bool() {
                    return Err(ECError::NotOnCurve);
                }
                let odd = Choice::from_bit(bytes[0] & 1);
                let y = FieldElement::select(&y, &y.neg(), y.is_odd() ^ odd);
                AffinePoint::new(x, y)
            }
            (Some(4), size) if size == 1 + 2 * length => {
                let x = FieldElement::from_be_bytes(&bytes[1..1 + length]).map_err(|_| ECError::InvalidEncoding)?;
                let y = FieldElement::from_be_bytes(&bytes[1 + length..]).map_err(|_| ECError::InvalidEncoding)?;
                AffinePoint::new(x, y)
            }
            _ => Err(ECError::InvalidEncoding),
        }
    }
}

impl<C: WeierstrassCurve> Clone for AffinePoint<C> {
    fn clone(&self) -> AffinePoint<C> {
        *self
    }
}

impl<C: WeierstrassCurve> Copy for AffinePoint<C> {}

impl<C: WeierstrassCurve> ConstantTimeEq for AffinePoint<C> {
    fn ct_eq(&self, other: &AffinePoint<C>) -> Choice {
        let both = self.identity & other.identity;
        let neither = !self.identity & !other.identity;
        both | (neither & self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y))
    }
}

impl<C: WeierstrassCurve> PartialEq for AffinePoint<C> {
    fn eq(&self, other: &AffinePoint<C>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<C: WeierstrassCurve> Eq for AffinePoint<C> {}

impl<C: WeierstrassCurve> ConditionallySelectable for AffinePoint<C> {
    fn select(a: &AffinePoint<C>, b: &AffinePoint<C>, choice: Choice) -> AffinePoint<C> {
        AffinePoint {
            x: FieldElement::select(&a.x, &b.x, choice),
            y: FieldElement::select(&a.y, &b.y, choice),
            identity: Choice::select(&a.identity, &b.identity, choice),
        }
    }
}

impl<C: WeierstrassCurve> Zeroize for AffinePoint<C> {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.identity = Choice::FALSE;
    }
}

/// Prints the coordinates: keep secret points out of formatted output.
impl<C: WeierstrassCurve> fmt::Debug for AffinePoint<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = core::any::type_name::<C>();
        let name = name.rsplit("::").next().unwrap_or(name);
        if self.identity.into_bool() {
            return write!(formatter, "AffinePoint<{name}>(identity)");
        }
        write!(formatter, "AffinePoint<{name}>({:?}, {:?})", self.x, self.y)
    }
}

/// A point of the curve `C` in homogeneous projective coordinates (X : Y : Z),
/// the point (X/Z, Y/Z), or the identity (0 : 1 : 0).
pub struct ProjectivePoint<C: WeierstrassCurve> {
    x: FieldElement<C::Field>,
    y: FieldElement<C::Field>,
    z: FieldElement<C::Field>,
}

impl<C: WeierstrassCurve> ProjectivePoint<C> {
    pub fn identity() -> ProjectivePoint<C> {
        ProjectivePoint { x: FieldElement::zero(), y: FieldElement::one(), z: FieldElement::zero() }
    }

    pub fn generator() -> ProjectivePoint<C> {
        ProjectivePoint::from_affine(&AffinePoint::generator())
    }

    pub fn from_affine(point: &AffinePoint<C>) -> ProjectivePoint<C> {
        let affine = ProjectivePoint { x: point.x, y: point.y, z: FieldElement::one() };
        ProjectivePoint::select(&affine, &ProjectivePoint::identity(), point.identity)
    }

    /// The affine point, with one inversion in constant time.
    pub fn to_affine(&self) -> AffinePoint<C> {
        let identity = self.is_identity();
        // Z^-1 exists unless Z = 0, the identity; Z^(p-2) is zero for zero.
        let p = *<C::Field as PrimeField>::MODULUS.value();
        let inverse = self.z.pow(&p.wrapping_sub(&FieldValue::<C::Field>::ONE.shl(1)));
        AffinePoint { x: self.x.mul(&inverse), y: self.y.mul(&inverse), identity }
    }

    /// The coordinate X of (X : Y : Z), x = X / Z.
    pub fn x(&self) -> &FieldElement<C::Field> {
        &self.x
    }

    /// The coordinate Y of (X : Y : Z), y = Y / Z.
    pub fn y(&self) -> &FieldElement<C::Field> {
        &self.y
    }

    /// The coordinate Z of (X : Y : Z), zero for the identity alone.
    pub fn z(&self) -> &FieldElement<C::Field> {
        &self.z
    }

    pub fn is_identity(&self) -> Choice {
        self.z.is_zero()
    }

    pub fn neg(&self) -> ProjectivePoint<C> {
        ProjectivePoint { x: self.x, y: self.y.neg(), z: self.z }
    }

    /// `self + other` by the complete formulas of Renes, Costello and Batina
    /// (algorithms 1, 4 and 7 of their paper, by the shape of a).
    pub fn add(&self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        match C::SHAPE {
            CoefficientA::MinusThree => self.add_a_minus_three(other),
            CoefficientA::Zero => self.add_a_zero(other),
            CoefficientA::General => self.add_general(other),
        }
    }

    /// `2 × self`, by the complete addition.
    pub fn double(&self) -> ProjectivePoint<C> {
        self.add(self)
    }

    pub fn sub(&self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        self.add(&other.neg())
    }

    /// Algorithm 1: any a.
    pub fn add_general(&self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let (x2, y2, z2) = (&other.x, &other.y, &other.z);
        let (a, b3) = (&C::A, C::B.add(&C::B).add(&C::B));
        let mut t0 = x1.mul(x2);
        let mut t1 = y1.mul(y2);
        let mut t2 = z1.mul(z2);
        let mut t3 = x1.add(y1);
        let mut t4 = x2.add(y2);
        t3 = t3.mul(&t4);
        t4 = t0.add(&t1);
        t3 = t3.sub(&t4);
        t4 = x1.add(z1);
        let mut t5 = x2.add(z2);
        t4 = t4.mul(&t5);
        t5 = t0.add(&t2);
        t4 = t4.sub(&t5);
        t5 = y1.add(z1);
        let mut x3 = y2.add(z2);
        t5 = t5.mul(&x3);
        x3 = t1.add(&t2);
        t5 = t5.sub(&x3);
        let mut z3 = a.mul(&t4);
        x3 = b3.mul(&t2);
        z3 = x3.add(&z3);
        x3 = t1.sub(&z3);
        z3 = t1.add(&z3);
        let mut y3 = x3.mul(&z3);
        t1 = t0.add(&t0);
        t1 = t1.add(&t0);
        t2 = a.mul(&t2);
        t4 = b3.mul(&t4);
        t1 = t1.add(&t2);
        t2 = t0.sub(&t2);
        t2 = a.mul(&t2);
        t4 = t4.add(&t2);
        t0 = t1.mul(&t4);
        y3 = y3.add(&t0);
        t0 = t5.mul(&t4);
        x3 = t3.mul(&x3);
        x3 = x3.sub(&t0);
        t0 = t3.mul(&t1);
        z3 = t5.mul(&z3);
        z3 = z3.add(&t0);
        ProjectivePoint { x: x3, y: y3, z: z3 }
    }

    /// Algorithm 4: a = -3.
    pub fn add_a_minus_three(&self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let (x2, y2, z2) = (&other.x, &other.y, &other.z);
        let b = &C::B;
        let mut t0 = x1.mul(x2);
        let mut t1 = y1.mul(y2);
        let mut t2 = z1.mul(z2);
        let mut t3 = x1.add(y1);
        let mut t4 = x2.add(y2);
        t3 = t3.mul(&t4);
        t4 = t0.add(&t1);
        t3 = t3.sub(&t4);
        t4 = y1.add(z1);
        let mut x3 = y2.add(z2);
        t4 = t4.mul(&x3);
        x3 = t1.add(&t2);
        t4 = t4.sub(&x3);
        x3 = x1.add(z1);
        let mut y3 = x2.add(z2);
        x3 = x3.mul(&y3);
        y3 = t0.add(&t2);
        y3 = x3.sub(&y3);
        let mut z3 = b.mul(&t2);
        x3 = y3.sub(&z3);
        z3 = x3.add(&x3);
        x3 = x3.add(&z3);
        z3 = t1.sub(&x3);
        x3 = t1.add(&x3);
        y3 = b.mul(&y3);
        t1 = t2.add(&t2);
        t2 = t1.add(&t2);
        y3 = y3.sub(&t2);
        y3 = y3.sub(&t0);
        t1 = y3.add(&y3);
        y3 = t1.add(&y3);
        t1 = t0.add(&t0);
        t0 = t1.add(&t0);
        t0 = t0.sub(&t2);
        t1 = t4.mul(&y3);
        t2 = t0.mul(&y3);
        y3 = x3.mul(&z3);
        y3 = y3.add(&t2);
        x3 = t3.mul(&x3);
        x3 = x3.sub(&t1);
        z3 = t4.mul(&z3);
        t1 = t3.mul(&t0);
        z3 = z3.add(&t1);
        ProjectivePoint { x: x3, y: y3, z: z3 }
    }

    /// Algorithm 7: a = 0.
    pub fn add_a_zero(&self, other: &ProjectivePoint<C>) -> ProjectivePoint<C> {
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let (x2, y2, z2) = (&other.x, &other.y, &other.z);
        let b3 = C::B.add(&C::B).add(&C::B);
        let mut t0 = x1.mul(x2);
        let mut t1 = y1.mul(y2);
        let mut t2 = z1.mul(z2);
        let mut t3 = x1.add(y1);
        let mut t4 = x2.add(y2);
        t3 = t3.mul(&t4);
        t4 = t0.add(&t1);
        t3 = t3.sub(&t4);
        t4 = y1.add(z1);
        let mut x3 = y2.add(z2);
        t4 = t4.mul(&x3);
        x3 = t1.add(&t2);
        t4 = t4.sub(&x3);
        x3 = x1.add(z1);
        let mut y3 = x2.add(z2);
        x3 = x3.mul(&y3);
        y3 = t0.add(&t2);
        y3 = x3.sub(&y3);
        x3 = t0.add(&t0);
        t0 = x3.add(&t0);
        t2 = b3.mul(&t2);
        let mut z3 = t1.add(&t2);
        t1 = t1.sub(&t2);
        y3 = b3.mul(&y3);
        x3 = t4.mul(&y3);
        t2 = t3.mul(&t1);
        x3 = t2.sub(&x3);
        y3 = y3.mul(&t0);
        t1 = t1.mul(&z3);
        y3 = t1.add(&y3);
        t0 = t0.mul(&t3);
        z3 = z3.mul(&t4);
        z3 = z3.add(&t0);
        ProjectivePoint { x: x3, y: y3, z: z3 }
    }

    /// `scalar × self` in constant time: windows of [`Window::BITS`]
    /// bits over every bit of the precision of the scalars, each adding an
    /// entry of a table of the multiples read in full.
    pub fn mul(&self, scalar: &FieldElement<C::Scalar>) -> ProjectivePoint<C> {
        let mut value = scalar.value();
        let result = self.mul_value(&value);
        value.zeroize();
        result
    }

    /// `value × self` in constant time for any integer of the precision of
    /// the scalars, reduced or not.
    pub fn mul_value(&self, value: &FieldValue<C::Scalar>) -> ProjectivePoint<C> {
        let mut table = [ProjectivePoint::identity(); Window::ENTRIES];
        for index in 1..table.len() {
            table[index] = table[index - 1].add(self);
        }
        let mut result = ProjectivePoint::identity();
        for window in (0..Window::count::<FieldValue<C::Scalar>>()).rev() {
            for _ in 0..Window::BITS {
                result = result.double();
            }
            let mut digit = Window::digit(value, window);
            let mut entry = ProjectivePoint::identity();
            for (index, candidate) in table.iter().enumerate() {
                entry.conditional_assign(candidate, (index as u8).ct_eq(&digit));
            }
            result = result.add(&entry);
            Window::erase(&mut digit);
        }
        table.iter_mut().for_each(|entry| entry.zeroize());
        result
    }

    /// `value × self` in time that depends on the value, which must be public
    /// (as in the verification of a signature).
    pub fn mul_value_vartime(&self, value: &FieldValue<C::Scalar>) -> ProjectivePoint<C> {
        let mut result = ProjectivePoint::identity();
        for index in (0..value.bit_length()).rev() {
            result = result.double();
            if value.bit(index).into_bool() {
                result = result.add(self);
            }
        }
        result
    }

    /// `scalar × self` in time that depends on the public scalar.
    pub fn mul_vartime(&self, scalar: &FieldElement<C::Scalar>) -> ProjectivePoint<C> {
        self.mul_value_vartime(&scalar.value())
    }

    /// `a × self + b × other` with one sequence of doublings (Shamir's
    /// trick), in time that depends on the public scalars.
    pub fn mul_add_vartime(
        &self,
        a: &FieldElement<C::Scalar>,
        other: &ProjectivePoint<C>,
        b: &FieldElement<C::Scalar>,
    ) -> ProjectivePoint<C> {
        let (a, b) = (a.value(), b.value());
        let sum = self.add(other);
        let mut result = ProjectivePoint::identity();
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
}

impl<C: WeierstrassCurve> Clone for ProjectivePoint<C> {
    fn clone(&self) -> ProjectivePoint<C> {
        *self
    }
}

impl<C: WeierstrassCurve> Copy for ProjectivePoint<C> {}

/// Equality of the points, whatever their coordinates: X1 Z2 = X2 Z1 and Y1 Z2 = Y2 Z1.
impl<C: WeierstrassCurve> ConstantTimeEq for ProjectivePoint<C> {
    fn ct_eq(&self, other: &ProjectivePoint<C>) -> Choice {
        self.x.mul(&other.z).ct_eq(&other.x.mul(&self.z)) & self.y.mul(&other.z).ct_eq(&other.y.mul(&self.z))
    }
}

impl<C: WeierstrassCurve> PartialEq for ProjectivePoint<C> {
    fn eq(&self, other: &ProjectivePoint<C>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<C: WeierstrassCurve> Eq for ProjectivePoint<C> {}

impl<C: WeierstrassCurve> ConditionallySelectable for ProjectivePoint<C> {
    fn select(a: &ProjectivePoint<C>, b: &ProjectivePoint<C>, choice: Choice) -> ProjectivePoint<C> {
        ProjectivePoint {
            x: FieldElement::select(&a.x, &b.x, choice),
            y: FieldElement::select(&a.y, &b.y, choice),
            z: FieldElement::select(&a.z, &b.z, choice),
        }
    }
}

impl<C: WeierstrassCurve> Zeroize for ProjectivePoint<C> {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }
}

impl<C: WeierstrassCurve> fmt::Debug for ProjectivePoint<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.to_affine(), formatter)
    }
}
