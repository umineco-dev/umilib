use core::fmt;

use super::{Fp2, PairingCurve};
use crate::math::bigint::UnsignedInteger;
use crate::math::ec::{ECError, FieldElement, FieldValue, PrimeField, Window};
use crate::math::modular::ModularArithmetic;
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// A point of the twist E': y^2 = x^3 + b' over GF(p^2) of the curve `C` in
/// affine coordinates, or the identity: an element of G_2 once in the
/// subgroup of order r.
pub struct G2Affine<C: PairingCurve> {
    x: Fp2<C::Field>,
    y: Fp2<C::Field>,
    identity: Choice,
}

impl<C: PairingCurve> G2Affine<C> {
    pub fn identity() -> G2Affine<C> {
        G2Affine { x: Fp2::zero(), y: Fp2::zero(), identity: Choice::TRUE }
    }

    pub fn generator() -> G2Affine<C> {
        G2Affine { x: C::G2_GENERATOR_X, y: C::G2_GENERATOR_Y, identity: Choice::FALSE }
    }

    /// The point (x, y); fails with `NotOnCurve` unless it satisfies the equation.
    pub fn new(x: Fp2<C::Field>, y: Fp2<C::Field>) -> Result<G2Affine<C>, ECError> {
        let point = G2Affine { x, y, identity: Choice::FALSE };
        if !point.is_on_curve().into_bool() {
            return Err(ECError::NotOnCurve);
        }
        Ok(point)
    }

    pub fn x(&self) -> &Fp2<C::Field> {
        &self.x
    }

    pub fn y(&self) -> &Fp2<C::Field> {
        &self.y
    }

    pub fn is_identity(&self) -> Choice {
        self.identity
    }

    /// Whether y^2 = x^3 + b' (the identity is).
    pub fn is_on_curve(&self) -> Choice {
        self.y.square().ct_eq(&self.x.square().mul(&self.x).add(&C::TWIST_B)) | self.identity
    }

    /// Whether r × point is the identity. The time depends only on the curve.
    pub fn is_in_subgroup(&self) -> Choice {
        let order = *<C::Scalar as PrimeField>::MODULUS.value();
        G2Projective::from_affine(self).mul_value_vartime(&order).is_identity()
    }

    pub fn neg(&self) -> G2Affine<C> {
        G2Affine { x: self.x, y: self.y.neg(), identity: self.identity }
    }

    pub fn to_projective(&self) -> G2Projective<C> {
        G2Projective::from_affine(self)
    }

    /// The bytes of the encoding of a point other than the identity:
    /// x0, x1, y0 and y1, each big-endian of the bytes of p.
    pub const fn encoded_length() -> usize {
        4 * <C::Field as PrimeField>::BYTES
    }

    /// Writes x0 || x1 || y0 || y1 into `out` of [`G2Affine::encoded_length`]
    /// bytes; fails with `InvalidEncoding` for the identity or another length.
    pub fn write_encoded(&self, out: &mut [u8]) -> Result<(), ECError> {
        let size = <C::Field as PrimeField>::BYTES;
        if self.identity.into_bool() || out.len() != 4 * size {
            return Err(ECError::InvalidEncoding);
        }
        let parts = [self.x.c0(), self.x.c1(), self.y.c0(), self.y.c1()];
        for (chunk, part) in out.chunks_mut(size).zip(parts) {
            part.write_be_bytes(chunk).map_err(|_| ECError::InvalidEncoding)?;
        }
        Ok(())
    }

    /// The point of the encoding of [`G2Affine::write_encoded`]; fails with
    /// `InvalidEncoding` or `NotOnCurve`. The subgroup is not checked.
    pub fn from_encoded(bytes: &[u8]) -> Result<G2Affine<C>, ECError> {
        let size = <C::Field as PrimeField>::BYTES;
        if bytes.len() != 4 * size {
            return Err(ECError::InvalidEncoding);
        }
        let read = |index: usize| {
            FieldElement::<C::Field>::from_be_bytes(&bytes[index * size..(index + 1) * size])
                .map_err(|_| ECError::InvalidEncoding)
        };
        G2Affine::new(Fp2::new(read(0)?, read(1)?), Fp2::new(read(2)?, read(3)?))
    }
}

impl<C: PairingCurve> Clone for G2Affine<C> {
    fn clone(&self) -> G2Affine<C> {
        *self
    }
}

impl<C: PairingCurve> Copy for G2Affine<C> {}

impl<C: PairingCurve> ConstantTimeEq for G2Affine<C> {
    fn ct_eq(&self, other: &G2Affine<C>) -> Choice {
        let both = self.identity & other.identity;
        let neither = !self.identity & !other.identity;
        both | (neither & self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y))
    }
}

impl<C: PairingCurve> PartialEq for G2Affine<C> {
    fn eq(&self, other: &G2Affine<C>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<C: PairingCurve> Eq for G2Affine<C> {}

impl<C: PairingCurve> ConditionallySelectable for G2Affine<C> {
    fn select(a: &G2Affine<C>, b: &G2Affine<C>, choice: Choice) -> G2Affine<C> {
        G2Affine {
            x: Fp2::select(&a.x, &b.x, choice),
            y: Fp2::select(&a.y, &b.y, choice),
            identity: Choice::select(&a.identity, &b.identity, choice),
        }
    }
}

impl<C: PairingCurve> Zeroize for G2Affine<C> {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.identity = Choice::FALSE;
    }
}

impl<C: PairingCurve> fmt::Debug for G2Affine<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.identity.into_bool() {
            return formatter.write_str("G2Affine(identity)");
        }
        write!(formatter, "G2Affine({:?}, {:?})", self.x, self.y)
    }
}

/// A point of the twist E' in homogeneous projective coordinates
/// (X : Y : Z), with the complete formulas for a = 0 of Renes, Costello and
/// Batina (algorithm 7), exact for the points of the subgroup of order r.
pub struct G2Projective<C: PairingCurve> {
    x: Fp2<C::Field>,
    y: Fp2<C::Field>,
    z: Fp2<C::Field>,
}

impl<C: PairingCurve> G2Projective<C> {
    pub fn identity() -> G2Projective<C> {
        G2Projective { x: Fp2::zero(), y: Fp2::one(), z: Fp2::zero() }
    }

    pub fn generator() -> G2Projective<C> {
        G2Projective::from_affine(&G2Affine::generator())
    }

    pub fn from_affine(point: &G2Affine<C>) -> G2Projective<C> {
        let z = Fp2::select(&Fp2::one(), &Fp2::zero(), point.identity);
        let y = Fp2::select(&point.y, &Fp2::one(), point.identity);
        G2Projective { x: point.x, y, z }
    }

    /// The affine point, with one inversion in constant time.
    pub fn to_affine(&self) -> G2Affine<C> {
        let identity = self.is_identity();
        let inverse = self.z.invert().unwrap_or_default();
        G2Affine { x: self.x.mul(&inverse), y: self.y.mul(&inverse), identity }
    }

    pub fn is_identity(&self) -> Choice {
        self.z.is_zero()
    }

    pub fn neg(&self) -> G2Projective<C> {
        G2Projective { x: self.x, y: self.y.neg(), z: self.z }
    }

    pub fn add(&self, other: &G2Projective<C>) -> G2Projective<C> {
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let (x2, y2, z2) = (&other.x, &other.y, &other.z);
        let b3 = C::TWIST_B.add(&C::TWIST_B).add(&C::TWIST_B);
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
        G2Projective { x: x3, y: y3, z: z3 }
    }

    pub fn double(&self) -> G2Projective<C> {
        self.add(self)
    }

    pub fn sub(&self, other: &G2Projective<C>) -> G2Projective<C> {
        self.add(&other.neg())
    }

    /// `scalar × self` in constant time (see [`G2Projective::mul_value`]).
    pub fn mul(&self, scalar: &FieldElement<C::Scalar>) -> G2Projective<C> {
        let mut value = scalar.value();
        let result = self.mul_value(&value);
        value.zeroize();
        result
    }

    /// `value × self` in constant time for any integer of the precision of
    /// the scalars: windows of [`Window::BITS`] bits, each adding an entry
    /// of a table read in full.
    pub fn mul_value(&self, value: &FieldValue<C::Scalar>) -> G2Projective<C> {
        let mut table = [G2Projective::identity(); Window::ENTRIES];
        for index in 1..table.len() {
            table[index] = table[index - 1].add(self);
        }
        let mut result = G2Projective::identity();
        for window in (0..Window::count::<FieldValue<C::Scalar>>()).rev() {
            for _ in 0..Window::BITS {
                result = result.double();
            }
            let mut digit = Window::digit(value, window);
            let mut entry = G2Projective::identity();
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
    pub fn mul_value_vartime(&self, value: &FieldValue<C::Scalar>) -> G2Projective<C> {
        let mut result = G2Projective::identity();
        for index in (0..value.bit_length()).rev() {
            result = result.double();
            if value.bit(index).into_bool() {
                result = result.add(self);
            }
        }
        result
    }

    /// `value × self` for a public integer of any precision (a cofactor).
    pub fn mul_boxed_vartime(&self, value: &crate::math::bigint::BoxedUint) -> G2Projective<C> {
        let mut result = G2Projective::identity();
        for index in (0..value.bit_length()).rev() {
            result = result.double();
            if value.bit(index).into_bool() {
                result = result.add(self);
            }
        }
        result
    }
}

impl<C: PairingCurve> Clone for G2Projective<C> {
    fn clone(&self) -> G2Projective<C> {
        *self
    }
}

impl<C: PairingCurve> Copy for G2Projective<C> {}

/// Equality of the points: X1 Z2 = X2 Z1 and Y1 Z2 = Y2 Z1.
impl<C: PairingCurve> ConstantTimeEq for G2Projective<C> {
    fn ct_eq(&self, other: &G2Projective<C>) -> Choice {
        self.x.mul(&other.z).ct_eq(&other.x.mul(&self.z)) & self.y.mul(&other.z).ct_eq(&other.y.mul(&self.z))
    }
}

impl<C: PairingCurve> PartialEq for G2Projective<C> {
    fn eq(&self, other: &G2Projective<C>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<C: PairingCurve> Eq for G2Projective<C> {}

impl<C: PairingCurve> ConditionallySelectable for G2Projective<C> {
    fn select(a: &G2Projective<C>, b: &G2Projective<C>, choice: Choice) -> G2Projective<C> {
        G2Projective {
            x: Fp2::select(&a.x, &b.x, choice),
            y: Fp2::select(&a.y, &b.y, choice),
            z: Fp2::select(&a.z, &b.z, choice),
        }
    }
}

impl<C: PairingCurve> Zeroize for G2Projective<C> {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }
}

impl<C: PairingCurve> fmt::Debug for G2Projective<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "G2Projective({:?})", self.to_affine())
    }
}
