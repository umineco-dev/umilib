use core::fmt;

use crate::math::bigint::{MathError, UnsignedInteger};
use crate::math::modular::ModularArithmetic;
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// The integers of the precision of the prime field `F`.
pub type FieldValue<F> = <<F as PrimeField>::Modulus as ModularArithmetic>::Value;
/// The residues of the prime field `F`.
pub type FieldResidue<F> = <<F as PrimeField>::Modulus as ModularArithmetic>::Residue;

/// A prime field: the integers modulo the prime [`PrimeField::MODULUS`],
/// such as the field of the coordinates of a curve or that of its scalars.
pub trait PrimeField: Copy + fmt::Debug + 'static {
    type Modulus: ModularArithmetic;
    /// The prime, with its Montgomery constants.
    const MODULUS: Self::Modulus;
    /// The bytes of an encoded element: the length of the prime in bytes.
    const BYTES: usize;
}

/// An element of the prime field `F`, in the Montgomery form, with
/// arithmetic in constant time.
pub struct FieldElement<F: PrimeField> {
    residue: FieldResidue<F>,
}

impl<F: PrimeField> FieldElement<F> {
    /// The element whose Montgomery form is the residue `residue`, which must
    /// come from `F::MODULUS`: for constants built with `residue_vartime`.
    pub const fn from_residue(residue: FieldResidue<F>) -> FieldElement<F> {
        FieldElement { residue }
    }

    pub const fn residue(&self) -> &FieldResidue<F> {
        &self.residue
    }

    pub fn zero() -> FieldElement<F> {
        FieldElement { residue: F::MODULUS.zero() }
    }

    pub fn one() -> FieldElement<F> {
        FieldElement { residue: F::MODULUS.one() }
    }

    /// `value mod p`; `value` may be any integer of the precision.
    pub fn from_value_reduced(value: &FieldValue<F>) -> FieldElement<F> {
        FieldElement { residue: F::MODULUS.residue(value) }
    }

    /// The element `value`; fails with `Overflow` unless it is below the
    /// prime, the one fact the time reveals.
    pub fn from_value(value: &FieldValue<F>) -> Result<FieldElement<F>, MathError> {
        if !value.ct_lt(F::MODULUS.value()).into_bool() {
            return Err(MathError::Overflow);
        }
        Ok(FieldElement::from_value_reduced(value))
    }

    /// A uniformly random nonzero element by rejection sampling (FIPS 186-5
    /// appendix A.2.2): candidates of the bit length of the prime, from the
    /// bytes `fill` writes (see [`UnsignedInteger::from_byte_source`]), until
    /// one is nonzero and below the prime. The time reveals the number of
    /// candidates rejected, nothing of the one kept.
    pub fn random_nonzero<E>(mut fill: impl FnMut(&mut [u8]) -> Result<(), E>) -> Result<FieldElement<F>, E> {
        let prime = *F::MODULUS.value();
        let unused = <FieldValue<F> as UnsignedInteger>::BITS - prime.bit_length();
        loop {
            let mut value = FieldValue::<F>::from_byte_source(&mut fill)?.shl(unused).shr(unused);
            let accepted = !value.is_zero() & value.ct_lt(&prime);
            if accepted.into_bool() {
                let element = FieldElement::from_value_reduced(&value);
                value.zeroize();
                return Ok(element);
            }
            value.zeroize();
        }
    }

    /// The canonical value, below the prime.
    pub fn value(&self) -> FieldValue<F> {
        F::MODULUS.retrieve(&self.residue)
    }

    /// The element of exactly [`PrimeField::BYTES`] big-endian bytes; fails
    /// with `Overflow` for another length or a value not below the prime.
    pub fn from_be_bytes(bytes: &[u8]) -> Result<FieldElement<F>, MathError> {
        if bytes.len() != F::BYTES {
            return Err(MathError::Overflow);
        }
        FieldElement::from_value(&FieldValue::<F>::from_be_bytes(bytes)?)
    }

    /// The element of exactly [`PrimeField::BYTES`] little-endian bytes; fails
    /// with `Overflow` for another length or a value not below the prime.
    pub fn from_le_bytes(bytes: &[u8]) -> Result<FieldElement<F>, MathError> {
        if bytes.len() != F::BYTES {
            return Err(MathError::Overflow);
        }
        FieldElement::from_value(&FieldValue::<F>::from_le_bytes(bytes)?)
    }

    /// The element of the big-endian integer `bytes` of any length, reduced
    /// modulo the prime (as a hash is mapped to a scalar), in time that
    /// depends on the length alone.
    pub fn from_be_bytes_reduced(bytes: &[u8]) -> FieldElement<F> {
        let size = <FieldValue<F> as UnsignedInteger>::BYTES;
        FieldElement::from_chunks_reduced(bytes.rchunks(size).rev().map(FieldValue::<F>::from_be_bytes))
    }

    /// The element of the little-endian integer `bytes` of any length,
    /// reduced modulo the prime (as RFC 8032 maps a hash to a scalar), in
    /// time that depends on the length alone.
    pub fn from_le_bytes_reduced(bytes: &[u8]) -> FieldElement<F> {
        let size = <FieldValue<F> as UnsignedInteger>::BYTES;
        FieldElement::from_chunks_reduced(bytes.chunks(size).rev().map(FieldValue::<F>::from_le_bytes))
    }

    /// The element of the integer whose digits in base 2^BITS of the
    /// precision are `chunks`, most significant first: Horner's rule with a
    /// reduction at each digit.
    pub fn from_chunks_reduced(chunks: impl Iterator<Item = Result<FieldValue<F>, MathError>>) -> FieldElement<F> {
        let prime = *F::MODULUS.value();
        let mut remainder = FieldValue::<F>::ZERO;
        for chunk in chunks {
            // A chunk of at most the bytes of the precision always fits.
            let mut digit = chunk.unwrap_or(FieldValue::<F>::ZERO);
            remainder = FieldValue::<F>::rem_wide(&digit, &remainder, &prime).unwrap_or(FieldValue::<F>::ZERO);
            digit.zeroize();
        }
        let element = FieldElement::from_value_reduced(&remainder);
        remainder.zeroize();
        element
    }

    /// Writes the canonical value into `out` big-endian, padded to its length.
    pub fn write_be_bytes(&self, out: &mut [u8]) -> Result<(), MathError> {
        let mut value = self.value();
        let result = value.write_be_bytes(out);
        value.zeroize();
        result
    }

    /// Writes the canonical value into `out` little-endian, padded to its length.
    pub fn write_le_bytes(&self, out: &mut [u8]) -> Result<(), MathError> {
        let mut value = self.value();
        let result = value.write_le_bytes(out);
        value.zeroize();
        result
    }

    pub fn add(&self, other: &FieldElement<F>) -> FieldElement<F> {
        FieldElement { residue: F::MODULUS.add(&self.residue, &other.residue) }
    }

    pub fn sub(&self, other: &FieldElement<F>) -> FieldElement<F> {
        FieldElement { residue: F::MODULUS.sub(&self.residue, &other.residue) }
    }

    pub fn neg(&self) -> FieldElement<F> {
        FieldElement { residue: F::MODULUS.neg(&self.residue) }
    }

    pub fn double(&self) -> FieldElement<F> {
        self.add(self)
    }

    pub fn mul(&self, other: &FieldElement<F>) -> FieldElement<F> {
        FieldElement { residue: F::MODULUS.mul(&self.residue, &other.residue) }
    }

    pub fn square(&self) -> FieldElement<F> {
        FieldElement { residue: F::MODULUS.square(&self.residue) }
    }

    /// `self^exponent` in constant time.
    pub fn pow(&self, exponent: &FieldValue<F>) -> FieldElement<F> {
        FieldElement { residue: F::MODULUS.pow(&self.residue, exponent) }
    }

    /// `self^exponent` in time that depends on the public exponent.
    pub fn pow_vartime(&self, exponent: &FieldValue<F>) -> FieldElement<F> {
        FieldElement { residue: F::MODULUS.pow_vartime(&self.residue, exponent) }
    }

    /// `self^-1`; fails with `NotInvertible` for zero, the one fact the time reveals.
    pub fn invert(&self) -> Result<FieldElement<F>, MathError> {
        Ok(FieldElement { residue: F::MODULUS.invert(&self.residue)? })
    }

    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&FieldElement::zero())
    }

    /// Whether the canonical value is odd: the sign of the encodings of
    /// SEC1 (compressed points) and RFC 8032.
    pub fn is_odd(&self) -> Choice {
        let mut value = self.value();
        let odd = value.is_odd();
        value.zeroize();
        odd
    }

    /// A square root and whether `self` is a square, in constant time; the
    /// root is meaningless when it is not. Primes p ≡ 3 (mod 4) use
    /// `self^((p+1)/4)`, primes p ≡ 5 (mod 8) Atkin's method as in RFC 8032,
    /// and other primes the constant-time Tonelli–Shanks method of RFC 9380
    /// appendix I.4.
    pub fn sqrt(&self) -> (FieldElement<F>, Choice) {
        let p = *F::MODULUS.value();
        let one = FieldValue::<F>::ONE;
        let root = if p.bit(1).into_bool() {
            // p ≡ 3 (mod 4): x = a^((p+1)/4).
            self.pow_vartime(&p.wrapping_add(&one).shr(2))
        } else if p.bit(2).into_bool() {
            // p ≡ 5 (mod 8): x = a^((p+3)/8), times sqrt(-1) = 2^((p-1)/4) if x^2 = -a.
            let candidate = self.pow_vartime(&p.wrapping_add(&one.shl(1)).wrapping_add(&one).shr(3));
            let two = FieldElement::<F>::one().double();
            let sqrt_minus_one = two.pow_vartime(&p.wrapping_sub(&one).shr(2));
            let other = candidate.mul(&sqrt_minus_one);
            FieldElement::select(&candidate, &other, candidate.square().ct_eq(&self.neg()))
        } else {
            self.sqrt_tonelli_shanks()
        };
        let is_square = root.square().ct_eq(self);
        (root, is_square)
    }

    /// The square root of RFC 9380 appendix I.4 for any odd prime, in time
    /// that depends only on the prime: p - 1 = 2^s × q with q odd, and a
    /// non-square c found from the prime alone.
    pub fn sqrt_tonelli_shanks(&self) -> FieldElement<F> {
        let p = *F::MODULUS.value();
        let one = FieldValue::<F>::ONE;
        let p_minus_1 = p.wrapping_sub(&one);
        let mut s = 0;
        while !p_minus_1.bit(s).into_bool() {
            s += 1;
        }
        let q = p_minus_1.shr(s);
        // The smallest non-square: n^((p-1)/2) = -1 (Euler's criterion).
        let minus_one = FieldElement::<F>::one().neg();
        let mut non_square = FieldElement::<F>::one().double();
        while non_square.pow_vartime(&p_minus_1.shr(1)) != minus_one {
            non_square = non_square.add(&FieldElement::one());
        }
        let mut z = self.pow(&q.wrapping_sub(&one).shr(1));
        let mut t = z.square().mul(self);
        z = z.mul(self);
        let mut b = t;
        let mut c = non_square.pow_vartime(&q);
        for i in (2..=s).rev() {
            for _ in 1..i - 1 {
                b = b.square();
            }
            let e = b.ct_eq(&FieldElement::one());
            z = FieldElement::select(&z.mul(&c), &z, e);
            c = c.square();
            t = FieldElement::select(&t.mul(&c), &t, e);
            b = t;
        }
        z
    }
}

impl<F: PrimeField> Clone for FieldElement<F> {
    fn clone(&self) -> FieldElement<F> {
        *self
    }
}

impl<F: PrimeField> Copy for FieldElement<F> {}

impl<F: PrimeField> Default for FieldElement<F> {
    fn default() -> FieldElement<F> {
        FieldElement { residue: FieldResidue::<F>::default() }
    }
}

impl<F: PrimeField> ConstantTimeEq for FieldElement<F> {
    fn ct_eq(&self, other: &FieldElement<F>) -> Choice {
        self.residue.ct_eq(&other.residue)
    }
}

impl<F: PrimeField> PartialEq for FieldElement<F> {
    fn eq(&self, other: &FieldElement<F>) -> bool {
        self.ct_eq(other).into_bool()
    }
}

impl<F: PrimeField> Eq for FieldElement<F> {}

impl<F: PrimeField> ConditionallySelectable for FieldElement<F> {
    fn select(a: &FieldElement<F>, b: &FieldElement<F>, choice: Choice) -> FieldElement<F> {
        FieldElement { residue: FieldResidue::<F>::select(&a.residue, &b.residue, choice) }
    }
}

impl<F: PrimeField> Zeroize for FieldElement<F> {
    fn zeroize(&mut self) {
        self.residue.zeroize();
    }
}

/// Prints the canonical value, like the integers of `math-bigint`: keep
/// secret elements out of formatted output.
impl<F: PrimeField> fmt::Debug for FieldElement<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "FieldElement({:x})", self.value())
    }
}
