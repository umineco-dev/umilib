//! Fuzz targets of `umilib::math`.

use umilib::platform::fuzz::{FuzzFunction, FuzzTarget};

/// Splits the input into a precision of 64 to 512 bits and two numbers of that precision.
pub struct Operands;

impl Operands {
    pub fn split(data: &[u8]) -> Option<(u32, &[u8], &[u8])> {
        let (&first, rest) = data.split_first()?;
        let precision = 64 * (1 + (first % 8) as u32);
        let length = (precision / 8) as usize;
        let (a, b) = rest.split_at(rest.len().min(length));
        Some((precision, a, &b[..b.len().min(length)]))
    }
}

#[cfg(umilib_feature = "math-bigint")]
mod bigint {
    use umilib::math::bigint::{BoxedUint, MathError, U512};

    /// Checks the defining identities of each operation, which hold for every
    /// input, and that `Uint` and `BoxedUint` agree.
    pub fn identities(data: &[u8]) {
        let Some((precision, a_bytes, b_bytes)) = super::Operands::split(data) else {
            return;
        };
        let a = BoxedUint::from_be_bytes(a_bytes, precision).unwrap();
        let b = BoxedUint::from_be_bytes(b_bytes, precision).unwrap();
        assert_eq!(BoxedUint::from_be_bytes(&a.to_be_bytes(), precision).unwrap(), a);
        assert_eq!(BoxedUint::from_le_bytes(&a.to_le_bytes(), precision).unwrap(), a);
        assert_eq!(BoxedUint::from_hex_vartime(&format!("{a:x}"), precision).unwrap(), a);
        let (sum, carry) = a.overflowing_add(&b);
        let (back, borrow) = sum.overflowing_sub(&b);
        assert_eq!(back, a);
        assert_eq!(carry.into_bool(), borrow.into_bool());
        assert_eq!(a.ct_lt(&b).into_bool(), a.compare_vartime(&b).is_lt());
        match a.div_rem(&b) {
            Err(error) => {
                assert_eq!(error, MathError::DivisionByZero);
                assert!(b.is_zero().into_bool());
            }
            Ok((quotient, remainder)) => {
                // a = quotient * b + remainder, with remainder < b, defines both.
                assert!(remainder.ct_lt(&b).into_bool());
                let (low, high) = quotient.widening_mul(&b);
                assert!(high.is_zero().into_bool());
                let (total, carry) = low.overflowing_add(&remainder);
                assert!(!carry.into_bool());
                assert_eq!(total, a);
            }
        }
        let shift = b_bytes.first().copied().unwrap_or(0) as u32 % (precision + 8);
        let shifted = a.shl(shift);
        assert_eq!(shifted.shr(shift).shl(shift), shifted);
        assert!(shifted.bit_length() <= precision);
        let fixed_a = U512::from_be_bytes(a_bytes).unwrap();
        let fixed_b = U512::from_be_bytes(b_bytes).unwrap();
        let (low, high) = fixed_a.widening_mul(&fixed_b);
        let (boxed_low, boxed_high) = a.resize(512).unwrap().widening_mul(&b.resize(512).unwrap());
        assert_eq!(low.to_be_bytes(), boxed_low.to_be_bytes());
        assert_eq!(high.to_be_bytes(), boxed_high.to_be_bytes());
        assert_eq!(fixed_a.bit_length(), a.bit_length());
    }
}

#[cfg(umilib_feature = "math-modular")]
mod modular {
    use umilib::math::bigint::{BoxedUint, MathError};
    use umilib::math::modular::BoxedModulus;

    /// The greatest common divisor, by Euclid's algorithm (variable time).
    pub fn gcd(a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        let (mut a, mut b) = (a.clone(), b.clone());
        while !b.is_zero().into_bool() {
            let remainder = a.rem(&b).unwrap().resize(a.precision()).unwrap();
            a = b;
            b = remainder;
        }
        a
    }

    /// Checks modular operations against the integer operations they are
    /// defined by: reduction, multiplication then division, and inverses.
    pub fn consistency(data: &[u8]) {
        let Some((precision, a_bytes, b_bytes)) = super::Operands::split(data) else {
            return;
        };
        let modulus_value = &BoxedUint::from_be_bytes(b_bytes, precision).unwrap() | &BoxedUint::one(64).unwrap();
        let field = match BoxedModulus::new(modulus_value.clone()) {
            Ok(field) => field,
            Err(error) => {
                assert_eq!(error, MathError::InvalidModulus);
                assert!(modulus_value.bit_length() < 2);
                return;
            }
        };
        let a = BoxedUint::from_be_bytes(a_bytes, precision).unwrap();
        let b = &a.shr(3) ^ &BoxedUint::from_be_bytes(b_bytes, precision).unwrap();
        let (x, y) = (field.residue(&a), field.residue(&b));
        let a_reduced = a.rem(&modulus_value).unwrap();
        let b_reduced = b.rem(&modulus_value).unwrap();
        assert_eq!(field.retrieve(&x).unwrap(), a_reduced);
        let (low, high) = a.widening_mul(&b);
        let product = BoxedUint::rem_wide(&low, &high, &modulus_value).unwrap();
        assert_eq!(field.retrieve(&field.mul(&x, &y).unwrap()).unwrap(), product);
        let (sum, carry) = a_reduced.overflowing_add(&b_reduced);
        let sum =
            BoxedUint::rem_wide(&sum, &BoxedUint::from_u64(carry.bit() as u64, 64).unwrap(), &modulus_value).unwrap();
        assert_eq!(field.retrieve(&field.add(&x, &y).unwrap()).unwrap(), sum);
        assert_eq!(field.add(&field.sub(&x, &y).unwrap(), &y).unwrap(), x);
        let exponent = BoxedUint::from_be_bytes(&a_bytes[..a_bytes.len().min(8)], 64).unwrap();
        assert_eq!(field.pow(&x, &exponent).unwrap(), field.pow_vartime(&x, &exponent).unwrap());
        match field.invert(&x) {
            Ok(inverse) => assert_eq!(field.mul(&x, &inverse).unwrap(), field.one()),
            Err(error) => {
                assert_eq!(error, MathError::NotInvertible);
                assert!(gcd(&a_reduced, &modulus_value) != BoxedUint::one(64).unwrap());
            }
        }
    }
}

#[cfg(umilib_feature = "math-lattice")]
mod lattice {
    use umilib::math::lattice::{LatticePacking, LatticeRing, MLDSARing, MLKEMRing, Polynomial};

    /// The coefficients of a polynomial of `R` taken from `data` (3 bytes each, repeated).
    fn polynomial<R: LatticeRing>(data: &[u8]) -> Polynomial<R> {
        let values: Vec<u32> = (0..R::N)
            .map(|index| {
                let at = |offset: usize| *data.get((3 * index + offset) % data.len().max(1)).unwrap_or(&0) as u32;
                at(0) | at(1) << 8 | at(2) << 16
            })
            .collect();
        Polynomial::from_values(&values).unwrap()
    }

    /// The transforms are inverse, linear and multiplicative, for both rings.
    fn check<R: LatticeRing>(data: &[u8]) {
        let (f, g) = (polynomial::<R>(data), polynomial::<R>(&data[data.len() / 2..]));
        assert_eq!(f.ntt().inverse_ntt(), f);
        assert_eq!(f.add(&g).ntt(), f.ntt().add(&g.ntt()));
        let product = f.ntt().multiply_ntt(&g.ntt()).inverse_ntt();
        assert_eq!(g.ntt().multiply_ntt(&f.ntt()).inverse_ntt(), product);
    }

    /// The transforms of both rings and the packing of integers: every
    /// encoding reads back to its integers, and the bit strings of
    /// [`Polynomial::read_bits`] write back to themselves when canonical.
    pub fn transforms(data: &[u8]) {
        let Some((&selector, rest)) = data.split_first() else {
            return;
        };
        check::<MLKEMRing>(rest);
        check::<MLDSARing>(rest);
        let bits = 1 + (selector % 32) as u32;
        let count = rest.len() * 8 / bits as usize;
        let mut values = vec![0u32; count];
        LatticePacking::new(bits).unwrap().read(rest, &mut values);
        let mut written = vec![0u8; LatticePacking::length(bits, count)];
        LatticePacking::new(bits).unwrap().write(&values, &mut written);
        let mut again = vec![0u32; count];
        LatticePacking::new(bits).unwrap().read(&written, &mut again);
        assert_eq!(again, values);
        let width = 1 + (selector % 12) as u32;
        let length = 32 * width as usize;
        if rest.len() >= length {
            let (polynomial, canonical) = Polynomial::<MLKEMRing>::read_bits(width, &rest[..length]).unwrap();
            let mut out = vec![0u8; length];
            polynomial.write_bits(width, &mut out).unwrap();
            assert_eq!(out == rest[..length], canonical.into_bool());
        }
    }
}

#[cfg(umilib_feature = "math-bigint")]
pub const BIGINT: FuzzFunction<fn(&[u8])> = FuzzFunction::new("math-bigint", bigint::identities);
#[cfg(umilib_feature = "math-modular")]
pub const MODULAR: FuzzFunction<fn(&[u8])> = FuzzFunction::new("math-modular", modular::consistency);
#[cfg(umilib_feature = "math-lattice")]
pub const LATTICE: FuzzFunction<fn(&[u8])> = FuzzFunction::new("math-lattice", lattice::transforms);

pub const TARGETS: &[&dyn FuzzTarget] = &[
    #[cfg(umilib_feature = "math-bigint")]
    &BIGINT,
    #[cfg(umilib_feature = "math-modular")]
    &MODULAR,
    #[cfg(umilib_feature = "math-lattice")]
    &LATTICE,
];
