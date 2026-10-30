//! NIST P-256 (secp256r1): y^2 = x^3 - 3x + b over the integers modulo
//! p = 2^256 - 2^224 + 2^192 + 2^96 - 1 (FIPS 186-5, SP 800-186 section
//! 3.2.1.3; SEC 2 section 2.4.2; RFC 5903 section 3.1).
//!
//! [`P256`] implements [`WeierstrassCurve`]: its points are
//! `AffinePoint<P256>` and `ProjectivePoint<P256>` and its scalars
//! `FieldElement<P256Scalar>` (see [`crate::math::ec`]).

use crate::math::bigint::U256;
use crate::math::ec::{CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use crate::math::modular::Modulus;

/// The field of the coordinates of NIST P-256: the integers modulo the prime p.
#[derive(Clone, Copy, Debug)]
pub struct P256Field;

impl P256Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<P256Field> {
        FieldElement::from_residue(
            <P256Field as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for P256Field {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    ));
    const BYTES: usize = 32;
}

/// The field of the scalars of NIST P-256: the integers modulo the order n of its generator.
#[derive(Clone, Copy, Debug)]
pub struct P256Scalar;

impl P256Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<P256Scalar> {
        FieldElement::from_residue(
            <P256Scalar as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for P256Scalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    ));
    const BYTES: usize = 32;
}

/// NIST P-256, with the coefficients and the generator of its specification.
#[derive(Clone, Copy, Debug)]
pub struct P256;

impl WeierstrassCurve for P256 {
    type Field = P256Field;
    type Scalar = P256Scalar;
    const A: FieldElement<P256Field> =
        P256Field::element("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
    const B: FieldElement<P256Field> =
        P256Field::element("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
    const SHAPE: CoefficientA = CoefficientA::MinusThree;
    const GENERATOR_X: FieldElement<P256Field> =
        P256Field::element("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    const GENERATOR_Y: FieldElement<P256Field> =
        P256Field::element("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    const COFACTOR: u128 = 1;
}
