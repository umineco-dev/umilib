//! NIST P-384 (secp384r1): y^2 = x^3 - 3x + b over the integers modulo
//! p = 2^384 - 2^128 - 2^96 + 2^32 - 1 (FIPS 186-5, SP 800-186 section
//! 3.2.1.4; SEC 2 section 2.5.1; RFC 5903 section 3.2).
//!
//! [`P384`] implements [`WeierstrassCurve`]: its points are
//! `AffinePoint<P384>` and `ProjectivePoint<P384>` and its scalars
//! `FieldElement<P384Scalar>` (see [`crate::math::ec`]).

use crate::math::bigint::U384;
use crate::math::ec::{CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use crate::math::modular::Modulus;

/// The field of the coordinates of NIST P-384: the integers modulo the prime p.
#[derive(Clone, Copy, Debug)]
pub struct P384Field;

impl P384Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<P384Field> {
        FieldElement::from_residue(
            <P384Field as PrimeField>::MODULUS.residue_vartime(&U384::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for P384Field {
    type Modulus = Modulus<{ U384::LIMBS }>;
    const MODULUS: Modulus<{ U384::LIMBS }> = Modulus::new_vartime_or_panic(U384::from_hex_vartime_or_panic(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    ));
    const BYTES: usize = 48;
}

/// The field of the scalars of NIST P-384: the integers modulo the order n of its generator.
#[derive(Clone, Copy, Debug)]
pub struct P384Scalar;

impl P384Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<P384Scalar> {
        FieldElement::from_residue(
            <P384Scalar as PrimeField>::MODULUS.residue_vartime(&U384::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for P384Scalar {
    type Modulus = Modulus<{ U384::LIMBS }>;
    const MODULUS: Modulus<{ U384::LIMBS }> = Modulus::new_vartime_or_panic(U384::from_hex_vartime_or_panic(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    ));
    const BYTES: usize = 48;
}

/// NIST P-384, with the coefficients and the generator of its specification.
#[derive(Clone, Copy, Debug)]
pub struct P384;

impl WeierstrassCurve for P384 {
    type Field = P384Field;
    type Scalar = P384Scalar;
    const A: FieldElement<P384Field> = P384Field::element(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
    );
    const B: FieldElement<P384Field> = P384Field::element(
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    );
    const SHAPE: CoefficientA = CoefficientA::MinusThree;
    const GENERATOR_X: FieldElement<P384Field> = P384Field::element(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    );
    const GENERATOR_Y: FieldElement<P384Field> = P384Field::element(
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
    );
    const COFACTOR: u128 = 1;
}
