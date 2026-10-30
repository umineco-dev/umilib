//! The curve of SM2 (curveSM2 of RFC 8998): y^2 = x^3 - 3x + b over the
//! integers modulo p = 2^256 - 2^224 - 2^96 + 2^64 - 1 (GB/T 32918.5-2017,
//! GM/T 0003.5-2012).
//!
//! [`SM2`] implements [`WeierstrassCurve`]: its points are
//! `AffinePoint<SM2>` and `ProjectivePoint<SM2>` and its scalars
//! `FieldElement<SM2Scalar>` (see [`crate::math::ec`]).

use crate::math::bigint::U256;
use crate::math::ec::{CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use crate::math::modular::Modulus;

/// The field of the coordinates of the curve of SM2: the integers modulo the prime p.
#[derive(Clone, Copy, Debug)]
pub struct SM2Field;

impl SM2Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<SM2Field> {
        FieldElement::from_residue(
            <SM2Field as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for SM2Field {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
    ));
    const BYTES: usize = 32;
}

/// The field of the scalars of the curve of SM2: the integers modulo the order n of its generator.
#[derive(Clone, Copy, Debug)]
pub struct SM2Scalar;

impl SM2Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<SM2Scalar> {
        FieldElement::from_residue(
            <SM2Scalar as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for SM2Scalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
    ));
    const BYTES: usize = 32;
}

/// the curve of SM2, with the coefficients and the generator of its specification.
#[derive(Clone, Copy, Debug)]
pub struct SM2;

impl WeierstrassCurve for SM2 {
    type Field = SM2Field;
    type Scalar = SM2Scalar;
    const A: FieldElement<SM2Field> =
        SM2Field::element("fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc");
    const B: FieldElement<SM2Field> =
        SM2Field::element("28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93");
    const SHAPE: CoefficientA = CoefficientA::MinusThree;
    const GENERATOR_X: FieldElement<SM2Field> =
        SM2Field::element("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7");
    const GENERATOR_Y: FieldElement<SM2Field> =
        SM2Field::element("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0");
    const COFACTOR: u128 = 1;
}
