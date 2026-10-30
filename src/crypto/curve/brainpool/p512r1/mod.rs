//! brainpoolP512r1: y^2 = x^3 + Ax + B over the integers modulo a
//! 512-bit prime p, generated verifiably at random (RFC 5639 section 3).
//!
//! [`BrainpoolP512r1`] implements [`WeierstrassCurve`]: its points are
//! `AffinePoint<BrainpoolP512r1>` and `ProjectivePoint<BrainpoolP512r1>` and its scalars
//! `FieldElement<BrainpoolP512r1Scalar>` (see [`crate::math::ec`]).

use crate::math::bigint::U512;
use crate::math::ec::{CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use crate::math::modular::Modulus;

/// The field of the coordinates of brainpoolP512r1: the integers modulo the prime p.
#[derive(Clone, Copy, Debug)]
pub struct BrainpoolP512r1Field;

impl BrainpoolP512r1Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<BrainpoolP512r1Field> {
        FieldElement::from_residue(
            <BrainpoolP512r1Field as PrimeField>::MODULUS.residue_vartime(&U512::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for BrainpoolP512r1Field {
    type Modulus = Modulus<{ U512::LIMBS }>;
    const MODULUS: Modulus<{ U512::LIMBS }> = Modulus::new_vartime_or_panic(U512::from_hex_vartime_or_panic(
        "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
    ));
    const BYTES: usize = 64;
}

/// The field of the scalars of brainpoolP512r1: the integers modulo the order n of its generator.
#[derive(Clone, Copy, Debug)]
pub struct BrainpoolP512r1Scalar;

impl BrainpoolP512r1Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<BrainpoolP512r1Scalar> {
        FieldElement::from_residue(
            <BrainpoolP512r1Scalar as PrimeField>::MODULUS.residue_vartime(&U512::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for BrainpoolP512r1Scalar {
    type Modulus = Modulus<{ U512::LIMBS }>;
    const MODULUS: Modulus<{ U512::LIMBS }> = Modulus::new_vartime_or_panic(U512::from_hex_vartime_or_panic(
        "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
    ));
    const BYTES: usize = 64;
}

/// brainpoolP512r1, with the coefficients and the generator of its specification.
#[derive(Clone, Copy, Debug)]
pub struct BrainpoolP512r1;

impl WeierstrassCurve for BrainpoolP512r1 {
    type Field = BrainpoolP512r1Field;
    type Scalar = BrainpoolP512r1Scalar;
    const A: FieldElement<BrainpoolP512r1Field> = BrainpoolP512r1Field::element(
        "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
    );
    const B: FieldElement<BrainpoolP512r1Field> = BrainpoolP512r1Field::element(
        "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
    );
    const SHAPE: CoefficientA = CoefficientA::General;
    const GENERATOR_X: FieldElement<BrainpoolP512r1Field> = BrainpoolP512r1Field::element(
        "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
    );
    const GENERATOR_Y: FieldElement<BrainpoolP512r1Field> = BrainpoolP512r1Field::element(
        "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
    );
    const COFACTOR: u128 = 1;
}
