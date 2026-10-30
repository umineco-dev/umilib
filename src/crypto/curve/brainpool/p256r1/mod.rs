//! brainpoolP256r1: y^2 = x^3 + Ax + B over the integers modulo a
//! 256-bit prime p, generated verifiably at random (RFC 5639 section 3).
//!
//! [`BrainpoolP256r1`] implements [`WeierstrassCurve`]: its points are
//! `AffinePoint<BrainpoolP256r1>` and `ProjectivePoint<BrainpoolP256r1>` and its scalars
//! `FieldElement<BrainpoolP256r1Scalar>` (see [`crate::math::ec`]).

use crate::math::bigint::U256;
use crate::math::ec::{CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use crate::math::modular::Modulus;

/// The field of the coordinates of brainpoolP256r1: the integers modulo the prime p.
#[derive(Clone, Copy, Debug)]
pub struct BrainpoolP256r1Field;

impl BrainpoolP256r1Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<BrainpoolP256r1Field> {
        FieldElement::from_residue(
            <BrainpoolP256r1Field as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for BrainpoolP256r1Field {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
    ));
    const BYTES: usize = 32;
}

/// The field of the scalars of brainpoolP256r1: the integers modulo the order n of its generator.
#[derive(Clone, Copy, Debug)]
pub struct BrainpoolP256r1Scalar;

impl BrainpoolP256r1Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<BrainpoolP256r1Scalar> {
        FieldElement::from_residue(
            <BrainpoolP256r1Scalar as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for BrainpoolP256r1Scalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
    ));
    const BYTES: usize = 32;
}

/// brainpoolP256r1, with the coefficients and the generator of its specification.
#[derive(Clone, Copy, Debug)]
pub struct BrainpoolP256r1;

impl WeierstrassCurve for BrainpoolP256r1 {
    type Field = BrainpoolP256r1Field;
    type Scalar = BrainpoolP256r1Scalar;
    const A: FieldElement<BrainpoolP256r1Field> =
        BrainpoolP256r1Field::element("7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9");
    const B: FieldElement<BrainpoolP256r1Field> =
        BrainpoolP256r1Field::element("26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6");
    const SHAPE: CoefficientA = CoefficientA::General;
    const GENERATOR_X: FieldElement<BrainpoolP256r1Field> =
        BrainpoolP256r1Field::element("8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262");
    const GENERATOR_Y: FieldElement<BrainpoolP256r1Field> =
        BrainpoolP256r1Field::element("547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997");
    const COFACTOR: u128 = 1;
}
