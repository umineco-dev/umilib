//! secp256k1: y^2 = x^3 + 7 over the integers modulo
//! p = 2^256 - 2^32 - 977 (SEC 2 section 2.4.1).
//!
//! [`Secp256k1`] implements [`WeierstrassCurve`]: its points are
//! `AffinePoint<Secp256k1>` and `ProjectivePoint<Secp256k1>` and its scalars
//! `FieldElement<Secp256k1Scalar>` (see [`crate::math::ec`]).

use crate::math::bigint::U256;
use crate::math::ec::{CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use crate::math::modular::Modulus;

/// The field of the coordinates of secp256k1: the integers modulo the prime p.
#[derive(Clone, Copy, Debug)]
pub struct Secp256k1Field;

impl Secp256k1Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<Secp256k1Field> {
        FieldElement::from_residue(
            <Secp256k1Field as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for Secp256k1Field {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    ));
    const BYTES: usize = 32;
}

/// The field of the scalars of secp256k1: the integers modulo the order n of its generator.
#[derive(Clone, Copy, Debug)]
pub struct Secp256k1Scalar;

impl Secp256k1Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<Secp256k1Scalar> {
        FieldElement::from_residue(
            <Secp256k1Scalar as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for Secp256k1Scalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    ));
    const BYTES: usize = 32;
}

/// secp256k1, with the coefficients and the generator of its specification.
#[derive(Clone, Copy, Debug)]
pub struct Secp256k1;

impl WeierstrassCurve for Secp256k1 {
    type Field = Secp256k1Field;
    type Scalar = Secp256k1Scalar;
    const A: FieldElement<Secp256k1Field> = Secp256k1Field::element("0");
    const B: FieldElement<Secp256k1Field> = Secp256k1Field::element("7");
    const SHAPE: CoefficientA = CoefficientA::Zero;
    const GENERATOR_X: FieldElement<Secp256k1Field> =
        Secp256k1Field::element("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const GENERATOR_Y: FieldElement<Secp256k1Field> =
        Secp256k1Field::element("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    const COFACTOR: u128 = 1;
}
