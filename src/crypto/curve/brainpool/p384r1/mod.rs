//! brainpoolP384r1: y^2 = x^3 + Ax + B over the integers modulo a
//! 384-bit prime p, generated verifiably at random (RFC 5639 section 3).
//!
//! [`BrainpoolP384r1`] implements [`WeierstrassCurve`]: its points are
//! `AffinePoint<BrainpoolP384r1>` and `ProjectivePoint<BrainpoolP384r1>` and its scalars
//! `FieldElement<BrainpoolP384r1Scalar>` (see [`crate::math::ec`]).

use crate::math::bigint::U384;
use crate::math::ec::{CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use crate::math::modular::Modulus;

/// The field of the coordinates of brainpoolP384r1: the integers modulo the prime p.
#[derive(Clone, Copy, Debug)]
pub struct BrainpoolP384r1Field;

impl BrainpoolP384r1Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<BrainpoolP384r1Field> {
        FieldElement::from_residue(
            <BrainpoolP384r1Field as PrimeField>::MODULUS.residue_vartime(&U384::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for BrainpoolP384r1Field {
    type Modulus = Modulus<{ U384::LIMBS }>;
    const MODULUS: Modulus<{ U384::LIMBS }> = Modulus::new_vartime_or_panic(U384::from_hex_vartime_or_panic(
        "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
    ));
    const BYTES: usize = 48;
}

/// The field of the scalars of brainpoolP384r1: the integers modulo the order n of its generator.
#[derive(Clone, Copy, Debug)]
pub struct BrainpoolP384r1Scalar;

impl BrainpoolP384r1Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<BrainpoolP384r1Scalar> {
        FieldElement::from_residue(
            <BrainpoolP384r1Scalar as PrimeField>::MODULUS.residue_vartime(&U384::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for BrainpoolP384r1Scalar {
    type Modulus = Modulus<{ U384::LIMBS }>;
    const MODULUS: Modulus<{ U384::LIMBS }> = Modulus::new_vartime_or_panic(U384::from_hex_vartime_or_panic(
        "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
    ));
    const BYTES: usize = 48;
}

/// brainpoolP384r1, with the coefficients and the generator of its specification.
#[derive(Clone, Copy, Debug)]
pub struct BrainpoolP384r1;

impl WeierstrassCurve for BrainpoolP384r1 {
    type Field = BrainpoolP384r1Field;
    type Scalar = BrainpoolP384r1Scalar;
    const A: FieldElement<BrainpoolP384r1Field> = BrainpoolP384r1Field::element(
        "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826",
    );
    const B: FieldElement<BrainpoolP384r1Field> = BrainpoolP384r1Field::element(
        "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11",
    );
    const SHAPE: CoefficientA = CoefficientA::General;
    const GENERATOR_X: FieldElement<BrainpoolP384r1Field> = BrainpoolP384r1Field::element(
        "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e",
    );
    const GENERATOR_Y: FieldElement<BrainpoolP384r1Field> = BrainpoolP384r1Field::element(
        "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
    );
    const COFACTOR: u128 = 1;
}
