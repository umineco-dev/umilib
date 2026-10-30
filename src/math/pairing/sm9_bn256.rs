//! The BN curve of SM9 (GM/T 0044.5-2016 section 3.1): t =
//! 0x600000000058F98A, E: y^2 = x^3 + 5, the tower of section 3.2 with
//! β = -2 (u^2 = -2) and ξ = u, and the M-type twist E': y^2 = x^3 + 5u,
//! whose map to E is (x, y) ↦ (x u^(-1/3), y u^(-1/2)) as in GM/T 0044.1
//! appendix B.6.2. The R-ate pairing of SM9 is the optimal ate pairing of
//! its BN family.

use super::{Fp2, PairingCurve, PairingFamily, PairingField, TwistType};
use crate::math::bigint::U256;
use crate::math::ec::{CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use crate::math::modular::Modulus;

/// The field GF(p) of the curve of SM9.
#[derive(Clone, Copy, Debug)]
pub struct SM9BN256Field;

impl SM9BN256Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<SM9BN256Field> {
        FieldElement::from_residue(
            <SM9BN256Field as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for SM9BN256Field {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d",
    ));
    const BYTES: usize = 32;
}

/// p ≡ 1 mod 4, so -1 is a square: β = -2 (GM/T 0044.5-2016 section 3.2).
impl PairingField for SM9BN256Field {
    const NON_RESIDUE: FieldElement<SM9BN256Field> =
        SM9BN256Field::element("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457b");

    fn mul_by_non_residue(value: &FieldElement<SM9BN256Field>) -> FieldElement<SM9BN256Field> {
        value.double().neg()
    }
}

/// The field of the scalars of the curve of SM9: the integers modulo the order N of G_1 and G_2.
#[derive(Clone, Copy, Debug)]
pub struct SM9BN256Scalar;

impl SM9BN256Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<SM9BN256Scalar> {
        FieldElement::from_residue(
            <SM9BN256Scalar as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for SM9BN256Scalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25",
    ));
    const BYTES: usize = 32;
}

/// E: y^2 = x^3 + 5 over GF(p), with the generator P1 of G_1.
#[derive(Clone, Copy, Debug)]
pub struct SM9BN256G1;

impl WeierstrassCurve for SM9BN256G1 {
    type Field = SM9BN256Field;
    type Scalar = SM9BN256Scalar;
    const A: FieldElement<SM9BN256Field> = SM9BN256Field::element("0");
    const B: FieldElement<SM9BN256Field> = SM9BN256Field::element("5");
    const SHAPE: CoefficientA = CoefficientA::Zero;
    const GENERATOR_X: FieldElement<SM9BN256Field> =
        SM9BN256Field::element("93de051d62bf718ff5ed0704487d01d6e1e4086909dc3280e8c4e4817c66dddd");
    const GENERATOR_Y: FieldElement<SM9BN256Field> =
        SM9BN256Field::element("21fe8dda4f21e607631065125c395bbc1c1c00cbfa6024350c464cd70a3ea616");
    const COFACTOR: u128 = 0x1;
}

/// SM9BN256, the pairing-friendly curve of SM9.
#[derive(Clone, Copy, Debug)]
pub struct SM9BN256;

impl PairingCurve for SM9BN256 {
    type Field = SM9BN256Field;
    type Scalar = SM9BN256Scalar;
    type G1 = SM9BN256G1;
    const FAMILY: PairingFamily = PairingFamily::BN;
    const TWIST: TwistType = TwistType::M;
    const PARAMETER: u128 = 0x600000000058f98a;
    const PARAMETER_NEGATIVE: bool = false;
    const XI: Fp2<SM9BN256Field> = Fp2::new(SM9BN256Field::element("0"), SM9BN256Field::element("1"));
    const TWIST_B: Fp2<SM9BN256Field> = Fp2::new(SM9BN256Field::element("0"), SM9BN256Field::element("5"));
    const G2_GENERATOR_X: Fp2<SM9BN256Field> = Fp2::new(
        SM9BN256Field::element("3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b"),
        SM9BN256Field::element("85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141"),
    );
    const G2_GENERATOR_Y: Fp2<SM9BN256Field> = Fp2::new(
        SM9BN256Field::element("a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7"),
        SM9BN256Field::element("17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96"),
    );
}
