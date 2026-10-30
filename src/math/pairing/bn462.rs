//! BN462 (draft-irtf-cfrg-pairing-friendly-curves section 4.2.2): the BN
//! curve with t = 2^114 + 2^101 - 2^14 - 1, E: y^2 = x^3 + 5, ξ = u + 2 and
//! the D-type twist E': y^2 = x^3 - u + 2.

use super::{Fp2, PairingCurve, PairingFamily, PairingField, TwistType};
use crate::math::bigint::U512;
use crate::math::ec::{CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use crate::math::modular::Modulus;

/// The field GF(p) of BN462.
#[derive(Clone, Copy, Debug)]
pub struct BN462Field;

impl BN462Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<BN462Field> {
        FieldElement::from_residue(
            <BN462Field as PrimeField>::MODULUS.residue_vartime(&U512::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for BN462Field {
    type Modulus = Modulus<{ U512::LIMBS }>;
    const MODULUS: Modulus<{ U512::LIMBS }> = Modulus::new_vartime_or_panic(U512::from_hex_vartime_or_panic(
        "240480360120023ffffffffff6ff0cf6b7d9bfca0000000000d812908f41c8020ffffffffff6ff66fc6ff687f640000000002401b00840138013",
    ));
    const BYTES: usize = 58;
}

/// p ≡ 3 mod 4: β = -1.
impl PairingField for BN462Field {
    const NON_RESIDUE: FieldElement<BN462Field> = BN462Field::element(
        "240480360120023ffffffffff6ff0cf6b7d9bfca0000000000d812908f41c8020ffffffffff6ff66fc6ff687f640000000002401b00840138012",
    );

    fn mul_by_non_residue(value: &FieldElement<BN462Field>) -> FieldElement<BN462Field> {
        value.neg()
    }
}

/// The field of the scalars of BN462: the integers modulo the order r of G_1 and G_2.
#[derive(Clone, Copy, Debug)]
pub struct BN462Scalar;

impl BN462Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<BN462Scalar> {
        FieldElement::from_residue(
            <BN462Scalar as PrimeField>::MODULUS.residue_vartime(&U512::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for BN462Scalar {
    type Modulus = Modulus<{ U512::LIMBS }>;
    const MODULUS: Modulus<{ U512::LIMBS }> = Modulus::new_vartime_or_panic(U512::from_hex_vartime_or_panic(
        "240480360120023ffffffffff6ff0cf6b7d9bfca0000000000d812908ee1c201f7fffffffff6ff66fc7bf717f7c0000000002401b007e010800d",
    ));
    const BYTES: usize = 58;
}

/// E: y^2 = x^3 + 5 over GF(p), with the generator of G_1.
#[derive(Clone, Copy, Debug)]
pub struct BN462G1;

impl WeierstrassCurve for BN462G1 {
    type Field = BN462Field;
    type Scalar = BN462Scalar;
    const A: FieldElement<BN462Field> = BN462Field::element("0");
    const B: FieldElement<BN462Field> = BN462Field::element("5");
    const SHAPE: CoefficientA = CoefficientA::Zero;
    const GENERATOR_X: FieldElement<BN462Field> = BN462Field::element(
        "21a6d67ef250191fadba34a0a30160b9ac9264b6f95f63b3edbec3cf4b2e689db1bbb4e69a416a0b1e79239c0372e5cd70113c98d91f36b6980d",
    );
    const GENERATOR_Y: FieldElement<BN462Field> = BN462Field::element(
        "118ea0460f7f7abb82b33676a7432a490eeda842cccfa7d788c659650426e6af77df11b8ae40eb80f475432c66600622ecaa8a5734d36fb03de",
    );
    const COFACTOR: u128 = 0x1;
}

/// BN462, the pairing-friendly curve.
#[derive(Clone, Copy, Debug)]
pub struct BN462;

impl PairingCurve for BN462 {
    type Field = BN462Field;
    type Scalar = BN462Scalar;
    type G1 = BN462G1;
    const FAMILY: PairingFamily = PairingFamily::BN;
    const TWIST: TwistType = TwistType::D;
    const PARAMETER: u128 = 0x4001fffffffffffffffffffffbfff;
    const PARAMETER_NEGATIVE: bool = false;
    const XI: Fp2<BN462Field> = Fp2::new(BN462Field::element("2"), BN462Field::element("1"));
    const TWIST_B: Fp2<BN462Field> = Fp2::new(
        BN462Field::element("2"),
        BN462Field::element(
            "240480360120023ffffffffff6ff0cf6b7d9bfca0000000000d812908f41c8020ffffffffff6ff66fc6ff687f640000000002401b00840138012",
        ),
    );
    const G2_GENERATOR_X: Fp2<BN462Field> = Fp2::new(
        BN462Field::element(
            "257ccc85b58dda0dfb38e3a8cbdc5482e0337e7c1cd96ed61c913820408208f9ad2699bad92e0032ae1f0aa6a8b48807695468e3d934ae1e4df",
        ),
        BN462Field::element(
            "1d2e4343e8599102af8edca849566ba3c98e2a354730cbed9176884058b18134dd86bae555b783718f50af8b59bf7e850e9b73108ba6aa8cd283",
        ),
    );
    const G2_GENERATOR_Y: Fp2<BN462Field> = Fp2::new(
        BN462Field::element(
            "a0650439da22c1979517427a20809eca035634706e23c3fa7a6bb42fe810f1399a1f41c9ddae32e03695a140e7b11d7c3376e5b68df0db7154e",
        ),
        BN462Field::element(
            "73ef0cbd438cbe0172c8ae37306324d44d5e6b0c69ac57b393f1ab370fd725cc647692444a04ef87387aa68d53743493b9eba14cc552ca2a93a",
        ),
    );
}
