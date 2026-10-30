//! BN254 as Ethereum uses it (alt_bn128 of EIP-196 and EIP-197): the BN
//! curve with t = 4965661367192848881, E: y^2 = x^3 + 3 with the generator
//! (1, 2), ξ = u + 9 and the D-type twist E': y^2 = x^3 + 3 / (u + 9). Its
//! security is about 100 bits since the improved number field sieves.

use super::{Fp2, PairingCurve, PairingFamily, PairingField, TwistType};
use crate::math::bigint::U256;
use crate::math::ec::{CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use crate::math::modular::Modulus;

/// The field GF(p) of BN254.
#[derive(Clone, Copy, Debug)]
pub struct BN254Field;

impl BN254Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<BN254Field> {
        FieldElement::from_residue(
            <BN254Field as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for BN254Field {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
    ));
    const BYTES: usize = 32;
}

/// p ≡ 3 mod 4: β = -1.
impl PairingField for BN254Field {
    const NON_RESIDUE: FieldElement<BN254Field> =
        BN254Field::element("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46");

    fn mul_by_non_residue(value: &FieldElement<BN254Field>) -> FieldElement<BN254Field> {
        value.neg()
    }
}

/// The field of the scalars of BN254: the integers modulo the order r of G_1 and G_2.
#[derive(Clone, Copy, Debug)]
pub struct BN254Scalar;

impl BN254Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<BN254Scalar> {
        FieldElement::from_residue(
            <BN254Scalar as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for BN254Scalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
    ));
    const BYTES: usize = 32;
}

/// E: y^2 = x^3 + 3 over GF(p), with the generator of G_1.
#[derive(Clone, Copy, Debug)]
pub struct BN254G1;

impl WeierstrassCurve for BN254G1 {
    type Field = BN254Field;
    type Scalar = BN254Scalar;
    const A: FieldElement<BN254Field> = BN254Field::element("0");
    const B: FieldElement<BN254Field> = BN254Field::element("3");
    const SHAPE: CoefficientA = CoefficientA::Zero;
    const GENERATOR_X: FieldElement<BN254Field> = BN254Field::element("1");
    const GENERATOR_Y: FieldElement<BN254Field> = BN254Field::element("2");
    const COFACTOR: u128 = 0x1;
}

/// BN254, the pairing-friendly curve.
#[derive(Clone, Copy, Debug)]
pub struct BN254;

impl PairingCurve for BN254 {
    type Field = BN254Field;
    type Scalar = BN254Scalar;
    type G1 = BN254G1;
    const FAMILY: PairingFamily = PairingFamily::BN;
    const TWIST: TwistType = TwistType::D;
    const PARAMETER: u128 = 0x44e992b44a6909f1;
    const PARAMETER_NEGATIVE: bool = false;
    const XI: Fp2<BN254Field> = Fp2::new(BN254Field::element("9"), BN254Field::element("1"));
    const TWIST_B: Fp2<BN254Field> = Fp2::new(
        BN254Field::element("2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5"),
        BN254Field::element("9713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2"),
    );
    const G2_GENERATOR_X: Fp2<BN254Field> = Fp2::new(
        BN254Field::element("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
        BN254Field::element("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
    );
    const G2_GENERATOR_Y: Fp2<BN254Field> = Fp2::new(
        BN254Field::element("12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"),
        BN254Field::element("90689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"),
    );
}
