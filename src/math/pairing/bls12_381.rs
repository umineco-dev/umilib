//! BLS12_381 (draft-irtf-cfrg-pairing-friendly-curves section 4.2.1): the
//! BLS curve of embedding degree 12 with t = -2^63 - 2^62 - 2^60 - 2^57 -
//! 2^48 - 2^16, E: y^2 = x^3 + 4, ξ = u + 1 and the M-type twist
//! E': y^2 = x^3 + 4(u + 1).

use super::{Fp2, PairingCurve, PairingFamily, PairingField, TwistType};
use crate::math::bigint::{U256, U384};
use crate::math::ec::{CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use crate::math::modular::Modulus;

/// The field GF(p) of BLS12381.
#[derive(Clone, Copy, Debug)]
pub struct BLS12381Field;

impl BLS12381Field {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<BLS12381Field> {
        FieldElement::from_residue(
            <BLS12381Field as PrimeField>::MODULUS.residue_vartime(&U384::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for BLS12381Field {
    type Modulus = Modulus<{ U384::LIMBS }>;
    const MODULUS: Modulus<{ U384::LIMBS }> = Modulus::new_vartime_or_panic(U384::from_hex_vartime_or_panic(
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    ));
    const BYTES: usize = 48;
}

/// p ≡ 3 mod 4: β = -1.
impl PairingField for BLS12381Field {
    const NON_RESIDUE: FieldElement<BLS12381Field> = BLS12381Field::element(
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa",
    );

    fn mul_by_non_residue(value: &FieldElement<BLS12381Field>) -> FieldElement<BLS12381Field> {
        value.neg()
    }
}

/// The field of the scalars of BLS12381: the integers modulo the order r of G_1 and G_2.
#[derive(Clone, Copy, Debug)]
pub struct BLS12381Scalar;

impl BLS12381Scalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<BLS12381Scalar> {
        FieldElement::from_residue(
            <BLS12381Scalar as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for BLS12381Scalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
    ));
    const BYTES: usize = 32;
}

/// E: y^2 = x^3 + 4 over GF(p), with the generator of G_1.
#[derive(Clone, Copy, Debug)]
pub struct BLS12381G1;

impl WeierstrassCurve for BLS12381G1 {
    type Field = BLS12381Field;
    type Scalar = BLS12381Scalar;
    const A: FieldElement<BLS12381Field> = BLS12381Field::element("0");
    const B: FieldElement<BLS12381Field> = BLS12381Field::element("4");
    const SHAPE: CoefficientA = CoefficientA::Zero;
    const GENERATOR_X: FieldElement<BLS12381Field> = BLS12381Field::element(
        "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
    );
    const GENERATOR_Y: FieldElement<BLS12381Field> = BLS12381Field::element(
        "8b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
    );
    const COFACTOR: u128 = 0x396c8c005555e1568c00aaab0000aaab;
}

/// BLS12381, the pairing-friendly curve.
#[derive(Clone, Copy, Debug)]
pub struct BLS12381;

impl PairingCurve for BLS12381 {
    type Field = BLS12381Field;
    type Scalar = BLS12381Scalar;
    type G1 = BLS12381G1;
    const FAMILY: PairingFamily = PairingFamily::BLS12;
    const TWIST: TwistType = TwistType::M;
    const PARAMETER: u128 = 0xd201000000010000;
    const PARAMETER_NEGATIVE: bool = true;
    const XI: Fp2<BLS12381Field> = Fp2::new(BLS12381Field::element("1"), BLS12381Field::element("1"));
    const TWIST_B: Fp2<BLS12381Field> = Fp2::new(BLS12381Field::element("4"), BLS12381Field::element("4"));
    const G2_GENERATOR_X: Fp2<BLS12381Field> = Fp2::new(
        BLS12381Field::element(
            "24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
        ),
        BLS12381Field::element(
            "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
        ),
    );
    const G2_GENERATOR_Y: Fp2<BLS12381Field> = Fp2::new(
        BLS12381Field::element(
            "ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801",
        ),
        BLS12381Field::element(
            "606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
        ),
    );
}
