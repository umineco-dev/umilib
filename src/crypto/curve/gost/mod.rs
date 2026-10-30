//! The elliptic curves of GOST R 34.10-2012 named by TC 26 (RFC 7836 section 5
//! and appendix A, R 1323565.1.024-2019): the parameter sets
//! id-tc26-gost-3410-2012-256-paramSetA to D (B, C and D being the
//! CryptoPro sets A, B and C of RFC 4357) and
//! id-tc26-gost-3410-2012-512-paramSetA to C, as short Weierstrass curves.
//! The sets A of 256 bits and C of 512 bits are twisted Edwards curves of
//! cofactor 4 given here in their Weierstrass form; their points must be
//! checked to lie in the subgroup of prime order.

use crate::math::bigint::{U256, U512};
use crate::math::ec::{CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use crate::math::modular::Modulus;

/// The field of the coordinates of id-tc26-gost-3410-2012-256-paramSetA.
#[derive(Clone, Copy, Debug)]
pub struct GOST256AField;

impl GOST256AField {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST256AField> {
        FieldElement::from_residue(
            <GOST256AField as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST256AField {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
    ));
    const BYTES: usize = 32;
}

/// The field of the scalars of id-tc26-gost-3410-2012-256-paramSetA: the integers modulo the order q of its generator.
#[derive(Clone, Copy, Debug)]
pub struct GOST256AScalar;

impl GOST256AScalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST256AScalar> {
        FieldElement::from_residue(
            <GOST256AScalar as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST256AScalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "400000000000000000000000000000000fd8cddfc87b6635c115af556c360c67",
    ));
    const BYTES: usize = 32;
}

/// id-tc26-gost-3410-2012-256-paramSetA (RFC 7836 appendix A.2 (the Weierstrass form of a twisted Edwards curve), cofactor 4).
#[derive(Clone, Copy, Debug)]
pub struct GOST256A;

impl WeierstrassCurve for GOST256A {
    type Field = GOST256AField;
    type Scalar = GOST256AScalar;
    const A: FieldElement<GOST256AField> =
        GOST256AField::element("c2173f1513981673af4892c23035a27ce25e2013bf95aa33b22c656f277e7335");
    const B: FieldElement<GOST256AField> =
        GOST256AField::element("295f9bae7428ed9ccc20e7c359a9d41a22fccd9108e17bf7ba9337a6f8ae9513");
    const SHAPE: CoefficientA = CoefficientA::General;
    const GENERATOR_X: FieldElement<GOST256AField> =
        GOST256AField::element("91e38443a5e82c0d880923425712b2bb658b9196932e02c78b2582fe742daa28");
    const GENERATOR_Y: FieldElement<GOST256AField> =
        GOST256AField::element("32879423ab1a0375895786c4bb46e9565fde0b5344766740af268adb32322e5c");
    const COFACTOR: u128 = 4;
}

/// The field of the coordinates of id-tc26-gost-3410-2012-256-paramSetB.
#[derive(Clone, Copy, Debug)]
pub struct GOST256BField;

impl GOST256BField {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST256BField> {
        FieldElement::from_residue(
            <GOST256BField as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST256BField {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
    ));
    const BYTES: usize = 32;
}

/// The field of the scalars of id-tc26-gost-3410-2012-256-paramSetB: the integers modulo the order q of its generator.
#[derive(Clone, Copy, Debug)]
pub struct GOST256BScalar;

impl GOST256BScalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST256BScalar> {
        FieldElement::from_residue(
            <GOST256BScalar as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST256BScalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893",
    ));
    const BYTES: usize = 32;
}

/// id-tc26-gost-3410-2012-256-paramSetB (RFC 4357 section 11.4, id-GostR3410-2001-CryptoPro-A-ParamSet).
#[derive(Clone, Copy, Debug)]
pub struct GOST256B;

impl WeierstrassCurve for GOST256B {
    type Field = GOST256BField;
    type Scalar = GOST256BScalar;
    const A: FieldElement<GOST256BField> =
        GOST256BField::element("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94");
    const B: FieldElement<GOST256BField> = GOST256BField::element("a6");
    const SHAPE: CoefficientA = CoefficientA::MinusThree;
    const GENERATOR_X: FieldElement<GOST256BField> = GOST256BField::element("1");
    const GENERATOR_Y: FieldElement<GOST256BField> =
        GOST256BField::element("8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14");
    const COFACTOR: u128 = 1;
}

/// The field of the coordinates of id-tc26-gost-3410-2012-256-paramSetC.
#[derive(Clone, Copy, Debug)]
pub struct GOST256CField;

impl GOST256CField {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST256CField> {
        FieldElement::from_residue(
            <GOST256CField as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST256CField {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "8000000000000000000000000000000000000000000000000000000000000c99",
    ));
    const BYTES: usize = 32;
}

/// The field of the scalars of id-tc26-gost-3410-2012-256-paramSetC: the integers modulo the order q of its generator.
#[derive(Clone, Copy, Debug)]
pub struct GOST256CScalar;

impl GOST256CScalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST256CScalar> {
        FieldElement::from_residue(
            <GOST256CScalar as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST256CScalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f",
    ));
    const BYTES: usize = 32;
}

/// id-tc26-gost-3410-2012-256-paramSetC (RFC 4357 section 11.4, id-GostR3410-2001-CryptoPro-B-ParamSet).
#[derive(Clone, Copy, Debug)]
pub struct GOST256C;

impl WeierstrassCurve for GOST256C {
    type Field = GOST256CField;
    type Scalar = GOST256CScalar;
    const A: FieldElement<GOST256CField> =
        GOST256CField::element("8000000000000000000000000000000000000000000000000000000000000c96");
    const B: FieldElement<GOST256CField> =
        GOST256CField::element("3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc8b");
    const SHAPE: CoefficientA = CoefficientA::MinusThree;
    const GENERATOR_X: FieldElement<GOST256CField> = GOST256CField::element("1");
    const GENERATOR_Y: FieldElement<GOST256CField> =
        GOST256CField::element("3fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717efc");
    const COFACTOR: u128 = 1;
}

/// The field of the coordinates of id-tc26-gost-3410-2012-256-paramSetD.
#[derive(Clone, Copy, Debug)]
pub struct GOST256DField;

impl GOST256DField {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST256DField> {
        FieldElement::from_residue(
            <GOST256DField as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST256DField {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b",
    ));
    const BYTES: usize = 32;
}

/// The field of the scalars of id-tc26-gost-3410-2012-256-paramSetD: the integers modulo the order q of its generator.
#[derive(Clone, Copy, Debug)]
pub struct GOST256DScalar;

impl GOST256DScalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST256DScalar> {
        FieldElement::from_residue(
            <GOST256DScalar as PrimeField>::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST256DScalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9",
    ));
    const BYTES: usize = 32;
}

/// id-tc26-gost-3410-2012-256-paramSetD (RFC 4357 section 11.4, id-GostR3410-2001-CryptoPro-C-ParamSet).
#[derive(Clone, Copy, Debug)]
pub struct GOST256D;

impl WeierstrassCurve for GOST256D {
    type Field = GOST256DField;
    type Scalar = GOST256DScalar;
    const A: FieldElement<GOST256DField> =
        GOST256DField::element("9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598");
    const B: FieldElement<GOST256DField> = GOST256DField::element("805a");
    const SHAPE: CoefficientA = CoefficientA::MinusThree;
    const GENERATOR_X: FieldElement<GOST256DField> = GOST256DField::element("0");
    const GENERATOR_Y: FieldElement<GOST256DField> =
        GOST256DField::element("41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67");
    const COFACTOR: u128 = 1;
}

/// The field of the coordinates of id-tc26-gost-3410-12-512-paramSetA.
#[derive(Clone, Copy, Debug)]
pub struct GOST512AField;

impl GOST512AField {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST512AField> {
        FieldElement::from_residue(
            <GOST512AField as PrimeField>::MODULUS.residue_vartime(&U512::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST512AField {
    type Modulus = Modulus<{ U512::LIMBS }>;
    const MODULUS: Modulus<{ U512::LIMBS }> = Modulus::new_vartime_or_panic(U512::from_hex_vartime_or_panic(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
    ));
    const BYTES: usize = 64;
}

/// The field of the scalars of id-tc26-gost-3410-12-512-paramSetA: the integers modulo the order q of its generator.
#[derive(Clone, Copy, Debug)]
pub struct GOST512AScalar;

impl GOST512AScalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST512AScalar> {
        FieldElement::from_residue(
            <GOST512AScalar as PrimeField>::MODULUS.residue_vartime(&U512::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST512AScalar {
    type Modulus = Modulus<{ U512::LIMBS }>;
    const MODULUS: Modulus<{ U512::LIMBS }> = Modulus::new_vartime_or_panic(U512::from_hex_vartime_or_panic(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27e69532f48d89116ff22b8d4e0560609b4b38abfad2b85dcacdb1411f10b275",
    ));
    const BYTES: usize = 64;
}

/// id-tc26-gost-3410-12-512-paramSetA (RFC 7836 appendix A.1).
#[derive(Clone, Copy, Debug)]
pub struct GOST512A;

impl WeierstrassCurve for GOST512A {
    type Field = GOST512AField;
    type Scalar = GOST512AScalar;
    const A: FieldElement<GOST512AField> = GOST512AField::element(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc4",
    );
    const B: FieldElement<GOST512AField> = GOST512AField::element(
        "e8c2505dedfc86ddc1bd0b2b6667f1da34b82574761cb0e879bd081cfd0b6265ee3cb090f30d27614cb4574010da90dd862ef9d4ebee4761503190785a71c760",
    );
    const SHAPE: CoefficientA = CoefficientA::MinusThree;
    const GENERATOR_X: FieldElement<GOST512AField> = GOST512AField::element("3");
    const GENERATOR_Y: FieldElement<GOST512AField> = GOST512AField::element(
        "7503cfe87a836ae3a61b8816e25450e6ce5e1c93acf1abc1778064fdcbefa921df1626be4fd036e93d75e6a50e3a41e98028fe5fc235f5b889a589cb5215f2a4",
    );
    const COFACTOR: u128 = 1;
}

/// The field of the coordinates of id-tc26-gost-3410-12-512-paramSetB.
#[derive(Clone, Copy, Debug)]
pub struct GOST512BField;

impl GOST512BField {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST512BField> {
        FieldElement::from_residue(
            <GOST512BField as PrimeField>::MODULUS.residue_vartime(&U512::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST512BField {
    type Modulus = Modulus<{ U512::LIMBS }>;
    const MODULUS: Modulus<{ U512::LIMBS }> = Modulus::new_vartime_or_panic(U512::from_hex_vartime_or_panic(
        "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006f",
    ));
    const BYTES: usize = 64;
}

/// The field of the scalars of id-tc26-gost-3410-12-512-paramSetB: the integers modulo the order q of its generator.
#[derive(Clone, Copy, Debug)]
pub struct GOST512BScalar;

impl GOST512BScalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST512BScalar> {
        FieldElement::from_residue(
            <GOST512BScalar as PrimeField>::MODULUS.residue_vartime(&U512::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST512BScalar {
    type Modulus = Modulus<{ U512::LIMBS }>;
    const MODULUS: Modulus<{ U512::LIMBS }> = Modulus::new_vartime_or_panic(U512::from_hex_vartime_or_panic(
        "800000000000000000000000000000000000000000000000000000000000000149a1ec142565a545acfdb77bd9d40cfa8b996712101bea0ec6346c54374f25bd",
    ));
    const BYTES: usize = 64;
}

/// id-tc26-gost-3410-12-512-paramSetB (RFC 7836 appendix A.1).
#[derive(Clone, Copy, Debug)]
pub struct GOST512B;

impl WeierstrassCurve for GOST512B {
    type Field = GOST512BField;
    type Scalar = GOST512BScalar;
    const A: FieldElement<GOST512BField> = GOST512BField::element(
        "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c",
    );
    const B: FieldElement<GOST512BField> = GOST512BField::element(
        "687d1b459dc841457e3e06cf6f5e2517b97c7d614af138bcbf85dc806c4b289f3e965d2db1416d217f8b276fad1ab69c50f78bee1fa3106efb8ccbc7c5140116",
    );
    const SHAPE: CoefficientA = CoefficientA::MinusThree;
    const GENERATOR_X: FieldElement<GOST512BField> = GOST512BField::element("2");
    const GENERATOR_Y: FieldElement<GOST512BField> = GOST512BField::element(
        "1a8f7eda389b094c2c071e3647a8940f3c123b697578c213be6dd9e6c8ec7335dcb228fd1edf4a39152cbcaaf8c0398828041055f94ceeec7e21340780fe41bd",
    );
    const COFACTOR: u128 = 1;
}

/// The field of the coordinates of id-tc26-gost-3410-2012-512-paramSetC.
#[derive(Clone, Copy, Debug)]
pub struct GOST512CField;

impl GOST512CField {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the prime fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST512CField> {
        FieldElement::from_residue(
            <GOST512CField as PrimeField>::MODULUS.residue_vartime(&U512::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST512CField {
    type Modulus = Modulus<{ U512::LIMBS }>;
    const MODULUS: Modulus<{ U512::LIMBS }> = Modulus::new_vartime_or_panic(U512::from_hex_vartime_or_panic(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7",
    ));
    const BYTES: usize = 64;
}

/// The field of the scalars of id-tc26-gost-3410-2012-512-paramSetC: the integers modulo the order q of its generator.
#[derive(Clone, Copy, Debug)]
pub struct GOST512CScalar;

impl GOST512CScalar {
    /// The element of hexadecimal value `hex`, for constants: a value not
    /// below the order fails the compilation.
    pub const fn element(hex: &str) -> FieldElement<GOST512CScalar> {
        FieldElement::from_residue(
            <GOST512CScalar as PrimeField>::MODULUS.residue_vartime(&U512::from_hex_vartime_or_panic(hex)),
        )
    }
}

impl PrimeField for GOST512CScalar {
    type Modulus = Modulus<{ U512::LIMBS }>;
    const MODULUS: Modulus<{ U512::LIMBS }> = Modulus::new_vartime_or_panic(U512::from_hex_vartime_or_panic(
        "3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc98cdba46506ab004c33a9ff5147502cc8eda9e7a769a12694623cef47f023ed",
    ));
    const BYTES: usize = 64;
}

/// id-tc26-gost-3410-2012-512-paramSetC (RFC 7836 appendix A.2 (the Weierstrass form of a twisted Edwards curve), cofactor 4).
#[derive(Clone, Copy, Debug)]
pub struct GOST512C;

impl WeierstrassCurve for GOST512C {
    type Field = GOST512CField;
    type Scalar = GOST512CScalar;
    const A: FieldElement<GOST512CField> = GOST512CField::element(
        "dc9203e514a721875485a529d2c722fb187bc8980eb866644de41c68e143064546e861c0e2c9edd92ade71f46fcf50ff2ad97f951fda9f2a2eb6546f39689bd3",
    );
    const B: FieldElement<GOST512CField> = GOST512CField::element(
        "b4c4ee28cebc6c2c8ac12952cf37f16ac7efb6a9f69f4b57ffda2e4f0de5ade038cbc2fff719d2c18de0284b8bfef3b52b8cc7a5f5bf0a3c8d2319a5312557e1",
    );
    const SHAPE: CoefficientA = CoefficientA::General;
    const GENERATOR_X: FieldElement<GOST512CField> = GOST512CField::element(
        "e2e31edfc23de7bdebe241ce593ef5de2295b7a9cbaef021d385f7074cea043aa27272a7ae602bf2a7b9033db9ed3610c6fb85487eae97aac5bc7928c1950148",
    );
    const GENERATOR_Y: FieldElement<GOST512CField> = GOST512CField::element(
        "f5ce40d95b5eb899abbccff5911cb8577939804d6527378b8c108c3d2090ff9be18e2d33e3021ed2ef32d85822423b6304f726aa854bae07d0396e9a9addc40f",
    );
    const COFACTOR: u128 = 4;
}
