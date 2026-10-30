//! Tests of `umilib::math::ec` on curves defined here from their
//! specifications: NIST P-256 (FIPS 186-5, a = -3), secp256k1 (SEC 2, a = 0),
//! brainpoolP256r1 (RFC 5639, a general), edwards25519 and edwards448
//! (RFC 8032) and curve25519 and curve448 (RFC 7748). The expected values
//! come from RFC 6979, RFC 7027 and RFC 7748, from the orders of the
//! generators, from the group laws, from agreement between the formulas of
//! the different shapes of a, and from the maps between the curves of
//! RFC 7748 section 4.

use umilib::math::bigint::{U256, U448, UnsignedInteger};
use umilib::math::ec::{
    CoefficientA, ECError, EdwardsCurve, EdwardsPoint, FieldElement, FieldValue, MontgomeryCurve, MontgomeryPoint,
    PrimeField, ProjectivePoint, WeierstrassCurve,
};
use umilib::math::modular::{ModularArithmetic, Modulus};

use super::ec_checks::ECChecks;

/// Defines a prime field from its prime in hexadecimal, with `element` to
/// write its constants.
macro_rules! prime_field {
    ($name:ident, $uint:ident, $bytes:expr, $prime:expr) => {
        #[derive(Clone, Copy, Debug)]
        struct $name;

        impl PrimeField for $name {
            type Modulus = Modulus<{ $uint::LIMBS }>;
            const MODULUS: Modulus<{ $uint::LIMBS }> =
                Modulus::new_vartime_or_panic($uint::from_hex_vartime_or_panic($prime));
            const BYTES: usize = $bytes;
        }

        #[allow(dead_code)]
        impl $name {
            const fn element(hex: &str) -> FieldElement<$name> {
                FieldElement::from_residue(
                    <$name as PrimeField>::MODULUS.residue_vartime(&$uint::from_hex_vartime_or_panic(hex)),
                )
            }
        }
    };
}

/// Defines a short Weierstrass curve of cofactor 1.
macro_rules! weierstrass_curve {
    ($name:ident, $field:ident, $scalar:ident, $shape:expr, $a:expr, $b:expr, $x:expr, $y:expr) => {
        #[derive(Clone, Copy, Debug)]
        struct $name;

        impl WeierstrassCurve for $name {
            type Field = $field;
            type Scalar = $scalar;
            const A: FieldElement<$field> = $field::element($a);
            const B: FieldElement<$field> = $field::element($b);
            const SHAPE: CoefficientA = $shape;
            const GENERATOR_X: FieldElement<$field> = $field::element($x);
            const GENERATOR_Y: FieldElement<$field> = $field::element($y);
            const COFACTOR: u128 = 1;
        }
    };
}

// FIPS 186-5 / SP 800-186 section 3.2.1.3.
prime_field!(P256Field, U256, 32, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
prime_field!(P256Scalar, U256, 32, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const P256_A: &str = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
const P256_B: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
const P256_X: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const P256_Y: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
weierstrass_curve!(P256, P256Field, P256Scalar, CoefficientA::MinusThree, P256_A, P256_B, P256_X, P256_Y);
weierstrass_curve!(P256General, P256Field, P256Scalar, CoefficientA::General, P256_A, P256_B, P256_X, P256_Y);

// SEC 2 version 2 section 2.4.1.
prime_field!(Secp256k1Field, U256, 32, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
prime_field!(Secp256k1Scalar, U256, 32, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const SECP256K1_B: &str = "7";
const SECP256K1_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SECP256K1_Y: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
weierstrass_curve!(
    Secp256k1,
    Secp256k1Field,
    Secp256k1Scalar,
    CoefficientA::Zero,
    "0",
    SECP256K1_B,
    SECP256K1_X,
    SECP256K1_Y
);
weierstrass_curve!(
    Secp256k1General,
    Secp256k1Field,
    Secp256k1Scalar,
    CoefficientA::General,
    "0",
    SECP256K1_B,
    SECP256K1_X,
    SECP256K1_Y
);

// RFC 5639 section 3.4.
prime_field!(BrainpoolP256r1Field, U256, 32, "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377");
prime_field!(BrainpoolP256r1Scalar, U256, 32, "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7");
weierstrass_curve!(
    BrainpoolP256r1,
    BrainpoolP256r1Field,
    BrainpoolP256r1Scalar,
    CoefficientA::General,
    "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
    "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
    "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
    "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997"
);

// RFC 7748 section 4.1 and RFC 8032 section 5.1.
prime_field!(Field25519, U256, 32, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
prime_field!(Scalar25519, U256, 32, "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");

#[derive(Clone, Copy, Debug)]
struct Edwards25519;

impl EdwardsCurve for Edwards25519 {
    type Field = Field25519;
    type Scalar = Scalar25519;
    const A: FieldElement<Field25519> =
        Field25519::element("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec");
    const D: FieldElement<Field25519> =
        Field25519::element("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3");
    const GENERATOR_X: FieldElement<Field25519> =
        Field25519::element("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a");
    const GENERATOR_Y: FieldElement<Field25519> =
        Field25519::element("6666666666666666666666666666666666666666666666666666666666666658");
    const COFACTOR: u32 = 8;
    const ENCODED_BYTES: usize = 32;
}

#[derive(Clone, Copy, Debug)]
struct Curve25519;

impl MontgomeryCurve for Curve25519 {
    type Field = Field25519;
    // (486662 - 2) / 4 = 121665.
    const A24: FieldElement<Field25519> = Field25519::element("1db41");
    const BASE_U: FieldElement<Field25519> = Field25519::element("9");
    const SCALAR_BITS: u32 = 255;
    const COFACTOR: u32 = 8;
}

// RFC 7748 section 4.2 and RFC 8032 section 5.2.
prime_field!(
    Field448,
    U448,
    56,
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
);
prime_field!(
    Scalar448,
    U448,
    56,
    "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"
);

#[derive(Clone, Copy, Debug)]
struct Edwards448;

impl EdwardsCurve for Edwards448 {
    type Field = Field448;
    type Scalar = Scalar448;
    const A: FieldElement<Field448> = Field448::element("1");
    // -39081.
    const D: FieldElement<Field448> = Field448::element(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6756",
    );
    const GENERATOR_X: FieldElement<Field448> = Field448::element(
        "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e",
    );
    const GENERATOR_Y: FieldElement<Field448> = Field448::element(
        "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14",
    );
    const COFACTOR: u32 = 4;
    const ENCODED_BYTES: usize = 57;
}

#[derive(Clone, Copy, Debug)]
struct Curve448;

impl MontgomeryCurve for Curve448 {
    type Field = Field448;
    // (156326 - 2) / 4 = 39081.
    const A24: FieldElement<Field448> = Field448::element("98a9");
    const BASE_U: FieldElement<Field448> = Field448::element("5");
    const SCALAR_BITS: u32 = 448;
    const COFACTOR: u32 = 4;
}

#[test]
fn p256_is_a_group_of_prime_order() {
    ECChecks::new(1).weierstrass::<P256>();
    ECChecks::new(2).weierstrass::<P256General>();
}

#[test]
fn secp256k1_is_a_group_of_prime_order() {
    ECChecks::new(3).weierstrass::<Secp256k1>();
    ECChecks::new(4).weierstrass::<Secp256k1General>();
}

#[test]
fn brainpool_p256r1_is_a_group_of_prime_order() {
    ECChecks::new(5).weierstrass::<BrainpoolP256r1>();
}

/// The formulas for a = -3 and a = 0 give the points of the general formulas.
#[test]
fn weierstrass_formulas_agree() {
    let mut checks = ECChecks::new(6);
    for _ in 0..8 {
        let k = checks.random_scalar::<P256Scalar>();
        let special = ProjectivePoint::<P256>::generator().mul(&k).to_affine();
        let general = ProjectivePoint::<P256General>::generator().mul(&k).to_affine();
        assert_eq!((special.x(), special.y()), (general.x(), general.y()));
        let k = checks.random_scalar::<Secp256k1Scalar>();
        let special = ProjectivePoint::<Secp256k1>::generator().mul(&k).to_affine();
        let general = ProjectivePoint::<Secp256k1General>::generator().mul(&k).to_affine();
        assert_eq!((special.x(), special.y()), (general.x(), general.y()));
    }
}

/// RFC 6979 appendix A.2.5: the P-256 key pair and the nonces.
#[test]
fn p256_multiples_of_rfc6979() {
    ECChecks::rfc6979::<P256>("A.2.5.", "A.2.6.");
}

/// RFC 7027 appendix A.1: the key pairs and the shared point of brainpoolP256r1.
#[test]
fn brainpool_p256r1_exchange_of_rfc7027() {
    ECChecks::rfc7027::<BrainpoolP256r1>("A.1.", "A.2.");
}

#[test]
fn edwards25519_is_a_group() {
    ECChecks::new(7).edwards::<Edwards25519>();
    // RFC 8032 section 5.1: B = (x, 4/5) with x positive, encoded 58 66 ... 66.
    let mut encoded = [0; 32];
    EdwardsPoint::<Edwards25519>::generator().write_encoded(&mut encoded).unwrap();
    let mut expected = [0x66; 32];
    expected[0] = 0x58;
    assert_eq!(encoded, expected);
    let four_fifths = ECChecks::small::<Field25519>(4).mul(&ECChecks::small::<Field25519>(5).invert().unwrap());
    assert_eq!(Edwards25519::GENERATOR_Y, four_fifths);
    assert!(!Edwards25519::GENERATOR_X.is_odd().into_bool());
    // In edwards25519 a y has x only from its 255 bits: the top bit is the sign alone.
    let mut with_sign = expected;
    with_sign[31] |= 0x80;
    assert_eq!(
        EdwardsPoint::<Edwards25519>::from_encoded(&with_sign).unwrap(),
        EdwardsPoint::<Edwards25519>::generator().neg()
    );
}

#[test]
fn edwards448_is_a_group() {
    ECChecks::new(8).edwards::<Edwards448>();
    // The last byte of an edwards448 encoding holds the sign alone.
    let mut encoded = [0; 57];
    EdwardsPoint::<Edwards448>::generator().write_encoded(&mut encoded).unwrap();
    for bit in 0..7 {
        let mut changed = encoded;
        changed[56] |= 1 << bit;
        assert_eq!(EdwardsPoint::<Edwards448>::from_encoded(&changed), Err(ECError::InvalidEncoding));
    }
}

#[test]
fn curve25519_ladder_of_rfc7748() {
    ECChecks::rfc7748::<Curve25519>("X25519", "6.1.", "6.2.", cfg!(not(miri)));
}

#[test]
fn curve448_ladder_of_rfc7748() {
    ECChecks::rfc7748::<Curve448>("X448", "6.2.", "7.  Security", cfg!(not(miri)));
}

/// RFC 7748 section 5: the coordinate u is read modulo p, its unused bits ignored.
#[test]
fn montgomery_coordinates_are_decoded_as_rfc7748() {
    // 2^256 - 1: the top bit is ignored, leaving 2^255 - 1 = p + 18, which is reduced to 18.
    let mut bytes = [0xFF; 32];
    let point = MontgomeryPoint::<Curve25519>::from_bytes(&bytes).unwrap();
    assert_eq!(*point.u(), ECChecks::small::<Field25519>(18));
    // 2^255 - 18 = p + 1.
    bytes[31] = 0x7F;
    bytes[0] = 0xEE;
    assert_eq!(*MontgomeryPoint::<Curve25519>::from_bytes(&bytes).unwrap().u(), ECChecks::small::<Field25519>(1));
    let mut out = [0; 32];
    MontgomeryPoint::<Curve25519>::from_bytes(&bytes).unwrap().write_bytes(&mut out).unwrap();
    let mut one = [0; 32];
    one[0] = 1;
    assert_eq!(out, one);
    // X448 uses every bit; p + 1 = 2^448 - 2^224 decodes as 1.
    let mut bytes = [0xFF; 56];
    bytes[..28].fill(0);
    assert_eq!(*MontgomeryPoint::<Curve448>::from_bytes(&bytes).unwrap().u(), ECChecks::small::<Field448>(1));
    for size in [0, 31, 33] {
        assert_eq!(MontgomeryPoint::<Curve25519>::from_bytes(&vec![0; size]), Err(ECError::InvalidEncoding));
        assert_eq!(
            MontgomeryPoint::<Curve25519>::base().write_bytes(&mut vec![0; size]),
            Err(ECError::InvalidEncoding)
        );
    }
    // u = 0 has order dividing the cofactor: every multiple is 0.
    let zero = MontgomeryPoint::<Curve25519>::new(FieldElement::zero());
    assert_eq!(*zero.mul_value(&U256::from_le_bytes(&ECChecks::clamp(&[0x55; 32])).unwrap()).u(), FieldElement::zero());
}

/// RFC 7748 section 4.1: the birational map u = (1 + y) / (1 - y) takes
/// k × the edwards25519 base point to k × the curve25519 base point.
#[test]
fn edwards25519_maps_to_curve25519() {
    let mut checks = ECChecks::new(9);
    for _ in 0..6 {
        let k = checks.random_scalar::<Scalar25519>();
        let (_, y) = EdwardsPoint::<Edwards25519>::generator().mul(&k).to_affine();
        let u = FieldElement::one().add(&y).mul(&FieldElement::one().sub(&y).invert().unwrap());
        assert_eq!(*MontgomeryPoint::<Curve25519>::base().mul_value(&k.value()).u(), u);
    }
}

/// RFC 7748 section 4.2: the 4-isogeny u = y^2 / x^2 takes the edwards448
/// base point to u = 5 and k × it to k × the curve448 base point.
#[test]
fn edwards448_maps_to_curve448() {
    let isogeny = |point: &EdwardsPoint<Edwards448>| {
        let (x, y) = point.to_affine();
        y.square().mul(&x.square().invert().unwrap())
    };
    assert_eq!(isogeny(&EdwardsPoint::generator()), Curve448::BASE_U);
    let mut checks = ECChecks::new(10);
    for _ in 0..4 {
        let k = checks.random_scalar::<Scalar448>();
        let u = *MontgomeryPoint::<Curve448>::base().mul_value(&k.value()).u();
        assert_eq!(isogeny(&EdwardsPoint::<Edwards448>::generator().mul(&k)), u);
    }
}

/// Square roots for each case of the prime: 3 (mod 4) (P-256), 5 (mod 8)
/// (2^255 - 19), 1 (mod 8) (the order of P-256, by Tonelli–Shanks).
#[test]
fn square_roots_exist_exactly_for_squares() {
    fn check<F: PrimeField>(seed: u64) {
        let mut checks = ECChecks::new(seed);
        let p = *F::MODULUS.value();
        let euler = p.wrapping_sub(&FieldValue::<F>::ONE).shr(1);
        for number in 0..40 {
            let x = if number < 20 { ECChecks::small::<F>(number) } else { checks.random_scalar::<F>() };
            let square = x.square();
            let (root, is_square) = square.sqrt();
            assert!(is_square.into_bool());
            assert_eq!(root.square(), square);
            // Euler's criterion decides whether x itself is a square.
            let expected = x.is_zero().into_bool() || x.pow_vartime(&euler) == FieldElement::one();
            let (root, is_square) = x.sqrt();
            assert_eq!(is_square.into_bool(), expected, "{x:?}");
            if expected {
                assert_eq!(root.square(), x);
            }
        }
    }
    check::<P256Field>(11);
    check::<Field25519>(12);
    check::<P256Scalar>(13);
    check::<Secp256k1Scalar>(14);
    check::<Field448>(15);
}

#[test]
fn field_elements_are_encoded_at_their_length() {
    let element = ECChecks::small::<P256Field>(0x0102);
    let mut be = [0; 32];
    element.write_be_bytes(&mut be).unwrap();
    assert_eq!(&be[30..], &[1, 2]);
    assert_eq!(FieldElement::<P256Field>::from_be_bytes(&be).unwrap(), element);
    let mut le = [0; 32];
    element.write_le_bytes(&mut le).unwrap();
    assert_eq!(&le[..2], &[2, 1]);
    assert_eq!(FieldElement::<P256Field>::from_le_bytes(&le).unwrap(), element);
    assert!(FieldElement::<P256Field>::from_be_bytes(&be[1..]).is_err());
    assert!(FieldElement::<P256Field>::from_be_bytes(&[0; 33]).is_err());
    let mut prime = [0; 32];
    P256Field::MODULUS.value().write_be_bytes(&mut prime).unwrap();
    assert!(FieldElement::<P256Field>::from_be_bytes(&prime).is_err());
    assert_eq!(FieldElement::<P256Field>::from_value_reduced(P256Field::MODULUS.value()), FieldElement::zero());
    assert_eq!(FieldElement::<P256Field>::default(), FieldElement::zero());
    assert_eq!(ECChecks::small::<P256Field>(3).invert().unwrap().mul(&ECChecks::small(3)), FieldElement::one());
    assert!(FieldElement::<P256Field>::zero().invert().is_err());
}
