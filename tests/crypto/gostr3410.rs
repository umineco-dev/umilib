//! GOST R 34.10-2012 against the example of RFC 7091 section 7 and the
//! curves of TC 26 against the parameters of RFC 7836 and RFC 4357.

use umilib::crypto::CryptoError;
use umilib::crypto::curve::gost::{GOST256A, GOST256B, GOST256C, GOST256D, GOST512A, GOST512B, GOST512C};
use umilib::crypto::gostr3410::{GOSTR3410, GOSTR3410Signature, GOSTR3410SigningKey};
use umilib::hash::streebog::{Streebog256, Streebog512};
use umilib::math::bigint::U256;
use umilib::math::ec::{AffinePoint, CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use umilib::math::modular::Modulus;

use super::ec_checks::ECChecks;
use crate::Vectors;

/// The hexadecimal values "name = 0x..." of RFC 7091 section 7, continued
/// on the next line after "\\".
fn rfc7091(name: &str, occurrence: usize) -> Vec<u8> {
    let text = Vectors::read("crypto/gostr3410/rfc7091.txt");
    let start = text.find("\n7.  Test Examples").unwrap();
    let lines: Vec<&str> = text[start..].lines().map(str::trim).collect();
    let prefix = format!("{name} = 0x");
    let index = lines.iter().enumerate().filter(|(_, line)| line.starts_with(&prefix)).nth(occurrence).unwrap().0;
    let mut hex = lines[index][prefix.len()..].to_owned();
    let mut next = index;
    while hex.ends_with("\\\\") {
        hex.truncate(hex.len() - 2);
        next += 1;
        hex.push_str(lines[next]);
    }
    let padded = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex };
    let bytes = Vectors::hex(&padded);
    let mut value = vec![0u8; 32usize.saturating_sub(bytes.len())];
    value.extend(bytes);
    value
}

#[derive(Clone, Copy, Debug)]
struct TestField;

impl PrimeField for TestField {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "8000000000000000000000000000000000000000000000000000000000000431",
    ));
    const BYTES: usize = 32;
}

#[derive(Clone, Copy, Debug)]
struct TestScalar;

impl PrimeField for TestScalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3",
    ));
    const BYTES: usize = 32;
}

const fn element(hex: &str) -> FieldElement<TestField> {
    FieldElement::from_residue(TestField::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)))
}

/// The curve of the example of RFC 7091 section 7.1.
#[derive(Clone, Copy, Debug)]
struct TestCurve;

impl WeierstrassCurve for TestCurve {
    type Field = TestField;
    type Scalar = TestScalar;
    const A: FieldElement<TestField> = element("7");
    const B: FieldElement<TestField> = element("5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e");
    const SHAPE: CoefficientA = CoefficientA::General;
    const GENERATOR_X: FieldElement<TestField> = element("2");
    const GENERATOR_Y: FieldElement<TestField> =
        element("08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8");
    const COFACTOR: u128 = 1;
}

/// RFC 7091 section 7: the parameters, the keys, and the signature (r, s)
/// of e, which verifies; sections 7.2 and 7.3 give the same e.
#[test]
fn rfc7091_example() {
    let field = |name: &str| FieldElement::<TestField>::from_be_bytes(&rfc7091(name, 0)).unwrap();
    let scalar = |name: &str| FieldElement::<TestScalar>::from_be_bytes(&rfc7091(name, 0)).unwrap();
    assert_eq!(TestCurve::B, field("b"));
    assert_eq!(TestCurve::GENERATOR_Y, field("y_p"));
    ECChecks::new(1).weierstrass::<TestCurve>();
    let key = GOSTR3410SigningKey::<TestCurve>::new(scalar("d")).unwrap();
    assert_eq!(*key.verifying_key().point(), AffinePoint::new(field("x_q"), field("y_q")).unwrap());
    let e = scalar("e");
    let signature = GOSTR3410Signature::<TestCurve>::new(scalar("r"), scalar("s")).unwrap();
    assert_eq!(GOSTR3410::<TestCurve, Streebog256>::verify_scalar(key.verifying_key(), &e, &signature), Ok(()));
    assert_eq!(e.invert().unwrap(), scalar("v"));
    let other = e.add(&FieldElement::one());
    assert_eq!(
        GOSTR3410::<TestCurve, Streebog256>::verify_scalar(key.verifying_key(), &other, &signature),
        Err(CryptoError::InvalidSignature)
    );
    // The encoding of RFC 9215 section 2: s then r, big-endian.
    let mut bytes = [0u8; 64];
    signature.write_bytes(&mut bytes).unwrap();
    assert_eq!(&bytes[..32], &rfc7091("s", 0)[..]);
    assert_eq!(&bytes[32..], &rfc7091("r", 0)[..]);
    assert_eq!(GOSTR3410Signature::<TestCurve>::from_bytes(&bytes).unwrap(), signature);
    // Our own signatures of e verify.
    let own = GOSTR3410::<TestCurve, Streebog256>::sign_scalar(&key, &e, &[]).unwrap();
    assert_eq!(GOSTR3410::<TestCurve, Streebog256>::verify_scalar(key.verifying_key(), &e, &own), Ok(()));
}

/// The INTEGERs of a parameter set of RFC 7836 appendix A (hexadecimal
/// octets on the lines after each INTEGER), in order.
fn rfc7836_integers(name: &str) -> Vec<Vec<u8>> {
    let text = Vectors::read("crypto/gostr3410/rfc7836.txt");
    let start = text.find(&format!("Parameter set: {name}")).unwrap();
    let end = text[start + 10..].find("Parameter set:").map_or(text.len(), |end| start + 10 + end);
    let mut integers: Vec<String> = Vec::new();
    for line in text[start..end].lines().map(str::trim) {
        let octets = !line.is_empty()
            && line.split_whitespace().all(|word| word.len() == 2 && u8::from_str_radix(word, 16).is_ok());
        if line == "INTEGER" {
            integers.push(String::new());
        } else if octets && let Some(integer) = integers.last_mut() {
            integer.push_str(&line.replace(' ', ""));
        }
    }
    integers.iter().map(|hex| Vectors::hex(hex).into_iter().skip_while(|byte| *byte == 0).collect()).collect()
}

/// The checks of a curve whose parameters (p, a, b, q, x, y) are `values`.
fn check_curve<C: WeierstrassCurve>(values: [&[u8]; 6]) {
    let field = |bytes: &[u8]| {
        let mut padded = vec![0u8; <C::Field as PrimeField>::BYTES - bytes.len()];
        padded.extend_from_slice(bytes);
        FieldElement::<C::Field>::from_be_bytes(&padded).unwrap()
    };
    use umilib::math::bigint::UnsignedInteger;
    use umilib::math::modular::ModularArithmetic;
    let mut p = vec![0u8; <C::Field as PrimeField>::BYTES];
    <C::Field as PrimeField>::MODULUS.value().write_be_bytes(&mut p).unwrap();
    assert_eq!(p.iter().copied().skip_while(|byte| *byte == 0).collect::<Vec<u8>>(), values[0]);
    let mut q = vec![0u8; <C::Scalar as PrimeField>::BYTES];
    <C::Scalar as PrimeField>::MODULUS.value().write_be_bytes(&mut q).unwrap();
    assert_eq!(q.iter().copied().skip_while(|byte| *byte == 0).collect::<Vec<u8>>(), values[3]);
    assert_eq!(
        (C::A, C::B, C::GENERATOR_X, C::GENERATOR_Y),
        (field(values[1]), field(values[2]), field(values[4]), field(values[5]))
    );
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn tc26_curves() {
    // RFC 7836 appendix A.1: (p, a, b, m, q, x, y); A.2: (p, a, b, e, d, m, q, x, y, u, v).
    let a1 = |name: &str| rfc7836_integers(name);
    let set = a1("id-tc26-gost-3410-12-512-paramSetA");
    check_curve::<GOST512A>([&set[0], &set[1], &set[2], &set[4], &set[5], &set[6]]);
    let set = a1("id-tc26-gost-3410-12-512-paramSetB");
    check_curve::<GOST512B>([&set[0], &set[1], &set[2], &set[4], &set[5], &set[6]]);
    let set = a1("id-tc26-gost-3410-2012-256-paramSetA");
    check_curve::<GOST256A>([&set[0], &set[1], &set[2], &set[6], &set[7], &set[8]]);
    let set = a1("id-tc26-gost-3410-2012-512-paramSetC");
    check_curve::<GOST512C>([&set[0], &set[1], &set[2], &set[6], &set[7], &set[8]]);

    super::ecdsa::check_scheme::<GOSTR3410<GOST256A, Streebog256>>();
    super::ecdsa::check_scheme::<GOSTR3410<GOST256B, Streebog256>>();
    super::ecdsa::check_scheme::<GOSTR3410<GOST256C, Streebog256>>();
    super::ecdsa::check_scheme::<GOSTR3410<GOST256D, Streebog256>>();
    super::ecdsa::check_scheme::<GOSTR3410<GOST512A, Streebog512>>();
    super::ecdsa::check_scheme::<GOSTR3410<GOST512B, Streebog512>>();
    super::ecdsa::check_scheme::<GOSTR3410<GOST512C, Streebog512>>();
    ECChecks::new(2).weierstrass::<GOST256B>();
    ECChecks::new(3).weierstrass::<GOST256C>();
    ECChecks::new(4).weierstrass::<GOST256D>();
    ECChecks::new(5).weierstrass::<GOST512A>();
    ECChecks::new(6).weierstrass::<GOST512B>();
    // The curves of cofactor 4: the formulas stay exact in the subgroup of order q.
    ECChecks::new(7).weierstrass::<GOST256A>();
    ECChecks::new(8).weierstrass::<GOST512C>();
}
