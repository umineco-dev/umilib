//! The curves of `umilib::crypto::curve`: each is a group of the order of
//! its specification with the encodings of SEC 1 or RFC 8032 (the checks of
//! `tests/common/ec.rs`), and gives the points of the RFCs: the keys and
//! nonces of RFC 6979, the exchanges of RFC 7027 and the ladder of RFC 7748.

use umilib::math::ec::{EdwardsCurve, EdwardsPoint, FieldElement, MontgomeryCurve, MontgomeryPoint};

use super::ec_checks::ECChecks;

#[cfg(umilib_feature = "crypto-curve-p256")]
#[test]
fn p256() {
    use umilib::crypto::curve::p256::P256;
    ECChecks::new(1).weierstrass::<P256>();
    ECChecks::rfc6979::<P256>("A.2.5.", "A.2.6.");
}

#[cfg(umilib_feature = "crypto-curve-p384")]
#[test]
fn p384() {
    use umilib::crypto::curve::p384::P384;
    ECChecks::new(2).weierstrass::<P384>();
    ECChecks::rfc6979::<P384>("A.2.6.", "A.2.7.");
}

#[cfg(umilib_feature = "crypto-curve-p521")]
#[test]
fn p521() {
    use umilib::crypto::curve::p521::P521;
    ECChecks::new(3).weierstrass::<P521>();
    ECChecks::rfc6979::<P521>("A.2.7.", "A.2.8.");
}

#[cfg(umilib_feature = "crypto-curve-secp256k1")]
#[test]
fn secp256k1() {
    ECChecks::new(4).weierstrass::<umilib::crypto::curve::secp256k1::Secp256k1>();
}

#[cfg(umilib_feature = "crypto-curve-sm2")]
#[test]
fn sm2() {
    ECChecks::new(5).weierstrass::<umilib::crypto::curve::sm2::SM2>();
}

#[cfg(umilib_feature = "crypto-curve-brainpool-p256r1")]
#[test]
fn brainpool_p256r1() {
    use umilib::crypto::curve::brainpool::p256r1::BrainpoolP256r1;
    ECChecks::new(6).weierstrass::<BrainpoolP256r1>();
    ECChecks::rfc7027::<BrainpoolP256r1>("A.1.", "A.2.");
}

#[cfg(umilib_feature = "crypto-curve-brainpool-p384r1")]
#[test]
fn brainpool_p384r1() {
    use umilib::crypto::curve::brainpool::p384r1::BrainpoolP384r1;
    ECChecks::new(7).weierstrass::<BrainpoolP384r1>();
    ECChecks::rfc7027::<BrainpoolP384r1>("A.2.", "A.3.");
}

#[cfg(umilib_feature = "crypto-curve-brainpool-p512r1")]
#[test]
fn brainpool_p512r1() {
    use umilib::crypto::curve::brainpool::p512r1::BrainpoolP512r1;
    ECChecks::new(8).weierstrass::<BrainpoolP512r1>();
    ECChecks::rfc7027::<BrainpoolP512r1>("A.3.", "Authors' Addresses");
}

#[cfg(umilib_feature = "crypto-curve-curve25519")]
#[test]
fn curve25519() {
    use umilib::crypto::curve::curve25519::{Curve25519, Curve25519Field, Edwards25519};
    ECChecks::new(9).edwards::<Edwards25519>();
    ECChecks::rfc7748::<Curve25519>("X25519", "6.1.", "6.2.", false);
    // RFC 8032 section 5.1: B = (x, 4/5) with x even, encoded 58 66 ... 66.
    let mut encoded = [0; 32];
    EdwardsPoint::<Edwards25519>::generator().write_encoded(&mut encoded).unwrap();
    let mut expected = [0x66; 32];
    expected[0] = 0x58;
    assert_eq!(encoded, expected);
    let four_fifths = ECChecks::small::<Curve25519Field>(4).mul(&ECChecks::small(5).invert().unwrap());
    assert_eq!(Edwards25519::GENERATOR_Y, four_fifths);
    // RFC 7748 section 4.1: the base points correspond, u = (1 + y) / (1 - y).
    let y = Edwards25519::GENERATOR_Y;
    let one = FieldElement::<Curve25519Field>::one();
    assert_eq!(one.add(&y).mul(&one.sub(&y).invert().unwrap()), Curve25519::BASE_U);
    assert_eq!(*MontgomeryPoint::<Curve25519>::base().u(), ECChecks::small(9));
}

#[cfg(umilib_feature = "crypto-curve-curve448")]
#[test]
fn curve448() {
    use umilib::crypto::curve::curve448::{Curve448, Edwards448};
    ECChecks::new(10).edwards::<Edwards448>();
    ECChecks::rfc7748::<Curve448>("X448", "6.2.", "7.  Security", false);
    // RFC 7748 section 4.2: the 4-isogeny u = y^2 / x^2 maps the base points.
    let (x, y) = (Edwards448::GENERATOR_X, Edwards448::GENERATOR_Y);
    assert_eq!(y.square().mul(&x.square().invert().unwrap()), Curve448::BASE_U);
}
