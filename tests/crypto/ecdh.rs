//! ECDH (SEC 1 section 3.3.1, SP 800-56A section 5.7.1.2) and X25519/X448
//! (RFC 7748) against the CAVP ECC CDH primitive tests, the vectors of
//! RFC 7748 and Project Wycheproof, and the requirements on keys of their
//! specifications.

use umilib::crypto::ecdh::{ECDH, XDH};
use umilib::crypto::random::HMACDRBG;
use umilib::crypto::{CryptoError, KeyAgreement};
use umilib::hash::sha::v2::SHA256;
use umilib::math::ec::{AffinePoint, MontgomeryCurve, PrimeField, WeierstrassCurve};

use crate::{JSON, Record, Vectors, Wycheproof};

/// The shared secret of `private` and `public`, or the error of the first
/// step that refuses them.
fn agree<K: KeyAgreement>(private: &[u8], public: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let private = K::private_key_from_bytes(private)?;
    let public = K::public_key_from_bytes(public)?;
    let mut shared = vec![0; K::SHARED_SECRET_SIZE];
    K::agree(&private, &public, &mut shared)?;
    Ok(shared)
}

/// The private key of a test, as an integer of any length, padded or cut to `length` bytes.
fn private_bytes(hex: &str, length: usize) -> Vec<u8> {
    let bytes = Vectors::hex(hex);
    let significant: Vec<u8> = bytes.iter().copied().skip_while(|byte| *byte == 0).collect();
    assert!(significant.len() <= length, "{hex}");
    let mut padded = vec![0; length - significant.len()];
    padded.extend(significant);
    padded
}

/// What every key agreement must do: two parties agree, and keys survive
/// their encodings.
fn check_agreement<K: KeyAgreement>() {
    let mut random = HMACDRBG::<SHA256>::new(&[7; 32], &[8; 16], b"ecdh").unwrap();
    for _ in 0..4 {
        let (a, b) = (K::generate(&mut random).unwrap(), K::generate(&mut random).unwrap());
        let (public_a, public_b) = (K::public_key(&a), K::public_key(&b));
        let (mut shared_a, mut shared_b) = (vec![0; K::SHARED_SECRET_SIZE], vec![0; K::SHARED_SECRET_SIZE]);
        K::agree(&a, &public_b, &mut shared_a).unwrap();
        K::agree(&b, &public_a, &mut shared_b).unwrap();
        assert_eq!(shared_a, shared_b);
        assert_ne!(public_a, public_b);

        let mut encoded = vec![0; K::PRIVATE_KEY_SIZE];
        K::write_private_key(&a, &mut encoded).unwrap();
        let decoded = K::private_key_from_bytes(&encoded).unwrap();
        assert_eq!(K::public_key(&decoded), public_a);
        let mut encoded = vec![0; K::PUBLIC_KEY_SIZE];
        K::write_public_key(&public_a, &mut encoded).unwrap();
        assert_eq!(K::public_key_from_bytes(&encoded).unwrap(), public_a);

        for length in [0, K::PRIVATE_KEY_SIZE - 1, K::PRIVATE_KEY_SIZE + 1] {
            assert_eq!(K::private_key_from_bytes(&vec![1; length]).err(), Some(CryptoError::InvalidKey));
            assert_eq!(K::write_private_key(&a, &mut vec![0; length]), Err(CryptoError::InputLength { length }));
        }
        for length in [0, K::PUBLIC_KEY_SIZE - 1, K::PUBLIC_KEY_SIZE + 1] {
            assert_eq!(K::public_key_from_bytes(&vec![4; length]).err(), Some(CryptoError::InvalidKey));
            assert_eq!(K::write_public_key(&public_a, &mut vec![0; length]), Err(CryptoError::InputLength { length }));
        }
        for length in [0, K::SHARED_SECRET_SIZE - 1, K::SHARED_SECRET_SIZE + 1] {
            assert_eq!(K::agree(&a, &public_b, &mut vec![0; length]), Err(CryptoError::InputLength { length }));
        }
        // Private keys print nothing of the key.
        assert!(format!("{a:?}").ends_with("(..)"));
    }
}

/// SEC 1 section 2.3.6 and 3.2.2.1: the private key is in 1..n, the public
/// key a point of the curve other than the identity.
fn check_weierstrass_keys<C: WeierstrassCurve>() {
    check_agreement::<ECDH<C>>();
    let size = <ECDH<C> as KeyAgreement>::PRIVATE_KEY_SIZE;
    assert_eq!(size, <C::Scalar as PrimeField>::BYTES);
    assert_eq!(<ECDH<C> as KeyAgreement>::PUBLIC_KEY_SIZE, 1 + 2 * <C::Field as PrimeField>::BYTES);
    assert_eq!(<ECDH<C> as KeyAgreement>::SHARED_SECRET_SIZE, <C::Field as PrimeField>::BYTES);
    // 0 and n are refused, n - 1 accepted.
    assert_eq!(ECDH::<C>::private_key_from_bytes(&vec![0; size]).err(), Some(CryptoError::InvalidKey));
    let mut order = vec![0; size];
    use umilib::math::bigint::UnsignedInteger;
    use umilib::math::modular::ModularArithmetic;
    <C::Scalar as PrimeField>::MODULUS.value().write_be_bytes(&mut order).unwrap();
    assert_eq!(ECDH::<C>::private_key_from_bytes(&order).err(), Some(CryptoError::InvalidKey));
    *order.last_mut().unwrap() -= 1;
    let largest = ECDH::<C>::private_key_from_bytes(&order).unwrap();
    // (n - 1) G = -G.
    let public = ECDH::<C>::public_key(&largest);
    assert_eq!(*public.point(), AffinePoint::<C>::generator().neg());
    // The identity is not a public key.
    assert_eq!(ECDH::<C>::public_key_from_bytes(&[0]).err(), Some(CryptoError::InvalidKey));
    // The compressed encoding of a key is accepted and names the same key.
    let mut compressed = vec![0; AffinePoint::<C>::encoded_length(true)];
    public.write_encoded(&mut compressed, true).unwrap();
    assert_eq!(ECDH::<C>::public_key_from_bytes(&compressed).unwrap(), public);
}

/// CAVP: QIUT = dIUT G and ZIUT = x(dIUT QCAVS) for the records under `[curve]`.
fn check_cavp<C: WeierstrassCurve>(curve: &str) {
    let records: Vec<Record> = Record::all("crypto/ecdh/KAS_ECC_CDH_PrimitiveTest.txt")
        .into_iter()
        .filter(|record| record.header.contains_key(curve))
        .collect();
    assert_eq!(records.len(), 25, "{curve}");
    let field = <C::Field as PrimeField>::BYTES;
    for record in &records {
        let point = |x: &str, y: &str| {
            let mut encoded = vec![4];
            encoded.extend(private_bytes(record.field(x), field));
            encoded.extend(private_bytes(record.field(y), field));
            encoded
        };
        let private = private_bytes(record.field("dIUT"), <C::Scalar as PrimeField>::BYTES);
        let key = ECDH::<C>::private_key_from_bytes(&private).unwrap();
        let mut public = vec![0; <ECDH<C> as KeyAgreement>::PUBLIC_KEY_SIZE];
        ECDH::<C>::write_public_key(&ECDH::<C>::public_key(&key), &mut public).unwrap();
        assert_eq!(public, point("QIUTx", "QIUTy"), "{curve} {}", record.field("COUNT"));
        let shared = agree::<ECDH<C>>(&private, &point("QCAVSx", "QCAVSy")).unwrap();
        assert_eq!(shared, private_bytes(record.field("ZIUT"), field), "{curve} {}", record.field("COUNT"));
    }
}

/// A Wycheproof test of a key agreement: valid results must be computed,
/// invalid ones refused, and acceptable ones, if computed, right.
fn check_wycheproof_test<K: KeyAgreement>(test: &JSON, public: &[u8], label: &str) {
    let private = private_bytes(test.field("private").as_str(), K::PRIVATE_KEY_SIZE);
    let result = agree::<K>(&private, public);
    match test.field("result").as_str() {
        "valid" => assert_eq!(result, Ok(test.bytes("shared")), "{label}"),
        "invalid" => assert!(result.is_err(), "{label}: {result:?}"),
        _ => {
            if let Ok(shared) = result {
                assert_eq!(shared, test.bytes("shared"), "{label}");
            }
        }
    }
}

/// The Wycheproof files of SEC 1 points.
fn check_wycheproof_points<C: WeierstrassCurve>(file: &str, count: usize) {
    let tests = Wycheproof::tests(&format!("crypto/ecdh/{file}"));
    assert_eq!(tests.len(), count, "{file}");
    for (_, test) in &tests {
        let label = format!("{file} {}", test.field("tcId").as_usize());
        check_wycheproof_test::<ECDH<C>>(test, &test.bytes("public"), &label);
    }
}

/// A reader of the DER structures of the Wycheproof files: SEC 1 section
/// C.3, a SubjectPublicKeyInfo naming the curve `oid`.
struct SubjectPublicKeyInfo;

impl SubjectPublicKeyInfo {
    /// The tag and contents of the element at the start of `bytes`, and the
    /// rest; DER only (definite, minimal lengths).
    fn element(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let (&tag, rest) = bytes.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (length, rest) = if first < 0x80 {
            (first as usize, rest)
        } else {
            let count = (first & 0x7F) as usize;
            if count == 0 || count > 2 || rest.len() < count || rest[0] == 0 {
                return None;
            }
            let length = rest[..count].iter().fold(0usize, |length, byte| (length << 8) | *byte as usize);
            if length < 0x80 {
                return None;
            }
            (length, &rest[count..])
        };
        (rest.len() >= length).then(|| (tag, &rest[..length], &rest[length..]))
    }

    /// The point of `bytes` if it is a SubjectPublicKeyInfo of an
    /// id-ecPublicKey of the named curve `oid` (RFC 5480 section 2).
    fn point<'a>(bytes: &'a [u8], oid: &[u8]) -> Option<&'a [u8]> {
        const EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        let (0x30, info, []) = SubjectPublicKeyInfo::element(bytes)? else { return None };
        let (0x30, algorithm, rest) = SubjectPublicKeyInfo::element(info)? else { return None };
        let (0x03, key, []) = SubjectPublicKeyInfo::element(rest)? else { return None };
        let (0x06, kind, parameters) = SubjectPublicKeyInfo::element(algorithm)? else { return None };
        let (0x06, curve, []) = SubjectPublicKeyInfo::element(parameters)? else { return None };
        let (0, point) = key.split_first()? else { return None };
        (kind == EC_PUBLIC_KEY && curve == oid).then_some(point)
    }
}

/// The Wycheproof files of SubjectPublicKeyInfo structures of the curve `oid`.
fn check_wycheproof_structures<C: WeierstrassCurve>(file: &str, oid: &[u8], count: usize) {
    let tests = Wycheproof::tests(&format!("crypto/ecdh/{file}"));
    assert_eq!(tests.len(), count, "{file}");
    let mut checked = 0;
    for (_, test) in &tests {
        let label = format!("{file} {}", test.field("tcId").as_usize());
        match SubjectPublicKeyInfo::point(&test.bytes("public"), oid) {
            Some(point) => {
                check_wycheproof_test::<ECDH<C>>(test, point, &label);
                checked += 1;
            }
            None => assert_ne!(test.field("result").as_str(), "valid", "{label}"),
        }
    }
    assert!(checked * 2 > count, "{file}: {checked} of {count}");
}

/// The Wycheproof files of X25519 and X448.
fn check_wycheproof_montgomery<C: MontgomeryCurve>(file: &str, count: usize) {
    let tests = Wycheproof::tests(&format!("crypto/ecdh/{file}"));
    assert_eq!(tests.len(), count, "{file}");
    for (_, test) in &tests {
        let label = format!("{file} {}", test.field("tcId").as_usize());
        let zero = test.field("flags").items().iter().any(|flag| flag.as_str() == "ZeroSharedSecret");
        let result = agree::<XDH<C>>(&test.bytes("private"), &test.bytes("public"));
        if zero {
            // RFC 7748 section 6: a shared secret of zero is refused here.
            assert!(test.bytes("shared").iter().all(|byte| *byte == 0), "{label}");
            assert_eq!(result, Err(CryptoError::InvalidKey), "{label}");
        } else if test.field("result").as_str() == "invalid" {
            assert_eq!(result, Err(CryptoError::InvalidKey), "{label}");
        } else {
            assert_eq!(result, Ok(test.bytes("shared")), "{label}");
        }
    }
}

/// RFC 7748 sections 5.2 and 6 through the key agreement.
fn check_rfc7748<C: MontgomeryCurve>(name: &str, section: &str, end: &str) {
    use crate::RFC;
    let tests = RFC::section("math/ec/rfc7748.txt", "5.2.  Test Vectors", "6.  Diffie");
    let (pairs, iterated) = tests.split_at(tests.find("   The second type").unwrap());
    let pick = |text: &str| {
        let (x25519, x448) = text.split_at(text.find("   X448:").unwrap());
        if name == "X25519" { x25519.to_owned() } else { x448.to_owned() }
    };
    let (pairs, iterated) = (pick(pairs), pick(iterated));
    let scalars = RFC::values(&pairs, "Input scalar:");
    let inputs = RFC::values(&pairs, "Input u-coordinate:");
    let outputs = RFC::values(&pairs, "Output u-coordinate:");
    for ((scalar, u), expected) in scalars.iter().zip(&inputs).zip(&outputs) {
        assert_eq!(agree::<XDH<C>>(&Vectors::hex(scalar), &Vectors::hex(u)), Ok(Vectors::hex(expected)));
    }
    let size = <XDH<C> as KeyAgreement>::PUBLIC_KEY_SIZE;
    let mut base = vec![0; size];
    C::BASE_U.write_le_bytes(&mut base).unwrap();
    let (mut k, mut u) = (base.clone(), base.clone());
    let counts: &[(usize, &str)] = if cfg!(miri) {
        &[(1, "After one iteration:")]
    } else {
        &[(1, "After one iteration:"), (1000, "After 1,000 iterations:")]
    };
    let mut done = 0;
    for (count, label) in counts {
        while done < *count {
            let result = agree::<XDH<C>>(&k, &u).unwrap();
            u = core::mem::replace(&mut k, result);
            done += 1;
        }
        assert_eq!(k, Vectors::hex(&RFC::value(&iterated, label)), "{name} {label}");
    }
    let exchange = RFC::section("math/ec/rfc7748.txt", section, end);
    let a = XDH::<C>::private_key_from_bytes(&Vectors::hex(&RFC::value(&exchange, "Alice's private key, a:"))).unwrap();
    let b = XDH::<C>::private_key_from_bytes(&Vectors::hex(&RFC::value(&exchange, "Bob's private key, b:"))).unwrap();
    for (key, who, letter) in [(&a, "Alice", "a"), (&b, "Bob", "b")] {
        let mut public = vec![0; size];
        XDH::<C>::write_public_key(&XDH::<C>::public_key(key), &mut public).unwrap();
        let label = format!("{who}'s public key, {name}({letter}, {}):", base[0]);
        assert_eq!(public, Vectors::hex(&RFC::value(&exchange, &label)));
    }
    let mut shared = vec![0; size];
    XDH::<C>::agree(&a, &XDH::<C>::public_key(&b), &mut shared).unwrap();
    assert_eq!(shared, Vectors::hex(&RFC::value(&exchange, "Their shared secret, K:")));
}

#[cfg(umilib_feature = "crypto-curve-p256")]
#[test]
fn p256() {
    use umilib::crypto::curve::p256::P256;
    check_weierstrass_keys::<P256>();
    check_cavp::<P256>("P-256");
    check_wycheproof_points::<P256>("ecdh_secp256r1_ecpoint_test.json", 355);
}

#[cfg(umilib_feature = "crypto-curve-p384")]
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn p384() {
    use umilib::crypto::curve::p384::P384;
    check_weierstrass_keys::<P384>();
    check_cavp::<P384>("P-384");
    check_wycheproof_points::<P384>("ecdh_secp384r1_ecpoint_test.json", 790);
}

#[cfg(umilib_feature = "crypto-curve-p521")]
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn p521() {
    use umilib::crypto::curve::p521::P521;
    check_weierstrass_keys::<P521>();
    check_cavp::<P521>("P-521");
    check_wycheproof_points::<P521>("ecdh_secp521r1_ecpoint_test.json", 661);
}

#[cfg(umilib_feature = "crypto-curve-secp256k1")]
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn secp256k1() {
    use umilib::crypto::curve::secp256k1::Secp256k1;
    check_weierstrass_keys::<Secp256k1>();
    let oid = [0x2B, 0x81, 0x04, 0x00, 0x0A];
    check_wycheproof_structures::<Secp256k1>("ecdh_secp256k1_test.json", &oid, 752);
}

#[cfg(umilib_feature = "crypto-curve-brainpool")]
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn brainpool() {
    use umilib::crypto::curve::brainpool::p256r1::BrainpoolP256r1;
    use umilib::crypto::curve::brainpool::p384r1::BrainpoolP384r1;
    use umilib::crypto::curve::brainpool::p512r1::BrainpoolP512r1;
    // 1.3.36.3.3.2.8.1.1 followed by 7, 11 or 13 (RFC 5639 section 4.1).
    let oid = |last: u8| [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, last];
    check_weierstrass_keys::<BrainpoolP256r1>();
    check_wycheproof_structures::<BrainpoolP256r1>("ecdh_brainpoolP256r1_test.json", &oid(7), 804);
    check_weierstrass_keys::<BrainpoolP384r1>();
    check_wycheproof_structures::<BrainpoolP384r1>("ecdh_brainpoolP384r1_test.json", &oid(11), 936);
    check_weierstrass_keys::<BrainpoolP512r1>();
    check_wycheproof_structures::<BrainpoolP512r1>("ecdh_brainpoolP512r1_test.json", &oid(13), 794);
}

#[cfg(umilib_feature = "crypto-curve-curve25519")]
#[test]
fn x25519() {
    use umilib::crypto::curve::curve25519::Curve25519;
    use umilib::crypto::ecdh::X25519;
    check_agreement::<X25519>();
    check_rfc7748::<Curve25519>("X25519", "6.1.", "6.2.");
    check_wycheproof_montgomery::<Curve25519>("x25519_test.json", 518);
    // decodeScalar25519: the low 3 bits and the top bit are ignored, bit 254 is set.
    let mut scalar = [0u8; 32];
    let public = [9u8; 32];
    let reference = agree::<X25519>(&scalar, &public).unwrap();
    scalar[0] = 7;
    scalar[31] = 0xC0;
    assert_eq!(agree::<X25519>(&scalar, &public).unwrap(), reference);
}

#[cfg(umilib_feature = "crypto-curve-curve448")]
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn x448() {
    use umilib::crypto::curve::curve448::Curve448;
    use umilib::crypto::ecdh::X448;
    check_agreement::<X448>();
    check_rfc7748::<Curve448>("X448", "6.2.", "7.  Security");
    check_wycheproof_montgomery::<Curve448>("x448_test.json", 510);
    // decodeScalar448: the low 2 bits are ignored, bit 447 is set.
    let mut scalar = [0u8; 56];
    let public = [5u8; 56];
    let reference = agree::<X448>(&scalar, &public).unwrap();
    scalar[0] = 3;
    scalar[55] = 0x80;
    assert_eq!(agree::<X448>(&scalar, &public).unwrap(), reference);
}
