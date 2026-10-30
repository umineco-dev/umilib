//! DSA (FIPS 186-4 section 4) against the deterministic signatures of RFC
//! 6979 and Project Wycheproof (DER and IEEE P1363 signatures).

use umilib::crypto::CryptoError;
use umilib::crypto::dsa::{DSA, DSAParameters, DSASignature, DSASigningKey, DSAVerifyingKey};
use umilib::crypto::random::HMACDRBG;
use umilib::hash::CryptographicDigest;
use umilib::hash::sha::v1::SHA1;
use umilib::hash::sha::v2::{SHA224, SHA256, SHA384, SHA512};
use umilib::math::bigint::BoxedUint;

use crate::{RFC, Vectors, Wycheproof};

fn integer(hex: &str) -> BoxedUint {
    let padded = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex.to_owned() };
    let bytes = Vectors::hex(&padded);
    BoxedUint::from_be_bytes(&bytes, (bytes.len().max(1) * 8) as u32).unwrap()
}

/// RFC 6979 appendix A.2.1 or A.2.2: the key pair and the signatures of
/// "sample" and "test" with SHA-1 to SHA-512.
fn check_rfc6979(start: &str, end: &str) {
    let section = RFC::section("math/ec/rfc6979.txt", start, end);
    let value = |prefix: &str| integer(&RFC::value_after(&section, prefix));
    let parameters = DSAParameters::new(&value("p = "), &value("q = "), &value("g = ")).unwrap();
    let key = DSASigningKey::new(parameters.clone(), &value("x = ")).unwrap();
    assert!(key.verifying_key().y().compare_vartime(&value("y = ")).is_eq(), "{start}");
    let headers: Vec<&str> = section.lines().map(str::trim).filter(|line| line.starts_with("With SHA-")).collect();
    let (rs, ss) = (RFC::values_after(&section, "r = "), RFC::values_after(&section, "s = "));
    assert_eq!((headers.len(), rs.len(), ss.len()), (10, 10, 10));
    for ((header, r), s) in headers.iter().zip(&rs).zip(&ss) {
        let message = if header.ends_with("\"sample\":") { &b"sample"[..] } else { b"test" };
        fn sign<H: CryptographicDigest + Default>(key: &DSASigningKey, message: &[u8]) -> DSASignature {
            let signature = DSA::<H>::sign(key, message).unwrap();
            assert_eq!(DSA::<H>::verify(key.verifying_key(), message, &signature), Ok(()));
            assert_eq!(DSA::<H>::verify(key.verifying_key(), b"other", &signature), Err(CryptoError::InvalidSignature));
            signature
        }
        let signature = match header.trim_start_matches("With ").split(',').next().unwrap() {
            "SHA-1" => sign::<SHA1>(&key, message),
            "SHA-224" => sign::<SHA224>(&key, message),
            "SHA-256" => sign::<SHA256>(&key, message),
            "SHA-384" => sign::<SHA384>(&key, message),
            "SHA-512" => sign::<SHA512>(&key, message),
            other => panic!("{other}"),
        };
        assert!(signature.r().compare_vartime(&integer(r)).is_eq(), "{start} {header}");
        assert!(signature.s().compare_vartime(&integer(s)).is_eq(), "{start} {header}");
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn rfc6979() {
    check_rfc6979("A.2.1.", "A.2.2.");
    check_rfc6979("A.2.2.", "A.2.3.");
}

fn check_wycheproof<H: CryptographicDigest + Default>(file: &str) {
    let tests = Wycheproof::tests(&format!("crypto/dsa/{file}"));
    assert!(!tests.is_empty());
    let p1363 = file.ends_with("_p1363_test.json");
    for (group, test) in &tests {
        let label = format!("{file} {}", test.field("tcId").as_usize());
        let key = group.field("publicKey");
        let field = |name: &str| integer(key.field(name).as_str());
        let parameters = DSAParameters::new(&field("p"), &field("q"), &field("g")).unwrap();
        let verifying = DSAVerifyingKey::new(parameters.clone(), &field("y")).unwrap();
        let bytes = test.bytes("sig");
        let signature = if p1363 {
            DSASignature::from_bytes(&parameters, &bytes)
        } else {
            #[cfg(umilib_feature = "codec-asn1-der")]
            {
                DSASignature::from_der(&parameters, &bytes)
            }
            #[cfg(not(umilib_feature = "codec-asn1-der"))]
            return;
        };
        let result = signature.and_then(|signature| DSA::<H>::verify(&verifying, &test.bytes("msg"), &signature));
        match test.field("result").as_str() {
            "valid" => assert_eq!(result, Ok(()), "{label}"),
            "invalid" => assert_eq!(result, Err(CryptoError::InvalidSignature), "{label}"),
            _ => {}
        }
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn wycheproof() {
    check_wycheproof::<SHA224>("dsa_2048_224_sha224_test.json");
    check_wycheproof::<SHA224>("dsa_2048_224_sha224_p1363_test.json");
    check_wycheproof::<SHA256>("dsa_2048_224_sha256_test.json");
    check_wycheproof::<SHA256>("dsa_2048_224_sha256_p1363_test.json");
    check_wycheproof::<SHA256>("dsa_2048_256_sha256_test.json");
    check_wycheproof::<SHA256>("dsa_2048_256_sha256_p1363_test.json");
    check_wycheproof::<SHA256>("dsa_3072_256_sha256_test.json");
    check_wycheproof::<SHA256>("dsa_3072_256_sha256_p1363_test.json");
}

/// FIPS 186-4: parameters of other sizes and keys outside their ranges are refused.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn parameters_and_keys() {
    let section = RFC::section("math/ec/rfc6979.txt", "A.2.2.", "A.2.3.");
    let value = |prefix: &str| integer(&RFC::value_after(&section, prefix));
    let (p, q, g) = (value("p = "), value("q = "), value("g = "));
    let parameters = DSAParameters::new(&p, &q, &g).unwrap();
    assert_eq!((parameters.p_bytes(), parameters.q_bytes()), (256, 32));
    // g = 1, g = p, q not dividing p - 1, and other sizes.
    let one = BoxedUint::one(64).unwrap();
    assert!(DSAParameters::new(&p, &q, &one).is_err());
    assert!(DSAParameters::new(&p, &q, &p).is_err());
    assert!(DSAParameters::new(&p, &q.wrapping_sub(&BoxedUint::from_u64(2, 64).unwrap()), &g).is_err());
    assert!(DSAParameters::new(&p, &q.shr(1), &g).is_err());

    let mut random = HMACDRBG::<SHA256>::new(&[4; 32], &[5; 16], b"dsa").unwrap();
    let key = DSASigningKey::generate(parameters.clone(), &mut random).unwrap();
    let signature = DSA::<SHA256>::sign(&key, b"message").unwrap();
    assert_eq!(DSA::<SHA256>::verify(key.verifying_key(), b"message", &signature), Ok(()));
    let mut fixed = vec![0; 64];
    signature.write_bytes(&parameters, &mut fixed).unwrap();
    assert_eq!(DSASignature::from_bytes(&parameters, &fixed).unwrap(), signature);
    #[cfg(umilib_feature = "codec-asn1-der")]
    assert_eq!(DSASignature::from_der(&parameters, &signature.to_der()).unwrap(), signature);
    assert!(format!("{key:?}").ends_with(", ..)"));
    // x = 0 and x = q; y = 1 and y = p - 1; r = 0 and s = q.
    assert_eq!(
        DSASigningKey::new(parameters.clone(), &BoxedUint::zero(64).unwrap()).err(),
        Some(CryptoError::InvalidKey)
    );
    assert_eq!(DSASigningKey::new(parameters.clone(), &q).err(), Some(CryptoError::InvalidKey));
    assert_eq!(DSAVerifyingKey::new(parameters.clone(), &one).err(), Some(CryptoError::InvalidKey));
    assert_eq!(DSAVerifyingKey::new(parameters.clone(), &p.wrapping_sub(&one)).err(), Some(CryptoError::InvalidKey));
    assert_eq!(
        DSASignature::new(&parameters, &BoxedUint::zero(64).unwrap(), &one).err(),
        Some(CryptoError::InvalidSignature)
    );
    assert_eq!(DSASignature::new(&parameters, &one, &q).err(), Some(CryptoError::InvalidSignature));
}
