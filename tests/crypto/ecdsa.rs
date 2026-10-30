//! ECDSA (FIPS 186-5 section 6, SEC 1 section 4.1) against the deterministic
//! signatures of RFC 6979, Project Wycheproof (DER and IEEE P1363
//! signatures) and the properties every signature scheme must have.

use umilib::crypto::ecdsa::{ECDSA, ECDSASignature};
use umilib::crypto::random::HMACDRBG;
use umilib::crypto::{CryptoError, SignatureScheme};
use umilib::hash::sha::v1::SHA1;
use umilib::hash::sha::v2::{SHA224, SHA256, SHA384, SHA512};
use umilib::hash::{CryptographicDigest, Digest};
use umilib::math::ec::{PrimeField, WeierstrassCurve};

use crate::{Json, RFC, Vectors, Wycheproof};

/// What every signature scheme must do: signatures verify under the key that
/// made them and fail under any change; keys survive their encodings.
pub fn check_scheme<S: SignatureScheme>() {
    let mut random = HMACDRBG::<SHA256>::new(&[3; 32], &[4; 16], b"signature").unwrap();
    let key = S::generate(&mut random).unwrap();
    let other = S::generate(&mut random).unwrap();
    let verifying = S::verifying_key(&key);
    assert_ne!(verifying, S::verifying_key(&other));
    for message in [&b""[..], b"abc", &[0x5A; 1000]] {
        let mut signature = vec![0; S::SIGNATURE_SIZE];
        S::sign(&key, message, &mut signature).unwrap();
        assert_eq!(S::verify(&verifying, message, &signature), Ok(()));
        assert_eq!(S::verify(&S::verifying_key(&other), message, &signature), Err(CryptoError::InvalidSignature));
        assert_eq!(S::verify(&verifying, b"another message", &signature), Err(CryptoError::InvalidSignature));
        for index in [0, S::SIGNATURE_SIZE / 2, S::SIGNATURE_SIZE - 1] {
            let mut changed = signature.clone();
            changed[index] ^= 1;
            assert_eq!(S::verify(&verifying, message, &changed), Err(CryptoError::InvalidSignature));
        }
        for length in [0, S::SIGNATURE_SIZE - 1, S::SIGNATURE_SIZE + 1] {
            let mut resized = signature.clone();
            resized.resize(length, 0);
            assert_eq!(S::verify(&verifying, message, &resized), Err(CryptoError::InvalidSignature));
            assert_eq!(S::sign(&key, message, &mut vec![0; length]), Err(CryptoError::InputLength { length }));
        }
    }
    let mut encoded = vec![0; S::SIGNING_KEY_SIZE];
    S::write_signing_key(&key, &mut encoded).unwrap();
    assert_eq!(S::verifying_key(&S::signing_key_from_bytes(&encoded).unwrap()), verifying);
    let mut encoded = vec![0; S::VERIFYING_KEY_SIZE];
    S::write_verifying_key(&verifying, &mut encoded).unwrap();
    assert_eq!(S::verifying_key_from_bytes(&encoded).unwrap(), verifying);
    for length in [0, S::SIGNING_KEY_SIZE - 1, S::SIGNING_KEY_SIZE + 1] {
        assert_eq!(S::signing_key_from_bytes(&vec![1; length]).err(), Some(CryptoError::InvalidKey));
        assert_eq!(S::write_signing_key(&key, &mut vec![0; length]), Err(CryptoError::InputLength { length }));
    }
    for length in [0, S::VERIFYING_KEY_SIZE - 1, S::VERIFYING_KEY_SIZE + 1] {
        assert_eq!(S::verifying_key_from_bytes(&vec![4; length]).err(), Some(CryptoError::InvalidKey));
    }
    // Keys print nothing of their secret.
    let mut secret = vec![0; S::SIGNING_KEY_SIZE];
    S::write_signing_key(&key, &mut secret).unwrap();
    let hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
    let printed = format!("{key:?}").to_ascii_lowercase();
    assert!(!printed.contains(&hex[..16]), "{printed}");
}

/// The ECDSA properties beyond those of every scheme.
fn check_ecdsa<C: WeierstrassCurve>() {
    check_scheme::<ECDSA<C, SHA256>>();
    let mut random = HMACDRBG::<SHA256>::new(&[5; 32], &[6; 16], b"ecdsa").unwrap();
    let key = ECDSA::<C, SHA256>::generate(&mut random).unwrap();
    let verifying = ECDSA::<C, SHA256>::verifying_key(&key);
    let digest = SHA256::digest(b"hedged");
    // Deterministic signatures repeat; hedged ones differ and verify.
    let deterministic = ECDSA::<C, SHA256>::sign_digest(&key, &digest).unwrap();
    assert_eq!(ECDSA::<C, SHA256>::sign_digest(&key, &digest).unwrap(), deterministic);
    let hedged = ECDSA::<C, SHA256>::sign_digest_hedged(&key, &digest, &mut random).unwrap();
    assert_ne!(hedged, deterministic);
    assert_eq!(ECDSA::<C, SHA256>::verify_digest(&verifying, &digest, &hedged), Ok(()));
    // (r, -s) verifies too: ECDSA signatures are malleable.
    let negated = ECDSASignature::<C>::new(*deterministic.r(), deterministic.s().neg()).unwrap();
    assert_eq!(ECDSA::<C, SHA256>::verify_digest(&verifying, &digest, &negated), Ok(()));
    // r and s outside 1..n are not signatures.
    let size = <C::Scalar as PrimeField>::BYTES;
    let mut bytes = vec![0; 2 * size];
    deterministic.write_bytes(&mut bytes).unwrap();
    for (start, value) in [(0, 0u8), (size, 0)] {
        let mut changed = bytes.clone();
        changed[start..start + size].fill(value);
        assert_eq!(ECDSASignature::<C>::from_bytes(&changed).err(), Some(CryptoError::InvalidSignature));
    }
    let mut order = vec![0; size];
    use umilib::math::bigint::UnsignedInteger;
    use umilib::math::modular::ModularArithmetic;
    <C::Scalar as PrimeField>::MODULUS.value().write_be_bytes(&mut order).unwrap();
    let mut changed = bytes.clone();
    changed[size..].copy_from_slice(&order);
    assert_eq!(ECDSASignature::<C>::from_bytes(&changed).err(), Some(CryptoError::InvalidSignature));
    assert_eq!(ECDSASignature::<C>::from_bytes(&bytes).unwrap(), deterministic);
    #[cfg(umilib_feature = "codec-asn1-der")]
    {
        let der = deterministic.to_der();
        assert_eq!(ECDSASignature::<C>::from_der(&der).unwrap(), deterministic);
        let mut extended = der.clone();
        extended.push(0);
        assert_eq!(ECDSASignature::<C>::from_der(&extended).err(), Some(CryptoError::InvalidSignature));
    }
    // A zero scalar is not a key.
    assert_eq!(ECDSA::<C, SHA256>::signing_key_from_bytes(&vec![0; size]).err(), Some(CryptoError::InvalidKey));
    assert_eq!(ECDSA::<C, SHA256>::verifying_key_from_bytes(&[0]).err(), Some(CryptoError::InvalidKey));
}

/// RFC 6979 appendix A.2: the deterministic signatures of "sample" and
/// "test" under the key of the section from `start` to `end`.
fn check_rfc6979<C: WeierstrassCurve>(start: &str, end: &str) {
    let section = RFC::section("math/ec/rfc6979.txt", start, end);
    let size = <C::Scalar as PrimeField>::BYTES;
    let private = Vectors::hex(&format!("{:0>width$}", RFC::value_after(&section, "x = "), width = 2 * size));
    let key = ECDSA::<C, SHA256>::signing_key_from_bytes(&private[private.len() - size..]).unwrap();
    let headers: Vec<&str> = section.lines().map(str::trim).filter(|line| line.starts_with("With SHA-")).collect();
    let rs = RFC::values_after(&section, "r = ");
    let ss = RFC::values_after(&section, "s = ");
    assert_eq!((headers.len(), rs.len(), ss.len()), (10, 10, 10));
    for ((header, r), s) in headers.iter().zip(&rs).zip(&ss) {
        let message = if header.ends_with("\"sample\":") { &b"sample"[..] } else { b"test" };
        let hash = header.trim_start_matches("With ").split(',').next().unwrap();
        fn sign<C: WeierstrassCurve, H: CryptographicDigest + Default>(
            key: &umilib::crypto::ecdsa::ECDSASigningKey<C>,
            message: &[u8],
        ) -> ECDSASignature<C> {
            ECDSA::<C, H>::sign_digest(key, H::digest(message).as_ref()).unwrap()
        }
        let signature = match hash {
            "SHA-1" => sign::<C, SHA1>(&key, message),
            "SHA-224" => sign::<C, SHA224>(&key, message),
            "SHA-256" => sign::<C, SHA256>(&key, message),
            "SHA-384" => sign::<C, SHA384>(&key, message),
            "SHA-512" => sign::<C, SHA512>(&key, message),
            other => panic!("{other}"),
        };
        let expected = |hex: &str| super::ec_checks::ECChecks::element::<C::Scalar>(hex);
        assert_eq!(*signature.r(), expected(r), "{start} {header}");
        assert_eq!(*signature.s(), expected(s), "{start} {header}");
    }
}

/// A Wycheproof file of ECDSA signatures with the hash `H`: valid signatures
/// verify, invalid ones are refused.
fn check_wycheproof<C: WeierstrassCurve, H: CryptographicDigest + Default>(file: &str, count: usize) {
    let p1363 = file.ends_with("_p1363_test.json");
    #[cfg(not(umilib_feature = "codec-asn1-der"))]
    if !p1363 {
        return;
    }
    let tests = Wycheproof::tests(&format!("crypto/ecdsa/{file}"));
    assert_eq!(tests.len(), count, "{file}");
    for (group, test) in &tests {
        let label = format!("{file} {}", test.field("tcId").as_usize());
        let public = Vectors::hex(group.field("publicKey").field("uncompressed").as_str());
        let key = ECDSA::<C, H>::verifying_key_from_bytes(&public).unwrap();
        let signature = test.bytes("sig");
        let parsed = if p1363 { ECDSASignature::<C>::from_bytes(&signature) } else { from_der::<C>(&signature) };
        let digest = H::digest(&test.bytes("msg"));
        let result = parsed.and_then(|signature| ECDSA::<C, H>::verify_digest(&key, digest.as_ref(), &signature));
        match test.field("result").as_str() {
            "valid" => assert_eq!(result, Ok(()), "{label}"),
            "invalid" => assert_eq!(result, Err(CryptoError::InvalidSignature), "{label}"),
            _ => {}
        }
        if p1363 && test.field("result").as_str() == "valid" {
            // The fixed form is also what the scheme verifies.
            assert_eq!(ECDSA::<C, H>::verify(&key, &test.bytes("msg"), &signature), Ok(()), "{label}");
        }
    }
}

#[cfg(umilib_feature = "codec-asn1-der")]
fn from_der<C: WeierstrassCurve>(bytes: &[u8]) -> Result<ECDSASignature<C>, CryptoError> {
    ECDSASignature::from_der(bytes)
}

#[cfg(not(umilib_feature = "codec-asn1-der"))]
fn from_der<C: WeierstrassCurve>(_: &[u8]) -> Result<ECDSASignature<C>, CryptoError> {
    unreachable!("DER signatures are read with codec-asn1-der")
}

/// Every Wycheproof file of `prefix`, with the hash its name gives.
fn check_wycheproof_files<C: WeierstrassCurve>(prefix: &str) {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/crypto/ecdsa");
    let mut files: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with(&format!("ecdsa_{prefix}_")))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "{prefix}");
    for file in &files {
        let count = Json::read(&format!("crypto/ecdsa/{file}"))
            .field("testGroups")
            .items()
            .iter()
            .map(|group| group.field("tests").items().len())
            .sum();
        let hash = file.trim_start_matches(&format!("ecdsa_{prefix}_")).trim_end_matches("_test.json");
        match hash.trim_end_matches("_p1363") {
            "sha256" => check_wycheproof::<C, SHA256>(file, count),
            "sha384" => check_wycheproof::<C, SHA384>(file, count),
            "sha512" => check_wycheproof::<C, SHA512>(file, count),
            "sha3_256" => check_wycheproof::<C, umilib::hash::sha::v3::SHA3_256>(file, count),
            "sha3_384" => check_wycheproof::<C, umilib::hash::sha::v3::SHA3_384>(file, count),
            "sha3_512" => check_wycheproof::<C, umilib::hash::sha::v3::SHA3_512>(file, count),
            other => panic!("{file}: {other}"),
        }
    }
}

#[cfg(umilib_feature = "crypto-curve-p256")]
#[test]
fn p256() {
    use umilib::crypto::curve::p256::P256;
    check_ecdsa::<P256>();
    check_rfc6979::<P256>("A.2.5.", "A.2.6.");
    check_wycheproof_files::<P256>("secp256r1");
}

#[cfg(umilib_feature = "crypto-curve-p384")]
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn p384() {
    use umilib::crypto::curve::p384::P384;
    check_ecdsa::<P384>();
    check_rfc6979::<P384>("A.2.6.", "A.2.7.");
    check_wycheproof_files::<P384>("secp384r1");
}

#[cfg(umilib_feature = "crypto-curve-p521")]
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn p521() {
    use umilib::crypto::curve::p521::P521;
    check_ecdsa::<P521>();
    check_rfc6979::<P521>("A.2.7.", "A.2.8.");
    check_wycheproof_files::<P521>("secp521r1");
}

#[cfg(umilib_feature = "crypto-curve-secp256k1")]
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn secp256k1() {
    use umilib::crypto::curve::secp256k1::Secp256k1;
    check_ecdsa::<Secp256k1>();
    check_wycheproof_files::<Secp256k1>("secp256k1");
}

#[cfg(umilib_feature = "crypto-curve-brainpool")]
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn brainpool() {
    use umilib::crypto::curve::brainpool::p256r1::BrainpoolP256r1;
    use umilib::crypto::curve::brainpool::p384r1::BrainpoolP384r1;
    use umilib::crypto::curve::brainpool::p512r1::BrainpoolP512r1;
    check_ecdsa::<BrainpoolP256r1>();
    check_wycheproof_files::<BrainpoolP256r1>("brainpoolP256r1");
    check_ecdsa::<BrainpoolP384r1>();
    check_wycheproof_files::<BrainpoolP384r1>("brainpoolP384r1");
    check_ecdsa::<BrainpoolP512r1>();
    check_wycheproof_files::<BrainpoolP512r1>("brainpoolP512r1");
}
