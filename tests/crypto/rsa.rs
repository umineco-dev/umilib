//! RSA (RFC 8017, FIPS 186-5) against the CAVP signature tests of FIPS
//! 186-3, Project Wycheproof (RSASSA-PKCS1-v1_5, RSASSA-PSS, RSAES-OAEP)
//! and the requirements on keys of its specifications.

use umilib::crypto::CryptoError;
use umilib::crypto::random::HMACDRBG;
use umilib::crypto::rsa::{MGF1, RSAOAEP, RSAPKCS1v15, RSAPSS, RSAPrivateKey, RSAPublicKey};
use umilib::hash::Digest;
use umilib::hash::sha::v1::SHA1;
use umilib::hash::sha::v2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use umilib::hash::sha::v3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use umilib::math::bigint::BoxedUint;

use crate::{Json, Record, Vectors, Wycheproof};

/// Runs `$body` with the type `$hash` the hash function named `$name`, in
/// any of the spellings of CAVP and Wycheproof ("SHA-256", "SHA256",
/// "SHA512224", "SHA-512/224", "SHA3-256").
macro_rules! with_hash {
    ($name:expr, $hash:ident => $body:expr) => {{
        let name: String = $name.chars().filter(|character| character.is_ascii_alphanumeric()).collect();
        match name.to_ascii_uppercase().as_str() {
            "SHA1" => {
                type $hash = SHA1;
                $body
            }
            "SHA224" => {
                type $hash = SHA224;
                $body
            }
            "SHA256" => {
                type $hash = SHA256;
                $body
            }
            "SHA384" => {
                type $hash = SHA384;
                $body
            }
            "SHA512" => {
                type $hash = SHA512;
                $body
            }
            "SHA512224" => {
                type $hash = SHA512_224;
                $body
            }
            "SHA512256" => {
                type $hash = SHA512_256;
                $body
            }
            "SHA3224" => {
                type $hash = SHA3_224;
                $body
            }
            "SHA3256" => {
                type $hash = SHA3_256;
                $body
            }
            "SHA3384" => {
                type $hash = SHA3_384;
                $body
            }
            "SHA3512" => {
                type $hash = SHA3_512;
                $body
            }
            other => panic!("unknown hash {other}"),
        }
    }};
}

/// The integer of hexadecimal `hex` (an odd number of digits allowed).
fn integer(hex: &str) -> BoxedUint {
    let padded = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex.to_owned() };
    let bytes = Vectors::hex(&padded);
    BoxedUint::from_be_bytes(&bytes, (bytes.len().max(1) * 8) as u32).unwrap()
}

fn random() -> HMACDRBG<SHA256> {
    HMACDRBG::new(&[1; 32], &[2; 16], b"rsa").unwrap()
}

/// CAVP SigGen: the deterministic signatures of PKCS #1 v1.5, and those of
/// PSS with the salt of each record, under the private exponents of the file.
fn check_signature_generation(path: &str, pss: bool) {
    let mut n: Option<BoxedUint> = None;
    let mut key: Option<RSAPrivateKey> = None;
    let mut count = 0;
    let mut random = random();
    for record in Record::all(path) {
        // The modulus and the exponents are records of their own.
        if let Some(modulus) = record.get("n") {
            n = Some(integer(modulus));
        }
        if let (Some(e), Some(d)) = (record.get("e"), record.get("d")) {
            let public = RSAPublicKey::new(n.as_ref().unwrap(), &integer(e)).unwrap();
            key = Some(RSAPrivateKey::new(public, &integer(d)).unwrap());
        }
        if record.get("SHAAlg").is_none() {
            continue;
        }
        let key = key.as_ref().unwrap();
        let (message, expected) = (record.bytes("Msg"), record.bytes("S"));
        let label = format!("{path} {} {}", record.field("SHAAlg"), record.field("Msg"));
        let signature = with_hash!(record.field("SHAAlg"), H => {
            let digest = H::digest(&message);
            if pss {
                // CAVP writes the empty salt (of length 0, as the file's header states) as 00.
                let salt = if record.field("SaltVal") == "00" { Vec::new() } else { record.bytes("SaltVal") };
                let signature = RSAPSS::<H>::sign_digest_with_salt(key, digest.as_ref(), &salt, &mut random).unwrap();
                assert_eq!(RSAPSS::<H>::verify(key.public_key(), &message, &signature, salt.len()), Ok(()), "{label}");
                signature
            } else {
                let signature = RSAPKCS1v15::<H>::sign(key, &message, &mut random).unwrap();
                assert_eq!(RSAPKCS1v15::<H>::verify(key.public_key(), &message, &signature), Ok(()), "{label}");
                signature
            }
        });
        assert_eq!(signature, expected, "{label}");
        count += 1;
    }
    assert!(count >= 40, "{path}: {count}");
}

/// CAVP SigVer: the result P or F of each record.
fn check_signature_verification(path: &str, pss: bool) {
    let mut n: Option<BoxedUint> = None;
    let mut count = 0;
    for record in Record::all(path) {
        if let Some(modulus) = record.get("n") {
            n = Some(integer(modulus));
            continue;
        }
        let Some(algorithm) = record.get("SHAAlg") else { continue };
        let public = RSAPublicKey::new(n.as_ref().unwrap(), &integer(record.field("e"))).unwrap();
        // S is an integer, written without its leading zeros: I2OSP(S, k).
        let mut signature = vec![0u8; public.size()];
        let value = integer(record.field("S"));
        let fits = value.bit_length() as usize <= 8 * signature.len();
        if fits {
            value.resize(8 * signature.len() as u32).unwrap().write_be_bytes(&mut signature).unwrap();
        }
        // A few records of SigVer15 have a message of an odd number of digits,
        // which is no byte string: their result is F.
        if record.field("Msg").len() % 2 == 1 {
            assert!(record.field("Result").starts_with('F'), "{path} {}", record.field("Msg"));
            continue;
        }
        let message = record.bytes("Msg");
        let result = with_hash!(algorithm, H => {
            if pss {
                // As in SigGen, 00 is the empty salt.
                let salt = if record.field("SaltVal") == "00" { 0 } else { record.bytes("SaltVal").len() };
                RSAPSS::<H>::verify(&public, &message, &signature, salt)
            } else {
                RSAPKCS1v15::<H>::verify(&public, &message, &signature)
            }
        });
        let expected = record.field("Result").starts_with('P');
        assert_eq!(result.is_ok(), expected, "{path} {algorithm} {} {:?}", record.field("Msg"), record.get("Result"));
        count += 1;
    }
    assert!(count >= 100, "{path}: {count}");
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn cavp_signatures() {
    check_signature_generation("crypto/rsa/SigGen15_186-3.txt", false);
    check_signature_generation("crypto/rsa/SigGen15_186-3_TruncatedSHAs.txt", false);
    check_signature_generation("crypto/rsa/SigGenPSS_186-3.txt", true);
    check_signature_generation("crypto/rsa/SigGenPSS_186-3_TruncatedSHAs.txt", true);
    check_signature_verification("crypto/rsa/SigVer15_186-3.rsp", false);
    check_signature_verification("crypto/rsa/SigVerPSS_186-3.rsp", true);
}

/// The public key of a Wycheproof group.
fn public_key(group: &Json) -> RSAPublicKey {
    let key = group.field("publicKey");
    RSAPublicKey::new(&integer(key.field("modulus").as_str()), &integer(key.field("publicExponent").as_str())).unwrap()
}

/// The private key of a Wycheproof group, with its primes when it has them.
fn private_key(group: &Json) -> RSAPrivateKey {
    let key = group.field("privateKey");
    let field = |name: &str| integer(key.field(name).as_str());
    let public = RSAPublicKey::new(&field("modulus"), &field("publicExponent")).unwrap();
    if key.get("prime1").is_some() {
        RSAPrivateKey::from_components(
            public,
            &field("privateExponent"),
            &field("prime1"),
            &field("prime2"),
            &field("exponent1"),
            &field("exponent2"),
            &field("coefficient"),
        )
        .unwrap()
    } else {
        RSAPrivateKey::new(public, &field("privateExponent")).unwrap()
    }
}

/// Checks the result of a Wycheproof test: valid must succeed, invalid fail.
fn check_result<T: core::fmt::Debug>(test: &Json, result: &Result<T, CryptoError>, label: &str) {
    match test.field("result").as_str() {
        "valid" => assert!(result.is_ok(), "{label}: {result:?}"),
        "invalid" => assert!(result.is_err(), "{label}: {result:?}"),
        _ => {}
    }
}

fn check_wycheproof(file: &str) {
    let path = format!("crypto/rsa/{file}");
    let tests = Wycheproof::tests(&path);
    assert!(!tests.is_empty(), "{file}");
    let mut random = random();
    for (group, test) in &tests {
        let label = format!("{file} {}", test.field("tcId").as_usize());
        let message = test.bytes("msg");
        match group.field("type").as_str() {
            "RsassaPkcs1Verify" => {
                let key = public_key(group);
                let result = with_hash!(group.field("sha").as_str(), H => RSAPKCS1v15::<H>::verify(&key, &message, &test.bytes("sig")));
                check_result(test, &result, &label);
            }
            "RsassaPssVerify" => {
                let key = public_key(group);
                let salt = group.field("sLen").as_usize();
                let result = with_hash!(group.field("sha").as_str(), H => with_hash!(group.field("mgfSha").as_str(), G => {
                    RSAPSS::<H, G>::verify(&key, &message, &test.bytes("sig"), salt)
                }));
                check_result(test, &result, &label);
            }
            "RsaesOaepDecrypt" => {
                let key = private_key(group);
                let label_bytes = test.bytes("label");
                let result = with_hash!(group.field("sha").as_str(), H => with_hash!(group.field("mgfSha").as_str(), G => {
                    RSAOAEP::<H, G>::decrypt(&key, &test.bytes("ct"), &label_bytes, &mut random)
                }));
                check_result(test, &result, &label);
                if test.field("result").as_str() == "valid" {
                    assert_eq!(result.unwrap(), message, "{label}");
                }
            }
            "RsassaPkcs1Generate" => {
                let key = private_key(group);
                let result =
                    with_hash!(group.field("sha").as_str(), H => RSAPKCS1v15::<H>::sign(&key, &message, &mut random));
                assert_eq!(result.unwrap(), test.bytes("sig"), "{label}");
            }
            other => panic!("{file}: {other}"),
        }
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn wycheproof() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/crypto/rsa");
    let mut files: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with("_test.json"))
        .collect();
    files.sort();
    assert_eq!(files.len(), 16);
    for file in &files {
        check_wycheproof(file);
    }
}

/// Generated keys: FIPS 186-5 appendix A.1 sizes and the relations of RFC
/// 8017 section 3.2, used by every scheme.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn generated_keys() {
    let mut random = random();
    let e = BoxedUint::from_u64(65537, 64).unwrap();
    let key = RSAPrivateKey::generate(2048, &e, &mut random).unwrap();
    let public = key.public_key();
    assert_eq!(public.bits(), 2048);
    assert_eq!(public.size(), 256);
    let primes = key.primes().unwrap();
    assert_eq!((primes.p().bit_length(), primes.q().bit_length()), (1024, 1024));
    assert!(key.d().bit_length() > 1024);

    let message = b"generated";
    let signature = RSAPKCS1v15::<SHA256>::sign(&key, message, &mut random).unwrap();
    assert_eq!(RSAPKCS1v15::<SHA256>::verify(public, message, &signature), Ok(()));
    assert_eq!(RSAPKCS1v15::<SHA256>::verify(public, b"other", &signature), Err(CryptoError::InvalidSignature));
    assert_eq!(RSAPKCS1v15::<SHA384>::verify(public, message, &signature), Err(CryptoError::InvalidSignature));
    let signature = RSAPSS::<SHA256>::sign(&key, message, 32, &mut random).unwrap();
    assert_eq!(RSAPSS::<SHA256>::verify(public, message, &signature, 32), Ok(()));
    assert_eq!(RSAPSS::<SHA256>::verify(public, message, &signature, 31), Err(CryptoError::InvalidSignature));
    let ciphertext = RSAOAEP::<SHA256>::encrypt(public, message, b"label", &mut random).unwrap();
    assert_eq!(RSAOAEP::<SHA256>::decrypt(&key, &ciphertext, b"label", &mut random).unwrap(), message);
    assert_eq!(
        RSAOAEP::<SHA256>::decrypt(&key, &ciphertext, b"other", &mut random),
        Err(CryptoError::DecryptionFailed)
    );
    // The longest message, and one byte more.
    let maximum = RSAOAEP::<SHA256>::maximum_message(public).unwrap();
    assert_eq!(maximum, 256 - 2 * 32 - 2);
    let long = vec![7; maximum];
    let ciphertext = RSAOAEP::<SHA256>::encrypt(public, &long, b"", &mut random).unwrap();
    assert_eq!(RSAOAEP::<SHA256>::decrypt(&key, &ciphertext, b"", &mut random).unwrap(), long);
    assert_eq!(
        RSAOAEP::<SHA256>::encrypt(public, &[7; 191], b"", &mut random),
        Err(CryptoError::InputLength { length: 191 })
    );

    // The same key from its primes, and from d alone.
    let again = RSAPrivateKey::from_primes(primes.p(), primes.q(), &e).unwrap();
    assert_eq!(again.d(), key.d());
    let without_primes = RSAPrivateKey::new(public.clone(), key.d()).unwrap();
    let signature = RSAPKCS1v15::<SHA256>::sign(&without_primes, message, &mut random).unwrap();
    assert_eq!(signature, RSAPKCS1v15::<SHA256>::sign(&key, message, &mut random).unwrap());

    #[cfg(umilib_feature = "codec-asn1-der")]
    {
        let der = key.to_pkcs1_der().unwrap();
        let decoded = RSAPrivateKey::from_pkcs1_der(&der).unwrap();
        assert_eq!(decoded.public_key(), public);
        assert_eq!(decoded.d(), key.d());
        assert_eq!(RSAPublicKey::from_pkcs1_der(&public.to_pkcs1_der()).unwrap(), *public);
        assert!(RSAPublicKey::from_pkcs1_der(&der).is_err());
        assert!(RSAPrivateKey::from_pkcs1_der(&public.to_pkcs1_der()).is_err());
    }

    // Sizes and exponents FIPS 186-5 does not allow are refused.
    assert_eq!(RSAPrivateKey::generate(1024, &e, &mut random).err(), Some(CryptoError::InvalidParameter));
    assert_eq!(RSAPrivateKey::generate(2050 + 1, &e, &mut random).err(), Some(CryptoError::InvalidParameter));
    let three = BoxedUint::from_u64(3, 64).unwrap();
    assert_eq!(RSAPrivateKey::generate(2048, &three, &mut random).err(), Some(CryptoError::InvalidParameter));
}

/// RFC 8017 section 3: the ranges of keys and of inputs.
#[test]
fn key_and_input_ranges() {
    let n = integer(
        "c5062b58d8539c765e1e5dbaf14cf75dd56c2e13105fecfd1a930bbb5948ff328f126abe779359ca59bca752c308d281573bc6178b6c0fef7dc445e4f826430437b9f9d790581de5749c2cb9cb26d42b2fee15b6b26f09c99670336423b86bc5bec71113157be2d944d7ff3eebffb28413143ea36755db0ae62ff5b724eecb3d316b6bac67e89cacd8171937e2ab19bd353a89acea8c36f81c89a620d5fd2effea896601c7f9daca7f033f635a3a943331d1b1b4f5288790b53af352f1121ca1bef205f40dc012c412b40bdd27585b946466d75f7ee0a7f9d549b4bece6f43ac3ee65fe7fd37123359d9f1a850ad450aaf5c94eb11dea3fc0fc6e9856b1805ef",
    );
    let e = integer("010001");
    assert!(RSAPublicKey::new(&n, &e).is_ok());
    // An even modulus, an even exponent, e = 1 and e ≥ n are refused.
    let even = n.wrapping_sub(&BoxedUint::one(64).unwrap());
    assert_eq!(RSAPublicKey::new(&even, &e).err(), Some(CryptoError::InvalidKey));
    assert_eq!(RSAPublicKey::new(&n, &integer("010000")).err(), Some(CryptoError::InvalidKey));
    assert_eq!(RSAPublicKey::new(&n, &integer("01")).err(), Some(CryptoError::InvalidKey));
    assert_eq!(RSAPublicKey::new(&n, &n).err(), Some(CryptoError::InvalidKey));
    let public = RSAPublicKey::new(&n, &e).unwrap();
    // Signatures of another length, or not below n, are refused.
    let all_ones = vec![0xFF; public.size()];
    assert_eq!(RSAPKCS1v15::<SHA256>::verify(&public, b"m", &all_ones), Err(CryptoError::InvalidSignature));
    assert_eq!(RSAPKCS1v15::<SHA256>::verify(&public, b"m", &[1; 255]), Err(CryptoError::InvalidSignature));
    assert_eq!(public.integer(&all_ones).err(), Some(CryptoError::InvalidParameter));
    // A private exponent that does not invert e is refused.
    assert_eq!(RSAPrivateKey::new(public.clone(), &integer("1234567")).err(), Some(CryptoError::InvalidKey));
}

/// MGF1 of RFC 8017 appendix B.2.1: the concatenation of the hashes of the
/// seed and a counter.
#[test]
fn mgf1() {
    let mut mask = vec![0u8; 70];
    MGF1::<SHA256>::apply(b"seed", &mut mask);
    let mut expected = Vec::new();
    for counter in 0u32..3 {
        let mut hash = SHA256::default();
        hash.update(b"seed");
        hash.update(&counter.to_be_bytes());
        expected.extend_from_slice(&hash.finalize());
    }
    assert_eq!(mask, expected[..70]);
}

#[test]
fn pss_salt_lengths_that_do_not_fit_are_refused() {
    // RFC 8017 §9.1.1 step 3 and §9.1.2 step 3: emLen ≥ hLen + sLen + 2. A salt length that does not
    // fit (even one whose sum overflows a 32-bit usize) is "inconsistent", not a panic.
    let mut random = random();
    let e = BoxedUint::from_u64(65537, 64).unwrap();
    let key = RSAPrivateKey::generate(2048, &e, &mut random).unwrap();
    // emLen = ⌈(modBits - 1) / 8⌉ = 256 for a key of 2048 bits.
    let length = 256;
    assert_eq!(
        RSAPSS::<SHA256>::sign(&key, b"m", length - 32 - 1, &mut random).unwrap_err(),
        CryptoError::InvalidParameter
    );
    let fits = RSAPSS::<SHA256>::sign(&key, b"m", length - 32 - 2, &mut random).unwrap();
    RSAPSS::<SHA256>::verify(key.public_key(), b"m", &fits, length - 32 - 2).unwrap();
    for salt in [length - 32 - 1, usize::MAX - 32 - 1, usize::MAX - 1, usize::MAX] {
        assert_eq!(
            RSAPSS::<SHA256>::verify(key.public_key(), b"m", &fits, salt),
            Err(CryptoError::InvalidSignature),
            "{salt}"
        );
    }
    assert_eq!(RSAPSS::<SHA256>::sign(&key, b"m", usize::MAX, &mut random).unwrap_err(), CryptoError::InvalidParameter);
}
