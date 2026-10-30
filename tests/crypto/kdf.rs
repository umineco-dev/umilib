//! HKDF, PBKDF2 and KBKDF against RFC 5869, RFC 6070, NIST CAVP and Project Wycheproof.

use umilib::crypto::aes::{AES128, AES192, AES256};
use umilib::crypto::cmac::CMAC;
use umilib::crypto::des::TDES;
use umilib::crypto::hkdf::HKDF;
use umilib::crypto::hmac::HMAC;
use umilib::crypto::kbkdf::{KBKDF, KBKDFCounter};
use umilib::crypto::pbkdf2::PBKDF2;
use umilib::crypto::{CryptoError, KeyInit, PRF};
use umilib::hash::CryptographicDigest;
use umilib::hash::sha::v1::SHA1;
use umilib::hash::sha::v2::{SHA224, SHA256, SHA384, SHA512};

use crate::{Record, Wycheproof};

fn hkdf<H: CryptographicDigest + Default>(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let mut okm = vec![0u8; length];
    HKDF::<H>::derive(salt, ikm, info, &mut okm)?;
    Ok(okm)
}

#[test]
fn hkdf_follows_rfc5869_appendix_a() {
    let records = Record::all("crypto/hkdf/rfc5869.txt");
    assert_eq!(records.len(), 7);
    for record in records {
        let label = format!("A.{}", record.field("Case"));
        let (ikm, salt, info, prk, okm) =
            (record.bytes("IKM"), record.bytes("salt"), record.bytes("info"), record.bytes("PRK"), record.bytes("OKM"));
        let length: usize = record.field("L").parse().unwrap();
        match record.field("Hash") {
            "SHA-256" => {
                assert_eq!(HKDF::<SHA256>::extract(&salt, &ikm).to_vec(), prk, "{label}");
                let mut out = vec![0u8; length];
                HKDF::<SHA256>::new(&prk).unwrap().expand(&info, &mut out).unwrap();
                assert_eq!(out, okm, "{label}");
                assert_eq!(hkdf::<SHA256>(&salt, &ikm, &info, length).unwrap(), okm, "{label}");
            }
            "SHA-1" => {
                assert_eq!(HKDF::<SHA1>::extract(&salt, &ikm).to_vec(), prk, "{label}");
                assert_eq!(hkdf::<SHA1>(&salt, &ikm, &info, length).unwrap(), okm, "{label}");
            }
            hash => panic!("{hash}"),
        }
    }
}

#[test]
fn hkdf_follows_the_wycheproof_vectors() {
    for (path, run) in [
        (
            "crypto/hkdf/hkdf_sha1_test.json",
            hkdf::<SHA1> as fn(&[u8], &[u8], &[u8], usize) -> Result<Vec<u8>, CryptoError>,
        ),
        ("crypto/hkdf/hkdf_sha256_test.json", hkdf::<SHA256>),
        ("crypto/hkdf/hkdf_sha384_test.json", hkdf::<SHA384>),
        ("crypto/hkdf/hkdf_sha512_test.json", hkdf::<SHA512>),
    ] {
        let tests = Wycheproof::tests(path);
        assert!(tests.len() > 80, "{path}");
        for (_, test) in tests {
            let label = format!("{path} tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
            let result =
                run(&test.bytes("salt"), &test.bytes("ikm"), &test.bytes("info"), test.field("size").as_usize());
            if test.field("result").as_str() == "valid" {
                assert_eq!(result, Ok(test.bytes("okm")), "{label}");
            } else {
                assert!(result.is_err(), "{label}");
            }
        }
    }
    // Section 2.3: at most 255 × HashLen bytes, and a PRK of at least HashLen bytes.
    assert!(hkdf::<SHA256>(&[], b"ikm", &[], 255 * 32).is_ok());
    assert!(matches!(hkdf::<SHA256>(&[], b"ikm", &[], 255 * 32 + 1), Err(CryptoError::InputLength { .. })));
    assert!(matches!(HKDF::<SHA256>::new(&[0; 31]), Err(CryptoError::KeyLength { .. })));
}

fn pbkdf2<H: CryptographicDigest + Default>(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0u8; length];
    PBKDF2::<H>::derive(password, salt, iterations, &mut out)?;
    Ok(out)
}

#[test]
fn pbkdf2_follows_rfc6070() {
    let records = Record::all("crypto/pbkdf2/rfc6070.txt");
    assert_eq!(records.len(), 6);
    for record in records {
        let iterations: u32 = record.field("c").parse().unwrap();
        if iterations > 1 << 20 {
            continue;
        }
        let expected = record.bytes("DK");
        assert_eq!(
            pbkdf2::<SHA1>(&record.bytes("P"), &record.bytes("S"), iterations, expected.len()).unwrap(),
            expected,
            "c = {iterations}"
        );
    }
}

/// The vector of RFC 6070 with 2^24 iterations.
#[test]
#[ignore = "16777216 iterations take minutes"]
fn pbkdf2_follows_rfc6070_with_2_to_the_24_iterations() {
    let record =
        Record::all("crypto/pbkdf2/rfc6070.txt").into_iter().find(|record| record.field("c") == "16777216").unwrap();
    let expected = record.bytes("DK");
    assert_eq!(pbkdf2::<SHA1>(&record.bytes("P"), &record.bytes("S"), 16777216, expected.len()).unwrap(), expected);
}

#[test]
fn pbkdf2_follows_the_wycheproof_vectors() {
    for (path, run) in [
        (
            "crypto/pbkdf2/pbkdf2_hmacsha1_test.json",
            pbkdf2::<SHA1> as fn(&[u8], &[u8], u32, usize) -> Result<Vec<u8>, CryptoError>,
        ),
        ("crypto/pbkdf2/pbkdf2_hmacsha224_test.json", pbkdf2::<SHA224>),
        ("crypto/pbkdf2/pbkdf2_hmacsha256_test.json", pbkdf2::<SHA256>),
        ("crypto/pbkdf2/pbkdf2_hmacsha384_test.json", pbkdf2::<SHA384>),
        ("crypto/pbkdf2/pbkdf2_hmacsha512_test.json", pbkdf2::<SHA512>),
    ] {
        let tests = Wycheproof::tests(path);
        assert!(!tests.is_empty(), "{path}");
        for (_, test) in tests {
            let label = format!("{path} tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
            let result = run(
                &test.bytes("password"),
                &test.bytes("salt"),
                test.field("iterationCount").as_usize() as u32,
                test.field("dkLen").as_usize(),
            );
            if test.field("result").as_str() == "valid" {
                assert_eq!(result, Ok(test.bytes("dk")), "{label}");
            } else {
                assert!(result.is_err(), "{label}");
            }
        }
    }
    assert_eq!(pbkdf2::<SHA256>(b"p", b"s", 0, 32), Err(CryptoError::InvalidParameter));
}

/// Runs a KBKDF record with the PRF `prf`.
fn kbkdf<P: PRF>(prf: P, record: &Record, mode: &str) -> Vec<u8> {
    let bits = record.header.get("RLEN").map_or(32, |rlen| rlen.trim_end_matches("_BITS").parse().unwrap());
    let kbkdf = KBKDF::new(prf, bits).unwrap();
    let length: usize = record.field("L").parse().unwrap();
    let mut out = vec![0u8; length / 8];
    let location = match record.header.get("CTRLOCATION").map(String::as_str) {
        None => KBKDFCounter::Absent,
        Some("BEFORE_ITER") => KBKDFCounter::BeforeIteration,
        Some("AFTER_ITER") => KBKDFCounter::AfterIteration,
        Some("AFTER_FIXED") => KBKDFCounter::AfterFixed,
        Some(_) => KBKDFCounter::Absent,
    };
    match mode {
        "Counter" => {
            let (before, after) = match record.header["CTRLOCATION"].as_str() {
                "BEFORE_FIXED" => (Vec::new(), record.bytes("FixedInputData")),
                "AFTER_FIXED" => (record.bytes("FixedInputData"), Vec::new()),
                "MIDDLE_FIXED" => (record.bytes("DataBeforeCtrData"), record.bytes("DataAfterCtrData")),
                location => panic!("{location}"),
            };
            kbkdf.counter(&before, &after, &mut out).unwrap();
        }
        "Feedback" => {
            let iv = record.get("IV").map(|_| record.bytes("IV")).unwrap_or_default();
            kbkdf.feedback(&iv, &record.bytes("FixedInputData"), location, &mut out).unwrap();
        }
        "Pipeline" => kbkdf.double_pipeline(&record.bytes("FixedInputData"), location, &mut out).unwrap(),
        mode => panic!("{mode}"),
    }
    out
}

#[test]
fn kbkdf_follows_the_cavp_vectors() {
    let mut checked = 0;
    for (file, mode) in [
        ("KDFCTR_gen.rsp", "Counter"),
        ("KDFFeedback_gen_NOzeroiv.rsp", "Feedback"),
        ("KDFFeedback_gen_wzeroiv.rsp", "Feedback"),
        ("KDFFeedback_gen_nocounter.rsp", "Feedback"),
        ("KDFDblPipeline_gen_withCounter.rsp", "Pipeline"),
        ("KDFDblPipeline_gen_WOCounter.rsp", "Pipeline"),
    ] {
        let path = format!("crypto/kbkdf/{file}");
        for record in Record::all(&path) {
            let label = format!("{path} {:?} COUNT={}", record.header, record.field("COUNT"));
            let key = record.bytes("KI");
            let out = match record.header["PRF"].as_str() {
                "CMAC_AES128" => kbkdf(CMAC::new(AES128::new_from_slice(&key).unwrap()), &record, mode),
                "CMAC_AES192" => kbkdf(CMAC::new(AES192::new_from_slice(&key).unwrap()), &record, mode),
                "CMAC_AES256" => kbkdf(CMAC::new(AES256::new_from_slice(&key).unwrap()), &record, mode),
                "CMAC_TDES2" | "CMAC_TDES3" => kbkdf(CMAC::new(TDES::new_from_slice(&key).unwrap()), &record, mode),
                "HMAC_SHA1" => kbkdf(HMAC::<SHA1>::new(&key), &record, mode),
                "HMAC_SHA224" => kbkdf(HMAC::<SHA224>::new(&key), &record, mode),
                "HMAC_SHA256" => kbkdf(HMAC::<SHA256>::new(&key), &record, mode),
                "HMAC_SHA384" => kbkdf(HMAC::<SHA384>::new(&key), &record, mode),
                "HMAC_SHA512" => kbkdf(HMAC::<SHA512>::new(&key), &record, mode),
                prf => panic!("{prf}"),
            };
            assert_eq!(out, record.bytes("KO"), "{label}");
            checked += 1;
        }
    }
    assert_eq!(checked, 4800 + 4800 + 4800 + 400 + 4800 + 400);
}

#[test]
fn kbkdf_checks_its_parameters() {
    assert_eq!(KBKDF::new(HMAC::<SHA256>::new(b"key"), 12).err(), Some(CryptoError::InvalidParameter));
    // With an 8-bit counter, at most 255 blocks (section 4.1: n ≤ 2^r - 1).
    let kbkdf = KBKDF::new(HMAC::<SHA256>::new(b"key"), 8).unwrap();
    let mut out = vec![0u8; 255 * 32];
    assert!(kbkdf.counter(b"", b"fixed", &mut out).is_ok());
    let mut out = vec![0u8; 255 * 32 + 1];
    assert!(matches!(kbkdf.counter(b"", b"fixed", &mut out), Err(CryptoError::InputLength { .. })));
}

/// RFC 7836 appendix B, examples 9 (KDF_GOSTR3411_2012_256) and 10 (KDF_TREE_GOSTR3411_2012_256).
#[cfg(umilib_feature = "hash-streebog")]
#[test]
fn kdf_tree_follows_rfc7836_appendix_b() {
    use umilib::crypto::kdftree::KDFTree;
    use umilib::hash::streebog::Streebog256;
    let key = crate::Vectors::hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let (label, seed) = (crate::Vectors::hex("26bdb878"), crate::Vectors::hex("af21434145656378"));
    let tree = KDFTree::new(HMAC::<Streebog256>::new(&key), 1).unwrap();
    let mut out = [0u8; 32];
    tree.derive(&label, &seed, &mut out).unwrap();
    assert_eq!(out.to_vec(), crate::Vectors::hex("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"));
    let mut out = [0u8; 64];
    tree.derive(&label, &seed, &mut out).unwrap();
    assert_eq!(
        out.to_vec(),
        crate::Vectors::hex(
            "22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9"
        )
    );
    // With R = 1, at most 255 blocks.
    assert!(tree.derive(&label, &seed, &mut vec![0u8; 255 * 32]).is_ok());
    assert!(matches!(tree.derive(&label, &seed, &mut vec![0u8; 255 * 32 + 1]), Err(CryptoError::InputLength { .. })));
    assert_eq!(KDFTree::new(HMAC::<Streebog256>::new(&key), 5).err(), Some(CryptoError::InvalidParameter));
}
