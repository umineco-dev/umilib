//! The key derivation functions and CTR_DRBG of the C ABI: HKDF (RFC 5869,
//! Wycheproof), PBKDF2 (RFC 6070, Wycheproof), scrypt (RFC 7914), Argon2
//! (RFC 9106), KBKDF (CAVP), KDF_TREE (RFC 7836) and CTR_DRBG (CAVP).

use std::ptr;

use umilib::crypto::random::DRBGConfig;
use umilib::ffi::U128;
use umilib::ffi::crypto::random::ctr_drbg;
use umilib::ffi::crypto::{argon2, concatkdf, hkdf, kbkdf, kdftree, pbkdf2, scrypt};

use crate::Check;
use crate::vectors::{Record, Vectors, Wycheproof};

/// HKDF with the hash function named `hash` through `_derive`, checked against `_from_secret` and `_expand`.
fn hkdf(hash: &[u8], salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Option<Vec<u8>> {
    unsafe {
        let mut okm = vec![0u8; length];
        let status = hkdf::umilib_crypto_hkdf_hkdf_derive(
            hash.as_ptr(),
            hash.len(),
            salt.as_ptr(),
            salt.len(),
            ikm.as_ptr(),
            ikm.len(),
            info.as_ptr(),
            info.len(),
            okm.as_mut_ptr(),
            length,
        );
        if !status.is_null() {
            Check::fails(status, "crypto", "InputLength");
            return None;
        }
        let mut state = ptr::null_mut();
        Check::ok(hkdf::umilib_crypto_hkdf_hkdf_from_secret(
            hash.as_ptr(),
            hash.len(),
            salt.as_ptr(),
            salt.len(),
            ikm.as_ptr(),
            ikm.len(),
            &mut state,
        ));
        let mut expanded = vec![0u8; length];
        Check::ok(hkdf::umilib_crypto_hkdf_hkdf_expand(
            state,
            info.as_ptr(),
            info.len(),
            expanded.as_mut_ptr(),
            length,
        ));
        hkdf::umilib_crypto_hkdf_hkdf_free(state);
        assert_eq!(expanded, okm);
        Some(okm)
    }
}

#[test]
fn hkdf_follows_rfc5869_appendix_a() {
    let records = Record::all("crypto/hkdf/rfc5869.txt");
    assert_eq!(records.len(), 7);
    for record in records {
        let label = format!("A.{}", record.field("Case"));
        let hash: &[u8] = match record.field("Hash") {
            "SHA-256" => b"umilib_hash_sha_v2_SHA256",
            "SHA-1" => b"umilib_hash_sha_v1_SHA1",
            hash => panic!("{hash}"),
        };
        let (ikm, salt, info, prk, okm) =
            (record.bytes("IKM"), record.bytes("salt"), record.bytes("info"), record.bytes("PRK"), record.bytes("OKM"));
        let length: usize = record.field("L").parse().unwrap();
        assert_eq!(hkdf(hash, &salt, &ikm, &info, length), Some(okm.clone()), "{label}");
        unsafe {
            let mut extracted = vec![0u8; prk.len()];
            Check::ok(hkdf::umilib_crypto_hkdf_hkdf_extract(
                hash.as_ptr(),
                hash.len(),
                salt.as_ptr(),
                salt.len(),
                ikm.as_ptr(),
                ikm.len(),
                extracted.as_mut_ptr(),
                extracted.len(),
            ));
            assert_eq!(extracted, prk, "{label}");
            let mut state = ptr::null_mut();
            Check::ok(hkdf::umilib_crypto_hkdf_hkdf_new(
                hash.as_ptr(),
                hash.len(),
                prk.as_ptr(),
                prk.len(),
                &mut state,
            ));
            let mut copy = ptr::null_mut();
            Check::ok(hkdf::umilib_crypto_hkdf_hkdf_clone(state, &mut copy));
            let mut out = vec![0u8; length];
            Check::ok(hkdf::umilib_crypto_hkdf_hkdf_expand(copy, info.as_ptr(), info.len(), out.as_mut_ptr(), length));
            assert_eq!(out, okm, "{label}");
            let mut maximum = 0;
            Check::ok(hkdf::umilib_crypto_hkdf_hkdf_maximum_output(state, &mut maximum));
            assert_eq!(maximum, 255 * prk.len());
            hkdf::umilib_crypto_hkdf_hkdf_free(copy);
            hkdf::umilib_crypto_hkdf_hkdf_free(state);
        }
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn hkdf_follows_the_wycheproof_vectors() {
    for (path, hash) in [
        ("crypto/hkdf/hkdf_sha1_test.json", &b"umilib_hash_sha_v1_SHA1"[..]),
        ("crypto/hkdf/hkdf_sha256_test.json", b"umilib_hash_sha_v2_SHA256"),
        ("crypto/hkdf/hkdf_sha384_test.json", b"umilib_hash_sha_v2_SHA384"),
        ("crypto/hkdf/hkdf_sha512_test.json", b"umilib_hash_sha_v2_SHA512"),
    ] {
        let tests = Wycheproof::tests(path);
        assert!(tests.len() > 80, "{path}");
        for (_, test) in tests {
            let label = format!("{path} tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
            let result =
                hkdf(hash, &test.bytes("salt"), &test.bytes("ikm"), &test.bytes("info"), test.field("size").as_usize());
            if test.field("result").as_str() == "valid" {
                assert_eq!(result, Some(test.bytes("okm")), "{label}");
            } else {
                assert_eq!(result, None, "{label}");
            }
        }
    }
    unsafe {
        // Section 2.3: a PRK of at least HashLen bytes; an unknown hash function.
        let sha256 = b"umilib_hash_sha_v2_SHA256";
        let mut state = ptr::null_mut();
        Check::fails(
            hkdf::umilib_crypto_hkdf_hkdf_new(sha256.as_ptr(), sha256.len(), [0u8; 31].as_ptr(), 31, &mut state),
            "crypto",
            "KeyLength",
        );
        let unknown = b"umilib_hash_sha_v2_SHA";
        Check::fails(
            hkdf::umilib_crypto_hkdf_hkdf_new(unknown.as_ptr(), unknown.len(), [0u8; 32].as_ptr(), 32, &mut state),
            "ffi",
            "InvalidArgument",
        );
    }
}

/// PBKDF2 with the hash function named `hash`, or the status name of its failure.
fn pbkdf2(hash: &[u8], password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; length];
    let status = unsafe {
        pbkdf2::umilib_crypto_pbkdf2_pbkdf2_derive(
            hash.as_ptr(),
            hash.len(),
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            iterations,
            out.as_mut_ptr(),
            length,
        )
    };
    status.is_null().then_some(out)
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn pbkdf2_follows_rfc6070_and_the_wycheproof_vectors() {
    let sha1 = b"umilib_hash_sha_v1_SHA1";
    for record in Record::all("crypto/pbkdf2/rfc6070.txt") {
        let iterations: u32 = record.field("c").parse().unwrap();
        if iterations > 1 << 20 {
            continue;
        }
        let expected = record.bytes("DK");
        assert_eq!(
            pbkdf2(sha1, &record.bytes("P"), &record.bytes("S"), iterations, expected.len()),
            Some(expected),
            "c = {iterations}"
        );
    }
    for (path, hash) in [
        ("crypto/pbkdf2/pbkdf2_hmacsha1_test.json", &b"umilib_hash_sha_v1_SHA1"[..]),
        ("crypto/pbkdf2/pbkdf2_hmacsha224_test.json", b"umilib_hash_sha_v2_SHA224"),
        ("crypto/pbkdf2/pbkdf2_hmacsha256_test.json", b"umilib_hash_sha_v2_SHA256"),
        ("crypto/pbkdf2/pbkdf2_hmacsha384_test.json", b"umilib_hash_sha_v2_SHA384"),
        ("crypto/pbkdf2/pbkdf2_hmacsha512_test.json", b"umilib_hash_sha_v2_SHA512"),
    ] {
        for (_, test) in Wycheproof::tests(path) {
            let label = format!("{path} tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
            let result = pbkdf2(
                hash,
                &test.bytes("password"),
                &test.bytes("salt"),
                test.field("iterationCount").as_usize() as u32,
                test.field("dkLen").as_usize(),
            );
            if test.field("result").as_str() == "valid" {
                assert_eq!(result, Some(test.bytes("dk")), "{label}");
            } else {
                assert_eq!(result, None, "{label}");
            }
        }
    }
    unsafe {
        // RFC 8018 section 5.2: dkLen is at most (2^32 - 1) × hLen.
        let mut maximum = 0u64;
        Check::ok(pbkdf2::umilib_crypto_pbkdf2_pbkdf2_maximum_output(sha1.as_ptr(), sha1.len(), &mut maximum));
        assert_eq!(maximum, ((1u64 << 32) - 1) * 20);
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn scrypt_follows_rfc7914() {
    let records = Record::all("crypto/scrypt/rfc7914.txt");
    let mut checked = 0;
    for record in records.iter().filter(|record| record.get("N") != Some("1048576")) {
        match record.field("Function") {
            "Salsa20/8" => {
                let input = record.bytes("Input");
                let mut block: Vec<u32> =
                    input.chunks(4).map(|word| u32::from_le_bytes(word.try_into().unwrap())).collect();
                unsafe { Check::ok(scrypt::umilib_crypto_scrypt_scrypt_salsa20_8(block.as_mut_ptr())) };
                let output: Vec<u8> = block.iter().flat_map(|word| word.to_le_bytes()).collect();
                assert_eq!(output, record.bytes("Output"));
            }
            "scrypt" => unsafe {
                let parameter = |name: &str| record.field(name).parse::<u64>().unwrap();
                let (n, r, p) = (parameter("N"), parameter("r") as u32, parameter("p") as u32);
                let mut state = ptr::null_mut();
                Check::ok(scrypt::umilib_crypto_scrypt_scrypt_new(n, r, p, &mut state));
                let (mut got_n, mut got_r, mut got_p) = (0u64, 0u32, 0u32);
                Check::ok(scrypt::umilib_crypto_scrypt_scrypt_n(state, &mut got_n));
                Check::ok(scrypt::umilib_crypto_scrypt_scrypt_r(state, &mut got_r));
                Check::ok(scrypt::umilib_crypto_scrypt_scrypt_p(state, &mut got_p));
                assert_eq!((got_n, got_r, got_p), (n, r, p));
                let mut memory = U128::default();
                Check::ok(scrypt::umilib_crypto_scrypt_scrypt_memory(state, &mut memory));
                assert_eq!(u128::from(memory), 128 * r as u128 * (n as u128 + p as u128));
                let (password, salt, expected) = (record.bytes("P"), record.bytes("S"), record.bytes("DK"));
                let mut out = vec![0u8; expected.len()];
                Check::ok(scrypt::umilib_crypto_scrypt_scrypt_derive(
                    state,
                    password.as_ptr(),
                    password.len(),
                    salt.as_ptr(),
                    salt.len(),
                    out.as_mut_ptr(),
                    out.len(),
                ));
                assert_eq!(out, expected, "N = {n}");
                scrypt::umilib_crypto_scrypt_scrypt_free(state);
            },
            _ => continue,
        }
        checked += 1;
    }
    assert_eq!(checked, 4);
    unsafe {
        // Section 6: N is a power of two above 1.
        let mut state = ptr::null_mut();
        Check::fails(scrypt::umilib_crypto_scrypt_scrypt_new(3, 1, 1, &mut state), "crypto", "InvalidParameter");
        Check::fails(scrypt::umilib_crypto_scrypt_scrypt_new(1, 1, 1, &mut state), "crypto", "InvalidParameter");
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn argon2_follows_rfc9106_section_5() {
    let records = Record::all("crypto/argon2/rfc9106.txt");
    assert_eq!(records.len(), 3);
    for record in records {
        let label = record.field("Type");
        let variant = match label {
            "Argon2d" => 0,
            "Argon2i" => 1,
            "Argon2id" => 2,
            other => panic!("{other}"),
        };
        let number = |name: &str| record.field(name).parse::<u32>().unwrap();
        let (password, salt, secret, associated) =
            (record.bytes("Password"), record.bytes("Salt"), record.bytes("Secret"), record.bytes("Associated"));
        let tag = record.bytes("Tag");
        unsafe {
            let mut state = ptr::null_mut();
            Check::ok(argon2::umilib_crypto_argon2_argon2_new(
                variant,
                number("Memory"),
                number("Passes"),
                number("Lanes"),
                &mut state,
            ));
            let mut value = 0u32;
            Check::ok(argon2::umilib_crypto_argon2_argon2_variant(state, &mut value));
            assert_eq!(value, variant);
            Check::ok(argon2::umilib_crypto_argon2_argon2_blocks(state, &mut value));
            assert_eq!(value, 32);
            let mut out = vec![0u8; tag.len()];
            Check::ok(argon2::umilib_crypto_argon2_argon2_derive(
                state,
                password.as_ptr(),
                password.len(),
                salt.as_ptr(),
                salt.len(),
                secret.as_ptr(),
                secret.len(),
                associated.as_ptr(),
                associated.len(),
                out.as_mut_ptr(),
                out.len(),
            ));
            assert_eq!(out, tag, "{label}");
            argon2::umilib_crypto_argon2_argon2_free(state);
        }
    }
    unsafe {
        let mut state = ptr::null_mut();
        // Section 3.1: the type y is 0, 1 or 2; p is at least 1, m at least 8p KiB.
        Check::fails(argon2::umilib_crypto_argon2_argon2_new(3, 32, 1, 1, &mut state), "ffi", "InvalidArgument");
        Check::fails(argon2::umilib_crypto_argon2_argon2_new(2, 7, 1, 1, &mut state), "crypto", "InvalidParameter");
        // Section 3.3: H' of 64 bytes or fewer is BLAKE2b of LE32(T) and the input.
        let inputs = [b"umilib".as_ptr()];
        let lengths = [6usize];
        let mut out = [0u8; 32];
        Check::ok(argon2::umilib_crypto_argon2_argon2_variable_hash(
            inputs.as_ptr(),
            lengths.as_ptr(),
            1,
            out.as_mut_ptr(),
            32,
        ));
        let mut expected = [0u8; 32];
        let mut blake = umilib::hash::blake::v2::BLAKE2b::new(32).unwrap();
        blake.update(&32u32.to_le_bytes());
        blake.update(b"umilib");
        blake.finalize_into(&mut expected).unwrap();
        assert_eq!(out, expected);
    }
}

/// The C names of the PRF and its primitive of a KBKDF record, with its key.
fn prf(record: &Record) -> (&'static [u8], &'static [u8]) {
    const HMAC: &[u8] = b"umilib_crypto_hmac_HMAC";
    const CMAC: &[u8] = b"umilib_crypto_cmac_CMAC";
    match record.header["PRF"].as_str() {
        "CMAC_AES128" => (CMAC, b"umilib_crypto_aes_AES128"),
        "CMAC_AES192" => (CMAC, b"umilib_crypto_aes_AES192"),
        "CMAC_AES256" => (CMAC, b"umilib_crypto_aes_AES256"),
        "CMAC_TDES2" | "CMAC_TDES3" => (CMAC, b"umilib_crypto_des_TDES"),
        "HMAC_SHA1" => (HMAC, b"umilib_hash_sha_v1_SHA1"),
        "HMAC_SHA224" => (HMAC, b"umilib_hash_sha_v2_SHA224"),
        "HMAC_SHA256" => (HMAC, b"umilib_hash_sha_v2_SHA256"),
        "HMAC_SHA384" => (HMAC, b"umilib_hash_sha_v2_SHA384"),
        "HMAC_SHA512" => (HMAC, b"umilib_hash_sha_v2_SHA512"),
        prf => panic!("{prf}"),
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
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
            let (function, primitive) = prf(&record);
            let key = record.bytes("KI");
            let bits = record.header.get("RLEN").map_or(32, |rlen| rlen.trim_end_matches("_BITS").parse().unwrap());
            let location = match record.header.get("CTRLOCATION").map(String::as_str) {
                Some("BEFORE_ITER") => 1,
                Some("AFTER_ITER") => 2,
                Some("AFTER_FIXED") => 3,
                _ => 0,
            };
            let length: usize = record.field("L").parse().unwrap();
            let mut out = vec![0u8; length / 8];
            unsafe {
                let mut state = ptr::null_mut();
                Check::ok(kbkdf::umilib_crypto_kbkdf_kbkdf_new(
                    function.as_ptr(),
                    function.len(),
                    primitive.as_ptr(),
                    primitive.len(),
                    key.as_ptr(),
                    key.len(),
                    bits,
                    &mut state,
                ));
                match mode {
                    "Counter" => {
                        let (before, after) = match record.header["CTRLOCATION"].as_str() {
                            "BEFORE_FIXED" => (Vec::new(), record.bytes("FixedInputData")),
                            "AFTER_FIXED" => (record.bytes("FixedInputData"), Vec::new()),
                            "MIDDLE_FIXED" => (record.bytes("DataBeforeCtrData"), record.bytes("DataAfterCtrData")),
                            location => panic!("{location}"),
                        };
                        Check::ok(kbkdf::umilib_crypto_kbkdf_kbkdf_counter(
                            state,
                            before.as_ptr(),
                            before.len(),
                            after.as_ptr(),
                            after.len(),
                            out.as_mut_ptr(),
                            out.len(),
                        ));
                    }
                    "Feedback" => {
                        let iv = record.get("IV").map(Vectors::hex).unwrap_or_default();
                        let fixed = record.bytes("FixedInputData");
                        Check::ok(kbkdf::umilib_crypto_kbkdf_kbkdf_feedback(
                            state,
                            iv.as_ptr(),
                            iv.len(),
                            fixed.as_ptr(),
                            fixed.len(),
                            location,
                            out.as_mut_ptr(),
                            out.len(),
                        ));
                    }
                    _ => {
                        let fixed = record.bytes("FixedInputData");
                        Check::ok(kbkdf::umilib_crypto_kbkdf_kbkdf_double_pipeline(
                            state,
                            fixed.as_ptr(),
                            fixed.len(),
                            location,
                            out.as_mut_ptr(),
                            out.len(),
                        ));
                    }
                }
                kbkdf::umilib_crypto_kbkdf_kbkdf_free(state);
            }
            assert_eq!(out, record.bytes("KO"), "{label}");
            checked += 1;
        }
    }
    assert_eq!(checked, 4800 + 4800 + 4800 + 400 + 4800 + 400);
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn kbkdf_checks_its_prf_and_parameters() {
    let (hmac, sha256) = (b"umilib_crypto_hmac_HMAC", b"umilib_hash_sha_v2_SHA256");
    let key = b"key";
    unsafe {
        let mut state = ptr::null_mut();
        for (function, primitive, bits, domain, name) in [
            (&b"umilib_crypto_kmac_KMAC"[..], &sha256[..], 32, "ffi", "InvalidArgument"),
            (hmac, b"umilib_crypto_aes_AES128", 32, "ffi", "InvalidArgument"),
            (b"umilib_crypto_cmac_CMAC", sha256, 32, "ffi", "InvalidArgument"),
            (hmac, sha256, 12, "crypto", "InvalidParameter"),
        ] {
            Check::fails(
                kbkdf::umilib_crypto_kbkdf_kbkdf_new(
                    function.as_ptr(),
                    function.len(),
                    primitive.as_ptr(),
                    primitive.len(),
                    key.as_ptr(),
                    3,
                    bits,
                    &mut state,
                ),
                domain,
                name,
            );
        }
        Check::ok(kbkdf::umilib_crypto_kbkdf_kbkdf_new(
            hmac.as_ptr(),
            hmac.len(),
            sha256.as_ptr(),
            sha256.len(),
            key.as_ptr(),
            3,
            8,
            &mut state,
        ));
        // Section 4.1: with an 8-bit counter, at most 255 blocks.
        let mut out = vec![0u8; 255 * 32 + 1];
        Check::fails(
            kbkdf::umilib_crypto_kbkdf_kbkdf_counter(
                state,
                ptr::null(),
                0,
                b"fixed".as_ptr(),
                5,
                out.as_mut_ptr(),
                out.len(),
            ),
            "crypto",
            "InputLength",
        );
        Check::ok(kbkdf::umilib_crypto_kbkdf_kbkdf_counter(
            state,
            ptr::null(),
            0,
            b"fixed".as_ptr(),
            5,
            out.as_mut_ptr(),
            255 * 32,
        ));
        Check::fails(
            kbkdf::umilib_crypto_kbkdf_kbkdf_double_pipeline(state, ptr::null(), 0, 4, out.as_mut_ptr(), 32),
            "ffi",
            "InvalidArgument",
        );
        kbkdf::umilib_crypto_kbkdf_kbkdf_free(state);
    }
}

#[test]
fn kdf_tree_follows_rfc7836_appendix_b() {
    let (hmac, streebog) = (b"umilib_crypto_hmac_HMAC", b"umilib_hash_streebog_Streebog256");
    let key = Vectors::hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let (label, seed) = (Vectors::hex("26bdb878"), Vectors::hex("af21434145656378"));
    unsafe {
        let mut tree = ptr::null_mut();
        Check::ok(kdftree::umilib_crypto_kdftree_kdftree_new(
            hmac.as_ptr(),
            hmac.len(),
            streebog.as_ptr(),
            streebog.len(),
            key.as_ptr(),
            32,
            1,
            &mut tree,
        ));
        let mut out = [0u8; 32];
        Check::ok(kdftree::umilib_crypto_kdftree_kdftree_derive(
            tree,
            label.as_ptr(),
            4,
            seed.as_ptr(),
            8,
            out.as_mut_ptr(),
            32,
        ));
        assert_eq!(out.to_vec(), Vectors::hex("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"));
        let mut out = [0u8; 64];
        Check::ok(kdftree::umilib_crypto_kdftree_kdftree_derive(
            tree,
            label.as_ptr(),
            4,
            seed.as_ptr(),
            8,
            out.as_mut_ptr(),
            64,
        ));
        assert_eq!(
            out.to_vec(),
            Vectors::hex(
                "22b6837845c6bef65ea71672b265831086d3c76aebe6dae91cad51d83f79d16b074c9330599d7f8d712fca54392f4ddde93751206b3584c8f43f9e6dc51531f9"
            )
        );
        kdftree::umilib_crypto_kdftree_kdftree_free(tree);
        Check::fails(
            kdftree::umilib_crypto_kdftree_kdftree_new(
                hmac.as_ptr(),
                hmac.len(),
                streebog.as_ptr(),
                streebog.len(),
                key.as_ptr(),
                32,
                5,
                &mut tree,
            ),
            "crypto",
            "InvalidParameter",
        );
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn ctr_drbg_follows_the_cavp_vectors() {
    let mut checked = 0;
    for mode in ["no_reseed", "pr_false", "pr_true"] {
        let path = format!("crypto/random/CTR_DRBG_{mode}.rsp");
        for record in &Record::all(&path) {
            let group = record.header.keys().find(|key| key.contains(" df")).unwrap().as_str();
            let cipher: &[u8] = match &group[..7] {
                "AES-128" => b"umilib_crypto_aes_AES128",
                "AES-192" => b"umilib_crypto_aes_AES192",
                "AES-256" => b"umilib_crypto_aes_AES256",
                // TDEA is not approved for CTR_DRBG any more (SP 800-131A).
                _ => continue,
            };
            let label = format!("{path} [{group}] COUNT = {}", record.field("COUNT"));
            let (entropy, nonce, personalization) =
                (record.bytes("EntropyInput"), record.bytes("Nonce"), record.bytes("PersonalizationString"));
            let config = DRBGConfig::default();
            unsafe {
                let mut state = ptr::null_mut();
                if group.ends_with("use df") {
                    Check::ok(ctr_drbg::new(
                        cipher.as_ptr(),
                        cipher.len(),
                        entropy.as_ptr(),
                        entropy.len(),
                        nonce.as_ptr(),
                        nonce.len(),
                        personalization.as_ptr(),
                        personalization.len(),
                        &mut state,
                    ));
                } else {
                    Check::ok(ctr_drbg::umilib_crypto_random_ctr_drbg_instantiate_without_derivation(
                        cipher.as_ptr(),
                        cipher.len(),
                        &config,
                        entropy.as_ptr(),
                        entropy.len(),
                        personalization.as_ptr(),
                        personalization.len(),
                        &mut state,
                    ));
                }
                let expected = record.bytes("ReturnedBits");
                let mut out = vec![0u8; expected.len()];
                if let Some(entropy) = record.get("EntropyInputReseed") {
                    let (entropy, additional) = (Vectors::hex(entropy), record.bytes("AdditionalInputReseed"));
                    Check::ok(ctr_drbg::reseed(
                        state,
                        entropy.as_ptr(),
                        entropy.len(),
                        additional.as_ptr(),
                        additional.len(),
                    ));
                }
                let prediction_resistance = record.header["PredictionResistance"] == "True";
                let entropy_pr = record.values("EntropyInputPR");
                for (index, input) in record.values("AdditionalInput").iter().enumerate() {
                    let input = Vectors::hex(input);
                    if prediction_resistance {
                        let entropy = Vectors::hex(entropy_pr[index]);
                        Check::ok(ctr_drbg::reseed(
                            state,
                            entropy.as_ptr(),
                            entropy.len(),
                            input.as_ptr(),
                            input.len(),
                        ));
                        Check::ok(ctr_drbg::generate(state, out.as_mut_ptr(), out.len(), ptr::null(), 0));
                    } else {
                        Check::ok(ctr_drbg::generate(state, out.as_mut_ptr(), out.len(), input.as_ptr(), input.len()));
                    }
                }
                assert_eq!(out, expected, "{label}");
                let mut strength = 0;
                Check::ok(ctr_drbg::security_strength(state, &mut strength));
                // Table 3: the security strength is the key length.
                assert_eq!(strength, group[4..7].parse::<usize>().unwrap());
                ctr_drbg::free(state);
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 3 * 1440);
}

#[test]
fn ctr_drbg_checks_its_inputs() {
    let aes = b"umilib_crypto_aes_AES128";
    let config = DRBGConfig::default();
    unsafe {
        let mut state = ptr::null_mut();
        // Section 10.2.1.3.1: without the derivation function the entropy input is exactly seedlen bits.
        Check::fails(
            ctr_drbg::umilib_crypto_random_ctr_drbg_instantiate_without_derivation(
                aes.as_ptr(),
                aes.len(),
                &config,
                [0u8; 31].as_ptr(),
                31,
                ptr::null(),
                0,
                &mut state,
            ),
            "crypto.random",
            "EntropyLength",
        );
        let des = b"umilib_crypto_des_TDES";
        Check::fails(
            ctr_drbg::new(
                des.as_ptr(),
                des.len(),
                [0u8; 32].as_ptr(),
                32,
                [0u8; 16].as_ptr(),
                16,
                ptr::null(),
                0,
                &mut state,
            ),
            "ffi",
            "InvalidArgument",
        );
        Check::ok(ctr_drbg::new(
            aes.as_ptr(),
            aes.len(),
            [1u8; 32].as_ptr(),
            32,
            [2u8; 16].as_ptr(),
            16,
            ptr::null(),
            0,
            &mut state,
        ));
        let mut out = [0u8; 16];
        Check::ok(ctr_drbg::fill(state, out.as_mut_ptr(), 16));
        Check::ok(ctr_drbg::uninstantiate(state));
        Check::fails(ctr_drbg::fill(state, out.as_mut_ptr(), 16), "crypto.random", "Uninstantiated");
        ctr_drbg::free(state);
    }
}

#[test]
fn derivations_refuse_outputs_that_overlap_their_inputs() {
    let sha256 = b"umilib_hash_sha_v2_SHA256";
    let mut buffer = [9u8; 96];
    let pointer = buffer.as_mut_ptr();
    unsafe {
        // Writing the PRK over the input keying material would read and write the same bytes.
        Check::fails(
            hkdf::umilib_crypto_hkdf_hkdf_extract(
                sha256.as_ptr(),
                sha256.len(),
                ptr::null(),
                0,
                pointer,
                32,
                pointer,
                32,
            ),
            "ffi",
            "InvalidArgument",
        );
        Check::fails(
            hkdf::umilib_crypto_hkdf_hkdf_derive(
                sha256.as_ptr(),
                sha256.len(),
                ptr::null(),
                0,
                pointer,
                32,
                ptr::null(),
                0,
                pointer.add(16),
                32,
            ),
            "ffi",
            "InvalidArgument",
        );
        Check::fails(
            pbkdf2::umilib_crypto_pbkdf2_pbkdf2_derive(
                sha256.as_ptr(),
                sha256.len(),
                pointer,
                8,
                pointer.add(8),
                8,
                1,
                pointer.add(4),
                32,
            ),
            "ffi",
            "InvalidArgument",
        );
        Check::ok(hkdf::umilib_crypto_hkdf_hkdf_extract(
            sha256.as_ptr(),
            sha256.len(),
            ptr::null(),
            0,
            pointer,
            32,
            pointer.add(32),
            32,
        ));
    }
}

#[test]
fn concatkdf_follows_rfc_7518_appendix_c() {
    let z = [
        158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106,
        72, 246, 218, 167, 121, 140, 254, 144, 196,
    ];
    let other_info = [
        0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105, 99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0,
        128,
    ];
    let derived = [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26];
    let (function, hash) = (b"umilib_crypto_concatkdf_HashFunction", b"umilib_hash_sha_v2_SHA256");
    unsafe {
        let mut state = ptr::null_mut();
        Check::ok(concatkdf::umilib_crypto_concatkdf_concat_kdf_new(
            function.as_ptr(),
            function.len(),
            hash.as_ptr(),
            hash.len(),
            ptr::null(),
            0,
            &mut state,
        ));
        let mut out = [0u8; 16];
        Check::ok(concatkdf::umilib_crypto_concatkdf_concat_kdf_derive(
            state,
            z.as_ptr(),
            z.len(),
            other_info.as_ptr(),
            other_info.len(),
            out.as_mut_ptr(),
            out.len(),
        ));
        assert_eq!(out, derived);
        concatkdf::umilib_crypto_concatkdf_concat_kdf_free(state);
        // A hash function takes no salt.
        Check::fails(
            concatkdf::umilib_crypto_concatkdf_concat_kdf_new(
                function.as_ptr(),
                function.len(),
                hash.as_ptr(),
                hash.len(),
                b"salt".as_ptr(),
                4,
                &mut state,
            ),
            "ffi",
            "InvalidArgument",
        );
    }
}
