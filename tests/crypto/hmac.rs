use umilib::crypto::hmac::HMAC;
use umilib::hash::CryptographicDigest;
use umilib::hash::md::v5::MD5;
use umilib::hash::sha::v1::SHA1;
use umilib::hash::sha::v2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use umilib::hash::sha::v3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};

use crate::{Record, Vectors};

/// Checks HMAC-`H` of `data` under `key` against `expected`, which may be a
/// truncated tag: at once, in pieces, after a reset, and by verification.
fn check<H: CryptographicDigest + Default>(key: &[u8], data: &[u8], expected: &[u8], label: &str) {
    let tag = HMAC::<H>::mac(key, data);
    assert_eq!(&tag.as_ref()[..expected.len()], expected, "{label}");
    let mut hmac = HMAC::<H>::new(key);
    data.chunks(13).for_each(|piece| hmac.update(piece));
    assert_eq!(hmac.finalize_reset().as_ref(), tag.as_ref(), "{label} in pieces");
    hmac.update(data);
    let full = hmac.clone();
    if expected.len() == tag.as_ref().len() {
        assert!(full.verify(expected), "{label} verify");
    }
    let accepted = expected.len() >= HMAC::<H>::MINIMUM_TRUNCATED_LENGTH.min(H::OUTPUT_SIZE);
    assert_eq!(hmac.clone().verify_truncated(expected), accepted, "{label} verify truncated");
    let mut wrong = expected.to_vec();
    wrong[expected.len() - 1] ^= 1;
    assert!(!hmac.clone().verify_truncated(&wrong), "{label} wrong tag");
    assert!(!hmac.verify(&wrong), "{label} wrong tag");
}

/// The value of an RFC 2202 field: `0x` hexadecimal, `0xNN repeated N times`, or a quoted string.
fn rfc2202_value(value: &str) -> Vec<u8> {
    if let Some(repeated) = value.strip_prefix("0x").and_then(|rest| rest.split_once(" repeated ")) {
        let count: usize = repeated.1.trim_end_matches(" times").parse().unwrap();
        return vec![u8::from_str_radix(repeated.0, 16).unwrap(); count];
    }
    if let Some(hex) = value.strip_prefix("0x") {
        return Vectors::hex(hex);
    }
    value.trim_matches('"').as_bytes().to_vec()
}

/// The test cases of a section of RFC 2202 as (key, data, digest). The
/// section of HMAC-SHA-1 repeats test cases 6 and 7 after a fragment of test
/// case 5 (a page of the RFC as published); repeats must equal the first.
fn rfc2202(section: &str, next: &str) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let text = Vectors::read("crypto/hmac/rfc2202.txt");
    let body = &text[text.find(&format!("\n{section}")).unwrap()..text.find(&format!("\n{next}")).unwrap()];
    let mut cases: Vec<Vec<(String, String)>> = Vec::new();
    let mut open_quote = false;
    for line in body.lines() {
        if open_quote {
            // A quoted string continued on the next line.
            let last = cases.last_mut().unwrap().last_mut().unwrap();
            last.1 = format!("{} {}", last.1, line.trim());
            open_quote = !line.trim_end().ends_with('"');
            continue;
        }
        let Some((name, value)) = line.split_once(char::is_whitespace) else { continue };
        let value = value.trim().trim_start_matches('=').trim().to_string();
        match name {
            "test_case" => cases.push(vec![(name.to_string(), value)]),
            "key" | "data" | "digest" | "data_len" if !cases.is_empty() => {
                open_quote = value.starts_with('"') && !value.ends_with('"');
                cases.last_mut().unwrap().push((name.to_string(), value));
            }
            _ => {}
        }
    }
    type Case = (Vec<u8>, Vec<u8>, Vec<u8>);
    let mut unique: Vec<(String, Case)> = Vec::new();
    for fields in cases {
        let get = |name: &str| fields.iter().find(|field| field.0 == name).unwrap().1.clone();
        let data = rfc2202_value(&get("data"));
        assert_eq!(data.len(), get("data_len").parse::<usize>().unwrap(), "{section} {fields:?}");
        let case = (rfc2202_value(&get("key")), data, rfc2202_value(&get("digest")));
        match unique.iter().find(|entry| entry.0 == get("test_case")) {
            Some(first) => assert_eq!(first.1, case, "{section} repeated test case {}", first.0),
            None => unique.push((get("test_case"), case)),
        }
    }
    unique.into_iter().map(|entry| entry.1).collect()
}

#[test]
fn hmac_follows_rfc2202() {
    let md5 = rfc2202("2. Test Cases for HMAC-MD5", "3. Test Cases for HMAC-SHA-1");
    let sha1 = rfc2202("3. Test Cases for HMAC-SHA-1", "4. Security Considerations");
    assert_eq!((md5.len(), sha1.len()), (7, 7));
    for (index, (key, data, digest)) in md5.iter().enumerate() {
        check::<MD5>(key, data, digest, &format!("HMAC-MD5 test case {}", index + 1));
    }
    for (index, (key, data, digest)) in sha1.iter().enumerate() {
        check::<SHA1>(key, data, digest, &format!("HMAC-SHA-1 test case {}", index + 1));
    }
}

#[test]
fn hmac_follows_rfc4231() {
    let text = Vectors::read("crypto/hmac/rfc4231.txt");
    let body = &text[text.find("\n4.2.  Test Case 1").unwrap()..text.find("\n5.  Security Considerations").unwrap()];
    let mut cases = 0;
    for section in body.split("  Test Case ").skip(1) {
        let mut fields: Vec<(String, String)> = Vec::new();
        for line in section.lines() {
            // Test case 3 as published has no "=" after "Key".
            let named = line.starts_with("   ") && !line.starts_with("    ");
            let (name, rest) = match line.trim_start().split_once(char::is_whitespace) {
                Some((name, rest)) if named && (name == "Key" || name == "Data" || name.starts_with("HMAC-")) => {
                    (Some(name.to_string()), rest.trim_start().trim_start_matches('=').trim_start())
                }
                _ => (None, line.trim_start()),
            };
            let token = rest.split_whitespace().next().unwrap_or("");
            let is_hex = !token.is_empty() && token.chars().all(|character| character.is_ascii_hexdigit());
            match name {
                Some(name) if is_hex => fields.push((name, token.to_string())),
                None if is_hex && line.starts_with("                  ") && !fields.is_empty() => {
                    fields.last_mut().unwrap().1.push_str(token)
                }
                _ => {}
            }
        }
        let get = |name: &str| Vectors::hex(&fields.iter().find(|field| field.0 == name).unwrap().1);
        let (key, data) = (get("Key"), get("Data"));
        let label = format!("RFC 4231 test case {}", &section[..1]);
        check::<SHA224>(&key, &data, &get("HMAC-SHA-224"), &label);
        check::<SHA256>(&key, &data, &get("HMAC-SHA-256"), &label);
        check::<SHA384>(&key, &data, &get("HMAC-SHA-384"), &label);
        check::<SHA512>(&key, &data, &get("HMAC-SHA-512"), &label);
        cases += 1;
    }
    assert_eq!(cases, 7);
}

#[test]
fn hmac_follows_the_cavp_vectors() {
    let records = Record::all("crypto/hmac/HMAC.rsp");
    assert!(records.len() > 1000);
    for record in records {
        let key = record.bytes("Key");
        let data = record.bytes("Msg");
        let tag = record.bytes("Mac");
        assert_eq!(tag.len(), record.field("Tlen").parse::<usize>().unwrap());
        let label = format!("HMAC.rsp L = {} COUNT = {}", record.header["L"], record.field("Count"));
        match record.header["L"].as_str() {
            "20" => check::<SHA1>(&key, &data, &tag, &label),
            "28" => check::<SHA224>(&key, &data, &tag, &label),
            "32" => check::<SHA256>(&key, &data, &tag, &label),
            "48" => check::<SHA384>(&key, &data, &tag, &label),
            "64" => check::<SHA512>(&key, &data, &tag, &label),
            other => panic!("unknown L = {other}"),
        }
    }
}

#[test]
fn hmac_minimum_truncated_length_follows_rfc2104() {
    // Half of the output, and at least 80 bits.
    assert_eq!(HMAC::<SHA1>::MINIMUM_TRUNCATED_LENGTH, 10);
    assert_eq!(HMAC::<MD5>::MINIMUM_TRUNCATED_LENGTH, 10);
    assert_eq!(HMAC::<SHA256>::MINIMUM_TRUNCATED_LENGTH, 16);
    assert_eq!(HMAC::<SHA512>::MINIMUM_TRUNCATED_LENGTH, 32);
    let tag = HMAC::<SHA256>::mac(b"key", b"data");
    assert!(!HMAC::<SHA256>::new(b"key").verify_truncated(&tag.as_ref()[..15]));
    assert!(!HMAC::<SHA256>::new(b"key").verify(&tag.as_ref()[..31]));
    assert_eq!(format!("{:?}", HMAC::<SHA256>::new(b"key")), "HMAC(..)");
}

/// One test of a Wycheproof MAC file: key, message, tag, tag size in bits
/// and whether the tag is valid.
type MACTest = (Vec<u8>, Vec<u8>, Vec<u8>, usize, bool);

/// The tests of a Wycheproof MAC file.
fn wycheproof(name: &str) -> Vec<MACTest> {
    let text = Vectors::read(&format!("crypto/hmac/wycheproof/{name}"));
    let value = |text: &str, key: &str| -> Option<String> {
        let start = text.find(&format!("\"{key}\": "))? + key.len() + 4;
        let rest = text[start..].trim_start_matches('"');
        Some(rest[..rest.find(['"', ',', '\n']).unwrap()].to_string())
    };
    let mut tests = Vec::new();
    for group in text.split("\"type\": \"MacTest\"").skip(1) {
        let size: usize = value(group, "tagSize").unwrap().parse().unwrap();
        for test in group.split("\"tcId\"").skip(1) {
            let field = |key: &str| Vectors::hex(&value(test, key).unwrap());
            tests.push((field("key"), field("msg"), field("tag"), size, value(test, "result").unwrap() == "valid"));
        }
    }
    tests
}

/// Checks the Wycheproof tests of `name` with HMAC-`H`: a valid tag is the
/// leftmost bytes of the tag, an invalid one never verifies.
fn check_wycheproof<H: CryptographicDigest + Default>(name: &str) {
    let tests = wycheproof(name);
    assert!(tests.len() > 100, "{name}");
    for (key, message, tag, size, valid) in tests {
        let full = HMAC::<H>::mac(&key, &message);
        let truncated = &full.as_ref()[..size / 8];
        assert_eq!(truncated == tag.as_slice(), valid, "{name}");
        let mut hmac = HMAC::<H>::new(&key);
        hmac.update(&message);
        if size / 8 == H::OUTPUT_SIZE {
            assert_eq!(hmac.verify(&tag), valid, "{name}");
        } else if size / 8 >= HMAC::<H>::MINIMUM_TRUNCATED_LENGTH {
            assert_eq!(hmac.verify_truncated(&tag), valid, "{name}");
        }
    }
}

#[test]
fn hmac_follows_the_wycheproof_vectors() {
    check_wycheproof::<SHA3_224>("hmac_sha3_224_test.json");
    check_wycheproof::<SHA3_256>("hmac_sha3_256_test.json");
    check_wycheproof::<SHA3_384>("hmac_sha3_384_test.json");
    check_wycheproof::<SHA3_512>("hmac_sha3_512_test.json");
    check_wycheproof::<SHA512_224>("hmac_sha512_224_test.json");
    check_wycheproof::<SHA512_256>("hmac_sha512_256_test.json");
}

#[test]
fn hmac_zeroize_erases_the_key() {
    use umilib::secret::Zeroize;
    let mut hmac = HMAC::<SHA256>::new(b"key");
    hmac.update(b"message");
    hmac.zeroize();
    // The states are those of the empty input, which the key cannot be recovered from.
    let mut fresh = HMAC::<SHA256>::new(b"other key");
    fresh.zeroize();
    assert_eq!(hmac.finalize(), fresh.finalize());
}
