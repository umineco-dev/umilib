//! EdDSA (RFC 8032) against the test vectors of its section 7 and Project
//! Wycheproof, and the properties every signature scheme must have.

use umilib::crypto::eddsa::{Ed448, Ed25519, EdDSA, EdDSACurve};
use umilib::crypto::{CryptoError, SignatureScheme};

use super::ecdsa::check_scheme;
use crate::{Vectors, Wycheproof};

/// One test of RFC 8032 section 7: its name and its fields.
struct RFC8032Test {
    name: String,
    fields: Vec<(String, String)>,
}

impl RFC8032Test {
    /// Every test of section 7: from each "-----name" line, the fields are
    /// "LABEL:" lines followed by their value, across page breaks.
    fn all() -> Vec<RFC8032Test> {
        let text = Vectors::read("crypto/eddsa/rfc8032.txt");
        let start = text.find("7.  Test Vectors\n").unwrap();
        let end = text[start..].find("\n8.  Security Considerations").unwrap() + start;
        let mut tests: Vec<RFC8032Test> = Vec::new();
        // Text between a closing "-----" and the next test belongs to no test.
        let mut open = false;
        for line in text[start..end].lines() {
            let trimmed = line.trim();
            let page = line.starts_with("Josefsson") || line.starts_with("RFC 8032");
            if page || trimmed.is_empty() {
                continue;
            }
            if let Some(name) = trimmed.strip_prefix("-----") {
                open = !name.is_empty();
                if open {
                    tests.push(RFC8032Test { name: name.to_owned(), fields: Vec::new() });
                }
            } else if let Some(test) = tests.last_mut().filter(|_| open) {
                if line.starts_with("   ")
                    && trimmed.ends_with(':')
                    && trimmed.chars().next().unwrap().is_ascii_uppercase()
                {
                    test.fields.push((trimmed.trim_end_matches(':').to_owned(), String::new()));
                } else if let Some((_, value)) = test.fields.last_mut() {
                    value.push_str(trimmed);
                }
            }
        }
        tests
    }

    fn field(&self, prefix: &str) -> &str {
        let found = self.fields.iter().find(|(label, _)| label.starts_with(prefix));
        found.map(|(_, value)| value.as_str()).unwrap_or_else(|| panic!("{}: no {prefix}", self.name))
    }

    fn has(&self, prefix: &str) -> bool {
        self.fields.iter().any(|(label, _)| label.starts_with(prefix))
    }
}

/// The test `test` with the curve `C` in the variant its ALGORITHM names.
fn check_rfc8032_test<C: EdDSACurve>(test: &RFC8032Test) {
    let key = EdDSA::<C>::signing_key_from_bytes(&Vectors::hex(test.field("SECRET KEY"))).unwrap();
    let public = Vectors::hex(test.field("PUBLIC KEY"));
    assert_eq!(key.verifying_key().encoded(), &public[..], "{}", test.name);
    let verifying = EdDSA::<C>::verifying_key_from_bytes(&public).unwrap();
    let message = Vectors::hex(test.field("MESSAGE"));
    let context = if test.has("CONTEXT") { Vectors::hex(test.field("CONTEXT")) } else { Vec::new() };
    let expected = Vectors::hex(test.field("SIGNATURE"));
    let mut signature = vec![0; EdDSA::<C>::SIGNATURE_SIZE];
    match test.field("ALGORITHM") {
        "Ed25519" => {
            EdDSA::<C>::sign(&key, &message, &mut signature).unwrap();
            assert_eq!(EdDSA::<C>::verify(&verifying, &message, &signature), Ok(()));
        }
        "Ed448" if context.is_empty() => {
            EdDSA::<C>::sign(&key, &message, &mut signature).unwrap();
            assert_eq!(EdDSA::<C>::verify(&verifying, &message, &signature), Ok(()));
        }
        "Ed25519ctx" | "Ed448" => {
            EdDSA::<C>::sign_with_context(&key, &context, &message, &mut signature).unwrap();
            assert_eq!(EdDSA::<C>::verify_with_context(&verifying, &context, &message, &signature), Ok(()));
            // Another context is another signature.
            let other = [&context[..], b"!"].concat();
            assert_eq!(
                EdDSA::<C>::verify_with_context(&verifying, &other, &message, &signature),
                Err(CryptoError::InvalidSignature)
            );
        }
        "Ed25519ph" | "Ed448ph" => {
            EdDSA::<C>::sign_prehashed(&key, &context, &message, &mut signature).unwrap();
            assert_eq!(EdDSA::<C>::verify_prehashed(&verifying, &context, &message, &signature), Ok(()));
            // The prehash variant is not the pure one.
            assert_eq!(EdDSA::<C>::verify(&verifying, &message, &signature), Err(CryptoError::InvalidSignature));
        }
        other => panic!("{}: {other}", test.name),
    }
    assert_eq!(signature, expected, "{} {}", test.field("ALGORITHM"), test.name);
}

/// The Wycheproof file of the curve `C`: valid signatures verify, invalid
/// ones are refused, and acceptable ones (of public keys of small or mixed
/// order) may be either.
fn check_wycheproof<C: EdDSACurve>(file: &str, count: usize) {
    let tests = Wycheproof::tests(&format!("crypto/eddsa/{file}"));
    assert_eq!(tests.len(), count, "{file}");
    for (group, test) in &tests {
        let label = format!("{file} {}", test.field("tcId").as_usize());
        let key = EdDSA::<C>::verifying_key_from_bytes(&Vectors::hex(group.field("publicKey").field("pk").as_str()));
        let result = key.and_then(|key| EdDSA::<C>::verify(&key, &test.bytes("msg"), &test.bytes("sig")));
        match test.field("result").as_str() {
            "valid" => assert_eq!(result, Ok(()), "{label}"),
            "invalid" => assert!(result.is_err(), "{label}"),
            _ => {}
        }
    }
}

#[test]
fn rfc8032() {
    let tests = RFC8032Test::all();
    assert_eq!(tests.len(), 5 + 4 + 1 + 9 + 2);
    for test in &tests {
        if test.field("ALGORITHM").starts_with("Ed25519") {
            check_rfc8032_test::<umilib::crypto::curve::curve25519::Edwards25519>(test);
        } else {
            check_rfc8032_test::<umilib::crypto::curve::curve448::Edwards448>(test);
        }
    }
}

#[test]
fn ed25519() {
    check_scheme::<Ed25519>();
    check_wycheproof::<umilib::crypto::curve::curve25519::Edwards25519>("ed25519_test.json", 210);
    check_limits::<umilib::crypto::curve::curve25519::Edwards25519>();
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn ed448() {
    check_scheme::<Ed448>();
    check_wycheproof::<umilib::crypto::curve::curve448::Edwards448>("ed448_test.json", 87);
    check_limits::<umilib::crypto::curve::curve448::Edwards448>();
}

/// Contexts of at most 255 bytes; S below L.
fn check_limits<C: EdDSACurve>() {
    let key = EdDSA::<C>::signing_key_from_bytes(&vec![9; C::ENCODED_BYTES]).unwrap();
    let verifying = EdDSA::<C>::verifying_key(&key);
    let mut signature = vec![0; EdDSA::<C>::SIGNATURE_SIZE];
    EdDSA::<C>::sign_with_context(&key, &[1; 255], b"m", &mut signature).unwrap();
    assert_eq!(EdDSA::<C>::verify_with_context(&verifying, &[1; 255], b"m", &signature), Ok(()));
    let long = [1; 256];
    assert_eq!(EdDSA::<C>::sign_with_context(&key, &long, b"m", &mut signature), Err(CryptoError::InvalidParameter));
    assert_eq!(EdDSA::<C>::sign_prehashed(&key, &long, b"m", &mut signature), Err(CryptoError::InvalidParameter));
    assert_eq!(
        EdDSA::<C>::verify_with_context(&verifying, &long, b"m", &signature),
        Err(CryptoError::InvalidParameter)
    );
    // S + L encodes the same residue but is refused (section 5.1.7 step 1).
    EdDSA::<C>::sign(&key, b"m", &mut signature).unwrap();
    use umilib::math::bigint::UnsignedInteger;
    use umilib::math::ec::{FieldValue, PrimeField};
    use umilib::math::modular::ModularArithmetic;
    let size = C::ENCODED_BYTES;
    let s = FieldValue::<C::Scalar>::from_le_bytes(&signature[size..]).unwrap();
    let (sum, overflow) = s.overflowing_add(<C::Scalar as PrimeField>::MODULUS.value());
    if !overflow.into_bool() {
        let mut changed = signature.clone();
        changed[size..].fill(0);
        let precision = <FieldValue<C::Scalar> as UnsignedInteger>::BYTES.min(size);
        sum.write_le_bytes(&mut changed[size..size + precision]).unwrap();
        assert_eq!(EdDSA::<C>::verify(&verifying, b"m", &changed), Err(CryptoError::InvalidSignature));
    }
}
