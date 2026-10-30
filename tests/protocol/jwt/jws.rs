//! JWS against RFC 7515, RFC 7518 §3, RFC 7797, RFC 8037 appendix A,
//! RFC 8725, RFC 9864, RFC 9964 appendix A, the JOSE Cookbook (RFC 7520 §4)
//! and Project Wycheproof.

use umilib::protocol::jwt::{Base64URL, JOSEHeader, JWK, JWS, JWSAlgorithm, JWSConfig, JWTError};

use super::jwk::MLDSAExamples;
use super::{jwk, path, random};
use crate::{Json, RFC, Wycheproof};

/// Every algorithm but `none`.
fn every_algorithm() -> JWSConfig {
    let algorithms: Vec<JWSAlgorithm> =
        JWSAlgorithm::ALL.into_iter().filter(|algorithm| *algorithm != JWSAlgorithm::None).collect();
    JWSConfig::new(&algorithms)
}

/// Checks the examples of one cookbook file: every output verifies under
/// the key, reads back to its text, and a deterministic signature is
/// reproduced from the signing input.
fn check_cookbook(name: &str) {
    let example = Json::read(&path(name));
    let input = example.field("input");
    let keys: Vec<JWK> = match input.field("key") {
        Json::Array(keys) => keys.iter().map(jwk).collect(),
        key => vec![jwk(key)],
    };
    let signings: Vec<&Json> = match example.field("signing") {
        Json::Array(signings) => signings.iter().collect(),
        signing => vec![signing],
    };
    let payload = input.field("payload").as_str().as_bytes().to_vec();
    let config = every_algorithm();
    let reproducible = !matches!(example.get("reproducible"), Some(Json::Bool(false)));
    for (signing, key) in signings.iter().zip(&keys) {
        let algorithm = if let Some(protected) = signing.get("protected") {
            JWSAlgorithm::from_name(protected.field("alg").as_str())
        } else {
            JWSAlgorithm::from_name(signing.field("unprotected").field("alg").as_str())
        }
        .unwrap();
        let signature = Base64URL::decode(signing.field("sig").as_str()).unwrap();
        let input = signing.field("sig-input").as_str().as_bytes();
        algorithm.verify(&key.to_public().unwrap_or_else(|_| key.clone()), input, &signature).unwrap();
        let deterministic = matches!(
            algorithm,
            JWSAlgorithm::HS256 | JWSAlgorithm::HS384 | JWSAlgorithm::HS512 | JWSAlgorithm::RS256 | JWSAlgorithm::EdDSA
        );
        if deterministic && reproducible {
            assert_eq!(algorithm.sign(key, input, &mut random()).unwrap(), signature, "{name}");
        }
    }
    let output = example.field("output");
    let detached = output.get("json").is_some_and(|json| json.get("payload").is_none());
    if let Some(compact) = output.get("compact") {
        let compact = compact.as_str();
        let jws =
            if detached { JWS::from_compact_detached(compact, &payload) } else { JWS::from_compact(compact) }.unwrap();
        assert_eq!(jws.payload, payload, "{name}");
        assert_eq!(jws.verify(&keys[0], &config).map(|_| ()), Ok(()), "{name}");
        let written = if detached { jws.to_compact_detached() } else { jws.to_compact() }.unwrap();
        assert_eq!(written, compact, "{name}");
    }
    for member in ["json", "json_flat"] {
        let Some(serialization) = output.get(member) else { continue };
        let text = serialization.encode();
        let jws =
            if detached { JWS::from_json_detached(text.as_bytes(), &payload) } else { JWS::from_json(text.as_bytes()) }
                .unwrap_or_else(|error| panic!("{name} {member}: {error:?}"));
        assert_eq!(jws.payload, payload, "{name} {member}");
        for key in &keys {
            jws.verify(key, &config).unwrap_or_else(|error| panic!("{name} {member}: {error:?}"));
        }
        let written = match (member, detached) {
            ("json", false) => jws.to_json(),
            ("json", true) => jws.to_json_detached(),
            (_, false) => jws.to_flattened_json(),
            (_, true) => jws.to_flattened_json_detached(),
        }
        .unwrap();
        let read = if detached {
            JWS::from_json_detached(written.as_bytes(), &payload)
        } else {
            JWS::from_json(written.as_bytes())
        };
        assert_eq!(read.unwrap(), jws, "{name} {member}");
        assert_eq!(super::sorted(&Json::from_text(&written)), super::sorted(serialization), "{name} {member}");
    }
}

#[test]
fn the_jose_cookbook() {
    for name in [
        "4_1.rsa_v15_signature",
        "4_2.rsa-pss_signature",
        "4_3.ecdsa_signature",
        "4_4.hmac-sha2_integrity_protection",
        "4_5.signature_with_detached_content",
        "4_6.protecting_specific_header_fields",
        "4_7.protecting_content_only",
        "4_8.multiple_signatures",
    ] {
        check_cookbook(&format!("cookbook/jws/{name}.json"));
    }
    check_cookbook("cookbook/curve25519/jws.json");
}

#[test]
fn rfc_8037_appendix_a() {
    let key = jwk(&Json::from_text(&RFC::block_from(&path("rfc8037.txt"), r#"{"kty":"OKP","crv":"Ed25519","#)));
    let compact =
        RFC::block(&path("rfc8037.txt"), "signing input, a dot, and base64url encoding of the signature):", None);
    let protected = JOSEHeader::decode(br#"{"alg":"EdDSA"}"#).unwrap();
    let mut jws = JWS::new(b"Example of Ed25519 signing".to_vec());
    jws.sign(&protected, None, &key, &mut random()).unwrap();
    assert_eq!(jws.to_compact().unwrap(), compact, "Ed25519 is deterministic");
    let public = key.to_public().unwrap();
    JWS::from_compact(&compact).unwrap().verify(&public, &JWSConfig::new(&[JWSAlgorithm::EdDSA])).unwrap();
    // RFC 9864 §2.2: the fully specified Ed25519 signs the same input to the same signature.
    let input = jws.signing_input(&jws.signatures[0].protected, true);
    assert_eq!(JWSAlgorithm::Ed25519.sign(&key, &input, &mut random()).unwrap(), jws.signatures[0].signature);
    let mut fully = JWS::new(b"Example of Ed25519 signing".to_vec());
    fully.sign(&JOSEHeader::decode(br#"{"alg":"Ed25519"}"#).unwrap(), None, &key, &mut random()).unwrap();
    fully.verify(&public, &JWSConfig::new(&[JWSAlgorithm::Ed25519])).unwrap();
    // EdDSA does not verify where only Ed25519 is allowed, and Ed448 refuses an Ed25519 key.
    assert_eq!(
        JWS::from_compact(&compact).unwrap().verify(&public, &JWSConfig::new(&[JWSAlgorithm::Ed25519])).map(|_| ()),
        Err(JWTError::AlgorithmNotAllowed)
    );
    assert_eq!(JWSAlgorithm::Ed448.verify(&public, b"x", &[0; 114]), Err(JWTError::KeyMismatch));
}

#[test]
fn rfc_7797_section_4() {
    let key = jwk(&Json::from_text(&RFC::block(&path("rfc7797.txt"), "only):", Some("4.1."))));
    let config = JWSConfig::new(&[JWSAlgorithm::HS256]);
    let compact = RFC::block_from(&path("rfc7797.txt"), "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19");
    let jws = JWS::from_compact_detached(&compact, b"$.02").unwrap();
    assert!(!jws.b64().unwrap());
    jws.verify(&key, &config).unwrap();
    assert_eq!(jws.to_compact_detached().unwrap(), compact);
    // §5.2: an unencoded payload with a period cannot be in a compact serialization.
    assert_eq!(jws.to_compact(), Err(JWTError::Format));
    let flattened = RFC::block(&path("rfc7797.txt"), "JWS JSON Serialization and a non-detached payload is:", None);
    let jws = JWS::from_json(flattened.as_bytes()).unwrap();
    assert_eq!(jws.payload, b"$.02");
    jws.verify(&key, &config).unwrap();
    // The control example of §4.1 (b64 true).
    let control = RFC::block(&path("rfc7797.txt"), "JWS JSON Serialization is:", None);
    JWS::from_json(control.as_bytes()).unwrap().verify(&key, &config).unwrap();
}

#[test]
fn rfc_9964_appendix_a() {
    for (figure, algorithm) in [
        ("Figure 3: ML_DSA_44", JWSAlgorithm::MLDSA44),
        ("Figure 4: ML_DSA_65", JWSAlgorithm::MLDSA65),
        ("Figure 5: ML_DSA_87", JWSAlgorithm::MLDSA87),
    ] {
        let example = MLDSAExamples::figure(figure);
        let key = jwk(example.field("jwk"));
        let public = key.to_public().unwrap();
        let jws = JWS::from_compact(example.field("jws").as_str()).unwrap();
        assert_eq!(jws.signatures[0].algorithm(), Ok(algorithm));
        jws.verify(&public, &JWSConfig::new(&[algorithm])).unwrap_or_else(|error| panic!("{figure}: {error:?}"));
        // A signature made here verifies too (ML-DSA signatures are hedged, so they differ).
        let mut signed = JWS::new(jws.payload.clone());
        let mut protected = JOSEHeader::new();
        protected.set_string("alg", algorithm.name());
        signed.sign(&protected, None, &key, &mut random()).unwrap();
        signed.verify(&public, &JWSConfig::new(&[algorithm])).unwrap();
    }
}

/// Wycheproof tests whose expectation this library does not share, by test
/// number, with the reason.
const WYCHEPROOF_DIVERGENCES: [(usize, &str); 9] = [
    (346, "the key's alg is PS256 and the JWS's PS384: a key is for its alg only (RFC 7517 §4.4, RFC 8725 §2.1)"),
    (347, "the key's alg is the unregistered ES521 and the JWS's ES512 (RFC 7517 §4.4)"),
    (349, "the key's key_ops is the one string \"sign, verify\", which does not list \"verify\" (RFC 7517 §4.3)"),
    (350, "the key's alg is PS256 and the JWS's PS384 (RFC 7517 §4.4)"),
    (351, "the key's alg is the unregistered ES521 and the JWS's ES512 (RFC 7517 §4.4)"),
    (367, "the file's token is the token of the valid test 357: the padding the test is named after is not in it"),
    (370, "the file's token is the token of the valid test 357: the padding the test is named after is not in it"),
    (372, "'?' is not a base64url character (RFC 7515 §2), so the header does not decode"),
    (373, "'?' is not a base64url character (RFC 7515 §2), so the payload does not decode"),
];

#[test]
fn wycheproof() {
    let config = every_algorithm();
    let mut checked = 0;
    for (group, test) in Wycheproof::tests(&path("json_web_signature_test.json")) {
        let private = group.field("private");
        if WYCHEPROOF_DIVERGENCES.iter().any(|(id, _)| *id == test.field("tcId").as_usize()) {
            continue;
        }
        let key = jwk(private);
        let key = key.to_public().unwrap_or(key);
        let id = test.field("tcId").as_usize();
        let token = test.field("jws");
        let verified = match token {
            Json::String(compact) => JWS::from_compact(compact).and_then(|jws| jws.verify(&key, &config).map(|_| ())),
            json => JWS::from_json(json.encode().as_bytes()).and_then(|jws| jws.verify(&key, &config).map(|_| ())),
        };
        assert_eq!(
            verified.is_ok(),
            Wycheproof::valid(&test),
            "{} {id} {}: {verified:?}",
            group.field("comment").as_str(),
            test.field("comment").as_str()
        );
        checked += 1;
    }
    assert!(checked > 100, "{checked}");
}

#[test]
fn verification_follows_rfc_8725() {
    let key = JWK::symmetric(&[7; 32]);
    let mut protected = JOSEHeader::new();
    protected.set_string("alg", "HS256");
    let mut jws = JWS::new(b"payload".to_vec());
    jws.sign(&protected, None, &key, &mut random()).unwrap();
    let compact = jws.to_compact().unwrap();
    let hs256 = JWSConfig::new(&[JWSAlgorithm::HS256]);
    JWS::from_compact(&compact).unwrap().verify(&key, &hs256).unwrap();
    // §3.1: only the algorithms the configuration allows.
    assert_eq!(
        jws.verify(&key, &JWSConfig::new(&[JWSAlgorithm::RS256])).map(|_| ()),
        Err(JWTError::AlgorithmNotAllowed)
    );
    // §3.1: none is never accepted by verify, only by the explicit verify_unsecured.
    let mut none = JOSEHeader::new();
    none.set_string("alg", "none");
    let mut unsecured = JWS::new(b"payload".to_vec());
    unsecured.sign(&none, None, &key, &mut random()).unwrap();
    let text = unsecured.to_compact().unwrap();
    assert!(text.ends_with('.'), "an empty signature (RFC 7518 §3.6)");
    let unsecured = JWS::from_compact(&text).unwrap();
    let all = JWSConfig::new(&JWSAlgorithm::ALL);
    assert_eq!(unsecured.verify(&key, &all).map(|_| ()), Err(JWTError::AlgorithmNotAllowed));
    unsecured.verify_unsecured().unwrap();
    assert!(jws.verify_unsecured().is_err());
    // §2.1, §3.2: a key of another type than the algorithm's (an RSA public key used as an HMAC secret) does not verify.
    let rsa = jwk(&Json::read(&path("cookbook/jwk/3_3.rsa_public_key.json")));
    assert!(jws.verify(&rsa, &hs256).is_err());
    // RFC 7518 §3.2: an HMAC key shorter than the hash output.
    let short = JWK::symmetric(&[7; 31]);
    assert_eq!(JWSAlgorithm::HS256.sign(&short, b"x", &mut random()), Err(JWTError::KeyMismatch));
    // RFC 7518 §3.4: an ECDSA signature must be R || S of the curve's size, and of the algorithm's curve.
    let p521 = jwk(&Json::read(&path("cookbook/jwk/3_2.ec_private_key.json")));
    assert_eq!(JWSAlgorithm::ES256.sign(&p521, b"x", &mut random()), Err(JWTError::KeyMismatch));
    let signature = JWSAlgorithm::ES512.sign(&p521, b"x", &mut random()).unwrap();
    assert_eq!(signature.len(), 132);
    JWSAlgorithm::ES512.verify(&p521.to_public().unwrap(), b"x", &signature).unwrap();
    assert_eq!(JWSAlgorithm::ES512.verify(&p521, b"x", &signature[..131]), Err(JWTError::Signature));
    // RFC 7517 §4.2, §4.3: use and key_ops.
    let mut encryption_key = JWK::symmetric(&[7; 32]);
    encryption_key.key_use = Some(String::from("enc"));
    assert_eq!(JWSAlgorithm::HS256.sign(&encryption_key, b"x", &mut random()), Err(JWTError::KeyMismatch));
    let mut verify_only = JWK::symmetric(&[7; 32]);
    verify_only.key_operations = Some(vec![String::from("verify")]);
    assert_eq!(JWSAlgorithm::HS256.sign(&verify_only, b"x", &mut random()), Err(JWTError::KeyMismatch));
    jws.verify(&verify_only, &hs256).unwrap();
    // RFC 7515 §4.1.11: the example of crit, with HS256; a recipient accepts
    // only the extensions it understands.
    let critical = JOSEHeader::decode(br#"{"alg":"HS256","crit":["exp"],"exp":1363284000}"#).unwrap();
    let mut extended = JWS::new(b"payload".to_vec());
    extended.sign(&critical, None, &key, &mut random()).unwrap();
    let understood = JWSConfig { critical: vec![String::from("exp")], ..hs256.clone() };
    assert_eq!(extended.verify(&key, &hs256).map(|_| ()), Err(JWTError::Critical));
    extended.verify(&key, &understood).unwrap();
    // The listed parameter may be in the unprotected header: it is in the JOSE Header.
    let listed = JOSEHeader::decode(br#"{"alg":"HS256","crit":["exp"]}"#).unwrap();
    let unprotected = JOSEHeader::decode(br#"{"exp":1363284000}"#).unwrap();
    let mut split = JWS::new(b"payload".to_vec());
    split.sign(&listed, Some(&unprotected), &key, &mut random()).unwrap();
    JWS::from_json(split.to_json().unwrap().as_bytes()).unwrap().verify(&key, &understood).unwrap();
    // A listed parameter absent from every header, an empty list, a JOSE name, and crit outside the protected header.
    for (protected_text, header_text) in [
        (r#"{"alg":"HS256","crit":["exp"]}"#, None),
        (r#"{"alg":"HS256","crit":[]}"#, None),
        (r#"{"alg":"HS256","crit":["alg"]}"#, None),
        (r#"{"alg":"HS256"}"#, Some(r#"{"crit":["exp"],"exp":1}"#)),
    ] {
        let header = header_text.map(|text| JOSEHeader::decode(text.as_bytes()).unwrap());
        let protected = JOSEHeader::decode(protected_text.as_bytes()).unwrap();
        let signed = JWS::new(b"x".to_vec()).sign(&protected, header.as_ref(), &key, &mut random());
        assert_eq!(signed, Err(JWTError::Critical), "{protected_text} {header_text:?}");
    }
    // A JWS with more signatures than the configuration accepts (the work of one verification).
    let mut many = JWS::new(b"payload".to_vec());
    for _ in 0..=JWSConfig::MAXIMUM_SIGNATURES {
        many.sign(&protected, None, &key, &mut random()).unwrap();
    }
    assert_eq!(many.verify(&key, &hs256).map(|_| ()), Err(JWTError::Limit));
    let generous = JWSConfig { maximum_signatures: JWSConfig::MAXIMUM_SIGNATURES + 1, ..hs256.clone() };
    many.verify(&key, &generous).unwrap();
    // RFC 7797 §6: b64 must be listed in crit.
    let mut unencoded = protected.clone();
    unencoded.set("b64", umilib::codec::json::JSONValue::Bool(false));
    assert_eq!(JWS::new(b"x".to_vec()).sign(&unencoded, None, &key, &mut random()), Err(JWTError::Critical));
    // RFC 7515 §7.2.1: a parameter in both headers.
    let mut both = JOSEHeader::new();
    both.set_string("alg", "HS256");
    assert_eq!(JWS::new(b"x".to_vec()).sign(&protected, Some(&both), &key, &mut random()), Err(JWTError::Header));
    // RFC 7515 §4: a header parameter twice; §2: base64url without padding or other characters; §7.1: three parts.
    let duplicate = Base64URL::encode(br#"{"alg":"HS256","alg":"none"}"#);
    let parts: Vec<&str> = compact.split('.').collect();
    assert!(matches!(JWS::from_compact(&format!("{duplicate}.{}.{}", parts[1], parts[2])), Err(JWTError::JSON(_))));
    assert_eq!(
        JWS::from_compact(&format!("{}=.{}.{}", parts[0], parts[1], parts[2])).map(|_| ()),
        Err(JWTError::Base64)
    );
    assert_eq!(JWS::from_compact(&format!("{compact}.x")).map(|_| ()), Err(JWTError::Format));
    assert_eq!(JWS::from_compact("a.b").map(|_| ()), Err(JWTError::Format));
}
