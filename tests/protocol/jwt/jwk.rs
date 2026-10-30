//! JWK and JWK Sets against RFC 7517, RFC 7518 §6, RFC 7638, RFC 8037,
//! RFC 9278, RFC 9964 and the keys of the JOSE Cookbook (RFC 7520 §3).

use umilib::auth::cert::key::{
    HashAlgorithm, KeyAlgorithm, KeyError, MLDSAParameterSet, NamedCurve, PrivateKey, SignatureAlgorithm,
};
use umilib::protocol::jwt::{Base64URL, JWK, JWKCurve, JWKKey, JWKSet, JWTError};

use super::{jwk, path, random, sorted};
use crate::{Json, RFC};

#[test]
fn cookbook_keys_read_and_write_back() {
    for name in [
        "3_1.ec_public_key",
        "3_2.ec_private_key",
        "3_3.rsa_public_key",
        "3_4.rsa_private_key",
        "3_5.symmetric_key_mac_computation",
        "3_6.symmetric_key_encryption",
    ] {
        let value = Json::read(&path(&format!("cookbook/jwk/{name}.json")));
        let key = jwk(&value);
        let written = Json::from_text(&key.to_json());
        assert_eq!(sorted(&written), sorted(&value), "{name}");
    }
    // RFC 7520 §3.2: the private key holds the public key of §3.1.
    let public = jwk(&Json::read(&path("cookbook/jwk/3_1.ec_public_key.json")));
    let private = jwk(&Json::read(&path("cookbook/jwk/3_2.ec_private_key.json")));
    assert_eq!(private.to_public().unwrap().to_json(), public.to_json());
    assert_eq!(private.public_key().unwrap(), public.public_key().unwrap());
    let rsa = jwk(&Json::read(&path("cookbook/jwk/3_4.rsa_private_key.json")));
    assert_eq!(rsa.private_key().unwrap().public_key().unwrap(), rsa.public_key().unwrap());
}

#[test]
fn thumbprints_follow_rfc_7638_and_rfc_9278() {
    // RFC 7638 §3.1.
    let example = RFC::block(
        &path("rfc7638.txt"),
        "This section demonstrates the JWK Thumbprint computation",
        Some("As defined in"),
    );
    let key = jwk(&Json::from_text(example.split_once("only):").unwrap().1));
    let input = RFC::block_from(&path("rfc7638.txt"), r#"{"e":"AQAB""#);
    assert_eq!(key.thumbprint_input().unwrap(), input);
    let expected = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    assert_eq!(Base64URL::encode(&key.thumbprint(HashAlgorithm::SHA256).unwrap()), expected);
    // RFC 9278 §3: the URI of the same key.
    let uri = RFC::block_from(&path("rfc9278.txt"), "urn:ietf:params:oauth:jwk-thumbprint:sha-256:");
    assert_eq!(key.thumbprint_uri(HashAlgorithm::SHA256).unwrap(), uri);
    assert_eq!(uri, format!("urn:ietf:params:oauth:jwk-thumbprint:sha-256:{expected}"));
    // Members other than the required ones and private parameters do not change the thumbprint (RFC 7638 §3.2).
    let mut with_members = key.clone();
    with_members.key_id = Some(String::from("other"));
    assert_eq!(with_members.thumbprint(HashAlgorithm::SHA256).unwrap(), key.thumbprint(HashAlgorithm::SHA256).unwrap());
    // RFC 8037 A.3: an OKP key.
    let ed25519 = jwk(&Json::from_text(&RFC::block_from(&path("rfc8037.txt"), r#"{"kty":"OKP","crv":"Ed25519","#)));
    let canonical = RFC::block(&path("rfc8037.txt"), "linebreak inserted for formatting reasons) is:", None);
    assert_eq!(ed25519.thumbprint_input().unwrap(), canonical);
    assert_eq!(
        Base64URL::encode(&ed25519.thumbprint(HashAlgorithm::SHA256).unwrap()),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
    // RFC 9964 appendix A.1: the kid of each AKP key is its thumbprint (RFC 9964 §6).
    for figure in ["Figure 3: ML_DSA_44", "Figure 4: ML_DSA_65", "Figure 5: ML_DSA_87"] {
        let example = MLDSAExamples::figure(figure);
        let key = jwk(example.field("jwk"));
        let kid = key.key_id.clone().unwrap();
        assert_eq!(Base64URL::encode(&key.thumbprint(HashAlgorithm::SHA256).unwrap()), kid, "{figure}");
    }
}

/// The JOSE examples of RFC 9964 appendix A.1.
pub struct MLDSAExamples;

impl MLDSAExamples {
    /// The JSON object of the figure whose caption is `caption`.
    pub fn figure(caption: &str) -> Json {
        let text = crate::Vectors::read(&path("rfc9964.txt"));
        let end = text.find(caption).unwrap_or_else(|| panic!("no {caption}"));
        let start = text[..end].rfind("\n{\n").unwrap() + 1;
        let joined: String = text[start..end]
            .lines()
            .filter(|line| !RFC::is_page_break(line) && !line.trim().is_empty())
            .map(str::trim)
            .collect();
        Json::from_text(&joined)
    }
}

#[test]
fn keys_convert_to_and_from_the_key_module() {
    let mut random = random();
    let algorithms = [
        KeyAlgorithm::EC(NamedCurve::P256),
        KeyAlgorithm::EC(NamedCurve::P384),
        KeyAlgorithm::EC(NamedCurve::P521),
        KeyAlgorithm::EC(NamedCurve::Secp256k1),
        KeyAlgorithm::Ed25519,
        KeyAlgorithm::Ed448,
        KeyAlgorithm::X25519,
        KeyAlgorithm::X448,
        KeyAlgorithm::MLDSA(MLDSAParameterSet::MLDSA44),
    ];
    for algorithm in algorithms {
        let key = PrivateKey::generate(algorithm, &mut random).unwrap();
        // The raw form of the key module is the private parameter of the JWK.
        assert_eq!(
            PrivateKey::from_raw(algorithm, key.raw().unwrap().expose()).unwrap().public_key().unwrap(),
            key.public_key().unwrap()
        );
        let private = JWK::from_private_key(&key).unwrap();
        let read = JWK::from_json(private.to_json().as_bytes()).unwrap();
        assert_eq!(read.private_key().unwrap().public_key().unwrap(), key.public_key().unwrap(), "{algorithm:?}");
        let public = JWK::from_public_key(&key.public_key().unwrap()).unwrap();
        assert_eq!(public.to_json(), read.to_public().unwrap().to_json(), "{algorithm:?}");
        assert!(!public.key.is_secret() && read.key.is_secret());
    }
    let rsa = PrivateKey::generate_rsa(KeyAlgorithm::RSA, 2048, &mut random).unwrap();
    let private = JWK::from_private_key(&rsa).unwrap();
    let read = JWK::from_json(private.to_json().as_bytes()).unwrap();
    let signed = read
        .private_key()
        .unwrap()
        .sign(&SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA256), b"m", &mut random)
        .unwrap();
    rsa.public_key().unwrap().verify(&SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA256), b"m", &signed).unwrap();
    // RSA keys have no single raw form.
    assert_eq!(rsa.raw().map(|_| ()), Err(KeyError::Parameters));
}

#[test]
fn keys_follow_rfc_7517_and_rfc_7518() {
    let refused = |text: &str| JWK::from_json(text.as_bytes()).map(|_| ());
    let p256 = Json::read(&path("cookbook/jwk/3_2.ec_private_key.json"));
    type Members = Vec<(String, Json)>;
    let ec = |change: &dyn Fn(&mut Members)| {
        let Json::Object(mut members) = Json::read(&path("cookbook/jwk/3_1.ec_public_key.json")) else {
            unreachable!()
        };
        change(&mut members);
        Json::Object(members).encode()
    };
    let set = |members: &mut Members, name: &str, value: Json| {
        members.retain(|(key, _)| key != name);
        members.push((name.to_string(), value));
    };
    // The coordinates have the size of the field, the point is on the curve (RFC 7518 §6.2.1).
    let short = ec(&|members| set(members, "x", Json::String(Base64URL::encode(&[1; 65]))));
    assert!(refused(&short).is_err());
    let off_curve = ec(&|members| set(members, "y", Json::String(Base64URL::encode(&[1; 66]))));
    assert!(refused(&off_curve).is_err());
    // The curve of the key type (RFC 8037 §2: Ed25519 is OKP, not EC).
    let wrong_type = ec(&|members| set(members, "crv", Json::String(String::from("Ed25519"))));
    assert_eq!(refused(&wrong_type), Err(JWTError::UnknownKeyType));
    assert_eq!(refused(r#"{"kty":"XYZ"}"#), Err(JWTError::UnknownKeyType));
    // `use` and `key_ops` consistent, no operation twice (RFC 7517 §4.3).
    let inconsistent = ec(&|members| {
        set(members, "key_ops", Json::Array(vec![Json::String(String::from("encrypt"))]));
    });
    assert_eq!(refused(&inconsistent), Err(JWTError::Format));
    let repeated = ec(&|members| {
        members.retain(|(key, _)| key != "use");
        set(
            members,
            "key_ops",
            Json::Array(vec![Json::String(String::from("verify")), Json::String(String::from("verify"))]),
        );
    });
    assert_eq!(refused(&repeated), Err(JWTError::Format));
    // The private key of another public key.
    let Json::Object(mut mismatched) = p256.clone() else { unreachable!() };
    set(&mut mismatched, "d", Json::String(Base64URL::encode(&[2; 66])));
    assert!(matches!(refused(&Json::Object(mismatched).encode()), Err(JWTError::Key(_))));
    // RSA integers in the fewest octets (RFC 7518 §2), private parameters all or none (§6.3.2).
    let Json::Object(rsa) = Json::read(&path("cookbook/jwk/3_4.rsa_private_key.json")) else { unreachable!() };
    let mut padded = rsa.clone();
    let e = Base64URL::decode("AQAB").unwrap();
    set(&mut padded, "e", Json::String(Base64URL::encode(&[&[0][..], &e].concat())));
    assert_eq!(refused(&Json::Object(padded).encode()), Err(JWTError::Base64));
    let mut partial = rsa.clone();
    partial.retain(|(key, _)| key != "qi");
    assert_eq!(refused(&Json::Object(partial).encode()), Err(JWTError::Format));
    let mut multiprime = rsa.clone();
    set(&mut multiprime, "oth", Json::Array(Vec::new()));
    assert!(refused(&Json::Object(multiprime).encode()).is_err());
    let mut d_only = rsa.clone();
    d_only.retain(|(key, _)| !["p", "q", "dp", "dq", "qi"].contains(&key.as_str()));
    let key = JWK::from_json(Json::Object(d_only).encode().as_bytes()).unwrap();
    assert!(matches!(key.key, JWKKey::RSA { private: Some(ref private), .. } if private.primes.is_none()));
    // AKP keys need their alg (RFC 9964 §4), and an ML-DSA private key is a seed of 32 bytes.
    assert_eq!(refused(r#"{"kty":"AKP","pub":"AA"}"#), Err(JWTError::Format));
    let example = MLDSAExamples::figure("Figure 3: ML_DSA_44");
    let Json::Object(mut akp) = example.field("jwk").clone() else { unreachable!() };
    set(&mut akp, "priv", Json::String(Base64URL::encode(&[0; 31])));
    assert!(refused(&Json::Object(akp).encode()).is_err());
    // Members a JWK does not define are kept (RFC 7517 §4).
    let extra = ec(&|members| set(members, "ext", Json::Bool(true)));
    let key = JWK::from_json(extra.as_bytes()).unwrap();
    assert_eq!(key.other.get("ext").and_then(|value| value.as_bool()), Some(true));
    assert!(key.to_json().contains("\"ext\":true"));
    // A member twice in the JSON object.
    assert!(matches!(refused(r#"{"kty":"oct","k":"AA","k":"AQ"}"#), Err(JWTError::JSON(_))));
    // Curves and their sizes (RFC 7518 §6.2.1.1, RFC 8037 §2, RFC 8812 §3.1).
    assert_eq!(JWKCurve::P521.size(), 66);
    assert_eq!(JWKCurve::Ed448.size(), 57);
    assert_eq!(JWKCurve::from_name("secp256k1"), Some(JWKCurve::Secp256k1));
}

#[test]
fn sets_follow_rfc_7517_section_5() {
    let keys = ["3_1.ec_public_key", "3_3.rsa_public_key", "3_5.symmetric_key_mac_computation"]
        .map(|name| Json::read(&path(&format!("cookbook/jwk/{name}.json"))).encode());
    // A key of a type this library does not know is left out (RFC 7517 §5).
    let text = format!(r#"{{"keys":[{},{},{},{{"kty":"unknown","kid":"x"}}],"other":1}}"#, keys[0], keys[1], keys[2]);
    let set = JWKSet::from_json(text.as_bytes()).unwrap();
    assert_eq!(set.keys.len(), 3);
    assert_eq!(set.find("bilbo.baggins@hobbiton.example").count(), 2);
    assert_eq!(JWKSet::from_json(set.to_json().as_bytes()).unwrap().keys.len(), 3);
    assert!(set.to_json().contains("\"other\":1"));
    // RFC 7517 §5: keys missing required members or with values out of the
    // supported ranges are ignored too; a set without `keys` is an error.
    let ignored = [
        r#"{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}"#,
        r#"{"kty":"EC","crv":"P-256","x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ"}"#,
        r#"{"kty":"oct"}"#,
        r#"{"kty":"AKP","alg":"SLH-DSA-SHA2-128s","pub":"AAAA"}"#,
        r#"{"kty":"EC","crv":"P-257","x":"AA","y":"AA"}"#,
    ];
    let text = format!(r#"{{"keys":[{},{}]}}"#, ignored.join(","), keys[2]);
    let set = JWKSet::from_json(text.as_bytes()).unwrap();
    assert_eq!(set.keys.len(), 1);
    assert_eq!(set.keys[0].key.type_name(), "oct");
    assert_eq!(JWKSet::from_json(b"{}").map(|_| ()), Err(JWTError::Format));
    assert_eq!(JWKSet::from_json(br#"{"keys":[1]}"#).map(|_| ()), Err(JWTError::Format));
}
