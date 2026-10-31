//! JWT against RFC 7519 (§3.1, §6.1, appendix A), RFC 8725 and the nested
//! example of the JOSE Cookbook (RFC 7520 §6).

use umilib::codec::json::JSONValue;
use umilib::protocol::jwt::{
    JOSEHeader, JWE, JWEAlgorithm, JWEConfig, JWEEncryption, JWK, JWSAlgorithm, JWSConfig, JWT, JWTClaims, JWTError,
    JWTValidation,
};

use super::{decrypting, folded, jwk, object, path, random};
use crate::{JSON, RFC};

/// The expiration of the claims of RFC 7519 §3.1 and RFC 7520 §6.
const EXPIRATION: i64 = 1300819380;

#[test]
fn rfc_7519_section_3_1() {
    let section = RFC::section(&path("rfc7519.txt"), "3.1.  ", "4.  ");
    let compact = folded(&section, "   breaks for display purposes only):");
    let key = jwk(&object(&RFC::section(&path("rfc7515.txt"), "A.1.  ", "A.2.  "), r#"{"kty":"oct","#));
    let config = JWSConfig::new(&[JWSAlgorithm::HS256]);
    let mut validation = JWTValidation::new(EXPIRATION - 1);
    validation.issuer = Some(String::from("joe"));
    validation.token_type = Some(String::from("JWT"));
    let jwt = JWT::verify(&compact, &key, &config, &validation).unwrap();
    assert_eq!(jwt.claims.issuer().unwrap(), Some("joe"));
    assert_eq!(jwt.claims.expiration().unwrap(), Some(EXPIRATION as f64));
    assert_eq!(jwt.claims.get("http://example.com/is_root"), Some(&JSONValue::Bool(true)));
    // RFC 7519 §4.1.4: the current time must be before exp.
    let mut late = validation.clone();
    late.now = EXPIRATION;
    assert_eq!(JWT::verify(&compact, &key, &config, &late), Err(JWTError::Expired));
    late.leeway = 1;
    JWT::verify(&compact, &key, &config, &late).unwrap();
    // RFC 7519 §4.1.1 and RFC 8725 §3.8: the issuer expected.
    let mut other = validation.clone();
    other.issuer = Some(String::from("john"));
    assert_eq!(JWT::verify(&compact, &key, &config, &other), Err(JWTError::Issuer));
    // RFC 8725 §3.9: an audience expected, none in the claims.
    let mut audience = validation.clone();
    audience.audience = Some(String::from("https://example.com"));
    assert_eq!(JWT::verify(&compact, &key, &config, &audience), Err(JWTError::Audience));
    let mut required = validation.clone();
    required.required = vec![String::from("sub")];
    assert_eq!(JWT::verify(&compact, &key, &config, &required), Err(JWTError::MissingClaim));
    // RFC 8725 §3.1: only the algorithms allowed.
    let others = JWSConfig::new(&[JWSAlgorithm::HS512]);
    assert_eq!(JWT::verify(&compact, &key, &others, &validation), Err(JWTError::AlgorithmNotAllowed));
}

#[test]
fn rfc_7519_section_6_1() {
    let section = RFC::section(&path("rfc7519.txt"), "6.1.  ", "7.  ");
    let compact = folded(&section, "   breaks for display purposes only):");
    assert!(compact.ends_with('.'), "the empty signature");
    let validation = JWTValidation::new(EXPIRATION - 1);
    let jwt = JWT::verify_unsecured(&compact, &validation).unwrap();
    assert_eq!(jwt.claims.issuer().unwrap(), Some("joe"));
    // RFC 8725 §3.1: verify never accepts an Unsecured JWT, whatever the key.
    let every: Vec<JWSAlgorithm> = JWSAlgorithm::ALL.to_vec();
    let key = JWK::symmetric(&[0; 32]);
    assert_eq!(JWT::verify(&compact, &key, &JWSConfig::new(&every), &validation), Err(JWTError::AlgorithmNotAllowed));
    // An Unsecured JWT made here reads back the same way.
    let mut none = JOSEHeader::new();
    none.set_string("alg", "none");
    let made = JWT::sign(&jwt.claims, &none, &key, &mut random()).unwrap();
    assert_eq!(JWT::verify_unsecured(&made, &validation).unwrap().claims, jwt.claims);
}

#[test]
fn rfc_7519_appendix_a() {
    // A.1 and A.2 use RSAES-PKCS1-v1_5, which this module does not implement
    // (RFC 8725 §3.2): both are refused, the nested one as well.
    let key = jwk(&object(
        &RFC::section(&path("rfc7516.txt"), "A.2.  ", "A.3.  "),
        "RSA key represented in JSON Web Key [JWK] format",
    ));
    let config = JWEConfig::new(&JWEAlgorithm::ALL, &JWEEncryption::ALL);
    let validation = JWTValidation::new(EXPIRATION - 1);
    let encrypted = folded(&RFC::section(&path("rfc7519.txt"), "A.1.  ", "A.2.  "), "purposes only) is:");
    assert_eq!(
        JWT::decrypt(&encrypted, &key, &config, &validation, &mut decrypting()),
        Err(JWTError::AlgorithmNotAllowed)
    );
    let nested = folded(&RFC::section(&path("rfc7519.txt"), "A.2.  ", "A.3.  "), "purposes only) is:");
    let jws = JWSConfig::new(&[JWSAlgorithm::RS256]);
    assert_eq!(
        JWT::decrypt_and_verify(&nested, &key, &config, &key, &jws, &validation, &mut decrypting()),
        Err(JWTError::AlgorithmNotAllowed)
    );
}

#[test]
fn the_jose_cookbook_nesting() {
    let example = JSON::read(&path("cookbook/6.nesting_signatures_and_encryption.json"));
    let sign = example.field("sign");
    let encrypt = example.field("encrypt");
    let signing_key = jwk(sign.field("input").field("key"));
    let encryption_key = jwk(encrypt.field("input").field("key"));
    let verification = JWSConfig::new(&[JWSAlgorithm::PS256]);
    let decryption = JWEConfig::new(&[JWEAlgorithm::RSAOAEP], &[JWEEncryption::A128GCM]);
    let mut validation = JWTValidation::new(EXPIRATION - 1);
    validation.issuer = Some(String::from("hobbiton.example"));
    validation.token_type = Some(String::from("JWT"));
    let inner = sign.field("output").field("compact").as_str();
    let outer = encrypt.field("output").field("compact").as_str();
    let verified = JWT::verify(inner, &signing_key.to_public().unwrap(), &verification, &validation).unwrap();
    let jwt = JWT::decrypt_and_verify(
        outer,
        &encryption_key,
        &decryption,
        &signing_key.to_public().unwrap(),
        &verification,
        &validation,
        &mut decrypting(),
    )
    .unwrap();
    assert_eq!(jwt, verified);
    assert_eq!(jwt.claims.encode(), sign.field("input").field("payload").as_str());
    // The JSON serializations of RFC 7520 §6 hold the same JWS.
    for member in ["json", "json_flat"] {
        let jwe = JWE::from_json(encrypt.field("output").field(member).encode().as_bytes()).unwrap();
        assert_eq!(
            jwe.decrypt(&encryption_key, &decryption, &mut decrypting()).unwrap().0,
            inner.as_bytes(),
            "{member}"
        );
    }
    // A nested JWT made here: the JWE gets the cty of RFC 7519 §5.2.
    let mut signing_header = JOSEHeader::new();
    signing_header.set_string("alg", "PS256");
    signing_header.set_string("typ", "JWT");
    let mut encryption_header = JOSEHeader::new();
    encryption_header.set_string("alg", "RSA-OAEP");
    encryption_header.set_string("enc", "A128GCM");
    let made = JWT::sign_and_encrypt(
        &jwt.claims,
        &signing_header,
        &signing_key,
        &encryption_header,
        &encryption_key.to_public().unwrap(),
        &mut random(),
    )
    .unwrap();
    assert_eq!(JWE::from_compact(&made).unwrap().protected_header.content_type().unwrap(), Some("JWT"));
    let read = JWT::decrypt_and_verify(
        &made,
        &encryption_key,
        &decryption,
        &signing_key.to_public().unwrap(),
        &verification,
        &validation,
        &mut decrypting(),
    )
    .unwrap();
    assert_eq!(read.claims, jwt.claims);
    // RFC 8725 §3.12: each form has its function; the others refuse it.
    assert_eq!(JWT::verify(outer, &signing_key, &verification, &validation), Err(JWTError::Format));
    assert_eq!(
        JWT::decrypt(outer, &encryption_key, &decryption, &validation, &mut decrypting()),
        Err(JWTError::Type),
        "a nested JWT is not a claims set"
    );
    assert_eq!(
        JWT::decrypt_and_verify(
            inner,
            &encryption_key,
            &decryption,
            &signing_key,
            &verification,
            &validation,
            &mut decrypting()
        ),
        Err(JWTError::Format)
    );
}

/// A JWS JWT of `claims` under an HMAC key, and that key.
fn signed(claims: &str, header: &[(&str, &str)]) -> (String, JWK) {
    let key = JWK::symmetric(&[9; 32]);
    let mut protected = JOSEHeader::new();
    protected.set_string("alg", "HS256");
    for (name, value) in header {
        protected.set_string(name, value);
    }
    let claims = JWTClaims::decode(claims.as_bytes()).unwrap();
    (JWT::sign(&claims, &protected, &key, &mut random()).unwrap(), key)
}

#[test]
fn validation_follows_rfc_7519_and_rfc_8725() {
    let config = JWSConfig::new(&[JWSAlgorithm::HS256]);
    let at = |now: i64| JWTValidation::new(now);
    let check = |claims: &str, validation: &JWTValidation| {
        let (token, key) = signed(claims, &[]);
        JWT::verify(&token, &key, &config, validation).map(|_| ())
    };
    // RFC 7519 §4.1.5: valid from nbf on, give or take the leeway.
    assert_eq!(check(r#"{"nbf":100}"#, &at(99)), Err(JWTError::NotYetValid));
    assert_eq!(check(r#"{"nbf":100}"#, &at(100)), Ok(()));
    assert_eq!(check(r#"{"nbf":100}"#, &JWTValidation { leeway: 1, ..at(99) }), Ok(()));
    // RFC 7519 §2: a NumericDate may have a fraction.
    assert_eq!(check(r#"{"exp":100.5}"#, &at(100)), Ok(()));
    assert_eq!(check(r#"{"exp":100.5}"#, &at(101)), Err(JWTError::Expired));
    // RFC 7519 §4.1: the registered claims have their types.
    for claims in
        [r#"{"exp":"100"}"#, r#"{"nbf":true}"#, r#"{"iat":null}"#, r#"{"iss":1}"#, r#"{"aud":[1]}"#, r#"{"jti":{}}"#]
    {
        assert_eq!(check(claims, &at(0)), Err(JWTError::InvalidClaim), "{claims}");
    }
    // RFC 7519 §4.1.3: the recipient must be in aud when aud is present.
    let audience = |name: &str| JWTValidation { audience: Some(name.to_string()), ..at(0) };
    assert_eq!(check(r#"{"aud":"a"}"#, &at(0)), Err(JWTError::Audience));
    assert_eq!(check(r#"{"aud":"a"}"#, &audience("a")), Ok(()));
    assert_eq!(check(r#"{"aud":["a","b"]}"#, &audience("b")), Ok(()));
    assert_eq!(check(r#"{"aud":["a","b"]}"#, &audience("c")), Err(JWTError::Audience));
    // RFC 8725 §3.8: the subject expected.
    let subject = JWTValidation { subject: Some(String::from("alice")), ..at(0) };
    assert_eq!(check(r#"{"sub":"alice"}"#, &subject), Ok(()));
    assert_eq!(check(r#"{"sub":"bob"}"#, &subject), Err(JWTError::Subject));
    assert_eq!(check(r#"{}"#, &subject), Err(JWTError::Subject));
    // RFC 7519 §4 and §7.2 step 10: a JSON object without duplicate names.
    assert!(JWTClaims::decode(br#"{"iss":"a","iss":"b"}"#).is_err());
    assert_eq!(JWTClaims::decode(b"[1]"), Err(JWTError::Format));
    // RFC 8725 §3.11: explicit typing, compared as media types (RFC 7515 §4.1.9).
    let typed = |expected: &str, actual: &str| {
        let (token, key) = signed("{}", &[("typ", actual)]);
        let validation = JWTValidation { token_type: Some(expected.to_string()), ..at(0) };
        JWT::verify(&token, &key, &config, &validation).map(|_| ())
    };
    assert_eq!(typed("at+jwt", "at+jwt"), Ok(()));
    assert_eq!(typed("application/at+jwt", "AT+JWT"), Ok(()));
    assert_eq!(typed("at+jwt", "JWT"), Err(JWTError::Type));
    let (untyped, key) = signed("{}", &[]);
    let validation = JWTValidation { token_type: Some(String::from("JWT")), ..at(0) };
    assert_eq!(JWT::verify(&untyped, &key, &config, &validation), Err(JWTError::Type));
    // RFC 7519 §7.2 step 8: a JWS holding a JWT is not a claims set.
    let (nested, key) = signed("{}", &[("cty", "JWT")]);
    assert_eq!(JWT::verify(&nested, &key, &config, &at(0)), Err(JWTError::Type));
    // A JWT payload is base64url-encoded: RFC 7797 b64 is refused.
    let mut unencoded = JOSEHeader::new();
    unencoded.set_string("alg", "HS256");
    unencoded.set("b64", JSONValue::Bool(false));
    unencoded.set("crit", JSONValue::Array(vec!["b64".into()]));
    assert_eq!(JWT::sign(&JWTClaims::new(), &unencoded, &key, &mut random()), Err(JWTError::Header));
}

#[test]
fn encrypted_jwts_round_trip() {
    let key = JWK::symmetric(&[3; 32]);
    let mut header = JOSEHeader::new();
    header.set_string("alg", "dir");
    header.set_string("enc", "A256GCM");
    header.set_string("typ", "secevent+jwt");
    let mut claims = JWTClaims::new();
    claims.set_string("iss", "https://issuer.example");
    claims.set_numeric_date("exp", 2_000_000_000);
    claims.set("aud", JSONValue::Array(vec!["one".into(), "two".into()]));
    let token = JWT::encrypt(&claims, &header, &key, &mut random()).unwrap();
    let config = JWEConfig::new(&[JWEAlgorithm::Dir], &[JWEEncryption::A256GCM]);
    let validation = JWTValidation {
        audience: Some(String::from("two")),
        token_type: Some(String::from("application/secevent+jwt")),
        ..JWTValidation::new(1_999_999_999)
    };
    let jwt = JWT::decrypt(&token, &key, &config, &validation, &mut decrypting()).unwrap();
    assert_eq!(jwt.claims, claims);
    assert_eq!(jwt.claims.audience().unwrap(), ["one", "two"]);
    assert_eq!(
        JWT::decrypt(
            &token,
            &key,
            &config,
            &JWTValidation { now: 2_000_000_000, ..validation.clone() },
            &mut decrypting()
        ),
        Err(JWTError::Expired)
    );
    // RFC 8725 §3.12: a JWE is not a JWS.
    assert_eq!(JWT::verify(&token, &key, &JWSConfig::new(&[JWSAlgorithm::HS256]), &validation), Err(JWTError::Format));
}
