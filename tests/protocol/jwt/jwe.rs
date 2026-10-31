//! JWE against RFC 7516 appendix A, RFC 7518 §4, §5 and appendix C,
//! RFC 8037 appendix A.6 and A.7, RFC 8725, the JOSE Cookbook (RFC 7520 §5)
//! and Project Wycheproof.

use umilib::crypto::KeyAgreement;
use umilib::crypto::ecdh::{X448, X25519};
use umilib::protocol::jwt::{
    Base64URL, JOSEHeader, JWE, JWEAlgorithm, JWEConfig, JWEEncryption, JWK, JWKCurve, JWKKey, JWTError,
};

use super::{decimals, decrypting, folded, hexadecimal, jwk, object, path, random, sorted};
use crate::{JSON, RFC, Vectors, Wycheproof};

/// Every algorithm and every content encryption, compression accepted.
fn everything() -> JWEConfig {
    let mut config = JWEConfig::new(&JWEAlgorithm::ALL, &JWEEncryption::ALL);
    config.compression = true;
    config
}

/// The public part of an asymmetric key, a symmetric key as it is.
fn public(key: &JWK) -> JWK {
    if matches!(key.key, JWKKey::Oct { .. }) { key.clone() } else { key.to_public().unwrap() }
}

/// The algorithm of a cookbook example by its name, `None` for one this
/// module does not implement (RSA1_5, deliberately).
fn algorithm(name: &JSON) -> Option<JWEAlgorithm> {
    JWEAlgorithm::from_name(name.as_str())
}

/// Checks the examples of one cookbook file: every output decrypts with
/// each key whose algorithm is implemented and reads back to its text;
/// the deterministic steps (content encryption, AES key wrapping, PBES2,
/// AES-GCM key wrapping, ECDH-ES with the ephemeral key given) reproduce
/// their outputs; and a JWE made again with the same headers decrypts.
fn check_cookbook(name: &str) {
    let example = JSON::read(&path(name));
    let input = example.field("input");
    let keys: Vec<JWK> = match (input.get("key"), input.get("pwd")) {
        (Some(JSON::Array(keys)), _) => keys.iter().map(jwk).collect(),
        (Some(key), _) => vec![jwk(key)],
        (None, Some(password)) => vec![JWK::symmetric(password.as_str().as_bytes())],
        (None, None) => panic!("{name}: no key"),
    };
    let algorithms: Vec<&JSON> = match input.field("alg") {
        JSON::Array(names) => names.iter().collect(),
        single => vec![single],
    };
    let plaintext = input.field("plaintext").as_str().as_bytes();
    // The enc of the headers: the input of RFC 7520 §5.13 misspells it "A128CBC-H256".
    let content = example.field("encrypting_content");
    let enc =
        ["protected", "unprotected"].iter().find_map(|member| content.get(member).and_then(|header| header.get("enc")));
    let encryption = JWEEncryption::from_name(enc.unwrap().as_str()).unwrap();
    let config = everything();
    let reproducible = !matches!(example.get("reproducible"), Some(JSON::Bool(false)));
    let output = example.field("output");
    for member in ["compact", "json", "json_flat"] {
        let Some(serialization) = output.get(member) else { continue };
        let jwe = match member {
            "compact" => JWE::from_compact(serialization.as_str()),
            _ => JWE::from_json(serialization.encode().as_bytes()),
        }
        .unwrap_or_else(|error| panic!("{name} {member}: {error:?}"));
        for (key, name_of_algorithm) in keys.iter().zip(&algorithms) {
            let decrypted = jwe.decrypt(key, &config, &mut decrypting()).map(|(plaintext, _)| plaintext);
            match algorithm(name_of_algorithm) {
                Some(_) => assert_eq!(decrypted.as_deref(), Ok(plaintext), "{name} {member}"),
                None => assert!(decrypted.is_err(), "{name} {member}: RSA1_5 is not implemented"),
            }
        }
        match member {
            "compact" => assert_eq!(jwe.to_compact().unwrap(), serialization.as_str(), "{name}"),
            _ => {
                // The cookbook writes a JWE of one recipient without a
                // per-recipient member flattened even as "json" (RFC 7520 §5.5, §5.6).
                let general = serialization.get("recipients").is_some();
                let written = if general { jwe.to_json() } else { jwe.to_flattened_json() }.unwrap();
                assert_eq!(JWE::from_json(written.as_bytes()).unwrap(), jwe, "{name} {member}");
                assert_eq!(sorted(&JSON::from_text(&written)), sorted(serialization), "{name} {member}");
            }
        }
    }
    let generated = example.field("generated");
    if reproducible && let (Some(cek), Some(iv)) = (generated.get("cek"), generated.get("iv")) {
        let cek = Base64URL::decode(cek.as_str()).unwrap();
        let iv = Base64URL::decode(iv.as_str()).unwrap();
        let mut aad = content.get("protected_b64u").map_or(String::new(), |text| text.as_str().to_string());
        if let Some(extra) = generated.get("aad_b64u") {
            aad = format!("{aad}.{}", extra.as_str());
        }
        let compressed = generated.get("plaintext_c").map(|text| Base64URL::decode(text.as_str()).unwrap());
        if let Some(compressed) = &compressed {
            assert_eq!(JWE::decompress(compressed, 1 << 16).unwrap(), plaintext, "{name}: RFC 1951");
        }
        let (ciphertext, tag) =
            encryption.encrypt(&cek, &iv, aad.as_bytes(), compressed.as_deref().unwrap_or(plaintext)).unwrap();
        assert_eq!(Base64URL::encode(&ciphertext), content.field("ciphertext").as_str(), "{name}");
        assert_eq!(Base64URL::encode(&tag), content.field("tag").as_str(), "{name}");
        let steps: Vec<&JSON> = match example.field("encrypting_key") {
            JSON::Array(steps) => steps.iter().collect(),
            single => vec![single],
        };
        for ((key, name_of_algorithm), step) in keys.iter().zip(&algorithms).zip(steps) {
            check_key_management(name, algorithm(name_of_algorithm), encryption, key, step, content, &cek);
        }
    }
    // The same JWE made again: each implemented recipient, its headers, a fresh CEK and IV.
    for (key, name_of_algorithm) in keys.iter().zip(&algorithms) {
        let Some(own) = algorithm(name_of_algorithm) else { continue };
        let mut protected = JOSEHeader::new();
        protected.set_string("alg", own.name());
        protected.set_string("enc", encryption.name());
        if let Some(zip) = input.get("zip") {
            protected.set_string("zip", zip.as_str());
        }
        let jwe = JWE::encrypt(plaintext, &protected, None, &[(&public(key), None)], None, &mut random()).unwrap();
        let read = JWE::from_compact(&jwe.to_compact().unwrap()).unwrap();
        assert_eq!(read.decrypt(key, &config, &mut decrypting()).unwrap().0, plaintext, "{name} again");
    }
}

/// Checks the deterministic key management of one recipient of a cookbook
/// example against its `step` (the "encrypting_key" member).
fn check_key_management(
    name: &str,
    algorithm: Option<JWEAlgorithm>,
    encryption: JWEEncryption,
    key: &JWK,
    step: &JSON,
    content: &JSON,
    cek: &[u8],
) {
    let Some(algorithm) = algorithm else { return };
    let encrypted_key = step.get("encrypted_key").map(|text| text.as_str());
    let bytes = |member: &str| Base64URL::decode(step.field(member).as_str()).unwrap();
    match (algorithm, &key.key) {
        (JWEAlgorithm::A128KW | JWEAlgorithm::A192KW | JWEAlgorithm::A256KW, JWKKey::Oct { k }) => {
            let wrapped = JWEAlgorithm::wrap(k.expose(), cek).unwrap();
            assert_eq!(Some(Base64URL::encode(&wrapped).as_str()), encrypted_key, "{name}: RFC 3394");
        }
        (JWEAlgorithm::A128GCMKW | JWEAlgorithm::A192GCMKW | JWEAlgorithm::A256GCMKW, JWKKey::Oct { k }) => {
            let (wrapped, tag) = JWEAlgorithm::encrypt_gcm(k.expose(), &bytes("iv"), cek).unwrap();
            assert_eq!(Some(Base64URL::encode(&wrapped).as_str()), encrypted_key, "{name}: RFC 7518 §4.7");
            assert_eq!(tag, bytes("tag"), "{name}: RFC 7518 §4.7");
        }
        (
            JWEAlgorithm::PBES2HS256A128KW | JWEAlgorithm::PBES2HS384A192KW | JWEAlgorithm::PBES2HS512A256KW,
            JWKKey::Oct { k },
        ) => {
            let count = step.field("iteration_count").as_usize() as u32;
            let kek = algorithm.pbes2_key(k.expose(), &bytes("salt"), count).unwrap();
            let wrapped = JWEAlgorithm::wrap(kek.expose(), cek).unwrap();
            assert_eq!(Some(Base64URL::encode(&wrapped).as_str()), encrypted_key, "{name}: RFC 7518 §4.8");
        }
        (
            JWEAlgorithm::ECDHES | JWEAlgorithm::ECDHESA128KW | JWEAlgorithm::ECDHESA192KW | JWEAlgorithm::ECDHESA256KW,
            _,
        ) => {
            let ephemeral = jwk(step.field("epk"));
            let (JWKKey::EC { curve, d: Some(d), .. } | JWKKey::OKP { curve, d: Some(d), .. }) = &ephemeral.key else {
                panic!("{name}: an ephemeral key without its private part")
            };
            let z =
                JWEAlgorithm::agree_static(*curve, d.expose(), &JWEAlgorithm::agreement_public(key).unwrap()).unwrap();
            let header = match content.get("protected") {
                Some(protected) => JOSEHeader::decode(protected.encode().as_bytes()).unwrap(),
                None => JOSEHeader::new(),
            };
            let kek = algorithm.derive(encryption, &header, z.expose()).unwrap();
            if algorithm.is_direct() {
                assert_eq!(kek.expose(), cek, "{name}: RFC 7518 §4.6");
            } else {
                let wrapped = JWEAlgorithm::wrap(kek.expose(), cek).unwrap();
                assert_eq!(Some(Base64URL::encode(&wrapped).as_str()), encrypted_key, "{name}: RFC 7518 §4.6");
            }
        }
        _ => {}
    }
}

#[test]
fn the_jose_cookbook() {
    for name in [
        "5_1.key_encryption_using_rsa_v15_and_aes-hmac-sha2",
        "5_2.key_encryption_using_rsa-oaep_with_aes-gcm",
        "5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2",
        "5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm",
        "5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2",
        "5_6.direct_encryption_using_aes-gcm",
        "5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2",
        "5_8.key_wrap_using_aes-keywrap_with_aes-gcm",
        "5_9.compressed_content",
        "5_10.including_additional_authentication_data",
        "5_11.protecting_specific_header_fields",
        "5_12.protecting_content_only",
        "5_13.encrypting_to_multiple_recipients",
    ] {
        check_cookbook(&format!("cookbook/jwe/{name}.json"));
    }
    check_cookbook("cookbook/curve25519/ecdh-es.json");
}

#[test]
fn rfc_7516_appendix_a() {
    let config = everything();
    // A.1: RSAES-OAEP and AES GCM.
    let a1 = RFC::section(&path("rfc7516.txt"), "A.1.  ", "A.2.  ");
    let key = jwk(&object(&a1, "RSA key represented in JSON Web Key [JWK] format"));
    let jwe = JWE::from_compact(&folded(&a1, "purposes only) is:")).unwrap();
    let (plaintext, _) = jwe.decrypt(&key, &config, &mut decrypting()).unwrap();
    assert_eq!(plaintext, b"The true sign of intelligence is not knowledge but imagination.");
    // A.1.6: AES GCM is deterministic.
    let cek = decimals(&RFC::section(&path("rfc7516.txt"), "A.1.2.", "A.1.3."), "JSON array notation) is:");
    let iv = Base64URL::decode(&folded(&a1, "Initialization Vector) gives this value:")).unwrap();
    let (ciphertext, tag) = JWEEncryption::A256GCM.encrypt(&cek, &iv, jwe.protected.as_bytes(), &plaintext).unwrap();
    assert_eq!((ciphertext, tag), (jwe.ciphertext.clone(), jwe.tag.clone()));
    // A.2: RSAES-PKCS1-v1_5 is not implemented (RFC 8725 §3.2 advises against it).
    let a2 = RFC::section(&path("rfc7516.txt"), "A.2.  ", "A.3.  ");
    let key = jwk(&object(&a2, "RSA key represented in JSON Web Key [JWK] format"));
    let jwe = JWE::from_compact(&folded(&a2, "purposes only) is:")).unwrap();
    assert_eq!(jwe.decrypt(&key, &config, &mut decrypting()).map(|_| ()), Err(JWTError::AlgorithmNotAllowed));
    // A.3: AES Key Wrap and AES_128_CBC_HMAC_SHA_256.
    let a3 = RFC::section(&path("rfc7516.txt"), "A.3.  ", "A.4.  ");
    let key = jwk(&object(&a3, "symmetric key represented in JSON Web Key [JWK] format below"));
    let compact = folded(&a3, "purposes only) is:");
    let jwe = JWE::from_compact(&compact).unwrap();
    assert_eq!(jwe.decrypt(&key, &config, &mut decrypting()).unwrap().0, b"Live long and prosper.");
    let cek = decimals(&a3, "Generate a 256-bit random CEK.  In this example, the value is:");
    let JWKKey::Oct { k } = &key.key else { unreachable!() };
    assert_eq!(JWEAlgorithm::wrap(k.expose(), &cek).unwrap(), jwe.recipients[0].encrypted_key);
    // A.3.7 and RFC 7518 §5.2.2.1: the tag is the first half of the HMAC.
    let (ciphertext, tag) = JWEEncryption::A128CBCHS256
        .encrypt(&cek, &jwe.iv, jwe.protected.as_bytes(), b"Live long and prosper.")
        .unwrap();
    assert_eq!((ciphertext, tag), (jwe.ciphertext.clone(), jwe.tag.clone()));
    assert_eq!(jwe.to_compact().unwrap(), compact);
    // A.4: the general JSON serialization with two recipients; the key of
    // A.3 decrypts the second (RSA1_5 is skipped).
    let general =
        object(&RFC::section(&path("rfc7516.txt"), "A.4.7.", "A.5.  "), "The complete JWE JSON Serialization");
    let jwe = JWE::from_json(general.encode().as_bytes()).unwrap();
    let (plaintext, recipient) = jwe.decrypt(&key, &config, &mut decrypting()).unwrap();
    assert_eq!(plaintext, b"Live long and prosper.");
    assert_eq!(recipient, &jwe.recipients[1]);
    assert_eq!(jwe.joined_header(recipient).unwrap().key_id().unwrap(), Some("7"));
    assert_eq!(sorted(&JSON::from_text(&jwe.to_json().unwrap())), sorted(&general));
    // A.5: the flattened JSON serialization of the second recipient.
    let flattened =
        object(&RFC::section(&path("rfc7516.txt"), "A.5.  ", "Appendix B."), "The complete JWE JSON Serialization");
    let jwe = JWE::from_json(flattened.encode().as_bytes()).unwrap();
    assert_eq!(jwe.decrypt(&key, &config, &mut decrypting()).unwrap().0, b"Live long and prosper.");
    assert_eq!(sorted(&JSON::from_text(&jwe.to_flattened_json().unwrap())), sorted(&flattened));
}

#[test]
fn rfc_7518_appendix_c() {
    let section = RFC::section(&path("rfc7518.txt"), "Appendix C.", "Appendix D.");
    let alice = jwk(&object(&section, "for the key agreement computation in this example (including the"));
    let bob = jwk(&object(&section, "computation in this example (including the private part) is:"));
    let header = JOSEHeader::decode(object(&section, "Parameter is used to communicate").encode().as_bytes()).unwrap();
    let (JWKKey::EC { d: Some(alice_d), .. }, JWKKey::EC { d: Some(bob_d), .. }) = (&alice.key, &bob.key) else {
        panic!("keys without their private parts")
    };
    let z = decimals(&section, "notation):");
    let from_alice =
        JWEAlgorithm::agree_static(JWKCurve::P256, alice_d.expose(), &JWEAlgorithm::agreement_public(&bob).unwrap())
            .unwrap();
    let from_bob =
        JWEAlgorithm::agree_static(JWKCurve::P256, bob_d.expose(), &JWEAlgorithm::agreement_public(&alice).unwrap())
            .unwrap();
    assert_eq!(from_alice.expose(), &z);
    assert_eq!(from_bob.expose(), &z);
    let info = JWEAlgorithm::ECDHES.agreement_info(JWEEncryption::A128GCM, &header, 16).unwrap();
    assert_eq!(info, decimals(&section, "in an OtherInfo value of:"));
    let derived = JWEAlgorithm::ECDHES.derive(JWEEncryption::A128GCM, &header, &z).unwrap();
    assert_eq!(
        Base64URL::encode(derived.expose()),
        folded(&section, "The base64url-encoded representation of this derived key is:")
    );
    // Bob recovers the same key from the header.
    let cek = JWEAlgorithm::ECDHES
        .decrypt_key(&bob, JWEEncryption::A128GCM, &header, &[], &everything(), &mut random())
        .unwrap();
    assert_eq!(cek.expose(), derived.expose());
}

#[test]
fn rfc_8037_appendix_a() {
    let checks = [
        ("A.6.  ", "A.7.  ", JWKCurve::X25519, "This is represented as the ephemeral public key value:"),
        ("A.7.  ", "Acknowledgements", JWKCurve::X448, "This is packed into the ephemeral public key value"),
    ];
    for (start, end, curve, epk_marker) in checks {
        let section = RFC::section(&path("rfc8037.txt"), start, end);
        let recipient = jwk(&object(&section, "The public key to encrypt to"));
        let target = hexadecimal(&section, "The public key from the target key is (hex):");
        assert_eq!(JWEAlgorithm::agreement_public(&recipient).unwrap(), target, "{start}");
        let ephemeral = hexadecimal(&section, "The ephemeral secret happens to be (hex):");
        let mut ephemeral_public = vec![0; target.len()];
        match curve {
            JWKCurve::X25519 => X25519::write_public_key(
                &X25519::public_key(&X25519::private_key_from_bytes(&ephemeral).unwrap()),
                &mut ephemeral_public,
            ),
            _ => X448::write_public_key(
                &X448::public_key(&X448::private_key_from_bytes(&ephemeral).unwrap()),
                &mut ephemeral_public,
            ),
        }
        .unwrap();
        assert_eq!(ephemeral_public, hexadecimal(&section, "So the ephemeral public key is"), "{start}");
        let epk = jwk(&object(&section, epk_marker));
        assert_eq!(JWEAlgorithm::agreement_public(&epk).unwrap(), ephemeral_public, "{start}");
        let z = hexadecimal(&section, "And the sender computes the DH Z value");
        let shared = JWEAlgorithm::agree_static(curve, &ephemeral, &target).unwrap();
        assert_eq!(shared.expose(), &z, "{start}");
        let header =
            JOSEHeader::decode(object(&section, "So the protected header could be").encode().as_bytes()).unwrap();
        assert_eq!(header.ephemeral_key().unwrap().unwrap().to_json(), epk.to_json(), "{start}");
    }
}

/// The Wycheproof tests whose expectation this module does not share, with
/// the reason. RSA1_5 (deliberately not implemented) is handled apart.
const WYCHEPROOF_DIVERGENCES: [(usize, &str); 1] = [(
    22,
    "a valid JWE in the flattened JSON serialization, which Wycheproof expects an API of the compact \
     serialization to refuse; JWE::from_json reads it and it decrypts",
)];

#[test]
fn wycheproof() {
    let config = everything();
    let mut checked = 0;
    for (group, test) in Wycheproof::tests(&path("json_web_encryption_test.json")) {
        let id = test.field("tcId").as_usize();
        let key = jwk(group.field("private"));
        let decrypted = match test.field("jwe") {
            JSON::String(json) if json.starts_with('{') => JWE::from_json(json.as_bytes()),
            JSON::String(compact) => JWE::from_compact(compact),
            json => JWE::from_json(json.encode().as_bytes()),
        }
        .and_then(|jwe| jwe.decrypt(&key, &config, &mut decrypting()).map(|(plaintext, _)| plaintext));
        let comment =
            format!("{} {id} {}: {decrypted:?}", group.field("comment").as_str(), test.field("comment").as_str());
        let rsa1_5 = match test.field("jwe") {
            JSON::String(compact) => JWE::from_compact(compact)
                .ok()
                .and_then(|jwe| jwe.protected_header.string("alg").ok().flatten().map(|name| name == "RSA1_5")),
            _ => None,
        };
        if WYCHEPROOF_DIVERGENCES.iter().any(|(divergent, _)| *divergent == id) {
            assert!(decrypted.is_ok(), "{comment}");
        } else if rsa1_5 == Some(true) {
            assert_eq!(decrypted, Err(JWTError::AlgorithmNotAllowed), "{comment}");
        } else if Wycheproof::valid(&test) {
            assert_eq!(decrypted.as_deref(), Ok(Vectors::hex(test.field("pt").as_str()).as_slice()), "{comment}");
        } else {
            assert!(decrypted.is_err(), "{comment}");
        }
        checked += 1;
    }
    assert!(checked > 100, "{checked}");
}

#[test]
fn every_algorithm_round_trips() {
    // The key of RFC 7520 §3.4, whose use is "sig", made a key of any use.
    let mut rsa = jwk(&JSON::read(&path("cookbook/jwk/3_4.rsa_private_key.json")));
    rsa.key_use = None;
    let mut keys: Vec<(JWEAlgorithm, JWK)> = Vec::new();
    for algorithm in JWEAlgorithm::ALL {
        for encryption in JWEEncryption::ALL {
            let key = match algorithm {
                JWEAlgorithm::Dir => JWK::symmetric(&vec![3; encryption.key_size()]),
                JWEAlgorithm::RSAOAEP
                | JWEAlgorithm::RSAOAEP256
                | JWEAlgorithm::RSAOAEP384
                | JWEAlgorithm::RSAOAEP512 => rsa.clone(),
                JWEAlgorithm::PBES2HS256A128KW | JWEAlgorithm::PBES2HS384A192KW | JWEAlgorithm::PBES2HS512A256KW => {
                    JWK::symmetric(b"correct horse battery staple")
                }
                JWEAlgorithm::ECDHES
                | JWEAlgorithm::ECDHESA128KW
                | JWEAlgorithm::ECDHESA192KW
                | JWEAlgorithm::ECDHESA256KW => continue,
                _ => JWK::symmetric(&vec![5; algorithm.wrapping_key_size().unwrap()]),
            };
            keys.push((algorithm, key));
            let mut protected = JOSEHeader::new();
            protected.set_string("alg", algorithm.name());
            protected.set_string("enc", encryption.name());
            if algorithm.wrapping_key_size().is_some() && algorithm.name().starts_with("PBES2") {
                // A small count keeps the test fast; at least the minimum of RFC 7518 §4.8.1.2.
                protected.set("p2c", 1000u64.into());
            }
            let key = &keys.last().unwrap().1;
            let jwe =
                JWE::encrypt(b"round trip", &protected, None, &[(&public(key), None)], None, &mut random()).unwrap();
            assert_eq!(jwe.iv.len(), encryption.iv_size(), "{} {}", algorithm.name(), encryption.name());
            assert_eq!(jwe.tag.len(), encryption.tag_size(), "{} {}", algorithm.name(), encryption.name());
            let read = JWE::from_compact(&jwe.to_compact().unwrap()).unwrap();
            let config = JWEConfig::new(&[algorithm], &[encryption]);
            assert_eq!(read.decrypt(key, &config, &mut decrypting()).unwrap().0, b"round trip", "{}", algorithm.name());
        }
    }
    // ECDH-ES on each curve of RFC 7518 §4.6 and RFC 8037 §3.2.
    for key in [
        JWK { key_use: None, ..jwk(&JSON::read(&path("cookbook/jwk/3_2.ec_private_key.json"))) },
        jwk(&JSON::from_text(
            r#"{"kty":"EC","crv":"P-256","x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ","y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck","d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"#,
        )),
        jwk(&JSON::read(&path("cookbook/curve25519/ecdh-es.json")).field("input").field("key").clone()),
        JWK::from_private_key(
            &umilib::auth::cert::key::PrivateKey::from_raw(umilib::auth::cert::key::KeyAlgorithm::X448, &[9; 56])
                .unwrap(),
        )
        .unwrap(),
        JWK::from_private_key(
            &umilib::auth::cert::key::PrivateKey::from_raw(
                umilib::auth::cert::key::KeyAlgorithm::EC(umilib::auth::cert::key::NamedCurve::P384),
                &[9; 48],
            )
            .unwrap(),
        )
        .unwrap(),
    ] {
        for algorithm in
            [JWEAlgorithm::ECDHES, JWEAlgorithm::ECDHESA128KW, JWEAlgorithm::ECDHESA192KW, JWEAlgorithm::ECDHESA256KW]
        {
            let mut protected = JOSEHeader::new();
            protected.set_string("alg", algorithm.name());
            protected.set_string("enc", "A256GCM");
            protected.set_string("apu", &Base64URL::encode(b"Alice"));
            let jwe = JWE::encrypt(b"agreed", &protected, None, &[(&public(&key), None)], None, &mut random()).unwrap();
            let epk = jwe.protected_header.ephemeral_key().unwrap().unwrap();
            assert!(!epk.key.is_secret());
            let config = JWEConfig::new(&[algorithm], &[JWEEncryption::A256GCM]);
            assert_eq!(jwe.decrypt(&key, &config, &mut decrypting()).unwrap().0, b"agreed", "{}", algorithm.name());
        }
    }
}

#[test]
fn multiple_recipients_share_the_content() {
    // The key of RFC 7520 §3.4, whose use is "sig", made a key of any use.
    let mut rsa = jwk(&JSON::read(&path("cookbook/jwk/3_4.rsa_private_key.json")));
    rsa.key_use = None;
    let wrap = JWK::symmetric(&[1; 16]);
    let gcm = JWK::symmetric(&[2; 32]);
    let header = |name: &str| {
        let mut header = JOSEHeader::new();
        header.set_string("alg", name);
        Some(header)
    };
    let mut protected = JOSEHeader::new();
    protected.set_string("enc", "A128CBC-HS256");
    let mut shared = JOSEHeader::new();
    shared.set_string("cty", "text/plain");
    let recipients = [(&public(&rsa), header("RSA-OAEP-256")), (&wrap, header("A128KW")), (&gcm, header("A256GCMKW"))];
    let jwe = JWE::encrypt(b"to all", &protected, Some(&shared), &recipients, Some(b"extra"), &mut random()).unwrap();
    // RFC 7518 §4.7.1: the IV and tag of AES-GCM key wrapping go into the per-recipient header.
    let third = jwe.recipients[2].header.as_ref().unwrap();
    assert!(third.get("iv").is_some() && third.get("tag").is_some());
    assert_eq!(jwe.to_compact(), Err(JWTError::Format), "RFC 7516 §7.1: one recipient only");
    let read = JWE::from_json(jwe.to_json().unwrap().as_bytes()).unwrap();
    assert_eq!(read, jwe);
    let config = JWEConfig::new(
        &[JWEAlgorithm::RSAOAEP256, JWEAlgorithm::A128KW, JWEAlgorithm::A256GCMKW],
        &[JWEEncryption::A128CBCHS256],
    );
    for (index, key) in [&rsa, &wrap, &gcm].into_iter().enumerate() {
        let (plaintext, recipient) = read.decrypt(key, &config, &mut decrypting()).unwrap();
        assert_eq!(plaintext, b"to all");
        assert_eq!(recipient, &read.recipients[index]);
    }
    // RFC 7516 §5.1 step 14: the JWE AAD is authenticated.
    let mut altered = read.clone();
    altered.aad = Some(b"other".to_vec());
    assert_eq!(altered.decrypt(&wrap, &config, &mut decrypting()).map(|_| ()), Err(JWTError::Decryption));
    // RFC 7516 §5.1: the direct algorithms take one recipient.
    let direct = [(&JWK::symmetric(&[1; 32]), header("dir")), (&wrap, header("A128KW"))];
    assert_eq!(JWE::encrypt(b"x", &protected, None, &direct, None, &mut random()).map(|_| ()), Err(JWTError::Header));
    // RFC 7516 §7.2.1: the headers must not share a parameter.
    let mut duplicated = shared.clone();
    duplicated.set_string("alg", "A128KW");
    assert_eq!(
        JWE::encrypt(b"x", &protected, Some(&duplicated), &[(&wrap, header("A128KW"))], None, &mut random())
            .map(|_| ()),
        Err(JWTError::Header)
    );
}

#[test]
fn decryption_follows_rfc_8725() {
    let key = JWK::symmetric(&[7; 16]);
    let mut protected = JOSEHeader::new();
    protected.set_string("alg", "A128KW");
    protected.set_string("enc", "A128GCM");
    let jwe = JWE::encrypt(b"secret", &protected, None, &[(&key, None)], None, &mut random()).unwrap();
    let allowed = JWEConfig::new(&[JWEAlgorithm::A128KW], &[JWEEncryption::A128GCM]);
    jwe.decrypt(&key, &allowed, &mut decrypting()).unwrap();
    // §3.1: only the algorithms the configuration allows.
    for config in [
        JWEConfig::new(&[JWEAlgorithm::A256KW], &[JWEEncryption::A128GCM]),
        JWEConfig::new(&[JWEAlgorithm::A128KW], &[JWEEncryption::A256GCM]),
    ] {
        assert_eq!(jwe.decrypt(&key, &config, &mut decrypting()).map(|_| ()), Err(JWTError::AlgorithmNotAllowed));
    }
    // A key of another size does not fit (RFC 7518 §4.4).
    assert_eq!(
        jwe.decrypt(&JWK::symmetric(&[7; 32]), &allowed, &mut decrypting()).map(|_| ()),
        Err(JWTError::KeyMismatch)
    );
    // A wrong key of the right size fails like a modified ciphertext (RFC 7516 §11.5).
    assert_eq!(
        jwe.decrypt(&JWK::symmetric(&[8; 16]), &allowed, &mut decrypting()).map(|_| ()),
        Err(JWTError::Decryption)
    );
    let mut modified = jwe.clone();
    modified.ciphertext[0] ^= 1;
    assert_eq!(modified.decrypt(&key, &allowed, &mut decrypting()).map(|_| ()), Err(JWTError::Decryption));
    let mut truncated = jwe.clone();
    truncated.tag.pop();
    assert_eq!(truncated.decrypt(&key, &allowed, &mut decrypting()).map(|_| ()), Err(JWTError::Decryption));
    // RFC 7517 §4.3: key_ops and use restrict the operations.
    let mut unwrap_only = key.clone();
    unwrap_only.key_operations = Some(vec![String::from("unwrapKey")]);
    jwe.decrypt(&unwrap_only, &allowed, &mut decrypting()).unwrap();
    assert_eq!(
        JWE::encrypt(b"x", &protected, None, &[(&unwrap_only, None)], None, &mut random()).map(|_| ()),
        Err(JWTError::KeyMismatch)
    );
    let mut signing = key.clone();
    signing.key_use = Some(String::from("sig"));
    assert_eq!(jwe.decrypt(&signing, &allowed, &mut decrypting()).map(|_| ()), Err(JWTError::KeyMismatch));
    // §3.1: a critical parameter is accepted only when understood.
    let mut critical = protected.clone();
    critical.set_string("example", "value");
    critical.set("crit", umilib::codec::json::JSONValue::Array(vec!["example".into()]));
    let jwe = JWE::encrypt(b"secret", &critical, None, &[(&key, None)], None, &mut random()).unwrap();
    assert_eq!(jwe.decrypt(&key, &allowed, &mut decrypting()).map(|_| ()), Err(JWTError::Critical));
    let mut understanding = allowed.clone();
    understanding.critical.push(String::from("example"));
    jwe.decrypt(&key, &understanding, &mut decrypting()).unwrap();
    // RFC 7516 §5.2 step 10: no encrypted key for direct encryption.
    let direct = JWK::symmetric(&[4; 16]);
    let mut dir = JOSEHeader::new();
    dir.set_string("alg", "dir");
    dir.set_string("enc", "A128GCM");
    let mut jwe = JWE::encrypt(b"secret", &dir, None, &[(&direct, None)], None, &mut random()).unwrap();
    assert!(jwe.recipients[0].encrypted_key.is_empty());
    let config = JWEConfig::new(&[JWEAlgorithm::Dir], &[JWEEncryption::A128GCM]);
    jwe.decrypt(&direct, &config, &mut decrypting()).unwrap();
    jwe.recipients[0].encrypted_key = vec![0; 24];
    assert_eq!(jwe.decrypt(&direct, &config, &mut decrypting()).map(|_| ()), Err(JWTError::Decryption));
    // A JWE with more recipients than the configuration accepts (each may cost a key derivation).
    let wrap = JWK::symmetric(&[9; 16]);
    let mut shared = JOSEHeader::new();
    shared.set_string("enc", "A128GCM");
    let header = || {
        let mut header = JOSEHeader::new();
        header.set_string("alg", "A128KW");
        Some(header)
    };
    let recipients: Vec<(&JWK, Option<JOSEHeader>)> =
        (0..=JWEConfig::MAXIMUM_RECIPIENTS).map(|_| (&wrap, header())).collect();
    let many = JWE::encrypt(b"secret", &shared, None, &recipients, None, &mut random()).unwrap();
    let config = JWEConfig::new(&[JWEAlgorithm::A128KW], &[JWEEncryption::A128GCM]);
    assert_eq!(many.decrypt(&wrap, &config, &mut decrypting()).map(|_| ()), Err(JWTError::Limit));
    let generous = JWEConfig { maximum_recipients: JWEConfig::MAXIMUM_RECIPIENTS + 1, ..config };
    many.decrypt(&wrap, &generous, &mut decrypting()).unwrap();
}

#[test]
fn pbes2_bounds_its_parameters() {
    let password = JWK::symmetric(b"password");
    let config = JWEConfig::new(&[JWEAlgorithm::PBES2HS256A128KW], &[JWEEncryption::A128GCM]);
    let mut protected = JOSEHeader::new();
    protected.set_string("alg", "PBES2-HS256+A128KW");
    protected.set_string("enc", "A128GCM");
    let jwe = JWE::encrypt(b"secret", &protected, None, &[(&password, None)], None, &mut random()).unwrap();
    // RFC 7518 §4.8.1.1: a salt of 8 or more octets; the default count of this module.
    assert!(Base64URL::decode(jwe.protected_header.string("p2s").unwrap().unwrap()).unwrap().len() >= 8);
    assert_eq!(jwe.protected_header.get("p2c"), Some(&u64::from(JWEAlgorithm::PBES2_COUNT).into()));
    let mut small = config.clone();
    small.maximum_pbes2_count = 1000;
    // RFC 8725 §3.2: a count beyond the configured maximum is refused before any work.
    assert_eq!(jwe.decrypt(&password, &small, &mut decrypting()).map(|_| ()), Err(JWTError::Header));
    for (count, expected) in [(999u64, Err(JWTError::Header)), (1000, Ok(()))] {
        let mut header = protected.clone();
        header.set("p2c", count.into());
        let made = JWE::encrypt(b"secret", &header, None, &[(&password, None)], None, &mut random());
        assert_eq!(made.as_ref().map(|_| ()).map_err(Clone::clone), expected, "{count}");
        if let Ok(made) = made {
            made.decrypt(&password, &config, &mut decrypting()).unwrap();
        }
    }
}

#[test]
fn compression_is_bounded_and_protected() {
    let key = JWK::symmetric(&[6; 16]);
    let mut protected = JOSEHeader::new();
    protected.set_string("alg", "A128KW");
    protected.set_string("enc", "A128GCM");
    protected.set_string("zip", "DEF");
    let plaintext = vec![b'a'; 100_000];
    let jwe = JWE::encrypt(&plaintext, &protected, None, &[(&key, None)], None, &mut random()).unwrap();
    assert!(jwe.ciphertext.len() < 1000, "compressed");
    let mut config = JWEConfig::new(&[JWEAlgorithm::A128KW], &[JWEEncryption::A128GCM]);
    // Compression is refused unless the configuration accepts it.
    assert_eq!(jwe.decrypt(&key, &config, &mut decrypting()).map(|_| ()), Err(JWTError::Compression));
    config.compression = true;
    assert_eq!(jwe.decrypt(&key, &config, &mut decrypting()).unwrap().0, plaintext);
    // A plaintext that decompresses beyond the limit is refused.
    config.maximum_decompressed = 99_999;
    assert_eq!(jwe.decrypt(&key, &config, &mut decrypting()).map(|_| ()), Err(JWTError::Compression));
    // RFC 7516 §4.1.3: zip must be integrity protected.
    let mut unprotected = JOSEHeader::new();
    unprotected.set_string("zip", "DEF");
    protected.remove("zip");
    assert_eq!(
        JWE::encrypt(b"x", &protected, Some(&unprotected), &[(&key, None)], None, &mut random()).map(|_| ()),
        Err(JWTError::Header)
    );
    // Only DEF is defined.
    protected.set_string("zip", "GZIP");
    assert_eq!(
        JWE::encrypt(b"x", &protected, None, &[(&key, None)], None, &mut random()).map(|_| ()),
        Err(JWTError::Compression)
    );
}

#[test]
fn serializations_follow_rfc_7516_section_7() {
    let key = JWK::symmetric(&[6; 16]);
    let mut protected = JOSEHeader::new();
    protected.set_string("alg", "A128KW");
    protected.set_string("enc", "A128GCM");
    let jwe = JWE::encrypt(b"x", &protected, None, &[(&key, None)], None, &mut random()).unwrap();
    let compact = jwe.to_compact().unwrap();
    assert_eq!(compact.split('.').count(), 5);
    for broken in [
        compact.rsplit_once('.').unwrap().0.to_string(),
        format!("{compact}."),
        format!(".{}", compact.split_once('.').unwrap().1),
    ] {
        assert!(JWE::from_compact(&broken).is_err(), "{broken}");
    }
    let flattened = jwe.to_flattened_json().unwrap();
    assert_eq!(JWE::from_json(flattened.as_bytes()).unwrap(), jwe);
    assert_eq!(JWE::from_json(jwe.to_json().unwrap().as_bytes()).unwrap(), jwe);
    // RFC 7516 §7.2.1: "recipients" excludes the members of a flattened recipient.
    let mut mixed = JSON::from_text(&jwe.to_json().unwrap());
    if let JSON::Object(members) = &mut mixed {
        members.push((String::from("encrypted_key"), JSON::String(String::from("AAAA"))));
    }
    assert_eq!(JWE::from_json(mixed.encode().as_bytes()), Err(JWTError::Format));
    // The JWE AAD exists only in the JSON serializations.
    let with_aad = JWE::encrypt(b"x", &protected, None, &[(&key, None)], Some(b"aad"), &mut random()).unwrap();
    assert_eq!(with_aad.to_compact(), Err(JWTError::Format));
}
