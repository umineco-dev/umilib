//! Keys and algorithm identifiers of PKIX against the examples of RFC 8410,
//! RFC 9881, RFC 9909 and RFC 9935, and the rules of the RFCs that define
//! the identifiers.

use umilib::auth::cert::key::{
    AlgorithmIdentifier, EncryptedPrivateKeyInfo, HashAlgorithm, KeyAlgorithm, KeyError, MLDSAParameterSet,
    MLKEMParameterSet, NamedCurve, PBES2Cipher, PBES2Config, PSSParameters, PrivateKey, PrivateKeyInfo, PublicKey,
    SLHDSAParameterSet, SignatureAlgorithm,
};
use umilib::codec::asn1::ObjectIdentifier;

use super::{DER, Fixtures, RFCExamples, random, random_with};

const RFC8410: &str = include_str!("../../vectors/auth/cert/key/rfc8410.txt");
const RFC9881: &str = include_str!("../../vectors/auth/cert/key/rfc9881.txt");
const RFC9909: &str = include_str!("../../vectors/auth/cert/key/rfc9909.txt");
const RFC9935: &str = include_str!("../../vectors/auth/cert/key/rfc9935.txt");

fn arcs(text: &str) -> ObjectIdentifier<'static> {
    ObjectIdentifier::parse(text).unwrap()
}

#[test]
fn identifiers_are_those_of_the_rfcs() {
    // The arcs as RFC 3279, RFC 4055, RFC 5480, RFC 5639, RFC 5758, RFC 8410, NIST CSOR, RFC 9881, RFC 9909 and RFC 9935 give them.
    let hashes = [
        (HashAlgorithm::SHA1, "1.3.14.3.2.26"),
        (HashAlgorithm::SHA224, "2.16.840.1.101.3.4.2.4"),
        (HashAlgorithm::SHA256, "2.16.840.1.101.3.4.2.1"),
        (HashAlgorithm::SHA384, "2.16.840.1.101.3.4.2.2"),
        (HashAlgorithm::SHA512, "2.16.840.1.101.3.4.2.3"),
        (HashAlgorithm::SHA512_224, "2.16.840.1.101.3.4.2.5"),
        (HashAlgorithm::SHA512_256, "2.16.840.1.101.3.4.2.6"),
        (HashAlgorithm::SHA3_224, "2.16.840.1.101.3.4.2.7"),
        (HashAlgorithm::SHA3_256, "2.16.840.1.101.3.4.2.8"),
        (HashAlgorithm::SHA3_384, "2.16.840.1.101.3.4.2.9"),
        (HashAlgorithm::SHA3_512, "2.16.840.1.101.3.4.2.10"),
        (HashAlgorithm::SHAKE128, "2.16.840.1.101.3.4.2.11"),
        (HashAlgorithm::SHAKE256, "2.16.840.1.101.3.4.2.12"),
    ];
    for (hash, oid) in hashes {
        assert_eq!(hash.oid(), arcs(oid), "{hash:?}");
        assert_eq!(HashAlgorithm::from_oid(&arcs(oid)), Some(hash));
    }
    let curves = [
        (NamedCurve::P256, "1.2.840.10045.3.1.7"),
        (NamedCurve::P384, "1.3.132.0.34"),
        (NamedCurve::P521, "1.3.132.0.35"),
        (NamedCurve::Secp256k1, "1.3.132.0.10"),
        (NamedCurve::BrainpoolP256r1, "1.3.36.3.3.2.8.1.1.7"),
        (NamedCurve::BrainpoolP384r1, "1.3.36.3.3.2.8.1.1.11"),
        (NamedCurve::BrainpoolP512r1, "1.3.36.3.3.2.8.1.1.13"),
    ];
    for (curve, oid) in curves {
        assert_eq!(curve.oid(), arcs(oid), "{curve:?}");
    }
    let signatures = [
        (SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA1), "1.2.840.113549.1.1.5"),
        (SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA224), "1.2.840.113549.1.1.14"),
        (SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA256), "1.2.840.113549.1.1.11"),
        (SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA384), "1.2.840.113549.1.1.12"),
        (SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA512), "1.2.840.113549.1.1.13"),
        (SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA512_224), "1.2.840.113549.1.1.15"),
        (SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA512_256), "1.2.840.113549.1.1.16"),
        (SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA3_256), "2.16.840.1.101.3.4.3.14"),
        (SignatureAlgorithm::ECDSA(HashAlgorithm::SHA1), "1.2.840.10045.4.1"),
        (SignatureAlgorithm::ECDSA(HashAlgorithm::SHA224), "1.2.840.10045.4.3.1"),
        (SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256), "1.2.840.10045.4.3.2"),
        (SignatureAlgorithm::ECDSA(HashAlgorithm::SHA384), "1.2.840.10045.4.3.3"),
        (SignatureAlgorithm::ECDSA(HashAlgorithm::SHA512), "1.2.840.10045.4.3.4"),
        (SignatureAlgorithm::ECDSA(HashAlgorithm::SHA3_512), "2.16.840.1.101.3.4.3.12"),
        (SignatureAlgorithm::Ed25519, "1.3.101.112"),
        (SignatureAlgorithm::Ed448, "1.3.101.113"),
        (SignatureAlgorithm::MLDSA(MLDSAParameterSet::MLDSA44), "2.16.840.1.101.3.4.3.17"),
        (SignatureAlgorithm::MLDSA(MLDSAParameterSet::MLDSA65), "2.16.840.1.101.3.4.3.18"),
        (SignatureAlgorithm::MLDSA(MLDSAParameterSet::MLDSA87), "2.16.840.1.101.3.4.3.19"),
        (SignatureAlgorithm::SLHDSA(SLHDSAParameterSet::SHA2_128s), "2.16.840.1.101.3.4.3.20"),
        (SignatureAlgorithm::SLHDSA(SLHDSAParameterSet::SHAKE_256f), "2.16.840.1.101.3.4.3.31"),
        (SignatureAlgorithm::HashSLHDSA(SLHDSAParameterSet::SHA2_128s), "2.16.840.1.101.3.4.3.35"),
        (SignatureAlgorithm::HashSLHDSA(SLHDSAParameterSet::SHAKE_256f), "2.16.840.1.101.3.4.3.46"),
    ];
    for (algorithm, oid) in signatures {
        let identifier = algorithm.identifier().unwrap();
        assert_eq!(identifier.oid, arcs(oid), "{algorithm:?}");
        assert_eq!(SignatureAlgorithm::from_identifier(&identifier).unwrap(), algorithm);
    }
    let keys = [
        (KeyAlgorithm::RSA, "1.2.840.113549.1.1.1"),
        (KeyAlgorithm::RSAPSS(None), "1.2.840.113549.1.1.10"),
        (KeyAlgorithm::EC(NamedCurve::P256), "1.2.840.10045.2.1"),
        (KeyAlgorithm::X25519, "1.3.101.110"),
        (KeyAlgorithm::X448, "1.3.101.111"),
        (KeyAlgorithm::Ed25519, "1.3.101.112"),
        (KeyAlgorithm::Ed448, "1.3.101.113"),
        (KeyAlgorithm::MLKEM(MLKEMParameterSet::MLKEM512), "2.16.840.1.101.3.4.4.1"),
        (KeyAlgorithm::MLKEM(MLKEMParameterSet::MLKEM768), "2.16.840.1.101.3.4.4.2"),
        (KeyAlgorithm::MLKEM(MLKEMParameterSet::MLKEM1024), "2.16.840.1.101.3.4.4.3"),
    ];
    for (algorithm, oid) in keys {
        let identifier = algorithm.identifier().unwrap();
        assert_eq!(identifier.oid, arcs(oid), "{algorithm:?}");
        assert_eq!(KeyAlgorithm::from_identifier(&identifier).unwrap(), algorithm);
    }
    for set in SLHDSAParameterSet::ALL {
        assert_eq!(SLHDSAParameterSet::from_oid(&set.oid()), Some(set));
        assert_eq!(SLHDSAParameterSet::from_hash_oid(&set.hash_oid()), Some(set));
    }
}

#[test]
fn parameters_are_checked_as_the_rfcs_require() {
    let null = |oid: &str| AlgorithmIdentifier::null(arcs(oid));
    let absent = |oid: &str| AlgorithmIdentifier::absent(arcs(oid));
    // RFC 4055 §5: RSASSA-PKCS1-v1_5 accepts NULL and absent parameters alike, and writes NULL.
    assert_eq!(
        SignatureAlgorithm::from_identifier(&null("1.2.840.113549.1.1.11")),
        Ok(SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA256))
    );
    assert_eq!(
        SignatureAlgorithm::from_identifier(&absent("1.2.840.113549.1.1.11")),
        Ok(SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA256))
    );
    assert_eq!(
        SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA256).identifier().unwrap().parameters.as_deref(),
        Some(&[5u8, 0][..])
    );
    // RFC 5758 §3.2, RFC 8410 §3, RFC 9881 §2: the parameters MUST be absent.
    for oid in ["1.2.840.10045.4.3.2", "1.3.101.112", "2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.20"] {
        assert_eq!(SignatureAlgorithm::from_identifier(&null(oid)), Err(KeyError::Parameters), "{oid}");
        // The same identifiers name keys (with the same rule), except ECDSA's, which names no key.
        let expected = if oid.starts_with("1.2.840.10045") { KeyError::UnknownAlgorithm } else { KeyError::Parameters };
        assert_eq!(KeyAlgorithm::from_identifier(&null(oid)), Err(expected), "{oid}");
    }
    // RFC 4055 §3.1: RSASSA-PSS needs its parameters in a signature.
    assert_eq!(SignatureAlgorithm::from_identifier(&absent("1.2.840.113549.1.1.10")), Err(KeyError::Parameters));
    // RFC 5480 §2.1.1: an EC key names its curve; another form (NULL, implicitCurve) is refused.
    assert_eq!(KeyAlgorithm::from_identifier(&absent("1.2.840.10045.2.1")), Err(KeyError::Parameters));
    assert_eq!(KeyAlgorithm::from_identifier(&null("1.2.840.10045.2.1")), Err(KeyError::Parameters));
    assert_eq!(SignatureAlgorithm::from_identifier(&absent("1.2.3.4")), Err(KeyError::UnknownAlgorithm));
}

#[test]
fn pss_parameters_and_their_defaults() {
    // RFC 4055 §3.1: an empty RSASSA-PSS-params is SHA-1, MGF1 with SHA-1, a salt of 20 bytes and the trailer 1.
    let defaults = PSSParameters::decode(&[0x30, 0x00]).unwrap();
    assert_eq!(defaults, PSSParameters { hash: HashAlgorithm::SHA1, mask_hash: HashAlgorithm::SHA1, salt_length: 20 });
    assert_eq!(defaults.encode().unwrap(), [0x30, 0x00]);
    let sha256 = PSSParameters::with_hash(HashAlgorithm::SHA256);
    assert_eq!(sha256.salt_length, 32);
    let encoded = sha256.encode().unwrap();
    assert_eq!(PSSParameters::decode(&encoded).unwrap(), sha256);
    // The parameters of RSASSA-PSS with SHA-256 as OpenSSL and RFC 4055 §5 (sha256Identifier with NULL) write them.
    let expected = [
        0x30, 0x34, 0xA0, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xA2, 0x03, 0x02, 0x01, 0x20,
    ];
    assert_eq!(encoded, expected);
    // A trailer other than 1, an MGF other than MGF1 and a hash RFC 4055 does not allow are refused.
    assert_eq!(PSSParameters::decode(&[0x30, 0x05, 0xA3, 0x03, 0x02, 0x01, 0x02]), Err(KeyError::Parameters));
    let mut sha3 = expected;
    sha3[16] = 0x08;
    assert_eq!(PSSParameters::decode(&sha3), Err(KeyError::Parameters));
}

#[test]
fn rfc8410_examples() {
    let blocks = RFCExamples::pem_blocks(RFC8410);
    let section =
        |name: &str| blocks.iter().filter(move |(heading, _, _)| heading.starts_with(name)).collect::<Vec<_>>();
    let public = &section("10.1.")[0].2;
    let key = PublicKey::from_der(public).unwrap();
    assert_eq!(key.algorithm(), &KeyAlgorithm::Ed25519);
    assert_eq!(key.to_der().unwrap(), *public);
    let private = section("10.3.");
    assert_eq!(private.len(), 2);
    // The first private key: the value the RFC prints after it.
    let first = PrivateKey::from_pkcs8_der(&private[0].2).unwrap();
    let expected = "D4 EE 72 DB F9 13 58 4A D5 B6 D8 F1 F7 69 F8 AD 3A FE 7C 28 CB F1 D4 FB E0 97 A8 8F 44 75 58 42";
    let value: Vec<u8> = expected.split(' ').map(|byte| u8::from_str_radix(byte, 16).unwrap()).collect();
    let typed =
        first.key::<umilib::crypto::eddsa::EdDSASigningKey<umilib::crypto::curve::curve25519::Edwards25519>>().unwrap();
    assert_eq!(typed.secret(), value.as_slice());
    assert_eq!(first.to_pkcs8_der().unwrap().expose(), &private[0].2);
    // The second: version 2, an attribute and the public key.
    let info = PrivateKeyInfo::from_der(&private[1].2).unwrap();
    assert_eq!(info.version, 1);
    assert!(info.attributes.is_some());
    assert!(info.public_key.is_some());
    match PrivateKey::from_pkcs8_der(&private[1].2) {
        Ok(second) => assert_eq!(second.public_key().unwrap(), first.public_key().unwrap()),
        Err(error) => panic!("the second example of RFC 8410 §10.3: {error:?}"),
    }
}

/// The private keys of an appendix C.1 of RFC 9881 or RFC 9935, by level, in the order seed, expanded, both.
fn private_examples(blocks: &[(String, String, Vec<u8>)], level: &str) -> Vec<Vec<u8>> {
    let examples: Vec<Vec<u8>> = blocks
        .iter()
        .filter(|(heading, label, _)| heading.starts_with(&format!("C.1.{level}.")) && label == "PRIVATE KEY")
        .map(|(_, _, data)| data.clone())
        .collect();
    assert_eq!(examples.len(), 3, "C.1.{level}: seed, expanded and both");
    examples
}

#[test]
fn rfc9881_examples() {
    let blocks = RFCExamples::pem_blocks(RFC9881);
    let public: Vec<&Vec<u8>> =
        blocks.iter().filter(|(heading, _, _)| heading.starts_with("C.2.")).map(|(_, _, data)| data).collect();
    assert_eq!(public.len(), 3);
    for (index, set) in MLDSAParameterSet::ALL.into_iter().enumerate() {
        let examples = private_examples(&blocks, &(index + 1).to_string());
        let keys: Vec<PrivateKey> = examples.iter().map(|der| PrivateKey::from_pkcs8_der(der).unwrap()).collect();
        let public_key = PublicKey::from_der(public[index]).unwrap();
        assert_eq!(public_key.algorithm(), &KeyAlgorithm::MLDSA(set));
        for key in &keys {
            assert_eq!(key.algorithm(), &KeyAlgorithm::MLDSA(set));
            assert_eq!(
                key.public_key().unwrap(),
                public_key,
                "{set:?}: every form is the key of the public key of C.2"
            );
        }
        // Keys known by their seed are written in the seed form; the others in the expanded form.
        assert_eq!(keys[0].to_pkcs8_der().unwrap().expose(), &examples[0]);
        assert_eq!(keys[1].to_pkcs8_der().unwrap().expose(), &examples[1]);
        assert_eq!(keys[2].to_pkcs8_der().unwrap().expose(), &examples[0]);
        // A signature of the key verifies with the public key, and not another message.
        let algorithm = SignatureAlgorithm::MLDSA(set);
        let signature = keys[1].sign(&algorithm, b"RFC 9881", &mut random()).unwrap();
        public_key.verify(&algorithm, b"RFC 9881", &signature).unwrap();
        assert_eq!(public_key.verify(&algorithm, b"RFC 9882", &signature), Err(KeyError::InvalidSignature));
        assert_eq!(public_key.to_der().unwrap(), *public[index]);
    }
    let bad: Vec<&Vec<u8>> =
        blocks.iter().filter(|(heading, _, _)| heading.starts_with("C.4.")).map(|(_, _, data)| data).collect();
    assert_eq!(bad.len(), 3);
    for (index, der) in bad.iter().enumerate() {
        let error = PrivateKey::from_pkcs8_der(der).unwrap_err();
        assert!(matches!(error, KeyError::Inconsistent | KeyError::InvalidKey), "C.4 example {}: {error:?}", index + 1);
    }
}

#[test]
fn rfc9935_examples() {
    let blocks = RFCExamples::pem_blocks(RFC9935);
    let public: Vec<&Vec<u8>> =
        blocks.iter().filter(|(heading, _, _)| heading.starts_with("C.2.")).map(|(_, _, data)| data).collect();
    assert_eq!(public.len(), 3);
    for (index, set) in MLKEMParameterSet::ALL.into_iter().enumerate() {
        let examples = private_examples(&blocks, &(index + 1).to_string());
        let keys: Vec<PrivateKey> = examples.iter().map(|der| PrivateKey::from_pkcs8_der(der).unwrap()).collect();
        let public_key = PublicKey::from_der(public[index]).unwrap();
        assert_eq!(public_key.algorithm(), &KeyAlgorithm::MLKEM(set));
        for key in &keys {
            assert_eq!(key.public_key().unwrap(), public_key, "{set:?}");
        }
        assert_eq!(keys[0].to_pkcs8_der().unwrap().expose(), &examples[0]);
        assert_eq!(keys[1].to_pkcs8_der().unwrap().expose(), &examples[1]);
        assert_eq!(keys[2].to_pkcs8_der().unwrap().expose(), &examples[0]);
        // A KEM key does not sign.
        assert_eq!(keys[0].sign(&SignatureAlgorithm::Ed25519, b"", &mut random()).unwrap_err(), KeyError::Mismatch);
    }
    // The second example (a mutated s with a valid public key hash) is found by the pairwise check.
    let bad: Vec<&Vec<u8>> =
        blocks.iter().filter(|(heading, _, _)| heading.starts_with("C.4.")).map(|(_, _, data)| data).collect();
    assert_eq!(bad.len(), 4);
    for (index, der) in bad.iter().enumerate() {
        let error = PrivateKey::from_pkcs8_der(der).unwrap_err();
        assert!(matches!(error, KeyError::Inconsistent | KeyError::InvalidKey), "C.4 example {}: {error:?}", index + 1);
    }
}

#[test]
fn rfc9909_examples() {
    let blocks = RFCExamples::pem_blocks(RFC9909);
    let find = |name: &str| {
        blocks.iter().find(|(heading, _, _)| heading.starts_with(name)).map(|(_, _, data)| data.clone()).unwrap()
    };
    let public_key = PublicKey::from_der(&find("C.1.")).unwrap();
    let private_key = PrivateKey::from_pkcs8_der(&find("C.2.")).unwrap();
    assert_eq!(private_key.public_key().unwrap(), public_key);
    let KeyAlgorithm::SLHDSA(set) = *public_key.algorithm() else { panic!("{:?}", public_key.algorithm()) };
    assert_eq!(private_key.to_pkcs8_der().unwrap().expose(), &find("C.2."));
    assert_eq!(public_key.to_der().unwrap(), find("C.1."));
    // A pure key does not make HashSLH-DSA signatures (RFC 9909 §3: the identifier commits the key).
    assert_eq!(public_key.verify(&SignatureAlgorithm::HashSLHDSA(set), b"", &[]), Err(KeyError::Mismatch));
}

#[test]
fn generated_keys_sign_verify_and_round_trip() {
    let mut random = random();
    let cases: Vec<(KeyAlgorithm, Vec<SignatureAlgorithm>)> = vec![
        (
            KeyAlgorithm::EC(NamedCurve::P256),
            vec![SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256), SignatureAlgorithm::ECDSA(HashAlgorithm::SHA3_384)],
        ),
        (KeyAlgorithm::EC(NamedCurve::P384), vec![SignatureAlgorithm::ECDSA(HashAlgorithm::SHA384)]),
        (KeyAlgorithm::EC(NamedCurve::P521), vec![SignatureAlgorithm::ECDSA(HashAlgorithm::SHA512)]),
        (KeyAlgorithm::Ed25519, vec![SignatureAlgorithm::Ed25519]),
        (KeyAlgorithm::Ed448, vec![SignatureAlgorithm::Ed448]),
        (KeyAlgorithm::X25519, vec![]),
        (KeyAlgorithm::X448, vec![]),
        (KeyAlgorithm::MLDSA(MLDSAParameterSet::MLDSA44), vec![SignatureAlgorithm::MLDSA(MLDSAParameterSet::MLDSA44)]),
        (
            KeyAlgorithm::SLHDSA(SLHDSAParameterSet::SHA2_128f),
            vec![SignatureAlgorithm::SLHDSA(SLHDSAParameterSet::SHA2_128f)],
        ),
        (
            KeyAlgorithm::HashSLHDSA(SLHDSAParameterSet::SHAKE_128f),
            vec![SignatureAlgorithm::HashSLHDSA(SLHDSAParameterSet::SHAKE_128f)],
        ),
        (KeyAlgorithm::MLKEM(MLKEMParameterSet::MLKEM768), vec![]),
    ];
    for (algorithm, signatures) in cases {
        let key = PrivateKey::generate(algorithm, &mut random).unwrap();
        assert_eq!(key.algorithm(), &algorithm);
        let public_key = key.public_key().unwrap();
        for signature_algorithm in &signatures {
            let signature = key.sign(signature_algorithm, b"message", &mut random).unwrap();
            public_key.verify(signature_algorithm, b"message", &signature).unwrap();
            assert_eq!(
                public_key.verify(signature_algorithm, b"messagf", &signature),
                Err(KeyError::InvalidSignature),
                "{algorithm:?}"
            );
        }
        // A signature algorithm of another family is a mismatch.
        assert_eq!(
            public_key.verify(&SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA256), b"", &[]),
            Err(KeyError::Mismatch)
        );
        // PKCS #8, PEM and SPKI round trips.
        let der = key.to_pkcs8_der().unwrap();
        let again = PrivateKey::from_pkcs8_der(der.expose()).unwrap();
        assert_eq!(again.public_key().unwrap(), public_key, "{algorithm:?}");
        assert_eq!(again.to_pkcs8_der().unwrap().expose(), der.expose());
        let pem = key.to_pem().unwrap();
        assert!(pem.expose().starts_with("-----BEGIN PRIVATE KEY-----"));
        assert_eq!(PrivateKey::from_pem(pem.expose()).unwrap().public_key().unwrap(), public_key);
        assert_eq!(PublicKey::from_pem(&public_key.to_pem().unwrap()).unwrap(), public_key);
        assert_eq!(PublicKey::from_der(&public_key.to_der().unwrap()).unwrap(), public_key);
    }
}

#[test]
fn rsa_keys_sign_with_both_paddings() {
    let mut random = random();
    let key = PrivateKey::generate_rsa(KeyAlgorithm::RSA, 2048, &mut random).unwrap();
    let public_key = key.public_key().unwrap();
    for algorithm in [
        SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA256),
        SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA3_256),
        SignatureAlgorithm::RSAPSS(PSSParameters::with_hash(HashAlgorithm::SHA256)),
        SignatureAlgorithm::RSAPSS(PSSParameters {
            hash: HashAlgorithm::SHA384,
            mask_hash: HashAlgorithm::SHA256,
            salt_length: 0,
        }),
    ] {
        let signature = key.sign(&algorithm, b"message", &mut random).unwrap();
        public_key.verify(&algorithm, b"message", &signature).unwrap();
        assert_eq!(public_key.verify(&algorithm, b"other", &signature), Err(KeyError::InvalidSignature));
    }
    let der = key.to_pkcs8_der().unwrap();
    assert_eq!(PrivateKey::from_pkcs8_der(der.expose()).unwrap().public_key().unwrap(), public_key);
    // RFC 4055 §3.3: a key restricted to RSASSA-PSS with parameters signs only with them (and a salt at least as long).
    let restricted = KeyAlgorithm::RSAPSS(Some(PSSParameters::with_hash(HashAlgorithm::SHA256)));
    assert!(restricted.signs(&SignatureAlgorithm::RSAPSS(PSSParameters::with_hash(HashAlgorithm::SHA256))));
    assert!(!restricted.signs(&SignatureAlgorithm::RSAPSS(PSSParameters::with_hash(HashAlgorithm::SHA384))));
    assert!(!restricted.signs(&SignatureAlgorithm::RSAPSS(PSSParameters {
        salt_length: 31,
        ..PSSParameters::with_hash(HashAlgorithm::SHA256)
    })));
    assert!(!restricted.signs(&SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA256)));
    assert_eq!(PrivateKey::generate(KeyAlgorithm::RSA, &mut random).unwrap_err(), KeyError::Parameters);
}

#[test]
fn encrypted_private_keys() {
    let mut random = random();
    let key = PrivateKey::generate(KeyAlgorithm::Ed25519, &mut random).unwrap();
    for (prf, cipher) in [
        (HashAlgorithm::SHA256, PBES2Cipher::AES256CBC),
        (HashAlgorithm::SHA1, PBES2Cipher::AES128CBC),
        (HashAlgorithm::SHA512, PBES2Cipher::AES192CBC),
    ] {
        let config = PBES2Config { prf, cipher, iterations: 1000, ..PBES2Config::default() };
        let der = key.to_encrypted_pkcs8_der(b"password", &config, &mut random).unwrap();
        let decrypted = PrivateKey::from_encrypted_pkcs8_der(&der, b"password", &config).unwrap();
        assert_eq!(decrypted.public_key().unwrap(), key.public_key().unwrap());
        assert_eq!(PrivateKey::from_encrypted_pkcs8_der(&der, b"wrong", &config).unwrap_err(), KeyError::Decryption);
        // More iterations than the configuration accepts are refused before any work.
        let strict = PBES2Config { maximum_iterations: 999, ..config };
        assert_eq!(PrivateKey::from_encrypted_pkcs8_der(&der, b"password", &strict).unwrap_err(), KeyError::Parameters);
        let info = EncryptedPrivateKeyInfo::from_der(&der).unwrap();
        assert_eq!(info.to_der().unwrap(), der);
        let pem = key.to_encrypted_pem(b"password", &config, &mut random).unwrap();
        assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        assert!(PrivateKey::from_encrypted_pem(&pem, b"password", &config).is_ok());
    }
}

#[test]
fn malformed_keys_are_refused() {
    // A public key that is not on its curve, of the wrong length or with unused bits.
    assert_eq!(PublicKey::new(KeyAlgorithm::Ed25519, &[0; 31]).unwrap_err(), KeyError::InvalidKey);
    assert_eq!(PublicKey::new(KeyAlgorithm::X25519, &[0; 33]).unwrap_err(), KeyError::InvalidKey);
    let mut point = vec![4u8; 65];
    point[64] ^= 1;
    assert_eq!(PublicKey::new(KeyAlgorithm::EC(NamedCurve::P256), &point).unwrap_err(), KeyError::InvalidKey);
    // A version 1 key with a public key, and an unknown version.
    let key = PrivateKey::generate(KeyAlgorithm::Ed25519, &mut random()).unwrap();
    let der = key.to_pkcs8_der().unwrap().expose().clone();
    let mut version = der.clone();
    version[4] = 2;
    assert_eq!(PrivateKey::from_pkcs8_der(&version).unwrap_err(), KeyError::Parameters);
    assert!(PrivateKey::from_pkcs8_der(&der[..der.len() - 1]).is_err());
    // Another key's public key in a version 2 key is inconsistent.
    let other = PrivateKey::generate(KeyAlgorithm::Ed25519, &mut random_with(8)).unwrap();
    let mut info = PrivateKeyInfo::from_der(&der).unwrap();
    info.version = 1;
    let foreign = other.public_key().unwrap();
    let mut wrong = foreign.key().to_vec();
    wrong[0] ^= 1;
    let bits = umilib::codec::asn1::BitString::new(0, wrong.as_slice()).unwrap();
    info.public_key = Some(bits);
    let mut writer = umilib::codec::asn1::der::DERWriter::new();
    info.encode(&mut writer).unwrap();
    assert!(matches!(
        PrivateKey::from_pkcs8_der(&writer.into_bytes()),
        Err(KeyError::Inconsistent | KeyError::InvalidKey)
    ));
}

#[test]
fn keys_and_signatures_of_openssl() {
    let message = Fixtures::KEY.bytes("message.txt");
    const PSS: SignatureAlgorithm = SignatureAlgorithm::RSAPSS(PSSParameters::with_hash(HashAlgorithm::SHA256));
    // A key, its algorithm, and its signatures: the suffix of the file, the algorithm and whether it is deterministic.
    type Case = (&'static str, KeyAlgorithm, &'static [(&'static str, SignatureAlgorithm, bool)]);
    let cases: [Case; 12] = [
        (
            "rsa",
            KeyAlgorithm::RSA,
            &[("rsa-sha256", SignatureAlgorithm::RSAPKCS1v15(HashAlgorithm::SHA256), true), ("pss-sha256", PSS, false)],
        ),
        (
            "rsa-pss",
            KeyAlgorithm::RSAPSS(Some(PSSParameters::with_hash(HashAlgorithm::SHA256))),
            &[("pss-sha256", PSS, false)],
        ),
        (
            "p256",
            KeyAlgorithm::EC(NamedCurve::P256),
            &[("ecdsa-sha256", SignatureAlgorithm::ECDSA(HashAlgorithm::SHA256), false)],
        ),
        (
            "p384",
            KeyAlgorithm::EC(NamedCurve::P384),
            &[("ecdsa-sha384", SignatureAlgorithm::ECDSA(HashAlgorithm::SHA384), false)],
        ),
        (
            "p521",
            KeyAlgorithm::EC(NamedCurve::P521),
            &[("ecdsa-sha512", SignatureAlgorithm::ECDSA(HashAlgorithm::SHA512), false)],
        ),
        ("ed25519", KeyAlgorithm::Ed25519, &[("ed25519", SignatureAlgorithm::Ed25519, true)]),
        ("ed448", KeyAlgorithm::Ed448, &[("ed448", SignatureAlgorithm::Ed448, true)]),
        ("x25519", KeyAlgorithm::X25519, &[]),
        ("x448", KeyAlgorithm::X448, &[]),
        (
            "mldsa65",
            KeyAlgorithm::MLDSA(MLDSAParameterSet::MLDSA65),
            &[("mldsa65", SignatureAlgorithm::MLDSA(MLDSAParameterSet::MLDSA65), false)],
        ),
        ("mlkem768", KeyAlgorithm::MLKEM(MLKEMParameterSet::MLKEM768), &[]),
        (
            "slhdsa-sha2-128f",
            KeyAlgorithm::SLHDSA(SLHDSAParameterSet::SHA2_128f),
            &[("slhdsa", SignatureAlgorithm::SLHDSA(SLHDSAParameterSet::SHA2_128f), false)],
        ),
    ];
    let mut random = random();
    for (name, algorithm, signatures) in cases {
        let key = PrivateKey::from_pem(&Fixtures::KEY.text(&format!("{name}.key")))
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(key.algorithm(), &algorithm, "{name}");
        let public_key = PublicKey::from_pem(&Fixtures::KEY.text(&format!("{name}.pub"))).unwrap();
        assert_eq!(key.public_key().unwrap(), public_key, "{name}: the public key OpenSSL derived");
        // The SubjectPublicKeyInfo is written as OpenSSL writes it.
        let pem = Fixtures::KEY.text(&format!("{name}.pub"));
        let document = umilib::codec::pem::PEMDocument::decode(pem.as_bytes(), Default::default()).unwrap();
        assert_eq!(public_key.to_der().unwrap(), document.data(), "{name}");
        for (suffix, signature_algorithm, deterministic) in signatures {
            let signature = Fixtures::KEY.bytes(&format!("{name}.{suffix}.sig"));
            public_key
                .verify(signature_algorithm, &message, &signature)
                .unwrap_or_else(|error| panic!("{name}.{suffix}: {error:?}"));
            let ours = key.sign(signature_algorithm, &message, &mut random).unwrap();
            public_key.verify(signature_algorithm, &message, &ours).unwrap();
            if *deterministic {
                assert_eq!(ours, signature, "{name}.{suffix}: the deterministic signature is OpenSSL's");
            }
        }
    }
    // PKCS #1 and RFC 5915 keys are the keys of their PKCS #8 forms.
    let rsa = PrivateKey::from_pem(&Fixtures::KEY.text("rsa.pkcs1.key")).unwrap();
    assert_eq!(rsa.public_key().unwrap(), PublicKey::from_pem(&Fixtures::KEY.text("rsa.pub")).unwrap());
    let p256 = PrivateKey::from_pem(&Fixtures::KEY.text("p256.sec1.key")).unwrap();
    assert_eq!(p256.public_key().unwrap(), PublicKey::from_pem(&Fixtures::KEY.text("p256.pub")).unwrap());
    // Encrypted PKCS #8 of OpenSSL (PBES2 with PBKDF2).
    let config = PBES2Config::default();
    for (name, plain) in [("p256.aes256-sha256", "p256"), ("ed25519.aes128-sha1", "ed25519")] {
        let key =
            PrivateKey::from_encrypted_pem(&Fixtures::KEY.text(&format!("{name}.key")), b"umilib", &config).unwrap();
        assert_eq!(
            key.public_key().unwrap(),
            PublicKey::from_pem(&Fixtures::KEY.text(&format!("{plain}.pub"))).unwrap(),
            "{name}"
        );
        assert_eq!(
            PrivateKey::from_encrypted_pem(&Fixtures::KEY.text(&format!("{name}.key")), b"umilia", &config)
                .unwrap_err(),
            KeyError::Decryption
        );
    }
}

#[test]
fn pss_parameters_given_explicitly_with_their_defaults_are_accepted() {
    // RFC 4055 §3.1: a decoder must accept the fields of their default value written out.
    let sha1 = DER::sequence(&[&DER::oid("1.3.14.3.2.26"), &[0x05, 0x00]]);
    let mgf1 = DER::sequence(&[&DER::oid("1.2.840.113549.1.1.8"), &sha1]);
    let explicit = DER::sequence(&[
        &DER::element(0xA0, &sha1),
        &DER::element(0xA1, &mgf1),
        &DER::element(0xA2, &DER::integer(20)),
        &DER::element(0xA3, &DER::integer(1)),
    ]);
    assert_eq!(PSSParameters::decode(&explicit).unwrap(), PSSParameters::with_hash(HashAlgorithm::SHA1));
    // SHA-1 without parameters is the same hash (RFC 4055 §2.1).
    let absent = DER::sequence(&[&DER::element(0xA0, &DER::sequence(&[&DER::oid("1.3.14.3.2.26")]))]);
    assert_eq!(PSSParameters::decode(&absent).unwrap(), PSSParameters::with_hash(HashAlgorithm::SHA1));
}

#[test]
fn rsa_encryption_keys_need_null_parameters() {
    // RFC 3279 §2.3.1, RFC 4055 §1.2: the parameters of rsaEncryption MUST be NULL.
    assert_eq!(
        KeyAlgorithm::from_identifier(&AlgorithmIdentifier::absent(arcs("1.2.840.113549.1.1.1"))),
        Err(KeyError::Parameters)
    );
    assert_eq!(
        KeyAlgorithm::from_identifier(&AlgorithmIdentifier::null(arcs("1.2.840.113549.1.1.1"))),
        Ok(KeyAlgorithm::RSA)
    );
}

#[test]
fn rsa_keys_above_the_limits_are_refused() {
    use umilib::auth::cert::key::KeyLimits;
    use umilib::crypto::rsa::RSAPublicKey;
    use umilib::math::bigint::BoxedUint;
    // A modulus of 16385 bits (2^16385 - 1, odd) and a 65-bit exponent (2^64 + 1) with a 2048-bit modulus.
    let ones = |bits: u32| {
        let mut bytes = vec![0xFFu8; bits.div_ceil(8) as usize];
        bytes[0] = 0xFF >> (8 * bytes.len() as u32 - bits);
        BoxedUint::from_be_bytes(&bytes, bits.div_ceil(64) * 64).unwrap()
    };
    let e = BoxedUint::from_u64(65537, 64).unwrap();
    let large = RSAPublicKey::new(&ones(16385), &e).unwrap().to_pkcs1_der();
    assert_eq!(PublicKey::new(KeyAlgorithm::RSA, &large).unwrap_err(), KeyError::Limit);
    let bigger = KeyLimits { maximum_rsa_bits: 16385, ..KeyLimits::default() };
    assert!(PublicKey::new_with_limits(KeyAlgorithm::RSA, &large, &bigger).is_ok());
    let mut exponent = vec![0u8; 9];
    exponent[0] = 1;
    exponent[8] = 1;
    let e = BoxedUint::from_be_bytes(&exponent, 128).unwrap();
    let wide = RSAPublicKey::new(&ones(2048), &e).unwrap().to_pkcs1_der();
    assert_eq!(PublicKey::new(KeyAlgorithm::RSA, &wide).unwrap_err(), KeyError::Limit);
}

#[test]
fn pkcs8_in_ber_is_read_as_rfc_5958_requires() {
    let key = PrivateKey::generate(KeyAlgorithm::Ed25519, &mut random()).unwrap();
    let der = key.to_pkcs8_der().unwrap().expose().clone();
    // The same key with the indefinite length form of BER for the outer SEQUENCE.
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&der[2..]);
    ber.extend_from_slice(&[0x00, 0x00]);
    assert!(matches!(PrivateKey::from_pkcs8_der(&ber), Err(KeyError::Encoding(_))));
    assert_eq!(PrivateKey::from_pkcs8_ber(&ber).unwrap().public_key().unwrap(), key.public_key().unwrap());
    use umilib::codec::base::Encoding;
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        umilib::codec::base::base64::Base64::STANDARD.encode(&ber)
    );
    assert_eq!(PrivateKey::from_pem(&pem).unwrap().public_key().unwrap(), key.public_key().unwrap());
}

#[test]
fn ec_private_keys_are_checked() {
    use umilib::auth::cert::key::ECPrivateKey;
    let key = PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), &mut random()).unwrap();
    let der = key.to_pkcs8_der().unwrap().expose().clone();
    let info = PrivateKeyInfo::from_der(&der).unwrap();
    let inner = ECPrivateKey::from_der(info.private_key).unwrap();
    assert_eq!(inner.curve, Some(NamedCurve::P256));
    assert!(inner.public_key.is_some(), "RFC 5915: the curve, and the public key, are written");
    let rewrap = |private_key: &[u8]| {
        let info = PrivateKeyInfo { private_key, ..PrivateKeyInfo::from_der(&der).unwrap() };
        let mut writer = umilib::codec::asn1::der::DERWriter::new();
        info.encode(&mut writer).unwrap();
        PrivateKey::from_pkcs8_der(&writer.into_bytes())
    };
    let scalar = inner.private_key.to_vec();
    let curve = DER::element(0xA0, &DER::oid("1.2.840.10045.3.1.7"));
    // Version 2, a short scalar, another curve and another point are refused.
    let version = DER::sequence(&[&DER::integer(2), &DER::element(0x04, &scalar), &curve]);
    assert_eq!(rewrap(&version).unwrap_err(), KeyError::Parameters);
    let short = DER::sequence(&[&DER::integer(1), &DER::element(0x04, &scalar[1..]), &curve]);
    assert_eq!(rewrap(&short).unwrap_err(), KeyError::InvalidKey);
    let other = DER::sequence(&[
        &DER::integer(1),
        &DER::element(0x04, &scalar),
        &DER::element(0xA0, &DER::oid("1.3.132.0.34")),
    ]);
    assert_eq!(rewrap(&other).unwrap_err(), KeyError::Inconsistent);
    let foreign =
        PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), &mut random_with(8)).unwrap().public_key().unwrap();
    let mut point = vec![0x00];
    point.extend_from_slice(foreign.key());
    let wrong = DER::sequence(&[
        &DER::integer(1),
        &DER::element(0x04, &scalar),
        &curve,
        &DER::element(0xA1, &DER::element(0x03, &point)),
    ]);
    assert_ne!(foreign, key.public_key().unwrap());
    assert_eq!(rewrap(&wrong).unwrap_err(), KeyError::Inconsistent);
    // Without the optional fields it is the same key.
    let bare = DER::sequence(&[&DER::integer(1), &DER::element(0x04, &scalar)]);
    assert_eq!(rewrap(&bare).unwrap().public_key().unwrap(), key.public_key().unwrap());
    // The Debug output does not show the scalar.
    let debug = format!("{inner:?}{info:?}");
    assert!(!debug.contains("private_key") && !debug.contains(&format!("{:?}", &scalar[..4])), "{debug}");
}

#[test]
fn version_2_keys_may_give_their_ec_point_compressed() {
    use umilib::crypto::curve::p256::P256;
    use umilib::crypto::ecdsa::ECDSAVerifyingKey;
    let key = PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), &mut random()).unwrap();
    let mut compressed = vec![0u8; 33];
    ECDSAVerifyingKey::<P256>::from_encoded(key.public_key().unwrap().key())
        .unwrap()
        .write_encoded(&mut compressed, true)
        .unwrap();
    let der = key.to_pkcs8_der().unwrap().expose().clone();
    let mut info = PrivateKeyInfo::from_der(&der).unwrap();
    info.version = 1;
    info.public_key = Some(umilib::codec::asn1::BitString::new(0, compressed.as_slice()).unwrap());
    let mut writer = umilib::codec::asn1::der::DERWriter::new();
    info.encode(&mut writer).unwrap();
    assert_eq!(
        PrivateKey::from_pkcs8_der(&writer.into_bytes()).unwrap().public_key().unwrap(),
        key.public_key().unwrap()
    );
}

#[test]
fn seed_choices_are_strict() {
    // RFC 9881 §6: the seed is [0] IMPLICIT OCTET STRING (primitive) of 32 bytes.
    let algorithm = AlgorithmIdentifier::absent(MLDSAParameterSet::MLDSA44.oid()).to_der().unwrap();
    let pkcs8 = |private_key: &[u8]| DER::sequence(&[&DER::integer(0), &algorithm, &DER::element(0x04, private_key)]);
    assert!(PrivateKey::from_pkcs8_der(&pkcs8(&DER::element(0x80, &[1; 32]))).is_ok());
    assert!(PrivateKey::from_pkcs8_der(&pkcs8(&DER::element(0xA0, &DER::element(0x04, &[1; 32])))).is_err());
    assert_eq!(PrivateKey::from_pkcs8_der(&pkcs8(&DER::element(0x80, &[1; 31]))).unwrap_err(), KeyError::InvalidKey);
    assert_eq!(PrivateKey::from_pkcs8_der(&pkcs8(&DER::element(0x02, &[1]))).unwrap_err(), KeyError::InvalidKey);
}

#[test]
fn signature_algorithms_and_keys_that_do_not_go_together() {
    let hash_key = KeyAlgorithm::HashSLHDSA(SLHDSAParameterSet::SHA2_128f);
    assert!(!hash_key.signs(&SignatureAlgorithm::SLHDSA(SLHDSAParameterSet::SHA2_128f)));
    assert!(hash_key.signs(&SignatureAlgorithm::HashSLHDSA(SLHDSAParameterSet::SHA2_128f)));
    assert!(
        !KeyAlgorithm::MLDSA(MLDSAParameterSet::MLDSA44).signs(&SignatureAlgorithm::MLDSA(MLDSAParameterSet::MLDSA65))
    );
    let restricted = KeyAlgorithm::RSAPSS(Some(PSSParameters::with_hash(HashAlgorithm::SHA256)));
    let other_mask =
        PSSParameters { mask_hash: HashAlgorithm::SHA384, ..PSSParameters::with_hash(HashAlgorithm::SHA256) };
    assert!(!restricted.signs(&SignatureAlgorithm::RSAPSS(other_mask)));
    assert!(!KeyAlgorithm::EC(NamedCurve::P256).signs(&SignatureAlgorithm::Ed25519));
}

#[test]
fn pbes2_parameters_are_checked() {
    use umilib::auth::cert::key::PBES2Parameters;
    let hmac_sha256 = DER::sequence(&[&DER::oid("1.2.840.113549.2.9"), &[0x05, 0x00]]);
    let kdf = |fields: &[&[u8]]| DER::sequence(&[&DER::oid("1.2.840.113549.1.5.12"), &DER::sequence(fields)]);
    let aes = |iv: &[u8]| DER::sequence(&[&DER::oid("2.16.840.1.101.3.4.1.42"), &DER::element(0x04, iv)]);
    let parameters = |kdf: &[u8], scheme: &[u8]| DER::sequence(&[kdf, scheme]);
    let salt = DER::element(0x04, &[7; 16]);
    let iterations = DER::element(0x02, &[0x08, 0x00]);
    let good = parameters(&kdf(&[&salt, &iterations, &hmac_sha256]), &aes(&[1; 16]));
    let decoded = PBES2Parameters::decode(&good).unwrap();
    assert_eq!(
        (decoded.prf, decoded.iterations, decoded.cipher),
        (HashAlgorithm::SHA256, 2048, PBES2Cipher::AES256CBC)
    );
    // RFC 8018 §A.2: the PRF defaults to hmacWithSHA1; a keyLength equal to the key size is allowed.
    let default_prf = parameters(&kdf(&[&salt, &iterations, &DER::integer(32)]), &aes(&[1; 16]));
    assert_eq!(PBES2Parameters::decode(&default_prf).unwrap().prf, HashAlgorithm::SHA1);
    let refused: [(Vec<u8>, KeyError); 6] = [
        (parameters(&kdf(&[&salt, &iterations, &DER::integer(16)]), &aes(&[1; 16])), KeyError::Parameters),
        (parameters(&kdf(&[&salt, &iterations]), &aes(&[1; 8])), KeyError::Parameters),
        (parameters(&kdf(&[&salt, &DER::integer(0)]), &aes(&[1; 16])), KeyError::Parameters),
        (
            parameters(&kdf(&[&DER::sequence(&[&DER::oid("1.2.3")]), &iterations]), &aes(&[1; 16])),
            KeyError::Unsupported,
        ),
        (
            parameters(
                &kdf(&[&salt, &iterations, &DER::sequence(&[&DER::oid("1.2.3"), &[0x05, 0x00]])]),
                &aes(&[1; 16]),
            ),
            KeyError::UnknownAlgorithm,
        ),
        (
            parameters(
                &kdf(&[&salt, &iterations, &DER::sequence(&[&DER::oid("1.2.840.113549.2.9"), &DER::integer(1)])]),
                &aes(&[1; 16]),
            ),
            KeyError::Parameters,
        ),
    ];
    for (index, (bytes, error)) in refused.iter().enumerate() {
        assert_eq!(PBES2Parameters::decode(bytes).unwrap_err(), *error, "case {index}");
    }
    // RFC 8018 §4: at least 8 bytes of salt and 1000 iterations are written.
    let key = PrivateKey::generate(KeyAlgorithm::Ed25519, &mut random()).unwrap();
    for config in [
        PBES2Config { salt_length: 7, ..PBES2Config::default() },
        PBES2Config { iterations: 999, ..PBES2Config::default() },
    ] {
        assert_eq!(key.to_encrypted_pkcs8_der(b"p", &config, &mut random()).unwrap_err(), KeyError::Parameters);
    }
}

#[test]
fn the_inconsistent_examples_are_refused_for_their_reason() {
    // RFC 9881 C.4: (1) a seed and an expanded key that differ; (2) a tr and (3) a t0 that are not the key's.
    let blocks = RFCExamples::pem_blocks(RFC9881);
    let bad: Vec<&Vec<u8>> =
        blocks.iter().filter(|(heading, _, _)| heading.starts_with("C.4.")).map(|(_, _, data)| data).collect();
    let errors: Vec<KeyError> = bad.iter().map(|der| PrivateKey::from_pkcs8_der(der).unwrap_err()).collect();
    assert_eq!(errors, vec![KeyError::Inconsistent, KeyError::InvalidKey, KeyError::InvalidKey]);
    // RFC 9935 C.4.1: (1) seed and expanded differ; (2) s mutated (pairwise check); (3) H(ek) mutated
    // (hash check of FIPS 203 §7.3); (4) seed and expanded differ in z.
    let blocks = RFCExamples::pem_blocks(RFC9935);
    let bad: Vec<&Vec<u8>> =
        blocks.iter().filter(|(heading, _, _)| heading.starts_with("C.4.")).map(|(_, _, data)| data).collect();
    let errors: Vec<KeyError> = bad.iter().map(|der| PrivateKey::from_pkcs8_der(der).unwrap_err()).collect();
    assert_eq!(
        errors,
        vec![KeyError::Inconsistent, KeyError::Inconsistent, KeyError::InvalidKey, KeyError::Inconsistent]
    );
}
