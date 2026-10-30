//! ML-DSA (FIPS 204) against the ACVP vectors of NIST (key generation,
//! signature generation and verification through every interface: pure,
//! pre-hash, internal and external μ) and Project Wycheproof, and the
//! requirements of FIPS 204 on keys, contexts and signatures.

use umilib::crypto::mldsa::{MLDSA, MLDSA44, MLDSA65, MLDSA87, MLDSAParameters};
use umilib::crypto::random::HMACDRBG;
use umilib::crypto::{CryptoError, PreHash, SignatureScheme};
use umilib::hash::sha::v2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use umilib::hash::sha::v3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};

use crate::{Json, Vectors, Wycheproof};

/// Calls `$check::<P>($arguments)` for the parameter set named `$name`.
macro_rules! with_parameters {
    ($name:expr, $check:ident($($argument:expr),*)) => {
        match $name {
            "ML-DSA-44" => $check::<MLDSA44>($($argument),*),
            "ML-DSA-65" => $check::<MLDSA65>($($argument),*),
            "ML-DSA-87" => $check::<MLDSA87>($($argument),*),
            other => panic!("unknown parameter set {other}"),
        }
    };
}

/// The value of `$function::<P, H>($arguments)` for the hash function named `$name` (as ACVP names them).
macro_rules! with_pre_hash {
    ($name:expr, $function:ident::<$parameters:ty>($($argument:expr),*)) => {
        match $name {
            "SHA2-224" => $function::<$parameters, SHA224>($($argument),*),
            "SHA2-256" => $function::<$parameters, SHA256>($($argument),*),
            "SHA2-384" => $function::<$parameters, SHA384>($($argument),*),
            "SHA2-512" => $function::<$parameters, SHA512>($($argument),*),
            "SHA2-512/224" => $function::<$parameters, SHA512_224>($($argument),*),
            "SHA2-512/256" => $function::<$parameters, SHA512_256>($($argument),*),
            "SHA3-224" => $function::<$parameters, SHA3_224>($($argument),*),
            "SHA3-256" => $function::<$parameters, SHA3_256>($($argument),*),
            "SHA3-384" => $function::<$parameters, SHA3_384>($($argument),*),
            "SHA3-512" => $function::<$parameters, SHA3_512>($($argument),*),
            "SHAKE-128" => $function::<$parameters, SHAKE128>($($argument),*),
            "SHAKE-256" => $function::<$parameters, SHAKE256>($($argument),*),
            other => panic!("unknown hash function {other}"),
        }
    };
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().unwrap()
}

fn signing_key<P: MLDSAParameters>(key: &<MLDSA<P> as SignatureScheme>::SigningKey) -> Vec<u8> {
    let mut out = vec![0; P::PRIVATE_KEY_SIZE];
    MLDSA::<P>::write_signing_key(key, &mut out).unwrap();
    out
}

fn verifying_key<P: MLDSAParameters>(key: &<MLDSA<P> as SignatureScheme>::VerifyingKey) -> Vec<u8> {
    let mut out = vec![0; P::PUBLIC_KEY_SIZE];
    MLDSA::<P>::write_verifying_key(key, &mut out).unwrap();
    out
}

fn check_key_gen<P: MLDSAParameters>(test: &Json) {
    let key = MLDSA::<P>::signing_key_from_seed(&test.bytes("seed")).unwrap();
    assert_eq!(signing_key::<P>(&key), test.bytes("sk"));
    assert_eq!(verifying_key::<P>(&MLDSA::<P>::verifying_key(&key)), test.bytes("pk"));
    // The expanded encoding reads back to the same key.
    let decoded = MLDSA::<P>::signing_key_from_bytes(&test.bytes("sk")).unwrap();
    assert_eq!(MLDSA::<P>::verifying_key(&decoded), MLDSA::<P>::verifying_key(&key));
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn mldsa_acvp_key_generation() {
    let vectors = Json::read("crypto/mldsa/acvp-keygen.json");
    let mut count = 0;
    for group in vectors.field("testGroups").items() {
        for test in group.field("tests").items() {
            with_parameters!(group.field("parameterSet").as_str(), check_key_gen(test));
            count += 1;
        }
    }
    assert_eq!(count, 75);
}

fn sign_pre_hash<P: MLDSAParameters, H: PreHash>(
    key: &<MLDSA<P> as SignatureScheme>::SigningKey,
    message: &[u8],
    context: &[u8],
    rnd: &[u8; 32],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    MLDSA::<P>::sign_pre_hash_with_rnd::<H>(key, message, context, rnd, out)
}

fn verify_pre_hash<P: MLDSAParameters, H: PreHash>(
    key: &<MLDSA<P> as SignatureScheme>::VerifyingKey,
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    MLDSA::<P>::verify_pre_hash::<H>(key, message, context, signature)
}

/// The interface of an ACVP group: internal with μ, internal on M', external pure or external pre-hash.
fn interface(group: &Json) -> &'static str {
    match (group.field("signatureInterface").as_str(), group.field("preHash").as_str()) {
        ("internal", _) if matches!(group.field("externalMu"), Json::Bool(true)) => "mu",
        ("internal", _) => "internal",
        ("external", "pure") => "pure",
        ("external", "preHash") => "preHash",
        other => panic!("unknown interface {other:?}"),
    }
}

fn check_signature_generation<P: MLDSAParameters>(group: &Json, test: &Json) {
    let key = MLDSA::<P>::signing_key_from_bytes(&test.bytes("sk")).unwrap();
    assert_eq!(verifying_key::<P>(&MLDSA::<P>::verifying_key(&key)), test.bytes("pk"));
    let rnd = match group.field("deterministic") {
        Json::Bool(true) => [0; 32],
        _ => array(&test.bytes("rnd")),
    };
    let mut signature = vec![0; P::SIGNATURE_SIZE];
    match interface(group) {
        "mu" => MLDSA::<P>::sign_mu(&key, &array(&test.bytes("mu")), &rnd, &mut signature).unwrap(),
        "internal" => MLDSA::<P>::sign_internal(&key, &[&test.bytes("message")], &rnd, &mut signature).unwrap(),
        "pure" => {
            let context = test.bytes("context");
            let prefix = MLDSA::<P>::prefix(0, &context).unwrap();
            MLDSA::<P>::sign_internal(&key, &[&prefix, &context, &test.bytes("message")], &rnd, &mut signature)
                .unwrap();
        }
        _ => {
            let (message, context) = (test.bytes("message"), test.bytes("context"));
            with_pre_hash!(
                test.field("hashAlg").as_str(),
                sign_pre_hash::<P>(&key, &message, &context, &rnd, &mut signature)
            )
            .unwrap();
        }
    }
    assert_eq!(signature, test.bytes("signature"), "tcId {:?}", test.field("tcId"));
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn mldsa_acvp_signature_generation() {
    let vectors = Json::read("crypto/mldsa/acvp-siggen-subset.json");
    let mut count = 0;
    for group in vectors.field("testGroups").items() {
        for test in group.field("tests").items() {
            with_parameters!(group.field("parameterSet").as_str(), check_signature_generation(group, test));
            count += 1;
        }
    }
    assert_eq!(count, 24 * 5);
}

fn check_signature_verification<P: MLDSAParameters>(group: &Json, test: &Json) {
    let key = MLDSA::<P>::verifying_key_from_bytes(&test.bytes("pk")).unwrap();
    let signature = test.bytes("signature");
    let result = match interface(group) {
        "mu" => MLDSA::<P>::verify_mu(&key, &array(&test.bytes("mu")), &signature),
        "internal" => MLDSA::<P>::verify_internal(&key, &[&test.bytes("message")], &signature),
        "pure" => MLDSA::<P>::verify_with_context(&key, &test.bytes("message"), &test.bytes("context"), &signature),
        _ => {
            let (message, context) = (test.bytes("message"), test.bytes("context"));
            with_pre_hash!(test.field("hashAlg").as_str(), verify_pre_hash::<P>(&key, &message, &context, &signature))
        }
    };
    let passed = matches!(test.field("testPassed"), Json::Bool(true));
    assert_eq!(result.is_ok(), passed, "tcId {:?}", test.field("tcId"));
    if !passed {
        assert_eq!(result, Err(CryptoError::InvalidSignature));
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn mldsa_acvp_signature_verification() {
    let vectors = Json::read("crypto/mldsa/acvp-sigver.json");
    let mut count = 0;
    for group in vectors.field("testGroups").items() {
        for test in group.field("tests").items() {
            with_parameters!(group.field("parameterSet").as_str(), check_signature_verification(group, test));
            count += 1;
        }
    }
    assert_eq!(count, 12 * 15);
}

/// mldsa_*_sign_{seed,noseed}_test.json: a key from its seed (or its
/// expanded encoding), the signature of a message with a context (or of
/// μ), deterministic or with rnd, and its verification.
fn check_wycheproof_signing<P: MLDSAParameters>(group: &Json, test: &Json) {
    let valid = Wycheproof::valid(test);
    let key = match group.get("privateSeed") {
        Some(seed) => MLDSA::<P>::signing_key_from_seed(&hex(seed.as_str())),
        None => MLDSA::<P>::signing_key_from_bytes(&group.bytes("privateKey")),
    };
    let key = match key {
        Ok(key) => key,
        Err(error) => {
            assert!(!valid, "tcId {:?}", test.field("tcId"));
            assert_eq!(error, CryptoError::InvalidKey);
            return;
        }
    };
    let public = MLDSA::<P>::verifying_key(&key);
    assert_eq!(verifying_key::<P>(&public), group.bytes("publicKey"));
    let rnd = test.get("rnd").map(|rnd| array(&hex(rnd.as_str()))).unwrap_or([0; 32]);
    let context = test.get("ctx").map(|context| hex(context.as_str())).unwrap_or_default();
    let mut signature = vec![0; P::SIGNATURE_SIZE];
    let result = match test.get("msg") {
        Some(message) => {
            let message = hex(message.as_str());
            MLDSA::<P>::prefix(0, &context).and_then(|prefix| {
                let mu = MLDSA::<P>::message_representative(&public, &[&prefix, &context, &message]);
                assert_eq!(mu.to_vec(), test.bytes("mu"));
                MLDSA::<P>::sign_internal(&key, &[&prefix, &context, &message], &rnd, &mut signature)?;
                MLDSA::<P>::verify_with_context(&public, &message, &context, &signature)
            })
        }
        None => MLDSA::<P>::sign_mu(&key, &array(&test.bytes("mu")), &rnd, &mut signature),
    };
    if valid {
        result.unwrap();
        assert_eq!(signature, test.bytes("sig"), "tcId {:?}", test.field("tcId"));
        MLDSA::<P>::verify_mu(&public, &array(&test.bytes("mu")), &signature).unwrap();
    } else {
        assert_eq!(result, Err(CryptoError::InvalidParameter), "tcId {:?}", test.field("tcId"));
    }
}

/// mldsa_*_verify_test.json.
fn check_wycheproof_verification<P: MLDSAParameters>(group: &Json, test: &Json) {
    let context = test.get("ctx").map(|context| hex(context.as_str())).unwrap_or_default();
    let result = MLDSA::<P>::verifying_key_from_bytes(&group.bytes("publicKey"))
        .and_then(|key| MLDSA::<P>::verify_with_context(&key, &test.bytes("msg"), &context, &test.bytes("sig")));
    assert_eq!(result.is_ok(), Wycheproof::valid(test), "tcId {:?}: {result:?}", test.field("tcId"));
}

fn hex(text: &str) -> Vec<u8> {
    Vectors::hex(text)
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn mldsa_wycheproof() {
    for size in ["44", "65", "87"] {
        let name = format!("ML-DSA-{size}");
        for file in ["sign_seed", "sign_noseed"] {
            let tests = Wycheproof::tests(&format!("crypto/mldsa/mldsa_{size}_{file}_test.json"));
            assert!(!tests.is_empty());
            for (group, test) in &tests {
                with_parameters!(name.as_str(), check_wycheproof_signing(group, test));
            }
        }
        let tests = Wycheproof::tests(&format!("crypto/mldsa/mldsa_{size}_verify_test.json"));
        assert!(!tests.is_empty());
        for (group, test) in &tests {
            with_parameters!(name.as_str(), check_wycheproof_verification(group, test));
        }
    }
}

/// What every parameter set must do: keys survive their encodings and
/// seeds, hedged signatures differ and verify, and contexts, lengths and
/// changed bits are refused (FIPS 204 sections 5 and 6).
fn check_scheme<P: MLDSAParameters>() {
    let mut random = HMACDRBG::<SHA256>::new(&[3; 32], &[4; 16], P::NAME.as_bytes()).unwrap();
    let key = MLDSA::<P>::generate(&mut random).unwrap();
    let public = MLDSA::<P>::verifying_key(&key);
    let mut seed = [0; 32];
    MLDSA::<P>::write_seed(&key, &mut seed).unwrap();
    assert_eq!(signing_key::<P>(&MLDSA::<P>::signing_key_from_seed(&seed).unwrap()), signing_key::<P>(&key));
    let decoded = MLDSA::<P>::signing_key_from_bytes(&signing_key::<P>(&key)).unwrap();
    assert_eq!(MLDSA::<P>::write_seed(&decoded, &mut seed), Err(CryptoError::InvalidKey));

    let (mut first, mut second) = (vec![0; P::SIGNATURE_SIZE], vec![0; P::SIGNATURE_SIZE]);
    MLDSA::<P>::sign_with_context(&key, b"message", b"context", &mut random, &mut first).unwrap();
    MLDSA::<P>::sign_with_context(&key, b"message", b"context", &mut random, &mut second).unwrap();
    assert_ne!(first, second);
    MLDSA::<P>::verify_with_context(&public, b"message", b"context", &first).unwrap();
    MLDSA::<P>::verify_with_context(&public, b"message", b"context", &second).unwrap();
    let invalid = Err(CryptoError::InvalidSignature);
    assert_eq!(MLDSA::<P>::verify_with_context(&public, b"message", b"other", &first), invalid);
    assert_eq!(MLDSA::<P>::verify_with_context(&public, b"massage", b"context", &first), invalid);
    // A signature of HashML-DSA is not one of ML-DSA.
    MLDSA::<P>::sign_pre_hash::<SHA512, _>(&key, b"message", b"context", &mut random, &mut first).unwrap();
    MLDSA::<P>::verify_pre_hash::<SHA512>(&public, b"message", b"context", &first).unwrap();
    assert_eq!(MLDSA::<P>::verify_with_context(&public, b"message", b"context", &first), invalid);
    assert_eq!(MLDSA::<P>::verify_pre_hash::<SHA256>(&public, b"message", b"context", &first), invalid);
    // The deterministic signature of SignatureScheme uses the empty context.
    MLDSA::<P>::sign_deterministic_with_context(&key, b"message", b"", &mut second).unwrap();
    let mut through_trait = vec![0; P::SIGNATURE_SIZE];
    <MLDSA<P> as SignatureScheme>::sign(&key, b"message", &mut through_trait).unwrap();
    assert_eq!(second, through_trait);
    <MLDSA<P> as SignatureScheme>::verify(&public, b"message", &second).unwrap();
    for index in [0, P::CHALLENGE_SIZE, P::SIGNATURE_SIZE - P::OMEGA - P::K - 1, P::SIGNATURE_SIZE - 1] {
        let mut changed = second.clone();
        changed[index] ^= 1;
        assert_eq!(<MLDSA<P> as SignatureScheme>::verify(&public, b"message", &changed), invalid);
    }
    // Contexts of at most 255 bytes.
    let long = [0u8; 256];
    assert_eq!(
        MLDSA::<P>::sign_deterministic_with_context(&key, b"message", &long, &mut second),
        Err(CryptoError::InvalidParameter)
    );
    assert_eq!(
        MLDSA::<P>::verify_with_context(&public, b"message", &long, &second),
        Err(CryptoError::InvalidParameter)
    );
    MLDSA::<P>::sign_deterministic_with_context(&key, b"message", &long[..255], &mut second).unwrap();
    MLDSA::<P>::verify_with_context(&public, b"message", &long[..255], &second).unwrap();
    // Lengths.
    assert_eq!(MLDSA::<P>::verify_with_context(&public, b"message", b"", &second[1..]), invalid);
    assert_eq!(
        MLDSA::<P>::sign_deterministic_with_context(&key, b"message", b"", &mut second[1..]),
        Err(CryptoError::InputLength { length: P::SIGNATURE_SIZE - 1 })
    );
    for length in [0, P::PUBLIC_KEY_SIZE - 1, P::PUBLIC_KEY_SIZE + 1] {
        assert_eq!(MLDSA::<P>::verifying_key_from_bytes(&vec![0; length]).err(), Some(CryptoError::InvalidKey));
    }
    for length in [0, P::PRIVATE_KEY_SIZE - 1, P::PRIVATE_KEY_SIZE + 1] {
        assert_eq!(MLDSA::<P>::signing_key_from_bytes(&vec![0; length]).err(), Some(CryptoError::InvalidKey));
    }
    // A private key whose tr is not the hash of its public key.
    let mut corrupted = signing_key::<P>(&key);
    corrupted[64] ^= 1;
    assert_eq!(MLDSA::<P>::signing_key_from_bytes(&corrupted).err(), Some(CryptoError::InvalidKey));
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn mldsa_parameter_sets() {
    for (sizes, expected) in [
        ([MLDSA44::PUBLIC_KEY_SIZE, MLDSA44::PRIVATE_KEY_SIZE, MLDSA44::SIGNATURE_SIZE], [1312, 2560, 2420]),
        ([MLDSA65::PUBLIC_KEY_SIZE, MLDSA65::PRIVATE_KEY_SIZE, MLDSA65::SIGNATURE_SIZE], [1952, 4032, 3309]),
        ([MLDSA87::PUBLIC_KEY_SIZE, MLDSA87::PRIVATE_KEY_SIZE, MLDSA87::SIGNATURE_SIZE], [2592, 4896, 4627]),
    ] {
        assert_eq!(sizes, expected);
    }
    check_scheme::<MLDSA44>();
    check_scheme::<MLDSA65>();
    check_scheme::<MLDSA87>();
}
