//! SLH-DSA (FIPS 205) against the ACVP vectors of NIST (key generation of
//! every parameter set, and signature generation and verification through
//! the pure, pre-hash and internal interfaces), and the requirements of
//! FIPS 205 on keys, contexts and signatures.

use umilib::crypto::random::HMACDRBG;
use umilib::crypto::slhdsa::{
    SLHDSA, SLHDSA_SHA2_128f, SLHDSA_SHA2_128s, SLHDSA_SHA2_192f, SLHDSA_SHA2_192s, SLHDSA_SHA2_256f, SLHDSA_SHA2_256s,
    SLHDSA_SHAKE_128f, SLHDSA_SHAKE_128s, SLHDSA_SHAKE_192f, SLHDSA_SHAKE_192s, SLHDSA_SHAKE_256f, SLHDSA_SHAKE_256s,
    SLHDSAParameters,
};
use umilib::crypto::{CryptoError, PreHash, SignatureScheme};
use umilib::hash::sha::v2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use umilib::hash::sha::v3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};

use crate::JSON;

/// Calls `$check::<P>($arguments)` for the parameter set named `$name`.
macro_rules! with_parameters {
    ($name:expr, $check:ident($($argument:expr),*)) => {
        match $name {
            "SLH-DSA-SHA2-128s" => $check::<SLHDSA_SHA2_128s>($($argument),*),
            "SLH-DSA-SHAKE-128s" => $check::<SLHDSA_SHAKE_128s>($($argument),*),
            "SLH-DSA-SHA2-128f" => $check::<SLHDSA_SHA2_128f>($($argument),*),
            "SLH-DSA-SHAKE-128f" => $check::<SLHDSA_SHAKE_128f>($($argument),*),
            "SLH-DSA-SHA2-192s" => $check::<SLHDSA_SHA2_192s>($($argument),*),
            "SLH-DSA-SHAKE-192s" => $check::<SLHDSA_SHAKE_192s>($($argument),*),
            "SLH-DSA-SHA2-192f" => $check::<SLHDSA_SHA2_192f>($($argument),*),
            "SLH-DSA-SHAKE-192f" => $check::<SLHDSA_SHAKE_192f>($($argument),*),
            "SLH-DSA-SHA2-256s" => $check::<SLHDSA_SHA2_256s>($($argument),*),
            "SLH-DSA-SHAKE-256s" => $check::<SLHDSA_SHAKE_256s>($($argument),*),
            "SLH-DSA-SHA2-256f" => $check::<SLHDSA_SHA2_256f>($($argument),*),
            "SLH-DSA-SHAKE-256f" => $check::<SLHDSA_SHAKE_256f>($($argument),*),
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

fn signing_key<P: SLHDSAParameters>(key: &<SLHDSA<P> as SignatureScheme>::SigningKey) -> Vec<u8> {
    let mut out = vec![0; P::PRIVATE_KEY_SIZE];
    SLHDSA::<P>::write_signing_key(key, &mut out).unwrap();
    out
}

fn verifying_key<P: SLHDSAParameters>(key: &<SLHDSA<P> as SignatureScheme>::VerifyingKey) -> Vec<u8> {
    let mut out = vec![0; P::PUBLIC_KEY_SIZE];
    SLHDSA::<P>::write_verifying_key(key, &mut out).unwrap();
    out
}

fn check_key_gen<P: SLHDSAParameters>(test: &JSON) {
    let key =
        SLHDSA::<P>::key_gen_internal(&test.bytes("skSeed"), &test.bytes("skPrf"), &test.bytes("pkSeed")).unwrap();
    assert_eq!(signing_key::<P>(&key), test.bytes("sk"));
    assert_eq!(verifying_key::<P>(&SLHDSA::<P>::verifying_key(&key)), test.bytes("pk"));
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn slhdsa_acvp_key_generation() {
    let vectors = JSON::read("crypto/slhdsa/acvp-keygen.json");
    let mut count = 0;
    for group in vectors.field("testGroups").items() {
        for test in group.field("tests").items() {
            with_parameters!(group.field("parameterSet").as_str(), check_key_gen(test));
            count += 1;
        }
    }
    assert_eq!(count, 120);
}

fn sign_pre_hash<P: SLHDSAParameters, H: PreHash>(
    key: &<SLHDSA<P> as SignatureScheme>::SigningKey,
    message: &[u8],
    context: &[u8],
    additional: Option<&[u8]>,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    SLHDSA::<P>::sign_pre_hash_with_additional::<H>(key, message, context, additional, out)
}

fn verify_pre_hash<P: SLHDSAParameters, H: PreHash>(
    key: &<SLHDSA<P> as SignatureScheme>::VerifyingKey,
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    SLHDSA::<P>::verify_pre_hash::<H>(key, message, context, signature)
}

fn check_signature_generation<P: SLHDSAParameters>(group: &JSON, test: &JSON) {
    let key = SLHDSA::<P>::signing_key_from_bytes(&test.bytes("sk")).unwrap();
    assert_eq!(verifying_key::<P>(&SLHDSA::<P>::verifying_key(&key)), test.bytes("pk"));
    let additional = match group.field("deterministic") {
        JSON::Bool(true) => None,
        _ => Some(test.bytes("additionalRandomness")),
    };
    let additional = additional.as_deref();
    let message = test.bytes("message");
    let mut signature = vec![0; P::SIGNATURE_SIZE];
    match (group.field("signatureInterface").as_str(), group.field("preHash").as_str()) {
        ("internal", _) => SLHDSA::<P>::sign_internal(&key, &[&message], additional, &mut signature).unwrap(),
        (_, "pure") => {
            let context = test.bytes("context");
            let prefix = SLHDSA::<P>::prefix(0, &context).unwrap();
            SLHDSA::<P>::sign_internal(&key, &[&prefix, &context, &message], additional, &mut signature).unwrap();
        }
        _ => {
            let context = test.bytes("context");
            with_pre_hash!(
                test.field("hashAlg").as_str(),
                sign_pre_hash::<P>(&key, &message, &context, additional, &mut signature)
            )
            .unwrap();
        }
    }
    assert_eq!(signature, test.bytes("signature"), "tcId {:?}", test.field("tcId"));
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn slhdsa_acvp_signature_generation() {
    let vectors = JSON::read("crypto/slhdsa/acvp-siggen-subset.json");
    let mut count = 0;
    for group in vectors.field("testGroups").items() {
        for test in group.field("tests").items() {
            with_parameters!(group.field("parameterSet").as_str(), check_signature_generation(group, test));
            count += 1;
        }
    }
    assert_eq!(count, 72);
}

fn check_signature_verification<P: SLHDSAParameters>(group: &JSON, test: &JSON) {
    let key = SLHDSA::<P>::verifying_key_from_bytes(&test.bytes("pk")).unwrap();
    let (message, signature) = (test.bytes("message"), test.bytes("signature"));
    let result = match (group.field("signatureInterface").as_str(), group.field("preHash").as_str()) {
        ("internal", _) => SLHDSA::<P>::verify_internal(&key, &[&message], &signature),
        (_, "pure") => SLHDSA::<P>::verify_with_context(&key, &message, &test.bytes("context"), &signature),
        _ => {
            let context = test.bytes("context");
            with_pre_hash!(test.field("hashAlg").as_str(), verify_pre_hash::<P>(&key, &message, &context, &signature))
        }
    };
    let passed = matches!(test.field("testPassed"), JSON::Bool(true));
    assert_eq!(result.is_ok(), passed, "tcId {:?}", test.field("tcId"));
    if !passed {
        assert_eq!(result, Err(CryptoError::InvalidSignature));
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn slhdsa_acvp_signature_verification() {
    let vectors = JSON::read("crypto/slhdsa/acvp-sigver-subset.json");
    let mut count = 0;
    for group in vectors.field("testGroups").items() {
        for test in group.field("tests").items() {
            with_parameters!(group.field("parameterSet").as_str(), check_signature_verification(group, test));
            count += 1;
        }
    }
    assert_eq!(count, 72);
}

/// What every parameter set must do: keys survive their encodings, the
/// deterministic and hedged signatures verify, and contexts, lengths,
/// changed bits and other roots are refused (FIPS 205 sections 3.1, 9 and 10).
fn check_scheme<P: SLHDSAParameters>() {
    let mut random = HMACDRBG::<SHA256>::new(&[5; 32], &[6; 16], P::NAME.as_bytes()).unwrap();
    let key = SLHDSA::<P>::generate(&mut random).unwrap();
    let public = SLHDSA::<P>::verifying_key(&key);
    let encoded = signing_key::<P>(&key);
    assert_eq!(signing_key::<P>(&SLHDSA::<P>::signing_key_from_bytes(&encoded).unwrap()), encoded);
    let mut other_root = encoded.clone();
    other_root[P::PRIVATE_KEY_SIZE - 1] ^= 1;
    assert_eq!(SLHDSA::<P>::signing_key_from_bytes(&other_root).err(), Some(CryptoError::InvalidKey));

    let (mut first, mut second) = (vec![0; P::SIGNATURE_SIZE], vec![0; P::SIGNATURE_SIZE]);
    SLHDSA::<P>::sign_with_context(&key, b"message", b"context", &mut random, &mut first).unwrap();
    SLHDSA::<P>::verify_with_context(&public, b"message", b"context", &first).unwrap();
    let invalid = Err(CryptoError::InvalidSignature);
    assert_eq!(SLHDSA::<P>::verify_with_context(&public, b"message", b"other", &first), invalid);
    <SLHDSA<P> as SignatureScheme>::sign(&key, b"message", &mut second).unwrap();
    SLHDSA::<P>::sign_deterministic_with_context(&key, b"message", b"", &mut first).unwrap();
    assert_eq!(first, second);
    <SLHDSA<P> as SignatureScheme>::verify(&public, b"message", &second).unwrap();
    for index in [0, P::N, P::N + P::FORS_SIGNATURE_SIZE, P::SIGNATURE_SIZE - 1] {
        let mut changed = second.clone();
        changed[index] ^= 1;
        assert_eq!(<SLHDSA<P> as SignatureScheme>::verify(&public, b"message", &changed), invalid);
    }
    assert_eq!(<SLHDSA<P> as SignatureScheme>::verify(&public, b"message", &second[1..]), invalid);
    // A signature of HashSLH-DSA is not one of SLH-DSA.
    SLHDSA::<P>::sign_pre_hash_deterministic::<SHAKE256>(&key, b"message", b"", &mut first).unwrap();
    SLHDSA::<P>::verify_pre_hash::<SHAKE256>(&public, b"message", b"", &first).unwrap();
    assert_eq!(<SLHDSA<P> as SignatureScheme>::verify(&public, b"message", &first), invalid);
    let long = [0u8; 256];
    assert_eq!(
        SLHDSA::<P>::sign_deterministic_with_context(&key, b"message", &long, &mut first),
        Err(CryptoError::InvalidParameter)
    );
    assert_eq!(
        SLHDSA::<P>::verify_with_context(&public, b"message", &long, &first),
        Err(CryptoError::InvalidParameter)
    );
    for length in [0, P::PUBLIC_KEY_SIZE - 1, P::PUBLIC_KEY_SIZE + 1] {
        assert_eq!(SLHDSA::<P>::verifying_key_from_bytes(&vec![0; length]).err(), Some(CryptoError::InvalidKey));
    }
    for length in [0, P::PRIVATE_KEY_SIZE - 1, P::PRIVATE_KEY_SIZE + 1] {
        assert_eq!(SLHDSA::<P>::signing_key_from_bytes(&vec![0; length]).err(), Some(CryptoError::InvalidKey));
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn slhdsa_parameter_sets() {
    let sizes = [
        (SLHDSA_SHA2_128s::PUBLIC_KEY_SIZE, SLHDSA_SHA2_128s::SIGNATURE_SIZE, 32, 7856),
        (SLHDSA_SHAKE_128f::PUBLIC_KEY_SIZE, SLHDSA_SHAKE_128f::SIGNATURE_SIZE, 32, 17088),
        (SLHDSA_SHA2_192s::PUBLIC_KEY_SIZE, SLHDSA_SHA2_192s::SIGNATURE_SIZE, 48, 16224),
        (SLHDSA_SHAKE_192f::PUBLIC_KEY_SIZE, SLHDSA_SHAKE_192f::SIGNATURE_SIZE, 48, 35664),
        (SLHDSA_SHA2_256s::PUBLIC_KEY_SIZE, SLHDSA_SHA2_256s::SIGNATURE_SIZE, 64, 29792),
        (SLHDSA_SHAKE_256f::PUBLIC_KEY_SIZE, SLHDSA_SHAKE_256f::SIGNATURE_SIZE, 64, 49856),
    ];
    for (public, signature, expected_public, expected_signature) in sizes {
        assert_eq!((public, signature), (expected_public, expected_signature));
    }
    assert_eq!([SLHDSA_SHA2_128s::M, SLHDSA_SHA2_128f::M, SLHDSA_SHA2_192s::M], [30, 34, 39]);
    assert_eq!([SLHDSA_SHA2_192f::M, SLHDSA_SHA2_256s::M, SLHDSA_SHA2_256f::M], [42, 47, 49]);
    assert_eq!(SLHDSA_SHA2_128s::LEN, 35);
    // The fast parameter sets sign quickly enough to check every family.
    check_scheme::<SLHDSA_SHA2_128f>();
    check_scheme::<SLHDSA_SHAKE_128f>();
    check_scheme::<SLHDSA_SHA2_192f>();
    check_scheme::<SLHDSA_SHAKE_256f>();
}
