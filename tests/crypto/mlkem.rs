//! ML-KEM (FIPS 203) against the ACVP vectors of NIST (key generation,
//! encapsulation, decapsulation and the checks of sections 7.2 and 7.3)
//! and Project Wycheproof, and the requirements of section 7 on keys,
//! ciphertexts and implicit rejection.

use umilib::crypto::mlkem::{MLKEM, MLKEM512, MLKEM768, MLKEM1024, MLKEMParameters};
use umilib::crypto::random::HMACDRBG;
use umilib::crypto::{CryptoError, KeyEncapsulation};
use umilib::hash::sha::v2::SHA256;

use crate::{Json, Wycheproof};

/// Calls `$check::<P>($arguments)` for the parameter set named `$name`.
macro_rules! with_parameters {
    ($name:expr, $check:ident($($argument:expr),*)) => {
        match $name {
            "ML-KEM-512" => $check::<MLKEM512>($($argument),*),
            "ML-KEM-768" => $check::<MLKEM768>($($argument),*),
            "ML-KEM-1024" => $check::<MLKEM1024>($($argument),*),
            other => panic!("unknown parameter set {other}"),
        }
    };
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().unwrap()
}

fn encapsulation_key<P: MLKEMParameters>(key: &<MLKEM<P> as KeyEncapsulation>::EncapsulationKey) -> Vec<u8> {
    let mut out = vec![0; P::ENCAPSULATION_KEY_SIZE];
    MLKEM::<P>::write_encapsulation_key(key, &mut out).unwrap();
    out
}

fn decapsulation_key<P: MLKEMParameters>(key: &<MLKEM<P> as KeyEncapsulation>::DecapsulationKey) -> Vec<u8> {
    let mut out = vec![0; P::DECAPSULATION_KEY_SIZE];
    MLKEM::<P>::write_decapsulation_key(key, &mut out).unwrap();
    out
}

/// K of the decapsulation of `ciphertext`, or the error of the first step that refuses the inputs.
fn decapsulate<P: MLKEMParameters>(dk: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = MLKEM::<P>::decapsulation_key_from_bytes(dk)?;
    let mut shared = vec![0; 32];
    MLKEM::<P>::decapsulate(&key, ciphertext, &mut shared)?;
    Ok(shared)
}

/// The ciphertext and K of the encapsulation with m, or the error of the check of ek.
fn encapsulate<P: MLKEMParameters>(ek: &[u8], m: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let key = MLKEM::<P>::encapsulation_key_from_bytes(ek)?;
    let (mut ciphertext, mut shared) = (vec![0; P::CIPHERTEXT_SIZE], vec![0; 32]);
    MLKEM::<P>::encapsulate_internal(&key, &array(m), &mut ciphertext, &mut shared)?;
    Ok((ciphertext, shared))
}

fn check_key_gen<P: MLKEMParameters>(test: &Json) {
    let key = MLKEM::<P>::key_gen_internal(&array(&test.bytes("d")), &array(&test.bytes("z")));
    assert_eq!(decapsulation_key::<P>(&key), test.bytes("dk"));
    assert_eq!(encapsulation_key::<P>(&MLKEM::<P>::encapsulation_key(&key)), test.bytes("ek"));
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn mlkem_acvp_key_generation() {
    let vectors = Json::read("crypto/mlkem/acvp-keygen.json");
    let mut count = 0;
    for group in vectors.field("testGroups").items() {
        for test in group.field("tests").items() {
            with_parameters!(group.field("parameterSet").as_str(), check_key_gen(test));
            count += 1;
        }
    }
    assert_eq!(count, 75);
}

fn check_acvp<P: MLKEMParameters>(function: &str, test: &Json) {
    match function {
        "encapsulation" => {
            let (ciphertext, shared) = encapsulate::<P>(&test.bytes("ek"), &test.bytes("m")).unwrap();
            assert_eq!(ciphertext, test.bytes("c"));
            assert_eq!(shared, test.bytes("k"));
            assert_eq!(decapsulate::<P>(&test.bytes("dk"), &ciphertext).unwrap(), shared);
        }
        "decapsulation" => assert_eq!(decapsulate::<P>(&test.bytes("dk"), &test.bytes("c")).unwrap(), test.bytes("k")),
        "decapsulationKeyCheck" => {
            let passed = matches!(test.field("testPassed"), Json::Bool(true));
            assert_eq!(MLKEM::<P>::decapsulation_key_from_bytes(&test.bytes("dk")).is_ok(), passed);
        }
        "encapsulationKeyCheck" => {
            let passed = matches!(test.field("testPassed"), Json::Bool(true));
            assert_eq!(MLKEM::<P>::encapsulation_key_from_bytes(&test.bytes("ek")).is_ok(), passed);
        }
        other => panic!("unknown function {other}"),
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn mlkem_acvp_encapsulation_and_decapsulation() {
    let vectors = Json::read("crypto/mlkem/acvp-encapdecap.json");
    let mut count = 0;
    for group in vectors.field("testGroups").items() {
        let function = group.field("function").as_str();
        for test in group.field("tests").items() {
            with_parameters!(group.field("parameterSet").as_str(), check_acvp(function, test));
            count += 1;
        }
    }
    assert_eq!(count, 75 + 30 + 60);
}

/// mlkem_*_test.json: a key from its seed d || z, its ek, and K of a ciphertext (implicit rejection
/// included); invalid tests have a seed or a ciphertext of another length.
fn check_wycheproof<P: MLKEMParameters>(test: &Json) {
    let valid = Wycheproof::valid(test);
    let key = match MLKEM::<P>::decapsulation_key_from_seed(&test.bytes("seed")) {
        Ok(key) => key,
        Err(error) => {
            assert!(!valid, "{test:?}");
            assert_eq!(error, CryptoError::InvalidKey);
            return;
        }
    };
    assert_eq!(encapsulation_key::<P>(&MLKEM::<P>::encapsulation_key(&key)), test.bytes("ek"));
    let mut shared = vec![0; 32];
    let result = MLKEM::<P>::decapsulate(&key, &test.bytes("c"), &mut shared);
    if valid {
        result.unwrap();
        assert_eq!(shared, test.bytes("K"));
    } else {
        assert_eq!(result, Err(CryptoError::InputLength { length: test.bytes("c").len() }));
    }
}

/// mlkem_*_encaps_test.json: encapsulation with m, or the modulus check of ek.
fn check_wycheproof_encapsulation<P: MLKEMParameters>(test: &Json) {
    match encapsulate::<P>(&test.bytes("ek"), &test.bytes("m")) {
        Ok((ciphertext, shared)) => {
            assert!(Wycheproof::valid(test), "{test:?}");
            assert_eq!(ciphertext, test.bytes("c"));
            assert_eq!(shared, test.bytes("K"));
        }
        Err(error) => {
            assert!(!Wycheproof::valid(test), "{test:?}");
            assert_eq!(error, CryptoError::InvalidKey);
        }
    }
}

/// mlkem_*_semi_expanded_decaps_test.json: decapsulation with an expanded key, checked first.
fn check_wycheproof_decapsulation<P: MLKEMParameters>(test: &Json) {
    match decapsulate::<P>(&test.bytes("dk"), &test.bytes("c")) {
        Ok(shared) => {
            assert!(Wycheproof::valid(test), "{test:?}");
            assert_eq!(shared, test.bytes("K"));
        }
        Err(_) => assert!(!Wycheproof::valid(test), "{test:?}"),
    }
}

/// mlkem_*_keygen_seed_test.json: the keys of a seed.
fn check_wycheproof_key_gen<P: MLKEMParameters>(test: &Json) {
    let key = MLKEM::<P>::decapsulation_key_from_seed(&test.bytes("seed")).unwrap();
    assert_eq!(decapsulation_key::<P>(&key), test.bytes("dk"));
    assert_eq!(encapsulation_key::<P>(&MLKEM::<P>::encapsulation_key(&key)), test.bytes("ek"));
    let mut seed = vec![0; 64];
    MLKEM::<P>::write_seed(&key, &mut seed).unwrap();
    assert_eq!(seed, test.bytes("seed"));
}

/// The check of a Wycheproof test of a parameter set named by its first argument.
type Check = fn(&str, &Json);

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn mlkem_wycheproof() {
    for size in ["512", "768", "1024"] {
        let files: [(&str, Check); 4] = [
            ("test", |name, test| with_parameters!(name, check_wycheproof(test))),
            ("encaps_test", |name, test| with_parameters!(name, check_wycheproof_encapsulation(test))),
            ("semi_expanded_decaps_test", |name, test| with_parameters!(name, check_wycheproof_decapsulation(test))),
            ("keygen_seed_test", |name, test| with_parameters!(name, check_wycheproof_key_gen(test))),
        ];
        for (file, check) in files {
            let tests = Wycheproof::tests(&format!("crypto/mlkem/mlkem_{size}_{file}.json"));
            assert!(!tests.is_empty());
            for (group, test) in &tests {
                check(group.field("parameterSet").as_str(), test);
            }
        }
    }
}

/// What every parameter set must do: keys survive their encodings, both
/// sides derive the same secret, a changed ciphertext gives J(z || c), and
/// inputs of other lengths are refused (FIPS 203 section 7).
fn check_scheme<P: MLKEMParameters>() {
    let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], P::NAME.as_bytes()).unwrap();
    let key = MLKEM::<P>::generate(&mut random).unwrap();
    let public = MLKEM::<P>::encapsulation_key(&key);
    let (mut ciphertext, mut sent, mut received) = (vec![0; P::CIPHERTEXT_SIZE], vec![0; 32], vec![0; 32]);
    MLKEM::<P>::encapsulate(&public, &mut random, &mut ciphertext, &mut sent).unwrap();
    MLKEM::<P>::decapsulate(&key, &ciphertext, &mut received).unwrap();
    assert_eq!(sent, received);

    let encoded = decapsulation_key::<P>(&key);
    let decoded = MLKEM::<P>::decapsulation_key_from_bytes(&encoded).unwrap();
    assert_eq!(decapsulation_key::<P>(&decoded), encoded);
    assert_eq!(MLKEM::<P>::encapsulation_key(&decoded), public);
    // A key read from its expanded encoding has no seed.
    assert_eq!(MLKEM::<P>::write_seed(&decoded, &mut [0; 64]), Err(CryptoError::InvalidKey));

    // Implicit rejection: K̄ = J(z || c) = SHAKE256(z || c, 32), z the last 32 bytes of dk.
    let mut changed = ciphertext.clone();
    changed[0] ^= 1;
    MLKEM::<P>::decapsulate(&key, &changed, &mut received).unwrap();
    let z = &encoded[P::DECAPSULATION_KEY_SIZE - 32..];
    let mut expected = vec![0; 32];
    <umilib::hash::sha::v3::SHAKE256 as umilib::hash::ExtendableOutput>::digest_xof(
        &[z, &changed].concat(),
        &mut expected,
    );
    assert_eq!(received, expected);

    // The hash check of dk and the lengths.
    let mut corrupted = encoded.clone();
    corrupted[384 * P::K] ^= 1;
    assert_eq!(MLKEM::<P>::decapsulation_key_from_bytes(&corrupted).err(), Some(CryptoError::InvalidKey));
    for length in [0, P::DECAPSULATION_KEY_SIZE - 1, P::DECAPSULATION_KEY_SIZE + 1] {
        assert_eq!(MLKEM::<P>::decapsulation_key_from_bytes(&vec![0; length]).err(), Some(CryptoError::InvalidKey));
    }
    for length in [0, P::ENCAPSULATION_KEY_SIZE - 1, P::ENCAPSULATION_KEY_SIZE + 1] {
        assert_eq!(MLKEM::<P>::encapsulation_key_from_bytes(&vec![0; length]).err(), Some(CryptoError::InvalidKey));
    }
    for length in [P::CIPHERTEXT_SIZE - 1, P::CIPHERTEXT_SIZE + 1] {
        let error = Some(CryptoError::InputLength { length });
        assert_eq!(MLKEM::<P>::decapsulate(&key, &vec![0; length], &mut received).err(), error);
        assert_eq!(MLKEM::<P>::encapsulate(&public, &mut random, &mut vec![0; length], &mut sent).err(), error);
    }
    assert_eq!(
        MLKEM::<P>::decapsulate(&key, &ciphertext, &mut [0; 31]).err(),
        Some(CryptoError::InputLength { length: 31 })
    );
    // The modulus check: a coefficient of q in t̂.
    let mut overflow = encapsulation_key::<P>(&public);
    overflow[0] = 0x01;
    overflow[1] = (overflow[1] & 0xF0) | 0x0D;
    assert_eq!(MLKEM::<P>::encapsulation_key_from_bytes(&overflow).err(), Some(CryptoError::InvalidKey));
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn mlkem_parameter_sets() {
    assert_eq!(
        [MLKEM512::ENCAPSULATION_KEY_SIZE, MLKEM512::DECAPSULATION_KEY_SIZE, MLKEM512::CIPHERTEXT_SIZE],
        [800, 1632, 768]
    );
    assert_eq!(
        [MLKEM768::ENCAPSULATION_KEY_SIZE, MLKEM768::DECAPSULATION_KEY_SIZE, MLKEM768::CIPHERTEXT_SIZE],
        [1184, 2400, 1088]
    );
    assert_eq!(
        [MLKEM1024::ENCAPSULATION_KEY_SIZE, MLKEM1024::DECAPSULATION_KEY_SIZE, MLKEM1024::CIPHERTEXT_SIZE],
        [1568, 3168, 1568]
    );
    check_scheme::<MLKEM512>();
    check_scheme::<MLKEM768>();
    check_scheme::<MLKEM1024>();
}
