use umilib::crypto::random::*;
use umilib::hash::Digest;
use umilib::hash::sha::v1::SHA1;
use umilib::hash::sha::v2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};

use crate::Record;

/// The DRBGVS procedure (DRBGVS section 6) on one record: instantiate,
/// reseed or reseed before each request with prediction resistance, then two
/// requests, the second of which gives the returned bits. `drbg` was
/// instantiated with the `EntropyInput`, `Nonce` and `PersonalizationString`
/// of `record`.
fn check<D: DRBG>(mut drbg: D, record: &Record, label: &str) {
    let additional = record.values("AdditionalInput");
    assert_eq!(additional.len(), 2, "{label}");
    let expected = record.bytes("ReturnedBits");
    let bits: usize = record.header["ReturnedBitsLen"].parse().unwrap();
    assert_eq!(expected.len() * 8, bits);
    let mut out = vec![0u8; expected.len()];
    let prediction_resistance = record.header["PredictionResistance"] == "True";
    if let Some(entropy) = record.get("EntropyInputReseed") {
        let reseed = umilib_hex(record.field("AdditionalInputReseed"));
        drbg.reseed(&umilib_hex(entropy), &reseed).unwrap();
    }
    let entropy_pr = record.values("EntropyInputPR");
    for (index, input) in additional.iter().enumerate() {
        if prediction_resistance {
            drbg.reseed(&umilib_hex(entropy_pr[index]), &umilib_hex(input)).unwrap();
            drbg.generate(&mut out, &[]).unwrap();
        } else {
            drbg.generate(&mut out, &umilib_hex(input)).unwrap();
        }
    }
    assert_eq!(out, expected, "{label}");
}

fn umilib_hex(text: &str) -> Vec<u8> {
    crate::Vectors::hex(text)
}

fn run(name: &str) {
    for mode in ["no_reseed", "pr_false", "pr_true"] {
        let path = format!("crypto/random/{name}_{mode}.rsp");
        let records = Record::all(&path);
        assert!(records.len() >= 7 * 4 * 15, "{path}");
        for record in &records {
            let hash = record.header.keys().find(|key| key.starts_with("SHA-")).unwrap().as_str();
            let label = format!("{path} [{hash}] {:?} COUNT = {}", record.header, record.field("COUNT"));
            let (entropy, nonce, personalization) =
                (record.bytes("EntropyInput"), record.bytes("Nonce"), record.bytes("PersonalizationString"));
            macro_rules! dispatch {
                ($($label:literal => $hash:ty),*) => {
                    match (name, hash) {
                        $(("HMAC_DRBG", $label) => check(HMACDRBG::<$hash>::new(&entropy, &nonce, &personalization).unwrap(), record, &label),)*
                        $(("Hash_DRBG", $label) => check(HashDRBG::<$hash>::new(&entropy, &nonce, &personalization).unwrap(), record, &label),)*
                        other => panic!("unknown {other:?}"),
                    }
                };
            }
            dispatch!(
                "SHA-1" => SHA1, "SHA-224" => SHA224, "SHA-256" => SHA256, "SHA-384" => SHA384,
                "SHA-512" => SHA512, "SHA-512/224" => SHA512_224, "SHA-512/256" => SHA512_256
            );
        }
    }
}

/// CTR_DRBG over AES with and without the derivation function; the TDEA records are skipped.
#[cfg(umilib_feature = "crypto-aes")]
#[test]
fn ctr_drbg_follows_the_cavp_vectors() {
    use umilib::crypto::aes::{AES128, AES192, AES256};
    let mut checked = 0;
    for mode in ["no_reseed", "pr_false", "pr_true"] {
        let path = format!("crypto/random/CTR_DRBG_{mode}.rsp");
        for record in &Record::all(&path) {
            let group = record.header.keys().find(|key| key.contains(" df")).unwrap().as_str();
            if group.starts_with("3KeyTDEA") {
                continue;
            }
            let label = format!("{path} [{group}] COUNT = {}", record.field("COUNT"));
            let (entropy, nonce, personalization) =
                (record.bytes("EntropyInput"), record.bytes("Nonce"), record.bytes("PersonalizationString"));
            macro_rules! dispatch {
                ($cipher:ty) => {
                    if group.ends_with("use df") {
                        check(CTRDRBG::<$cipher>::new(&entropy, &nonce, &personalization).unwrap(), record, &label)
                    } else {
                        assert!(nonce.is_empty(), "{label}");
                        check(
                            CTRDRBG::<$cipher>::instantiate_without_derivation(
                                DRBGConfig::default(),
                                &entropy,
                                &personalization,
                            )
                            .unwrap(),
                            record,
                            &label,
                        )
                    }
                };
            }
            match &group[..7] {
                "AES-128" => dispatch!(AES128),
                "AES-192" => dispatch!(AES192),
                "AES-256" => dispatch!(AES256),
                other => panic!("{other}"),
            }
            checked += 1;
        }
    }
    // Each file holds 1920 records, 1440 of them with AES.
    assert_eq!(checked, 3 * 1440);
}

#[test]
fn hmac_drbg_follows_the_cavp_vectors() {
    run("HMAC_DRBG");
}

#[test]
fn hash_drbg_follows_the_cavp_vectors() {
    run("Hash_DRBG");
}

/// The security strengths and seed lengths of SP 800-90A table 2.
#[test]
fn drbg_parameters_follow_table_2() {
    assert_eq!(<HMACDRBG<SHA1> as DRBG>::SECURITY_STRENGTH, 128);
    assert_eq!(<HMACDRBG<SHA224> as DRBG>::SECURITY_STRENGTH, 192);
    assert_eq!(<HMACDRBG<SHA512_224> as DRBG>::SECURITY_STRENGTH, 192);
    assert_eq!(<HMACDRBG<SHA256> as DRBG>::SECURITY_STRENGTH, 256);
    assert_eq!(<HashDRBG<SHA512> as DRBG>::SECURITY_STRENGTH, 256);
    assert_eq!(HashDRBG::<SHA1>::SEED_SIZE * 8, 440);
    assert_eq!(HashDRBG::<SHA256>::SEED_SIZE * 8, 440);
    assert_eq!(HashDRBG::<SHA512_256>::SEED_SIZE * 8, 440);
    assert_eq!(HashDRBG::<SHA384>::SEED_SIZE * 8, 888);
    assert_eq!(HashDRBG::<SHA512>::SEED_SIZE * 8, 888);
    assert_eq!(DRBGConfig::default().reseed_interval, 1 << 48);
    assert_eq!(DRBGConfig::default().maximum_request * 8, 1 << 19);
}

#[test]
fn drbg_enforces_its_limits() {
    assert_eq!(
        HMACDRBG::<SHA256>::new(&[0; 31], &[0; 16], &[]).unwrap_err(),
        RandomError::EntropyLength { length: 31, minimum: 32 }
    );
    // Section 8.6.7: the nonce brings the entropy input to 3/2 of the security strength.
    assert_eq!(
        HashDRBG::<SHA256>::new(&[0; 32], &[], &[]).unwrap_err(),
        RandomError::NonceLength { length: 0, minimum: 16 }
    );
    assert_eq!(
        HashDRBG::<SHA256>::new(&[0; 32], &[0; 15], &[]).unwrap_err(),
        RandomError::NonceLength { length: 15, minimum: 16 }
    );
    assert!(HashDRBG::<SHA256>::new(&[0; 32], &[0; 16], &[]).is_ok());
    assert!(HashDRBG::<SHA256>::new(&[0; 48], &[], &[]).is_ok());
    assert!(HMACDRBG::<SHA1>::new(&[0; 16], &[0; 8], &[]).is_ok());
    let config = DRBGConfig { reseed_interval: 2, maximum_request: 100 };
    let mut drbg = HashDRBG::<SHA256>::with_config(config, &[1; 32], &[2; 16], b"test").unwrap();
    let mut out = [0u8; 101];
    assert_eq!(drbg.generate(&mut out, &[]), Err(RandomError::RequestLength { length: 101, maximum: 100 }));
    drbg.generate(&mut out[..100], &[]).unwrap();
    drbg.generate(&mut out[..100], &[]).unwrap();
    assert_eq!(drbg.generate(&mut out[..1], &[]), Err(RandomError::ReseedRequired));
    assert_eq!(drbg.reseed(&[3; 31], &[]), Err(RandomError::EntropyLength { length: 31, minimum: 32 }));
    drbg.reseed(&[3; 32], &[]).unwrap();
    drbg.generate(&mut out[..1], &[]).unwrap();
    // The default maximum request is 2^16 bytes (2^19 bits).
    let mut drbg = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], &[]).unwrap();
    let mut large = vec![0u8; (1 << 16) + 1];
    assert_eq!(
        drbg.generate(&mut large, &[]),
        Err(RandomError::RequestLength { length: (1 << 16) + 1, maximum: 1 << 16 })
    );
    drbg.generate(&mut large[..1 << 16], &[]).unwrap();
    // As a Random, a long request is split into requests of the maximum size.
    let config = DRBGConfig { reseed_interval: 100, maximum_request: 7 };
    let mut drbg = HMACDRBG::<SHA256>::with_config(config, &[1; 32], &[2; 16], &[]).unwrap();
    let mut long = [0u8; 50];
    drbg.fill(&mut long).unwrap();
    let mut pieces = HMACDRBG::<SHA256>::with_config(config, &[1; 32], &[2; 16], &[]).unwrap();
    let mut expected = [0u8; 50];
    for piece in expected.chunks_mut(7) {
        pieces.generate(piece, &[]).unwrap();
    }
    assert_eq!(long, expected);
    assert!(drbg.next_u64().is_ok());
    // A configuration is clamped to table 2.
    let loose = DRBGConfig { reseed_interval: u64::MAX, maximum_request: usize::MAX }.clamped();
    assert_eq!(loose, DRBGConfig::default());
    let _ = SHA256::digest(b"");
}

/// Section 9.4: an uninstantiated generator, also after `zeroize`, refuses every function.
#[test]
fn drbg_uninstantiation_erases_the_state() {
    use umilib::secret::Zeroize;
    let mut hmac = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], &[]).unwrap();
    let mut hash = HashDRBG::<SHA512>::new(&[1; 32], &[2; 16], &[]).unwrap();
    assert!(hmac.is_instantiated() && hash.is_instantiated());
    hmac.uninstantiate();
    hash.zeroize();
    let mut out = [0u8; 16];
    for result in [
        hmac.generate(&mut out, &[]),
        hmac.reseed(&[1; 32], &[]),
        hmac.fill(&mut out),
        hash.generate(&mut out, &[]),
        hash.reseed(&[1; 32], &[]),
        hash.fill(&mut out),
    ] {
        assert_eq!(result, Err(RandomError::Uninstantiated));
    }
    assert_eq!(out, [0; 16]);
    assert!(!hmac.is_instantiated() && !hash.is_instantiated());
    // Generic code instantiates through the trait.
    fn fresh<D: DRBG>() -> D {
        D::instantiate(DRBGConfig::default(), &[5; 32], &[6; 16], b"generic").unwrap()
    }
    let mut generic: HashDRBG<SHA256> = fresh();
    let mut direct = HashDRBG::<SHA256>::new(&[5; 32], &[6; 16], b"generic").unwrap();
    let (mut a, mut b) = ([0u8; 40], [0u8; 40]);
    generic.generate(&mut a, &[]).unwrap();
    direct.generate(&mut b, &[]).unwrap();
    assert_eq!(a, b);
}

#[test]
fn hash_drbg_arithmetic_is_modulo_the_seed_length() {
    let mut value = [0xFFu8; 55];
    HashDRBG::<SHA256>::add(&mut value, &[1]);
    assert_eq!(value, [0; 55]);
    let mut value = [0u8; 4];
    HashDRBG::<SHA256>::add(&mut value, &[9, 0, 0, 1, 2]);
    assert_eq!(value, [0, 0, 1, 2]);
    let mut value = [0, 0xFF, 0xFF];
    HashDRBG::<SHA256>::add(&mut value, &[1]);
    assert_eq!(value, [1, 0, 0]);
}

/// CTR_DRBG: table 3, the inputs without the derivation function (section 10.2.1.3.1), and uninstantiation.
#[cfg(umilib_feature = "crypto-aes")]
#[test]
fn ctr_drbg_follows_section_10_2() {
    use umilib::crypto::aes::{AES128, AES192, AES256};
    use umilib::secret::Zeroize;
    // Table 3: the security strength is the key length, seedlen = outlen + keylen.
    assert_eq!(<CTRDRBG<AES128> as DRBG>::SECURITY_STRENGTH, 128);
    assert_eq!(<CTRDRBG<AES192> as DRBG>::SECURITY_STRENGTH, 192);
    assert_eq!(<CTRDRBG<AES256> as DRBG>::SECURITY_STRENGTH, 256);
    assert_eq!(CTRDRBG::<AES128>::SEED_LENGTH * 8, 256);
    assert_eq!(CTRDRBG::<AES192>::SEED_LENGTH * 8, 320);
    assert_eq!(CTRDRBG::<AES256>::SEED_LENGTH * 8, 384);
    // Without a derivation function the entropy input is exactly seedlen bits.
    let config = DRBGConfig::default();
    assert_eq!(
        CTRDRBG::<AES128>::instantiate_without_derivation(config, &[0; 31], &[]).unwrap_err(),
        RandomError::EntropyLength { length: 31, minimum: 32 }
    );
    assert_eq!(
        CTRDRBG::<AES128>::instantiate_without_derivation(config, &[0; 32], &[0; 33]).unwrap_err(),
        RandomError::InputLength { length: 33, maximum: 32 }
    );
    let mut plain = CTRDRBG::<AES128>::instantiate_without_derivation(config, &[1; 32], &[2; 32]).unwrap();
    let mut out = [0u8; 16];
    assert!(matches!(plain.generate(&mut out, &[0; 33]), Err(RandomError::InputLength { .. })));
    assert_eq!(plain.reseed(&[1; 31], &[]), Err(RandomError::EntropyLength { length: 31, minimum: 32 }));
    plain.generate(&mut out, &[0; 32]).unwrap();
    // With the derivation function, the nonce rule of section 8.6.7 applies.
    assert_eq!(
        CTRDRBG::<AES256>::new(&[0; 32], &[0; 15], &[]).unwrap_err(),
        RandomError::NonceLength { length: 15, minimum: 16 }
    );
    let mut derived =
        CTRDRBG::<AES256>::new(&[0; 32], &[0; 16], b"personalization of any length, longer than seedlen bits").unwrap();
    derived.generate(&mut out, b"additional input of any length, longer than seedlen bits too").unwrap();
    derived.zeroize();
    assert_eq!(derived.generate(&mut out, &[]), Err(RandomError::Uninstantiated));
    // Section 10.3.2: Block_Cipher_df depends on the concatenation of its input only, and returns
    // at most 512 bits.
    let pieces: [&[u8]; 7] = [b"a", b"bc", b"", b"def", b"g", b"hijklmnopqrstuvwxyz", b"0123456789"];
    let (mut split, mut whole) = ([0u8; 48], [0u8; 48]);
    CTRDRBG::<AES256>::derive(&pieces, &mut split).unwrap();
    CTRDRBG::<AES256>::derive(&[&pieces.concat()], &mut whole).unwrap();
    assert_eq!(split, whole);
    assert!(matches!(CTRDRBG::<AES256>::derive(&pieces, &mut [0u8; 65]), Err(RandomError::RequestLength { .. })));
    assert!(!derived.is_instantiated());
}
