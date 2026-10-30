//! AEGIS against draft-irtf-cfrg-aegis-aead-18 and Project Wycheproof.

use umilib::crypto::aegis::{AEGIS128X, AEGIS128XState, AEGIS256X, AEGIS256XState, AEGISMAC128X, AEGISMAC256X};
use umilib::crypto::aes::AESBitslice;
use umilib::crypto::{AEAD, CryptoError};

use crate::{Record, Vectors, Wycheproof};

const VECTORS: &str = "crypto/aegis/draft-irtf-cfrg-aegis-aead.txt";

fn block(record: &Record, name: &str) -> [u8; 16] {
    record.bytes(name).try_into().unwrap()
}

/// Encrypts and decrypts a vector with the AEAD `A`, or checks that a failing one fails and leaves zeros.
fn check<A: AEAD>(aead: &A, record: &Record, tag_name: &str, label: &str) {
    let (nonce, ad, ct, tag) = (record.bytes("nonce"), record.bytes("ad"), record.bytes("ct"), record.bytes(tag_name));
    let mut buffer = ct.clone();
    let result = aead.decrypt_in_place(&nonce, &ad, &mut buffer, &tag);
    if record.field("Result") == "fail" {
        assert_eq!(result, Err(CryptoError::AuthenticationFailed), "{label}");
        assert!(buffer.iter().all(|&byte| byte == 0), "{label}: a failed decryption leaves zeros");
        return;
    }
    assert_eq!(result, Ok(()), "{label}");
    let message = record.bytes("msg");
    assert_eq!(buffer, message, "{label}");
    let mut buffer = message;
    let computed = aead.encrypt_in_place(&nonce, &ad, &mut buffer).unwrap();
    assert_eq!(buffer, ct, "{label}");
    assert_eq!(computed.as_ref(), &tag[..], "{label}");
}

#[test]
fn aegis_round_and_updates_follow_the_draft() {
    let records = Record::all(VECTORS);
    let aes_round = records.iter().find(|record| record.field("Group") == "AESRound").unwrap();
    let mut blocks = [block(aes_round, "in")];
    AESBitslice::round(&mut blocks, &[block(aes_round, "rk")]);
    assert_eq!(blocks[0], block(aes_round, "out"));
    // A.2.1: the update of AEGIS-128L.
    let update = records
        .iter()
        .find(|record| record.field("Group") == "AEGIS-128L" && record.field("Name") == "Update")
        .unwrap();
    let lanes = [core::array::from_fn(|j| block(update, &format!("S{j}")))];
    let mut state = AEGIS128XState::<1>::from_lanes(lanes);
    state.update(&[block(update, "M0")], &[block(update, "M1")]);
    assert_eq!(state.lanes()[0], core::array::from_fn(|j| block(update, &format!("AfterS{j}"))));
    // A.3.1: the update of AEGIS-256.
    let update =
        records.iter().find(|record| record.field("Group") == "AEGIS-256" && record.field("Name") == "Update").unwrap();
    let lanes = [core::array::from_fn(|j| block(update, &format!("S{j}")))];
    let mut state = AEGIS256XState::<1>::from_lanes(lanes);
    state.update(&[block(update, "M")]);
    assert_eq!(state.lanes()[0], core::array::from_fn(|j| block(update, &format!("AfterS{j}"))));
}

#[test]
fn aegis_initial_states_follow_the_draft() {
    fn lanes<const D: usize, const N: usize>(record: &Record) -> [[[u8; 16]; N]; D] {
        core::array::from_fn(|i| core::array::from_fn(|j| block(record, &format!("AfterV{j}_{i}"))))
    }
    let mut checked = 0;
    for record in Record::all(VECTORS).iter().filter(|record| record.field("Name") == "Initial State") {
        let (key, nonce) = (record.bytes("key"), record.bytes("nonce"));
        match record.field("Group") {
            "AEGIS-128X2" => assert_eq!(
                *AEGIS128XState::<2>::new(&key[..].try_into().unwrap(), &nonce[..].try_into().unwrap()).lanes(),
                lanes::<2, 8>(record)
            ),
            "AEGIS-128X4" => assert_eq!(
                *AEGIS128XState::<4>::new(&key[..].try_into().unwrap(), &nonce[..].try_into().unwrap()).lanes(),
                lanes::<4, 8>(record)
            ),
            "AEGIS-256X2" => assert_eq!(
                *AEGIS256XState::<2>::new(&key[..].try_into().unwrap(), &nonce[..].try_into().unwrap()).lanes(),
                lanes::<2, 6>(record)
            ),
            "AEGIS-256X4" => assert_eq!(
                *AEGIS256XState::<4>::new(&key[..].try_into().unwrap(), &nonce[..].try_into().unwrap()).lanes(),
                lanes::<4, 6>(record)
            ),
            group => panic!("{group}"),
        }
        // The context separators of section 5.1.
        for lane in 0.. {
            let Some(context) = record.get(&format!("ctx{lane}")) else { break };
            let degree = record.field("Group").chars().last().unwrap().to_digit(10).unwrap() as usize;
            assert_eq!(umilib::crypto::aegis::AEGISComponents::context(lane, degree).to_vec(), Vectors::hex(context));
        }
        checked += 1;
    }
    assert_eq!(checked, 4);
}

#[test]
fn aegis_follows_the_test_vectors_of_the_draft() {
    let mut checked = 0;
    for record in Record::all(VECTORS).iter().filter(|record| record.field("Name").starts_with("Test Vector")) {
        let group = record.field("Group");
        let label = format!("{group} {}", record.field("Name"));
        let key = record.bytes("key");
        for tag in ["tag128", "tag256"] {
            macro_rules! run {
                ($aead:ident, $degree:literal, $key:literal) => {{
                    let key: [u8; $key] = key[..].try_into().unwrap();
                    if tag == "tag128" {
                        check(&$aead::<$degree, 16>::new(&key), record, tag, &label)
                    } else {
                        check(&$aead::<$degree, 32>::new(&key), record, tag, &label)
                    }
                }};
            }
            match group {
                "AEGIS-128L" => run!(AEGIS128X, 1, 16),
                "AEGIS-128X2" => run!(AEGIS128X, 2, 16),
                "AEGIS-128X4" => run!(AEGIS128X, 4, 16),
                "AEGIS-256" => run!(AEGIS256X, 1, 32),
                "AEGIS-256X2" => run!(AEGIS256X, 2, 32),
                "AEGIS-256X4" => run!(AEGIS256X, 4, 32),
                group => panic!("{group}"),
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 9 + 9 + 2 * 4);
}

#[test]
fn aegis_mac_follows_the_draft() {
    let mut checked = 0;
    for record in Record::all(VECTORS).iter().filter(|record| record.field("Group").starts_with("AEGISMAC")) {
        let group = record.field("Group");
        let (key, nonce, data) = (record.bytes("key"), record.bytes("nonce"), record.bytes("data"));
        macro_rules! run {
            ($mac:ident, $degree:literal, $key:literal) => {{
                let (key, nonce): ([u8; $key], [u8; $key]) =
                    (key[..].try_into().unwrap(), nonce[..].try_into().unwrap());
                assert_eq!($mac::<$degree, 16>::mac(&key, &nonce, &data).to_vec(), record.bytes("tag128"), "{group}");
                assert_eq!($mac::<$degree, 32>::mac(&key, &nonce, &data).to_vec(), record.bytes("tag256"), "{group}");
                // Pieces of any size give the same tag.
                let mut mac = $mac::<$degree, 16>::new(&key, &nonce);
                for piece in data.chunks(7) {
                    mac.update(piece);
                }
                assert_eq!(mac.finalize().to_vec(), record.bytes("tag128"), "{group}");
            }};
        }
        match group {
            "AEGISMAC-128L" => run!(AEGISMAC128X, 1, 16),
            "AEGISMAC-128X2" => run!(AEGISMAC128X, 2, 16),
            "AEGISMAC-128X4" => run!(AEGISMAC128X, 4, 16),
            "AEGISMAC-256" => run!(AEGISMAC256X, 1, 32),
            "AEGISMAC-256X2" => run!(AEGISMAC256X, 2, 32),
            "AEGISMAC-256X4" => run!(AEGISMAC256X, 4, 32),
            group => panic!("{group}"),
        }
        checked += 1;
    }
    assert_eq!(checked, 6);
}

#[test]
fn aegis_follows_the_wycheproof_vectors() {
    for (path, count) in [("crypto/aegis/aegis128L_test.json", 479), ("crypto/aegis/aegis256_test.json", 472)] {
        let tests = Wycheproof::tests(path);
        assert_eq!(tests.len(), count);
        for (_, test) in tests {
            let label = format!("{path} tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
            let (key, iv, aad, message, ciphertext, tag) = (
                test.bytes("key"),
                test.bytes("iv"),
                test.bytes("aad"),
                test.bytes("msg"),
                test.bytes("ct"),
                test.bytes("tag"),
            );
            let valid = test.field("result").as_str() == "valid";
            let mut decrypted = ciphertext.clone();
            let (result, encrypted) = if path.contains("128L") {
                let aead = AEGIS128X::<1, 16>::new(&key[..].try_into().unwrap());
                let mut buffer = message.clone();
                (
                    aead.decrypt_in_place(&iv, &aad, &mut decrypted, &tag),
                    aead.encrypt_in_place(&iv, &aad, &mut buffer).map(|tag| [buffer, tag.to_vec()].concat()),
                )
            } else {
                let aead = AEGIS256X::<1, 16>::new(&key[..].try_into().unwrap());
                let mut buffer = message.clone();
                (
                    aead.decrypt_in_place(&iv, &aad, &mut decrypted, &tag),
                    aead.encrypt_in_place(&iv, &aad, &mut buffer).map(|tag| [buffer, tag.to_vec()].concat()),
                )
            };
            if valid {
                assert_eq!(result, Ok(()), "{label}");
                assert_eq!(decrypted, message, "{label}");
                assert_eq!(encrypted, Ok([ciphertext, tag].concat()), "{label}");
            } else {
                assert!(result.is_err(), "{label}");
            }
        }
    }
}

#[test]
fn aegis_stream_is_the_encryption_of_zeros() {
    let (key, nonce) = ([3u8; 16], [4u8; 16]);
    let mut stream = [0xFFu8; 100];
    AEGIS128XState::<2>::stream(&key, &nonce, &mut stream);
    let mut zeros = [0u8; 100];
    AEGIS128X::<2, 16>::new(&key).encrypt_in_place(&nonce, &[], &mut zeros).unwrap();
    assert_eq!(stream, zeros);
    let mut buffer = [0u8; 4];
    assert!(matches!(
        AEGIS256X::<1, 32>::new(&[0; 32]).encrypt_in_place(&[0; 16], &[], &mut buffer),
        Err(CryptoError::NonceLength { .. })
    ));
}
