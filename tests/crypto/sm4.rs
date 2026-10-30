//! SM4 against draft-ribose-cfrg-sm4 (with the examples of GB/T 32907-2016) and Project Wycheproof.

use umilib::crypto::mode::cbc::CBC;
use umilib::crypto::mode::cfb::CFB;
use umilib::crypto::mode::ctr::CTR;
use umilib::crypto::mode::ecb::ECB;
use umilib::crypto::mode::ofb::OFB;
use umilib::crypto::sm4::SM4;
use umilib::crypto::{BlockCipher, KeyInit, StreamCipher};

use crate::{Record, wycheproof};

const VECTORS: &str = "crypto/sm4/draft-ribose-cfrg-sm4.txt";

fn words(record: &Record, name: &str) -> Vec<u32> {
    record.field(name).split(',').map(|word| u32::from_str_radix(word, 16).unwrap()).collect()
}

#[test]
fn sm4_follows_the_constants_of_the_specification() {
    let record = Record::all(VECTORS).into_iter().find(|record| record.field("Name") == "Constants").unwrap();
    assert_eq!(SM4::FAMILY_KEY.to_vec(), words(&record, "FamilyKey"));
    assert_eq!((0..32).map(SM4::constant_key).collect::<Vec<_>>(), words(&record, "ConstantKey"));
    assert_eq!(SM4::SBOX.get(record.bytes("SBoxInput")[0] as usize), record.bytes("SBoxOutput")[0] as u32);
    // The S-box is a permutation of the bytes.
    let mut seen = [false; 256];
    for index in 0..256 {
        seen[SM4::SBOX.get(index) as usize] = true;
    }
    assert!(seen.iter().all(|&seen| seen));
}

#[test]
fn sm4_follows_the_examples_of_the_specification() {
    let mut checked = 0;
    for record in
        Record::all(VECTORS).iter().filter(|record| record.field("Mode") == "SM4" && record.get("Key").is_some())
    {
        let name = record.field("Name");
        let key: [u8; 16] = record.bytes("Key").try_into().unwrap();
        let sm4 = SM4::new(&key);
        if record.get("RoundKeys").is_some() {
            assert_eq!(sm4.round_keys().to_vec(), words(record, "RoundKeys"), "{name}");
        }
        let iterations: usize = record.get("Iterations").map_or(1, |value| value.parse().unwrap());
        let (plaintext, ciphertext): ([u8; 16], [u8; 16]) =
            (record.bytes("Plaintext").try_into().unwrap(), record.bytes("Ciphertext").try_into().unwrap());
        if record.get("RoundOutputs").is_some() {
            // X_4 to X_35 of the rounds, from the definition of section 7.1.
            let mut x: Vec<u32> =
                plaintext.chunks(4).map(|word| u32::from_be_bytes(word.try_into().unwrap())).collect();
            for (index, key) in sm4.round_keys().iter().enumerate() {
                let next = x[index] ^ SM4::transform(x[index + 1] ^ x[index + 2] ^ x[index + 3] ^ key);
                x.push(next);
            }
            assert_eq!(x[4..].to_vec(), words(record, "RoundOutputs"), "{name}");
        }
        let mut block = plaintext;
        for _ in 0..iterations {
            sm4.encrypt_block(&mut block);
        }
        assert_eq!(block, ciphertext, "{name}");
        if iterations == 1 {
            sm4.decrypt_block(&mut block);
            assert_eq!(block, plaintext, "{name}");
        }
        checked += 1;
    }
    assert_eq!(checked, 6);
}

#[test]
fn sm4_follows_the_mode_examples_of_the_specification() {
    let mut checked = 0;
    for record in Record::all(VECTORS).iter().filter(|record| record.field("Mode").starts_with("SM4-")) {
        let label = format!("{} {}", record.field("Mode"), record.field("Name"));
        let sm4 = SM4::new_from_slice(&record.bytes("Key")).unwrap();
        let (plaintext, ciphertext) = (record.bytes("Plaintext"), record.bytes("Ciphertext"));
        let iv: Option<[u8; 16]> = record.get("IV").map(|_| record.bytes("IV").try_into().unwrap());
        let (mut encrypted, mut decrypted) = (plaintext.clone(), ciphertext.clone());
        match record.field("Mode") {
            "SM4-ECB" => {
                let ecb = ECB::new(sm4);
                ecb.encrypt(&mut encrypted).unwrap();
                ecb.decrypt(&mut decrypted).unwrap();
            }
            "SM4-CBC" => {
                CBC::new(sm4.clone(), &iv.unwrap()).encrypt(&mut encrypted).unwrap();
                CBC::new(sm4, &iv.unwrap()).decrypt(&mut decrypted).unwrap();
            }
            "SM4-OFB" => {
                OFB::new(sm4.clone(), &iv.unwrap()).apply(&mut encrypted);
                OFB::new(sm4, &iv.unwrap()).apply(&mut decrypted);
            }
            "SM4-CFB" => {
                CFB::new(sm4.clone(), &iv.unwrap()).encrypt(&mut encrypted);
                CFB::new(sm4, &iv.unwrap()).decrypt(&mut decrypted);
            }
            "SM4-CTR" => {
                CTR::new(sm4.clone(), &iv.unwrap()).apply_keystream(&mut encrypted).unwrap();
                CTR::new(sm4, &iv.unwrap()).apply_keystream(&mut decrypted).unwrap();
            }
            mode => panic!("{mode}"),
        }
        assert_eq!(encrypted, ciphertext, "{label}");
        assert_eq!(decrypted, plaintext, "{label}");
        checked += 1;
    }
    assert_eq!(checked, 10);
}

#[test]
fn sm4_follows_the_wycheproof_vectors() {
    assert_eq!(wycheproof!("crypto/sm4/sm4_gcm_test.json", gcm, { 16 => SM4 }), 104);
    assert!(wycheproof!("crypto/sm4/sm4_ccm_test.json", ccm, { 16 => SM4 }) > 100);
}

#[test]
fn sm4_rejects_other_key_lengths() {
    assert!(SM4::new_from_slice(&[0; 15]).is_err());
    assert!(SM4::new_from_slice(&[0; 32]).is_err());
    // Several blocks give the results of one block each.
    let sm4 = SM4::new(&[9; 16]);
    let mut blocks = [[1u8; 16], [2u8; 16], [3u8; 16]];
    let mut single = blocks;
    sm4.encrypt_blocks(&mut blocks);
    single.iter_mut().for_each(|block| sm4.encrypt_block(block));
    assert_eq!(blocks, single);
}
