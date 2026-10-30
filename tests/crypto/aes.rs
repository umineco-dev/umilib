use umilib::crypto::aes::*;
use umilib::crypto::{BlockCipher, KeyInit};

use crate::field::GF256;
use crate::{Record, Vectors};

#[test]
fn the_sbox_follows_its_definition() {
    let mut blocks = [[0u8; 16]; 4];
    for (index, byte) in blocks.as_flattened_mut().iter_mut().enumerate() {
        *byte = index as u8;
    }
    for start in [0u8, 64, 128, 192] {
        let mut group = blocks;
        for byte in group.as_flattened_mut() {
            *byte = byte.wrapping_add(start);
        }
        let mut state = AESBitslice::from_blocks(&group);
        state.sub_bytes();
        let mut out = [[0u8; 16]; 4];
        state.to_blocks(&mut out);
        for (input, output) in group.as_flattened().iter().zip(out.as_flattened()) {
            assert_eq!(*output, GF256::aes_sbox(*input), "S({input:#04x})");
        }
        state.inv_sub_bytes();
        state.to_blocks(&mut out);
        assert_eq!(out, group);
    }
    // FIPS 197 figure 7: S(0x53) = 0xED.
    assert_eq!(GF256::aes_sbox(0x53), 0xED);
}

#[test]
fn aes_follows_the_examples_of_fips197() {
    // Appendix C: the plaintext 00112233...ff under the keys 000102...
    let plaintext = Vectors::hex("00112233445566778899aabbccddeeff");
    let key: Vec<u8> = (0..32).collect();
    let check = |cipher: &dyn Fn(&mut [u8; 16]), inverse: &dyn Fn(&mut [u8; 16]), expected: &str| {
        let mut block: [u8; 16] = plaintext.clone().try_into().unwrap();
        cipher(&mut block);
        assert_eq!(block.to_vec(), Vectors::hex(expected));
        inverse(&mut block);
        assert_eq!(block.to_vec(), plaintext);
    };
    let aes128 = AES128::new_from_slice(&key[..16]).unwrap();
    check(&|b| aes128.encrypt_block(b), &|b| aes128.decrypt_block(b), "69c4e0d86a7b0430d8cdb78070b4c55a");
    let aes192 = AES192::new_from_slice(&key[..24]).unwrap();
    check(&|b| aes192.encrypt_block(b), &|b| aes192.decrypt_block(b), "dda97ca4864cdfe06eaf70a0ec0d7191");
    let aes256 = AES256::new_from_slice(&key[..32]).unwrap();
    check(&|b| aes256.encrypt_block(b), &|b| aes256.decrypt_block(b), "8ea2b7ca516745bfeafc49904b496089");
    assert!(AES128::new_from_slice(&key[..15]).is_err());
}

/// Encrypts (`true`) or decrypts (`false`) blocks.
type Apply<'a> = &'a dyn Fn(&mut [[u8; 16]], bool);

/// Runs `body` with the AES of the key size of `key`.
fn with_cipher(key: &[u8], body: &mut dyn FnMut(Apply)) {
    match key.len() {
        16 => {
            let aes = AES128::new_from_slice(key).unwrap();
            body(&|blocks, encrypt| if encrypt { aes.encrypt_blocks(blocks) } else { aes.decrypt_blocks(blocks) });
        }
        24 => {
            let aes = AES192::new_from_slice(key).unwrap();
            body(&|blocks, encrypt| if encrypt { aes.encrypt_blocks(blocks) } else { aes.decrypt_blocks(blocks) });
        }
        _ => {
            let aes = AES256::new_from_slice(key).unwrap();
            body(&|blocks, encrypt| if encrypt { aes.encrypt_blocks(blocks) } else { aes.decrypt_blocks(blocks) });
        }
    }
}

fn blocks(bytes: &[u8]) -> Vec<[u8; 16]> {
    bytes.chunks(16).map(|chunk| chunk.try_into().unwrap()).collect()
}

#[test]
fn aes_follows_the_cavp_known_answers_and_multiblock_tests() {
    let mut checked = 0;
    for kind in ["GFSbox", "KeySbox", "VarKey", "VarTxt", "MMT"] {
        for size in [128, 192, 256] {
            let path = format!("crypto/aes/ECB{kind}{size}.rsp");
            for record in Record::all(&path) {
                let encrypt = record.header.contains_key("ENCRYPT");
                let (input, output) = if encrypt { ("PLAINTEXT", "CIPHERTEXT") } else { ("CIPHERTEXT", "PLAINTEXT") };
                let mut data = blocks(&record.bytes(input));
                let expected = blocks(&record.bytes(output));
                with_cipher(&record.bytes("KEY"), &mut |cipher| cipher(&mut data, encrypt));
                assert_eq!(data, expected, "{path} {:?}", record.fields);
                checked += 1;
            }
        }
    }
    assert!(checked > 1500, "{checked}");
}

/// The Monte Carlo test of AESAVS section 6.4.1 for ECB.
#[test]
fn aes_follows_the_cavp_monte_carlo_tests() {
    for size in [128, 192, 256] {
        let path = format!("crypto/aes/ECBMCT{size}.rsp");
        let records = Record::all(&path);
        for encrypt in [true, false] {
            let section: Vec<&Record> =
                records.iter().filter(|record| record.header.contains_key("ENCRYPT") == encrypt).collect();
            let (input, output) = if encrypt { ("PLAINTEXT", "CIPHERTEXT") } else { ("CIPHERTEXT", "PLAINTEXT") };
            let mut key = section[0].bytes("KEY");
            let mut text: [u8; 16] = section[0].bytes(input).try_into().unwrap();
            for record in &section {
                assert_eq!(key, record.bytes("KEY"), "{path} {}", record.field("COUNT"));
                let mut previous = [0u8; 16];
                with_cipher(&key, &mut |cipher| {
                    for _ in 0..1000 {
                        previous = text;
                        let mut block = [text];
                        cipher(&mut block, encrypt);
                        text = block[0];
                    }
                });
                assert_eq!(text.to_vec(), record.bytes(output), "{path} {}", record.field("COUNT"));
                let mut material = previous.to_vec();
                material.extend_from_slice(&text);
                let material = &material[32 - key.len()..];
                for (byte, value) in key.iter_mut().zip(material) {
                    *byte ^= value;
                }
            }
        }
    }
}

#[test]
fn aes_groups_equal_single_blocks() {
    let aes = AES256::new(&[7; 32]);
    let mut many: Vec<[u8; 16]> = (0..9u8).map(|index| [index; 16]).collect();
    let mut single = many.clone();
    aes.encrypt_blocks(&mut many);
    single.iter_mut().for_each(|block| aes.encrypt_block(block));
    assert_eq!(many, single);
    // The group functions take any number of blocks, as the blocks functions do.
    let mut group: Vec<[u8; 16]> = (0..9u8).map(|index| [index; 16]).collect();
    aes.encrypt_group(&mut group);
    assert_eq!(group, single);
    aes.decrypt_group(&mut group);
    assert_eq!(group, (0..9u8).map(|index| [index; 16]).collect::<Vec<_>>());
    aes.decrypt_blocks(&mut many);
    assert_eq!(many, (0..9u8).map(|index| [index; 16]).collect::<Vec<_>>());
    assert_eq!(format!("{aes:?}"), "AES256(..)");
}
