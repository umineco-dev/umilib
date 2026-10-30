//! ARIA against RFC 5794 and Project Wycheproof.

use umilib::crypto::aria::{ARIA128, ARIA192, ARIA256, ARIAComponents};
use umilib::crypto::{BlockCipher, KeyInit};

use crate::field::GF256;
use crate::{Vectors, wycheproof};

fn block(hex: &str) -> [u8; 16] {
    Vectors::hex(hex).try_into().unwrap()
}

#[test]
fn aria_sboxes_follow_section_2_4_2() {
    for x in 0..=255u8 {
        // SB1 is the S-box of AES; SB3 and SB4 are the inverses of SB1 and SB2.
        assert_eq!(ARIAComponents::SB1.get(x as usize), GF256::aes_sbox(x) as u32, "SB1({x:#04x})");
        assert_eq!(ARIAComponents::SB3.get(ARIAComponents::SB1.get(x as usize) as usize), x as u32);
        assert_eq!(ARIAComponents::SB4.get(ARIAComponents::SB2.get(x as usize) as usize), x as u32);
    }
    assert_eq!(ARIAComponents::SB1.get(0x23), 0x26);
    assert_eq!(ARIAComponents::SB4.get(0xEF), 0xD3);
    // SL2 is the inverse of SL1 and A is an involution.
    let mut state = block("00112233445566778899aabbccddeeff");
    let original = state;
    ARIAComponents::substitute_odd(&mut state);
    ARIAComponents::substitute_even(&mut state);
    assert_eq!(state, original);
    ARIAComponents::diffuse(&mut state);
    assert_ne!(state, original);
    ARIAComponents::diffuse(&mut state);
    assert_eq!(state, original);
}

#[test]
fn aria_follows_rfc5794_appendix_a1() {
    let key = block("000102030405060708090a0b0c0d0e0f");
    let generators = ARIAComponents::generators(&key);
    let expected = [
        "000102030405060708090a0b0c0d0e0f",
        "2afbea741e1746dd55c63ba1afcea0a5",
        "7c8578018bb127e02dfe4e78c288e33c",
        "6785b52b74da46bf181054082763ff6d",
    ];
    for (generator, expected) in generators.iter().zip(expected) {
        assert_eq!(generator.to_be_bytes(), block(expected));
    }
    let aria = ARIA128::new(&key);
    let round_keys = [
        "d415a75c794b85c5e0d2a0b3cb793bf6",
        "369c65e4b11777ab713a3e1e6601b8f4",
        "0368d4f13d14497b6529ad7ac809e7d0",
        "c644552b549a263fb8d0b50906229eec",
        "5f9c434951f2d2ef342787b1a781794c",
        "afea2c0ce71db6de42a47461f4323c54",
        "324286db44ba4db6c44ac306f2a84b2c",
        "7f9fa93574d842b9101a58063771eb7b",
        "aab9c57731fcd213ad5677458fcfe6d4",
        "2f4423bb06465abada5694a19eb88459",
        "9f8772808f5d580d810ef8ddac13abeb",
        "8684946a155be77ef810744847e35fad",
        "0f0aa16daee61bd7dfee5a599970fb35",
    ];
    for (round_key, expected) in aria.encryption_keys().iter().zip(round_keys) {
        assert_eq!(*round_key, block(expected));
    }
    // The intermediate values P1 to P11 of the rounds of section 2.3.1.1.
    let intermediate = [
        "7fc7f12befd0a0791de87fa96b469f52",
        "ac8de17e49f7c5117618993162b189e9",
        "c3e8d59ec2e62d5249ca2741653cb7dd",
        "5d4aebb165e141ff759f669e1e85cc45",
        "7806e469f68874c5004b5f4a046bbcfa",
        "110f93c9a630cdd51f97d2202413345a",
        "e054428ef088fef97928241cd3be499e",
        "5734f38ea1ca3ddd102e71f95e1d5f97",
        "4903325be3e500cccd52fba4354a39ae",
        "cb8c508e2c4f87880639dc896d25ec9d",
        "e7e0d2457ed73d23d481424095afdca0",
    ];
    let mut state = block("00112233445566778899aabbccddeeff");
    for (round, expected) in intermediate.iter().enumerate() {
        if round % 2 == 0 {
            ARIAComponents::odd_round(&mut state, &aria.encryption_keys()[round]);
        } else {
            ARIAComponents::even_round(&mut state, &aria.encryption_keys()[round]);
        }
        assert_eq!(state, block(expected), "P{}", round + 1);
    }
    let mut data = block("00112233445566778899aabbccddeeff");
    aria.encrypt_block(&mut data);
    assert_eq!(data, block("d718fbd6ab644c739da95f3be6451778"));
    aria.decrypt_block(&mut data);
    assert_eq!(data, block("00112233445566778899aabbccddeeff"));
}

#[test]
fn aria_follows_rfc5794_appendix_a2_and_a3() {
    let plaintext = block("00112233445566778899aabbccddeeff");
    let key = Vectors::hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let mut data = plaintext;
    let aria = ARIA192::new_from_slice(&key[..24]).unwrap();
    aria.encrypt_block(&mut data);
    assert_eq!(data, block("26449c1805dbe7aa25a468ce263a9e79"));
    aria.decrypt_block(&mut data);
    assert_eq!(data, plaintext);
    let aria = ARIA256::new_from_slice(&key).unwrap();
    aria.encrypt_block(&mut data);
    assert_eq!(data, block("f92bd7c79fb72e2f2b8f80c1972d24fc"));
    aria.decrypt_block(&mut data);
    assert_eq!(data, plaintext);
    assert!(ARIA128::new_from_slice(&key[..17]).is_err());
}

#[test]
fn aria_follows_the_wycheproof_vectors() {
    assert!(wycheproof!("crypto/aria/aria_gcm_test.json", gcm, { 16 => ARIA128, 24 => ARIA192, 32 => ARIA256 }) > 200);
    assert!(wycheproof!("crypto/aria/aria_ccm_test.json", ccm, { 16 => ARIA128, 24 => ARIA192, 32 => ARIA256 }) > 200);
    assert_eq!(
        wycheproof!("crypto/aria/aria_cbc_pkcs5_test.json", cbc_pkcs5, { 16 => ARIA128, 24 => ARIA192, 32 => ARIA256 }),
        216
    );
    assert!(
        wycheproof!("crypto/aria/aria_cmac_test.json", cmac, { 16 => ARIA128, 24 => ARIA192, 32 => ARIA256 }) > 200
    );
}
