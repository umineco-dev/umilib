//! SEED against RFC 4269 and Project Wycheproof.

use umilib::crypto::seed::SEED;
use umilib::crypto::{BlockCipher, KeyInit};

use crate::{Record, wycheproof};

const VECTORS: &str = "crypto/seed/rfc4269.txt";

fn values(record: &Record, name: &str) -> Vec<u128> {
    record.field(name).split(',').map(|value| u128::from_str_radix(value, 16).unwrap()).collect()
}

/// The function G equals the xor of the extended S-boxes of section 2.2,
/// which the RFC lists independently of S0, S1 and the masks.
#[test]
fn seed_g_follows_the_extended_sboxes() {
    let record = Record::all(VECTORS).into_iter().find(|record| record.field("Name") == "Extended S-boxes").unwrap();
    let tables: Vec<Vec<u128>> = ["SS0", "SS1", "SS2", "SS3"].iter().map(|name| values(&record, name)).collect();
    let ss = |word: u32| (0..4).fold(0u128, |sum, byte| sum ^ tables[byte][((word >> (8 * byte)) & 0xFF) as usize]);
    // G(X) = SS0(X0) ^ SS1(X1) ^ SS2(X2) ^ SS3(X3), for every value of each byte.
    for x in 0..256u32 {
        for byte in 0..4 {
            let word = (x << (8 * byte)) | (0x5A5A_5A5A & !(0xFF << (8 * byte)));
            assert_eq!(SEED::g(word) as u128, ss(word), "G({word:#010x})");
        }
    }
    for word in [0u32, 0x0123_4567, 0x89AB_CDEF, 0xFFFF_FFFF, 0x8000_0001] {
        assert_eq!(SEED::g(word) as u128, ss(word));
    }
}

#[test]
fn seed_follows_rfc4269_appendix_b() {
    let mut checked = 0;
    for record in Record::all(VECTORS).iter().filter(|record| record.field("Name").starts_with("B.")) {
        let name = record.field("Name");
        let key: [u8; 16] = record.bytes("Key").try_into().unwrap();
        let seed = SEED::new(&key);
        let round_keys: Vec<u128> =
            seed.round_keys().iter().map(|[k0, k1]| ((*k0 as u128) << 32) | *k1 as u128).collect();
        assert_eq!(round_keys, values(record, "RoundKeys"), "{name}");
        // The inputs of the rounds: (L, R) becomes (R, L ^ F(Ki, R)).
        let inputs = values(record, "RoundInputs");
        for (round, key) in seed.round_keys().iter().enumerate().take(15) {
            let (left, right) = ((inputs[round] >> 64) as u64, inputs[round] as u64);
            let next = ((right as u128) << 64) | (left ^ SEED::f(right, key)) as u128;
            assert_eq!(next, inputs[round + 1], "{name} round {}", round + 1);
        }
        let plaintext: [u8; 16] = record.bytes("Plaintext").try_into().unwrap();
        let mut block = plaintext;
        seed.encrypt_block(&mut block);
        assert_eq!(block.to_vec(), record.bytes("Ciphertext"), "{name}");
        seed.decrypt_block(&mut block);
        assert_eq!(block, plaintext, "{name}");
        checked += 1;
    }
    assert_eq!(checked, 4);
    assert!(SEED::new_from_slice(&[0; 24]).is_err());
}

#[test]
fn seed_follows_the_wycheproof_vectors() {
    assert!(wycheproof!("crypto/seed/seed_gcm_test.json", gcm, { 16 => SEED }) > 50);
    assert!(wycheproof!("crypto/seed/seed_ccm_test.json", ccm, { 16 => SEED }) > 50);
}
