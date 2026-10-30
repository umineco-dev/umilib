//! IDEA against the NESSIE test vectors.

use umilib::crypto::idea::IDEA;
use umilib::crypto::{BlockCipher, KeyInit};

use crate::{Nessie, Vectors};

#[test]
fn idea_follows_the_nessie_vectors() {
    let vectors = Nessie::vectors("crypto/idea/Idea-128-64.verified.test-vectors");
    let mut checked = 0;
    for (label, fields) in &vectors {
        let bytes = |name: &str| -> [u8; 8] { Vectors::hex(&fields[name]).try_into().unwrap() };
        let key: [u8; 16] = Vectors::hex(&fields["key"]).try_into().unwrap();
        let idea = IDEA::new(&key);
        let (plain, cipher) = (bytes("plain"), bytes("cipher"));
        let mut block = plain;
        idea.encrypt_block(&mut block);
        assert_eq!(block, cipher, "{label}");
        idea.decrypt_block(&mut block);
        assert_eq!(block, plain, "{label}");
        for (name, count) in [("Iterated 100 times", 100), ("Iterated 1000 times", 1000)] {
            if let Some(expected) = fields.get(name) {
                let mut block = plain;
                for _ in 0..count {
                    idea.encrypt_block(&mut block);
                }
                assert_eq!(block.to_vec(), Vectors::hex(expected), "{label} {name}");
            }
        }
        checked += 1;
    }
    assert_eq!(checked, vectors.len());
    assert!(checked > 700, "{checked}");
}

#[test]
fn idea_multiplication_is_modulo_65537() {
    // 0 stands for 2^16 ≡ -1.
    let value = |x: u16| if x == 0 { 65536u64 } else { x as u64 };
    let mut state = 0x2545_F491u32;
    for _ in 0..10_000 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let (a, b) = (state as u16, (state >> 16) as u16);
        for (a, b) in [(a, b), (0, b), (a, 0), (0, 0), (1, b), (65535, b)] {
            let expected = (value(a) * value(b) % 65537) as u32;
            assert_eq!(value(IDEA::multiply(a, b)) as u32, expected, "{a} * {b}");
            // Every element, 0 (that is 2^16) included, has an inverse.
            assert_eq!(IDEA::multiply(a, IDEA::invert(a)), 1, "{a}");
        }
    }
    assert!(IDEA::new_from_slice(&[0; 8]).is_err());
}
