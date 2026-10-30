//! RC2 against RFC 2268.

use umilib::crypto::rc2::RC2;
use umilib::crypto::{BlockCipher, CryptoError, KeyInit};

use crate::Record;

#[test]
fn rc2_follows_rfc2268_section_5() {
    let records = Record::all("crypto/rc2/rfc2268.txt");
    assert_eq!(records.len(), 8);
    for record in records {
        let bits: usize = record.field("EffectiveBits").parse().unwrap();
        let rc2 = RC2::new(&record.bytes("Key"), bits).unwrap();
        let plaintext: [u8; 8] = record.bytes("Plaintext").try_into().unwrap();
        let mut block = plaintext;
        rc2.encrypt_block(&mut block);
        assert_eq!(block.to_vec(), record.bytes("Ciphertext"), "{:?}", record.fields);
        rc2.decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }
}

#[test]
fn rc2_checks_its_parameters() {
    // Section 2: T is 1 to 128 bytes; T1 is at most 1024 bits.
    assert!(matches!(RC2::new(&[], 64), Err(CryptoError::KeyLength { .. })));
    assert!(matches!(RC2::new(&[0; 129], 64), Err(CryptoError::KeyLength { .. })));
    assert_eq!(RC2::new(&[0; 8], 0).err(), Some(CryptoError::InvalidParameter));
    assert_eq!(RC2::new(&[0; 8], 1025).err(), Some(CryptoError::InvalidParameter));
    assert!(RC2::new(&[0; 128], 1024).is_ok());
    // The key initialization uses 8 bits for each byte of the key.
    let mut a = [0x55u8; 8];
    let mut b = a;
    RC2::new_from_slice(&[7; 5]).unwrap().encrypt_block(&mut a);
    RC2::new(&[7; 5], 40).unwrap().encrypt_block(&mut b);
    assert_eq!(a, b);
    // The PITABLE is a permutation.
    let mut seen = [false; 256];
    for index in 0..256 {
        seen[RC2::PITABLE.get(index) as usize] = true;
    }
    assert!(seen.iter().all(|&seen| seen));
}
