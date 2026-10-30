//! RC4 against RFC 6229.

use umilib::crypto::rc4::RC4;
use umilib::crypto::{CryptoError, StreamCipher};

use crate::Record;

#[test]
fn rc4_follows_rfc6229() {
    let records = Record::all("crypto/rc4/rfc6229.txt");
    assert_eq!(records.len(), 14);
    for record in records {
        let key = record.bytes("Key");
        let mut stream = vec![0u8; 4112];
        RC4::new(&key).unwrap().apply_keystream(&mut stream).unwrap();
        let mut offsets = 0;
        for (name, _) in record.fields.iter().filter(|(name, _)| name.starts_with("Offset")) {
            let offset: usize = name["Offset".len()..].parse().unwrap();
            assert_eq!(
                stream[offset..offset + 16].to_vec(),
                record.bytes(name),
                "key {} offset {offset}",
                record.field("Key")
            );
            offsets += 1;
        }
        assert_eq!(offsets, 18);
        // The key stream does not depend on how the data is split.
        let mut rc4 = RC4::new(&key).unwrap();
        let mut pieces = vec![0u8; 4112];
        for chunk in pieces.chunks_mut(37) {
            rc4.apply_keystream(chunk).unwrap();
        }
        assert_eq!(pieces, stream);
    }
}

#[test]
fn rc4_accepts_keys_of_1_to_256_bytes() {
    assert!(matches!(RC4::new(&[]), Err(CryptoError::KeyLength { .. })));
    assert!(matches!(RC4::new(&[0; 257]), Err(CryptoError::KeyLength { .. })));
    assert!(RC4::new(&[0]).is_ok());
    assert!(RC4::new(&[0; 256]).is_ok());
}
