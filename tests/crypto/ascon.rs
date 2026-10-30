//! Ascon-AEAD128 against the reference implementation, the ACVP vectors of
//! NIST SP 800-232 and Project Wycheproof.

use umilib::crypto::ascon::AsconAEAD128;
use umilib::crypto::{AEAD, CryptoError, KeyInit};

use crate::{Record, Wycheproof};

#[test]
fn ascon_aead128_follows_the_reference_known_answers() {
    let records = Record::all("crypto/ascon/LWC_AEAD_KAT_128_128.txt");
    assert_eq!(records.len(), 1089);
    for record in records {
        let label = format!("Count = {}", record.field("Count"));
        let aead = AsconAEAD128::<16>::new_from_slice(&record.bytes("Key")).unwrap();
        let (nonce, plaintext, associated, sealed) =
            (record.bytes("Nonce"), record.bytes("PT"), record.bytes("AD"), record.bytes("CT"));
        assert_eq!(aead.encrypt(&nonce, &associated, &plaintext).unwrap(), sealed, "{label}");
        assert_eq!(aead.decrypt(&nonce, &associated, &sealed).unwrap(), plaintext, "{label}");
        // A changed byte of the ciphertext or tag fails, and the buffer keeps the ciphertext.
        let mut wrong = sealed.clone();
        let last = wrong.len() - 1;
        wrong[last] ^= 0x80;
        let (body, tag) = wrong.split_at(plaintext.len());
        let mut buffer = body.to_vec();
        assert_eq!(
            aead.decrypt_in_place(&nonce, &associated, &mut buffer, tag),
            Err(CryptoError::AuthenticationFailed),
            "{label}"
        );
        assert_eq!(buffer, body, "{label}");
    }
}

#[test]
fn ascon_aead128_follows_the_acvp_vectors() {
    let records = Record::all("crypto/ascon/acvp.txt");
    assert_eq!(records.len(), 1);
    for record in records {
        let label = format!("tcId {}", record.field("tcId"));
        let mut key = record.bytes("key");
        if let Some(second) = record.get("secondKey") {
            key.extend_from_slice(&crate::Vectors::hex(second));
        }
        let (nonce, associated, plaintext, ciphertext, tag) =
            (record.bytes("nonce"), record.bytes("ad"), record.bytes("pt"), record.bytes("ct"), record.bytes("tag"));
        assert_eq!(tag.len(), 15, "the byte-aligned record has a 120-bit tag");
        let aead = AsconAEAD128::<15>::new_from_slice(&key).unwrap();
        let mut buffer = ciphertext.clone();
        let result = aead.decrypt_in_place(&nonce, &associated, &mut buffer, &tag);
        if record.field("Result") == "pass" {
            assert_eq!(result, Ok(()), "{label}");
            assert_eq!(buffer, plaintext, "{label}");
            let mut buffer = plaintext.clone();
            assert_eq!(aead.encrypt_in_place(&nonce, &associated, &mut buffer).unwrap().to_vec(), tag, "{label}");
            assert_eq!(buffer, ciphertext, "{label}");
        } else {
            assert!(result.is_err(), "{label}");
        }
    }
}

#[test]
fn ascon_aead128_follows_the_wycheproof_vectors() {
    let tests = Wycheproof::tests("crypto/ascon/ascon_sp800_232_aead128_test.json");
    assert_eq!(tests.len(), 252);
    for (_, test) in tests {
        let label = format!("tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
        let (key, iv, aad, message, ciphertext, tag) = (
            test.bytes("key"),
            test.bytes("iv"),
            test.bytes("aad"),
            test.bytes("msg"),
            test.bytes("ct"),
            test.bytes("tag"),
        );
        let aead = AsconAEAD128::<16>::new_from_slice(&key).unwrap();
        let mut decrypted = ciphertext.clone();
        let result = aead.decrypt_in_place(&iv, &aad, &mut decrypted, &tag);
        if test.field("result").as_str() == "valid" {
            assert_eq!(result, Ok(()), "{label}");
            assert_eq!(decrypted, message, "{label}");
            assert_eq!(aead.encrypt(&iv, &aad, &message).unwrap(), [ciphertext, tag].concat(), "{label}");
        } else {
            assert!(result.is_err(), "{label}");
            assert_eq!(decrypted, ciphertext, "{label}: a failed decryption keeps the ciphertext");
        }
    }
}

#[test]
fn ascon_aead128_options_follow_section_4_2() {
    let (key, mask, nonce) = ([1u8; 16], [2u8; 16], [3u8; 16]);
    // Nonce masking: Ascon-AEAD128.enc(K1, N ^ K2, A, P) (equation 52).
    let masked = AsconAEAD128::<16>::with_nonce_mask(&key, &mask).encrypt(&nonce, b"ad", b"message").unwrap();
    let xored: Vec<u8> = nonce.iter().zip(&mask).map(|(n, k)| n ^ k).collect();
    assert_eq!(masked, AsconAEAD128::<16>::new(&key).encrypt(&xored, b"ad", b"message").unwrap());
    assert_eq!(
        AsconAEAD128::<16>::new_from_slice(&[[1u8; 16], [2u8; 16]].concat())
            .unwrap()
            .encrypt(&nonce, b"ad", b"message")
            .unwrap(),
        masked
    );
    // Truncation: the leftmost bytes of the tag (section 4.2.1).
    let full = AsconAEAD128::<16>::new(&key).encrypt(&nonce, b"", b"").unwrap();
    assert_eq!(AsconAEAD128::<4>::new(&key).encrypt(&nonce, b"", b"").unwrap(), full[..4]);
    assert!(matches!(AsconAEAD128::<16>::new_from_slice(&[0; 24]), Err(CryptoError::KeyLength { .. })));
    assert!(matches!(
        AsconAEAD128::<16>::new(&key).encrypt_in_place(&[0; 12], &[], &mut []),
        Err(CryptoError::NonceLength { .. })
    ));
}
