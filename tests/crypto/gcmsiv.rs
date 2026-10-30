//! GCM-SIV and POLYVAL against RFC 8452 and Project Wycheproof.

use umilib::crypto::aes::{AES128, AES256};
use umilib::crypto::mode::gcmsiv::{GCMSIV, POLYVAL};
use umilib::crypto::{AEAD, BlockCipher, CryptoError, KeyInit};

use crate::{Record, Vectors, Wycheproof};

/// The ciphertext and tag of `plaintext`, and the decryption of `sealed` (ciphertext || tag).
fn run(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    sealed: &[u8],
) -> (Result<Vec<u8>, CryptoError>, Result<Vec<u8>, CryptoError>) {
    fn with<C: BlockCipher<Block = [u8; 16]> + KeyInit>(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        sealed: &[u8],
    ) -> (Result<Vec<u8>, CryptoError>, Result<Vec<u8>, CryptoError>) {
        let gcmsiv = GCMSIV::<C>::new_from_slice(key).unwrap();
        let decrypted = match sealed.len().checked_sub(16) {
            Some(length) => {
                let mut buffer = sealed[..length].to_vec();
                let result = gcmsiv.decrypt_in_place(nonce, aad, &mut buffer, &sealed[length..]);
                if result.is_err() {
                    assert_eq!(buffer, sealed[..length], "a failed decryption restores the ciphertext");
                }
                result.map(|()| buffer)
            }
            None => gcmsiv.decrypt(nonce, aad, sealed),
        };
        (gcmsiv.encrypt(nonce, aad, plaintext), decrypted)
    }
    match key.len() {
        16 => with::<AES128>(key, nonce, aad, plaintext, sealed),
        _ => with::<AES256>(key, nonce, aad, plaintext, sealed),
    }
}

#[test]
fn polyval_follows_rfc8452() {
    // Appendix A: the worked example, and mulX_GHASH.
    let h: [u8; 16] = Vectors::hex("25629347589242761d31f826ba4b757b").try_into().unwrap();
    let mut polyval = POLYVAL::new(&h);
    polyval.update(&Vectors::hex("4f4f95668c83dfb6401762bb2d01a262d1a24ddd2721d006bbe45f20d3c9f362"));
    assert_eq!(polyval.finalize().to_vec(), Vectors::hex("f7a3b47b846119fae5b7866cf5e5b77e"));
    for (input, expected) in [
        ("01000000000000000000000000000000", "00800000000000000000000000000000"),
        ("9c98c04df9387ded828175a92ba652d8", "4e4c6026fc9c3ef6c140bad495d3296c"),
    ] {
        let mut block: [u8; 16] = Vectors::hex(input).try_into().unwrap();
        POLYVAL::multiply_x_ghash(&mut block);
        assert_eq!(block.to_vec(), Vectors::hex(expected));
    }
    let mut reversed = h;
    reversed.reverse();
    POLYVAL::multiply_x_ghash(&mut reversed);
    assert_eq!(reversed.to_vec(), Vectors::hex("dcbaa5dd137c188ebb21492c23c9b112"));
    // Section 7: dot(a, b) is POLYVAL with H = b of the single block a.
    let b: [u8; 16] = Vectors::hex("ff000000000000000000000000000000").try_into().unwrap();
    let mut polyval = POLYVAL::new(&b);
    polyval.update(&Vectors::hex("66e94bd4ef8a2c3b884cfa59ca342b2e"));
    assert_eq!(polyval.finalize().to_vec(), Vectors::hex("ebe563401e7e91ea3ad6426b8140c394"));
}

#[test]
fn gcmsiv_follows_rfc8452_appendix_c() {
    let records = Record::all("crypto/mode/gcmsiv/rfc8452.txt");
    assert_eq!(records.len(), 50);
    for record in records {
        let (key, nonce, aad, plaintext, result) = (
            record.bytes("Key"),
            record.bytes("Nonce"),
            record.bytes("AAD"),
            record.bytes("Plaintext"),
            record.bytes("Result"),
        );
        let label = format!("{:?} {}", record.header, record.field("Result"));
        // The intermediate values: the derived keys and the POLYVAL of the input blocks.
        fn keys<C: BlockCipher<Block = [u8; 16]> + KeyInit>(key: &[u8], nonce: &[u8; 12], record: &crate::Record) {
            let gcmsiv = GCMSIV::<C>::new_from_slice(key).unwrap();
            let (authentication, cipher) = gcmsiv.derive_keys(nonce).unwrap();
            assert_eq!(authentication.to_vec(), record.bytes("AuthenticationKey"));
            let mut block = [0u8; 16];
            cipher.encrypt_block(&mut block);
            let mut expected = [0u8; 16];
            C::new_from_slice(&record.bytes("EncryptionKey")).unwrap().encrypt_block(&mut expected);
            assert_eq!(block, expected);
        }
        let nonce_array: [u8; 12] = nonce.clone().try_into().unwrap();
        match key.len() {
            16 => keys::<AES128>(&key, &nonce_array, &record),
            _ => keys::<AES256>(&key, &nonce_array, &record),
        }
        let authentication: [u8; 16] = record.bytes("AuthenticationKey").try_into().unwrap();
        let mut polyval = POLYVAL::new(&authentication);
        polyval.update(&record.bytes("POLYVALInput"));
        assert_eq!(polyval.finalize().to_vec(), record.bytes("POLYVALResult"), "{label}");
        let (encrypted, decrypted) = run(&key, &nonce, &aad, &plaintext, &result);
        assert_eq!(encrypted, Ok(result.clone()), "{label}");
        assert_eq!(&result[result.len() - 16..], record.bytes("Tag"), "{label}");
        assert_eq!(decrypted, Ok(plaintext), "{label}");
    }
}

#[test]
fn gcmsiv_follows_rfc8452_section_8() {
    let key = Vectors::hex("ee8e1ed9ff2540ae8f2ba9f50bc2f27c");
    let nonce = Vectors::hex("752abad3e0afb5f434dc4310");
    let expected = Vectors::hex("5d349ead175ef6b1def6fd4fbcdeb7e4793f4a1d7e4faa70100af1");
    let (encrypted, decrypted) = run(&key, &nonce, b"example", b"Hello world", &expected);
    assert_eq!(encrypted, Ok(expected));
    assert_eq!(decrypted, Ok(b"Hello world".to_vec()));
}

#[test]
fn gcmsiv_follows_the_wycheproof_vectors() {
    let tests = Wycheproof::tests("crypto/mode/gcmsiv/aes_gcm_siv_test.json");
    assert_eq!(tests.len(), 202);
    for (_, test) in tests {
        let (key, nonce, aad, message, ciphertext, tag) = (
            test.bytes("key"),
            test.bytes("iv"),
            test.bytes("aad"),
            test.bytes("msg"),
            test.bytes("ct"),
            test.bytes("tag"),
        );
        let valid = test.field("result").as_str() == "valid";
        let label = format!("tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
        let sealed = [&ciphertext[..], &tag].concat();
        let (encrypted, decrypted) = run(&key, &nonce, &aad, &message, &sealed);
        if valid {
            assert_eq!(encrypted, Ok(sealed.clone()), "{label}");
            assert_eq!(decrypted, Ok(message), "{label}");
        } else {
            assert!(decrypted.is_err(), "{label}");
        }
    }
}

#[test]
fn gcmsiv_checks_its_inputs() {
    // Section 6: the key-generating key has 16 or 32 bytes and the nonce 12.
    assert!(matches!(GCMSIV::<AES128>::new_from_slice(&[0; 24]), Err(CryptoError::KeyLength { .. })));
    assert!(GCMSIV::<AES128>::new_from_slice(&[0; 32]).is_err());
    assert!(GCMSIV::<AES256>::new_from_slice(&[0; 16]).is_err());
    let gcmsiv = GCMSIV::<AES128>::new_from_slice(&[1; 16]).unwrap();
    let mut buffer = [0u8; 8];
    assert!(matches!(gcmsiv.encrypt_in_place(&[0; 11], &[], &mut buffer), Err(CryptoError::NonceLength { .. })));
    assert!(matches!(gcmsiv.encrypt_in_place(&[0; 16], &[], &mut buffer), Err(CryptoError::NonceLength { .. })));
    assert!(matches!(
        gcmsiv.decrypt_in_place(&[0; 12], &[], &mut buffer, &[0; 15]),
        Err(CryptoError::TagLength { .. })
    ));
    assert!(matches!(gcmsiv.decrypt(&[0; 12], &[], &[0; 15]), Err(CryptoError::InputLength { .. })));
}
