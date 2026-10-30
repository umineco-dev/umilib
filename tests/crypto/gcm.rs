//! GCM against NIST CAVP (GCMVS) and Project Wycheproof.

use umilib::crypto::aes::{AES128, AES192, AES256};
use umilib::crypto::mode::gcm::{GCM, GHASH};
use umilib::crypto::{AEAD, CryptoError, KeyInit};

use crate::{Record, Vectors, Wycheproof};

/// Encrypts or decrypts with GCM of the key size of `key` and tags of
/// `tag_length` bytes; the result is the ciphertext and tag, or the
/// plaintext, or the error.
fn run(
    key: &[u8],
    tag_length: usize,
    iv: &[u8],
    associated: &[u8],
    data: &[u8],
    tag: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    macro_rules! with_tag {
        ($cipher:ty) => {
            match tag_length {
                16 => run_with::<GCM<$cipher, 16>>(key, iv, associated, data, tag),
                15 => run_with::<GCM<$cipher, 15>>(key, iv, associated, data, tag),
                14 => run_with::<GCM<$cipher, 14>>(key, iv, associated, data, tag),
                13 => run_with::<GCM<$cipher, 13>>(key, iv, associated, data, tag),
                12 => run_with::<GCM<$cipher, 12>>(key, iv, associated, data, tag),
                8 => run_with::<GCM<$cipher, 8>>(key, iv, associated, data, tag),
                4 => run_with::<GCM<$cipher, 4>>(key, iv, associated, data, tag),
                other => panic!("tag length {other}"),
            }
        };
    }
    match key.len() {
        16 => with_tag!(AES128),
        24 => with_tag!(AES192),
        32 => with_tag!(AES256),
        length => Err(CryptoError::KeyLength { length, minimum: 16, maximum: 32 }),
    }
}

fn run_with<A: AEAD + KeyInit>(
    key: &[u8],
    iv: &[u8],
    associated: &[u8],
    data: &[u8],
    tag: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let gcm = A::new_from_slice(key)?;
    let mut buffer = data.to_vec();
    match tag {
        None => {
            let tag = gcm.encrypt_in_place(iv, associated, &mut buffer)?;
            Ok((buffer, tag.as_ref().to_vec()))
        }
        Some(tag) => {
            gcm.decrypt_in_place(iv, associated, &mut buffer, tag)?;
            Ok((buffer, Vec::new()))
        }
    }
}

#[test]
fn gcm_follows_the_cavp_vectors() {
    let mut checked = 0;
    for size in [128, 192, 256] {
        for kind in ["EncryptExtIV", "Decrypt"] {
            let path = format!("crypto/mode/gcm/gcm{kind}{size}.rsp");
            for record in Record::all(&path) {
                let tag_length: usize = record.header["Taglen"].parse::<usize>().unwrap() / 8;
                let (key, iv, aad) = (record.bytes("Key"), record.bytes("IV"), record.bytes("AAD"));
                let label = format!("{path} {:?} Count = {}", record.header, record.field("Count"));
                if kind == "EncryptExtIV" {
                    let (ciphertext, tag) = run(&key, tag_length, &iv, &aad, &record.bytes("PT"), None).unwrap();
                    assert_eq!(ciphertext, record.bytes("CT"), "{label}");
                    assert_eq!(tag, record.bytes("Tag"), "{label}");
                } else {
                    let result = run(&key, tag_length, &iv, &aad, &record.bytes("CT"), Some(&record.bytes("Tag")));
                    match record.get("FAIL") {
                        Some(_) => assert_eq!(result, Err(CryptoError::AuthenticationFailed), "{label}"),
                        None => assert_eq!(result.unwrap().0, record.bytes("PT"), "{label}"),
                    }
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 40_000, "{checked}");
}

#[test]
fn gcm_follows_the_wycheproof_vectors() {
    let tests = Wycheproof::tests("crypto/mode/gcm/aes_gcm_test.json");
    assert!(tests.len() > 200);
    for (group, test) in tests {
        let tag_length = group.field("tagSize").as_usize() / 8;
        let (key, iv, aad, message, ciphertext, tag) = (
            test.bytes("key"),
            test.bytes("iv"),
            test.bytes("aad"),
            test.bytes("msg"),
            test.bytes("ct"),
            test.bytes("tag"),
        );
        let valid = test.field("result").as_str() == "valid";
        let label = format!("tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
        let encrypted = run(&key, tag_length, &iv, &aad, &message, None);
        let decrypted = run(&key, tag_length, &iv, &aad, &ciphertext, Some(&tag));
        if valid {
            assert_eq!(encrypted, Ok((ciphertext.clone(), tag.clone())), "{label}");
            assert_eq!(decrypted.map(|result| result.0), Ok(message), "{label}");
        } else {
            assert!(decrypted.is_err(), "{label}");
        }
    }
}

#[test]
fn gcm_checks_its_inputs() {
    let gcm = GCM::<AES128>::new(AES128::new(&[0; 16]));
    let mut buffer = [0u8; 4];
    assert!(matches!(gcm.encrypt_in_place(&[], &[], &mut buffer), Err(CryptoError::NonceLength { .. })));
    assert!(matches!(gcm.decrypt_in_place(&[0; 12], &[], &mut buffer, &[0; 15]), Err(CryptoError::TagLength { .. })));
    // A failed decryption leaves the ciphertext as it was.
    let tag = gcm.encrypt_in_place(&[1; 12], b"header", &mut buffer).unwrap();
    let ciphertext = buffer;
    let mut wrong = tag;
    wrong[0] ^= 1;
    assert_eq!(gcm.decrypt_in_place(&[1; 12], b"header", &mut buffer, &wrong), Err(CryptoError::AuthenticationFailed));
    assert_eq!(buffer, ciphertext);
    gcm.decrypt_in_place(&[1; 12], b"header", &mut buffer, &tag).unwrap();
    assert_eq!(buffer, [0; 4]);
    // The vectors for allocation-based use agree.
    let sealed = gcm.encrypt(&[2; 12], b"", b"message").unwrap();
    assert_eq!(gcm.decrypt(&[2; 12], b"", &sealed).unwrap(), b"message");
    assert!(gcm.decrypt(&[2; 12], b"", &sealed[..15]).is_err());
}

#[test]
fn ghash_follows_the_gcm_specification_example() {
    // The test case 2 of the GCM specification (McGrew and Viega): H and GHASH(C).
    let h: [u8; 16] = Vectors::hex("66e94bd4ef8a2c3b884cfa59ca342b2e").try_into().unwrap();
    let mut ghash = GHASH::new(&h);
    ghash.update(&Vectors::hex("0388dace60b6a392f328c2b971b2fe78"));
    let mut lengths = [0u8; 16];
    lengths[15] = 0x80;
    ghash.update(&lengths);
    assert_eq!(ghash.finalize().to_vec(), Vectors::hex("f38cbb1ad69223dcc3457ae5b6b0f885"));
}
