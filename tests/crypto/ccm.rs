//! CCM against NIST CAVP (CCMVS), SP 800-38C appendix C and Project Wycheproof.

use umilib::crypto::aes::{AES128, AES192, AES256};
use umilib::crypto::mode::ccm::CCM;
use umilib::crypto::{AEAD, CryptoError, KeyInit};

use crate::{Record, Vectors, Wycheproof};

/// Encrypts (`tag` is `None`) or decrypts with CCM of the key size of `key`
/// and tags of `tag_length` bytes.
fn run(
    key: &[u8],
    tag_length: usize,
    nonce: &[u8],
    associated: &[u8],
    data: &[u8],
    tag: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    macro_rules! with_tag {
        ($cipher:ty) => {
            match tag_length {
                4 => run_with::<CCM<$cipher, 4>>(key, nonce, associated, data, tag),
                6 => run_with::<CCM<$cipher, 6>>(key, nonce, associated, data, tag),
                8 => run_with::<CCM<$cipher, 8>>(key, nonce, associated, data, tag),
                10 => run_with::<CCM<$cipher, 10>>(key, nonce, associated, data, tag),
                12 => run_with::<CCM<$cipher, 12>>(key, nonce, associated, data, tag),
                14 => run_with::<CCM<$cipher, 14>>(key, nonce, associated, data, tag),
                16 => run_with::<CCM<$cipher, 16>>(key, nonce, associated, data, tag),
                length => Err(CryptoError::TagLength { length, minimum: 4, maximum: 16 }),
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
    nonce: &[u8],
    associated: &[u8],
    data: &[u8],
    tag: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let ccm = A::new_from_slice(key)?;
    let mut buffer = data.to_vec();
    match tag {
        None => {
            let tag = ccm.encrypt_in_place(nonce, associated, &mut buffer)?;
            Ok((buffer, tag.as_ref().to_vec()))
        }
        Some(tag) => {
            let result = ccm.decrypt_in_place(nonce, associated, &mut buffer, tag);
            if result.is_err() {
                // A failed decryption leaves the ciphertext as it was.
                assert_eq!(buffer, data);
            }
            result.map(|()| (buffer, Vec::new()))
        }
    }
}

/// The CCMVS files hold their lengths, keys and nonces in records and
/// headers of their own, which apply to the records that follow them.
#[test]
fn ccm_follows_the_cavp_vectors() {
    let mut checked = 0;
    for kind in ["VADT", "VNT", "VPT", "VTT", "DVPT"] {
        for size in [128, 192, 256] {
            let path = format!("crypto/mode/ccm/{kind}{size}.rsp");
            let mut lengths = std::collections::BTreeMap::new();
            let (mut key, mut nonce) = (Vec::new(), Vec::new());
            for record in Record::all(&path) {
                // A header may hold several lengths: "[Alen = 0, Plen = 0, Nlen = 7, Tlen = 4]".
                let mut pairs: Vec<(String, String)> = record.fields.clone();
                for (name, value) in &record.header {
                    let text = format!("{name} = {value}");
                    for pair in text.split(',') {
                        if let Some((name, value)) = pair.split_once('=') {
                            pairs.push((name.trim().to_string(), value.trim().to_string()));
                        }
                    }
                }
                for (name, value) in &pairs {
                    if let Some(&name) = ["Alen", "Plen", "Nlen", "Tlen"].iter().find(|known| **known == name.as_str())
                    {
                        lengths.insert(name, value.parse::<usize>().unwrap());
                    }
                }
                if let Some(value) = record.get("Key") {
                    key = Vectors::hex(value);
                }
                if let Some(value) = record.get("Nonce") {
                    nonce = Vectors::hex(value);
                }
                if record.get("Count").is_none() {
                    continue;
                }
                let mut associated = record.bytes("Adata");
                associated.truncate(lengths["Alen"]);
                let ciphertext = record.bytes("CT");
                let (body, tag) = ciphertext.split_at(ciphertext.len() - lengths["Tlen"]);
                let label = format!("{path} Count = {}", record.field("Count"));
                if kind == "DVPT" {
                    let result = run(&key, lengths["Tlen"], &nonce, &associated, body, Some(tag));
                    if record.field("Result").starts_with("Pass") {
                        let mut payload = record.bytes("Payload");
                        payload.truncate(lengths["Plen"]);
                        assert_eq!(result.map(|result| result.0), Ok(payload), "{label}");
                    } else {
                        assert_eq!(result, Err(CryptoError::AuthenticationFailed), "{label}");
                    }
                } else {
                    let mut payload = record.bytes("Payload");
                    payload.truncate(lengths["Plen"]);
                    let (encrypted, computed) =
                        run(&key, lengths["Tlen"], &nonce, &associated, &payload, None).unwrap();
                    assert_eq!((encrypted.as_slice(), computed.as_slice()), (body, tag), "{label}");
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 2880);
}

#[test]
fn ccm_follows_sp800_38c_appendix_c() {
    // Example 1: Klen 128, Tlen 32, Nlen 56, Alen 64, Plen 32.
    let key = Vectors::hex("404142434445464748494a4b4c4d4e4f");
    let (ciphertext, tag) = run(
        &key,
        4,
        &Vectors::hex("10111213141516"),
        &Vectors::hex("0001020304050607"),
        &Vectors::hex("20212223"),
        None,
    )
    .unwrap();
    assert_eq!((ciphertext, tag), (Vectors::hex("7162015b"), Vectors::hex("4dac255d")));
    // Example 2: Tlen 48, Nlen 64, Alen 128, Plen 128.
    let (ciphertext, tag) = run(
        &key,
        6,
        &Vectors::hex("1011121314151617"),
        &Vectors::hex("000102030405060708090a0b0c0d0e0f"),
        &Vectors::hex("202122232425262728292a2b2c2d2e2f"),
        None,
    )
    .unwrap();
    assert_eq!((ciphertext, tag), (Vectors::hex("d2a1f0e051ea5f62081a7792073d593d"), Vectors::hex("1fc64fbfaccd")));
    // Example 3: Tlen 64, Nlen 96, Alen 160, Plen 192.
    let (ciphertext, tag) = run(
        &key,
        8,
        &Vectors::hex("101112131415161718191a1b"),
        &Vectors::hex("000102030405060708090a0b0c0d0e0f10111213"),
        &Vectors::hex("202122232425262728292a2b2c2d2e2f3031323334353637"),
        None,
    )
    .unwrap();
    assert_eq!(ciphertext, Vectors::hex("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5"));
    assert_eq!(tag, Vectors::hex("484392fbc1b09951"));
    // Example 4: 2^16 bytes of associated data (00 to ff repeated) take the 0xFFFE length encoding.
    let associated: Vec<u8> = (0..65536u32).map(|index| index as u8).collect();
    let (ciphertext, tag) = run(
        &key,
        14,
        &Vectors::hex("101112131415161718191a1b1c"),
        &associated,
        &Vectors::hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
        None,
    )
    .unwrap();
    assert_eq!(ciphertext, Vectors::hex("69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72"));
    assert_eq!(tag, Vectors::hex("b4ac6bec93e8598e7f0dadbcea5b"));
}

#[test]
fn ccm_follows_the_wycheproof_vectors() {
    let tests = Wycheproof::tests("crypto/mode/ccm/aes_ccm_test.json");
    assert!(tests.len() > 400);
    for (group, test) in tests {
        let tag_length = group.field("tagSize").as_usize() / 8;
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
        let decrypted = run(&key, tag_length, &nonce, &aad, &ciphertext, Some(&tag));
        if valid {
            assert_eq!(
                run(&key, tag_length, &nonce, &aad, &message, None),
                Ok((ciphertext.clone(), tag.clone())),
                "{label}"
            );
            assert_eq!(decrypted.map(|result| result.0), Ok(message), "{label}");
        } else {
            assert!(decrypted.is_err(), "{label}");
        }
    }
}

#[test]
fn ccm_checks_its_nonce_and_payload_lengths() {
    let ccm = CCM::<AES128, 16>::new(AES128::new(&[0; 16]));
    let mut buffer = [0u8; 4];
    assert!(matches!(ccm.encrypt_in_place(&[0; 6], &[], &mut buffer), Err(CryptoError::NonceLength { .. })));
    assert!(matches!(ccm.encrypt_in_place(&[0; 14], &[], &mut buffer), Err(CryptoError::NonceLength { .. })));
    // With a 13-byte nonce the length field has 2 bytes: at most 65535 bytes.
    let mut long = vec![0u8; 65536];
    assert!(matches!(ccm.encrypt_in_place(&[0; 13], &[], &mut long), Err(CryptoError::InputLength { .. })));
    assert!(ccm.encrypt_in_place(&[0; 13], &[], &mut long[..65535]).is_ok());
}
