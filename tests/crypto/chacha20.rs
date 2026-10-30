//! ChaCha20, XChaCha20, Poly1305 and their AEADs against RFC 8439,
//! draft-irtf-cfrg-xchacha and Project Wycheproof.

use umilib::crypto::chacha20::{ChaCha20, XChaCha20};
use umilib::crypto::chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use umilib::crypto::poly1305::Poly1305;
use umilib::crypto::{AEAD, CryptoError, KeyInit, MAC, StreamCipher};

use crate::{Record, Vectors, Wycheproof};

fn array<const N: usize>(hex: &str) -> [u8; N] {
    Vectors::hex(hex).try_into().unwrap()
}

fn words(rows: &str) -> [u32; 16] {
    let values: Vec<u32> = rows.split_whitespace().map(|word| u32::from_str_radix(word, 16).unwrap()).collect();
    values.try_into().unwrap()
}

const SUNSCREEN: &str = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";

#[test]
fn chacha20_follows_rfc8439_section_2() {
    // 2.1.1.
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&[0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567]);
    ChaCha20::quarter_round(&mut state, 0, 1, 2, 3);
    assert_eq!(state[..4], [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]);
    // 2.2.1.
    let mut state = words(
        "879531e0 c5ecf37d 516461b1 c9a62f8a 44c20ef3 3390af7f d9fc690b 2a5f714c 53372767 b00a5631 974c541a 359e9963 5c971061 3d631689 2098d9d6 91dbd320",
    );
    ChaCha20::quarter_round(&mut state, 2, 7, 8, 13);
    assert_eq!(
        state,
        words(
            "879531e0 c5ecf37d bdb886dc c9a62f8a 44c20ef3 3390af7f d9fc690b cfacafd2 e46bea80 b00a5631 974c541a 359e9963 5c971061 ccc07c79 2098d9d6 91dbd320"
        )
    );
    // 2.3.2.
    let key: [u8; 32] = array("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let state = ChaCha20::initial_state(&key, 1, &array("000000090000004a00000000"));
    assert_eq!(
        state,
        words(
            "61707865 3320646e 79622d32 6b206574 03020100 07060504 0b0a0908 0f0e0d0c 13121110 17161514 1b1a1918 1f1e1d1c 00000001 09000000 4a000000 00000000"
        )
    );
    let mut rounds = state;
    ChaCha20::rounds(&mut rounds);
    assert_eq!(
        rounds,
        words(
            "837778ab e238d763 a67ae21e 5950bb2f c4f2d0c7 fc62bb2f 8fa018fc 3f5ec7b7 335271c2 f29489f3 eabda8fc 82e46ebd d19c12b4 b04e16de 9e83d0cb 4e3c50a2"
        )
    );
    assert_eq!(
        ChaCha20::block(&state).to_vec(),
        Vectors::hex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        )
    );
    // 2.4.2.
    let mut data = Vectors::hex(SUNSCREEN);
    ChaCha20::new(&key, &array("000000000000004a00000000"), 1).apply_keystream(&mut data).unwrap();
    assert_eq!(
        data,
        Vectors::hex(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
        )
    );
}

#[test]
fn poly1305_follows_rfc8439_section_2() {
    // 2.5.2, in one piece and in pieces.
    let key: [u8; 32] = array("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    let message = b"Cryptographic Forum Research Group";
    assert_eq!(Poly1305::mac(&key, message).to_vec(), Vectors::hex("a8061dc1305136c6c22b8baf0c0127a9"));
    let mut poly1305 = Poly1305::new(&key);
    for piece in message.chunks(5) {
        poly1305.update(piece);
    }
    assert!(poly1305.clone().verify(&Vectors::hex("a8061dc1305136c6c22b8baf0c0127a9")));
    MAC::reset(&mut poly1305);
    poly1305.update(message);
    assert_eq!(poly1305.finalize().to_vec(), Vectors::hex("a8061dc1305136c6c22b8baf0c0127a9"));
    // 2.6.2: the one-time key is the first half of the block with counter 0.
    let key: [u8; 32] = array("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let block = ChaCha20::block(&ChaCha20::initial_state(&key, 0, &array("000000000001020304050607")));
    assert_eq!(block[..32].to_vec(), Vectors::hex("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646"));
}

#[test]
fn chacha20_poly1305_follows_rfc8439_section_2_8_2() {
    let key: [u8; 32] = array("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = Vectors::hex("070000004041424344454647");
    let aad = Vectors::hex("50515253c0c1c2c3c4c5c6c7");
    let aead = ChaCha20Poly1305::new(&key);
    let sealed = aead.encrypt(&nonce, &aad, &Vectors::hex(SUNSCREEN)).unwrap();
    let expected = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
    assert_eq!(sealed, Vectors::hex(&format!("{expected}1ae10b594f09e26a7e902ecbd0600691")));
    assert_eq!(aead.decrypt(&nonce, &aad, &sealed).unwrap(), Vectors::hex(SUNSCREEN));
}

#[test]
fn chacha20_and_poly1305_follow_rfc8439_appendix_a() {
    let records = Record::all("crypto/chacha20/rfc8439.txt");
    assert_eq!(records.len(), 23);
    for record in &records {
        let label = format!("{} #{}", record.field("Section"), record.field("Vector"));
        match record.field("Section") {
            "A.1" | "A.2" => {
                let counter: u32 = record.field("Counter").parse().unwrap();
                let mut chacha20 = ChaCha20::new(&array(record.field("Key")), &array(record.field("Nonce")), counter);
                let (input, output) = if record.field("Section") == "A.1" {
                    (vec![0u8; 64], record.bytes("Keystream"))
                } else {
                    (record.bytes("Plaintext"), record.bytes("Ciphertext"))
                };
                let mut data = input;
                chacha20.apply_keystream(&mut data).unwrap();
                assert_eq!(data, output, "{label}");
            }
            "A.3" => {
                let key: [u8; 32] = match record.get("OneTimeKey") {
                    Some(key) => array(key),
                    None => array(&format!("{}{}", record.field("R"), record.field("S"))),
                };
                assert_eq!(Poly1305::mac(&key, &record.bytes("Text")).to_vec(), record.bytes("Tag"), "{label}");
            }
            "A.4" => {
                let block = ChaCha20::block(&ChaCha20::initial_state(
                    &array(record.field("Key")),
                    0,
                    &array(record.field("Nonce")),
                ));
                assert_eq!(block[..32].to_vec(), record.bytes("OneTimeKey"), "{label}");
            }
            "A.5" => {
                let aead = ChaCha20Poly1305::new(&array(record.field("Key")));
                let mut buffer = record.bytes("Ciphertext");
                aead.decrypt_in_place(&record.bytes("Nonce"), &record.bytes("AAD"), &mut buffer, &record.bytes("Tag"))
                    .unwrap();
                assert_eq!(buffer, record.bytes("Plaintext"), "{label}");
                assert_eq!(record.field("Tag"), record.field("CalculatedTag"));
            }
            section => panic!("{section}"),
        }
    }
}

#[test]
fn xchacha20_follows_the_draft() {
    // Section 2.2.1.
    let key: [u8; 32] = array("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let subkey = XChaCha20::hchacha20(&key, &array("000000090000004a0000000031415927"));
    assert_eq!(subkey.to_vec(), Vectors::hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"));
    let records = Record::all("crypto/chacha20/draft-irtf-cfrg-xchacha.txt");
    assert_eq!(records.len(), 3);
    for record in &records {
        let section = record.field("Section");
        let (key, nonce): ([u8; 32], [u8; 24]) = (array(record.field("Key")), array(record.field("Nonce")));
        if section == "A.1" {
            let aead = XChaCha20Poly1305::new(&key);
            let sealed = aead.encrypt(&nonce, &record.bytes("AAD"), &record.bytes("Plaintext")).unwrap();
            assert_eq!(sealed, [record.bytes("Ciphertext"), record.bytes("Tag")].concat(), "{section}");
            assert_eq!(aead.decrypt(&nonce, &record.bytes("AAD"), &sealed).unwrap(), record.bytes("Plaintext"));
            // The one-time key of the inner ChaCha20-Poly1305.
            let (subkey, inner) = XChaCha20::derive(&key, &nonce);
            assert_eq!(inner[..4].to_vec(), record.bytes("Fixed"));
            let block = ChaCha20::block(&ChaCha20::initial_state(&subkey, 0, &inner));
            assert_eq!(block[..32].to_vec(), record.bytes("OneTimeKey"));
        } else {
            let counter: u32 = record.field("Counter").parse().unwrap();
            let plaintext = record.bytes("Plaintext");
            let mut keystream = vec![0u8; plaintext.len()];
            XChaCha20::new(&key, &nonce, counter).apply_keystream(&mut keystream).unwrap();
            assert_eq!(keystream, record.bytes("Keystream"), "{section}");
            let mut data = plaintext.clone();
            XChaCha20::with_64_bit_counter(&key, &nonce, counter as u64).apply_keystream(&mut data).unwrap();
            assert_eq!(data, record.bytes("Ciphertext"), "{section}");
        }
    }
}

#[test]
fn chacha20_follows_the_wycheproof_counter_boundaries() {
    let tests = Wycheproof::tests("crypto/chacha20/chacha20_counter_test.json");
    assert_eq!(tests.len(), 42);
    for (group, test) in tests {
        let label = format!("tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
        let (key, iv, message, counter) =
            (test.bytes("key"), test.bytes("iv"), test.bytes("msg"), test.bytes("initialCounter"));
        let mut data = message.clone();
        let result = match group.field("algorithm").as_str() {
            "XChaCha20" => {
                let counter = u64::from_le_bytes(counter.try_into().unwrap());
                XChaCha20::with_64_bit_counter(&key.try_into().unwrap(), &iv.try_into().unwrap(), counter)
                    .apply_keystream(&mut data)
            }
            "ChaCha20-IETF" => {
                let counter = u32::from_le_bytes(counter.try_into().unwrap());
                ChaCha20::new(&key.try_into().unwrap(), &iv.try_into().unwrap(), counter).apply_keystream(&mut data)
            }
            algorithm => panic!("{algorithm}"),
        };
        if test.field("result").as_str() == "valid" {
            assert_eq!(result, Ok(()), "{label}");
            assert_eq!(data, test.bytes("ct"), "{label}");
        } else {
            assert_eq!(result, Err(CryptoError::LimitExceeded), "{label}");
        }
    }
}

#[test]
fn chacha20_poly1305_follows_the_wycheproof_vectors() {
    for (path, count) in [
        ("crypto/chacha20poly1305/chacha20_poly1305_test.json", 325),
        ("crypto/chacha20poly1305/xchacha20_poly1305_test.json", 315),
    ] {
        let tests = Wycheproof::tests(path);
        assert_eq!(tests.len(), count, "{path}");
        for (_, test) in tests {
            let label = format!("{path} tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
            let (key, iv, aad, message, ciphertext, tag) = (
                test.bytes("key"),
                test.bytes("iv"),
                test.bytes("aad"),
                test.bytes("msg"),
                test.bytes("ct"),
                test.bytes("tag"),
            );
            let run = |data: &[u8], tag: Option<&[u8]>| -> Result<Vec<u8>, CryptoError> {
                let mut buffer = data.to_vec();
                let result = if path.contains("xchacha") {
                    let aead = XChaCha20Poly1305::new_from_slice(&key)?;
                    match tag {
                        None => aead.encrypt_in_place(&iv, &aad, &mut buffer).map(|tag| buffer.extend_from_slice(&tag)),
                        Some(tag) => aead.decrypt_in_place(&iv, &aad, &mut buffer, tag),
                    }
                } else {
                    let aead = ChaCha20Poly1305::new_from_slice(&key)?;
                    match tag {
                        None => aead.encrypt_in_place(&iv, &aad, &mut buffer).map(|tag| buffer.extend_from_slice(&tag)),
                        Some(tag) => aead.decrypt_in_place(&iv, &aad, &mut buffer, tag),
                    }
                };
                if tag.is_some() && result.is_err() {
                    assert_eq!(buffer, data, "a failed decryption leaves the ciphertext");
                }
                result.map(|()| buffer)
            };
            let decrypted = run(&ciphertext, Some(&tag));
            if test.field("result").as_str() == "valid" {
                assert_eq!(run(&message, None), Ok([ciphertext.clone(), tag.clone()].concat()), "{label}");
                assert_eq!(decrypted, Ok(message), "{label}");
            } else {
                assert!(decrypted.is_err(), "{label}");
            }
        }
    }
}

#[test]
fn chacha20_stops_before_its_counter_wraps() {
    let key = [7u8; 32];
    let mut last = ChaCha20::new(&key, &[0; 12], u32::MAX);
    assert_eq!(last.remaining_bytes(), 64);
    let mut data = [0u8; 65];
    assert_eq!(last.apply_keystream(&mut data), Err(CryptoError::LimitExceeded));
    assert_eq!(data, [0u8; 65], "a refused request changes nothing");
    assert_eq!(last.apply_keystream(&mut data[..64]), Ok(()));
    assert_eq!(last.apply_keystream(&mut data[..1]), Err(CryptoError::LimitExceeded));
    // The 64-bit counter carries into word 13.
    let mut wide = ChaCha20::with_64_bit_counter(&key, &[1; 8], u32::MAX as u64);
    let mut stream = [0u8; 128];
    wide.apply_keystream(&mut stream).unwrap();
    let mut next = [0u8; 64];
    ChaCha20::with_64_bit_counter(&key, &[1; 8], 1 << 32).apply_keystream(&mut next).unwrap();
    assert_eq!(stream[64..], next);
    assert!(matches!(
        ChaCha20Poly1305::new(&key).encrypt_in_place(&[0; 11], &[], &mut []),
        Err(CryptoError::NonceLength { .. })
    ));
    assert!(matches!(
        XChaCha20Poly1305::new(&key).encrypt_in_place(&[0; 12], &[], &mut []),
        Err(CryptoError::NonceLength { .. })
    ));
    assert!(matches!(
        ChaCha20Poly1305::new(&key).decrypt_in_place(&[0; 12], &[], &mut [], &[0; 15]),
        Err(CryptoError::TagLength { .. })
    ));
}
