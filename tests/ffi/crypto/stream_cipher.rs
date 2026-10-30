//! The stream ciphers of the C ABI: RC4 (RFC 6229), ChaCha20 (RFC 8439 and
//! the Wycheproof counter boundaries) and XChaCha20 (its draft).

use std::ptr;

use umilib::ffi::U128;
use umilib::ffi::crypto::chacha20::{chacha20, xchacha20};
use umilib::ffi::crypto::rc4;

use crate::Check;
use crate::vectors::{Record, Vectors, Wycheproof};

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn rc4_follows_rfc6229() {
    let records = Record::all("crypto/rc4/rfc6229.txt");
    assert_eq!(records.len(), 14);
    for record in records {
        let key = record.bytes("Key");
        let mut stream = vec![0u8; 4112];
        unsafe {
            let mut cipher = ptr::null_mut();
            Check::ok(rc4::umilib_crypto_rc4_rc4_new(key.as_ptr(), key.len(), &mut cipher));
            for piece in stream.chunks_mut(37) {
                Check::ok(rc4::apply_keystream(cipher, piece.as_mut_ptr(), piece.len()));
            }
            rc4::free(cipher);
        }
        for (name, _) in record.fields.iter().filter(|(name, _)| name.starts_with("Offset")) {
            let offset: usize = name["Offset".len()..].parse().unwrap();
            assert_eq!(stream[offset..offset + 16].to_vec(), record.bytes(name), "key {} {name}", record.field("Key"));
        }
    }
    unsafe {
        let mut cipher = ptr::null_mut();
        Check::fails(rc4::umilib_crypto_rc4_rc4_new(ptr::null(), 0, &mut cipher), "crypto", "KeyLength");
        Check::fails(rc4::umilib_crypto_rc4_rc4_new([0u8; 257].as_ptr(), 257, &mut cipher), "crypto", "KeyLength");
    }
}

#[test]
fn chacha20_follows_rfc8439() {
    // Section 2.1.1: the quarter round on the words a, b, c and d.
    let mut words = [0u32; 16];
    words[..4].copy_from_slice(&[0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567]);
    unsafe {
        Check::ok(chacha20::umilib_crypto_chacha20_chacha20_quarter_round(words.as_mut_ptr(), 0, 1, 2, 3));
        assert_eq!(words[..4], [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]);
        Check::fails(
            chacha20::umilib_crypto_chacha20_chacha20_quarter_round(words.as_mut_ptr(), 0, 1, 2, 16),
            "ffi",
            "InvalidArgument",
        );
        // Section 2.6.2: the one-time key of Poly1305 is the first half of the block with counter 0.
        let key = Vectors::hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = Vectors::hex("000000000001020304050607");
        let mut state = [0u32; 16];
        Check::ok(chacha20::umilib_crypto_chacha20_chacha20_initial_state(
            key.as_ptr(),
            32,
            0,
            nonce.as_ptr(),
            12,
            state.as_mut_ptr(),
        ));
        assert_eq!(state[..4], [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
        let mut block = [0u8; 64];
        Check::ok(chacha20::umilib_crypto_chacha20_chacha20_block(state.as_ptr(), block.as_mut_ptr(), 64));
        assert_eq!(
            block[..32].to_vec(),
            Vectors::hex("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646")
        );
        // The block is the rounds with the input state added.
        let mut working = state;
        Check::ok(chacha20::umilib_crypto_chacha20_chacha20_rounds(working.as_mut_ptr()));
        let added: Vec<u8> =
            working.iter().zip(&state).flat_map(|(word, input)| word.wrapping_add(*input).to_le_bytes()).collect();
        assert_eq!(added, block.to_vec());
    }
    let records = Record::all("crypto/chacha20/rfc8439.txt");
    let mut checked = 0;
    for record in records.iter().filter(|record| ["A.1", "A.2"].contains(&record.field("Section"))) {
        let label = format!("{} #{}", record.field("Section"), record.field("Vector"));
        let (key, nonce) = (record.bytes("Key"), record.bytes("Nonce"));
        let counter: u32 = record.field("Counter").parse().unwrap();
        let (mut data, expected) = if record.field("Section") == "A.1" {
            (vec![0u8; 64], record.bytes("Keystream"))
        } else {
            (record.bytes("Plaintext"), record.bytes("Ciphertext"))
        };
        unsafe {
            let mut cipher = ptr::null_mut();
            Check::ok(chacha20::umilib_crypto_chacha20_chacha20_new(
                key.as_ptr(),
                32,
                nonce.as_ptr(),
                12,
                counter,
                &mut cipher,
            ));
            Check::ok(chacha20::apply_keystream(cipher, data.as_mut_ptr(), data.len()));
            chacha20::free(cipher);
        }
        assert_eq!(data, expected, "{label}");
        checked += 1;
    }
    assert_eq!(checked, 8);
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
        let status = unsafe {
            match group.field("algorithm").as_str() {
                "XChaCha20" => {
                    let counter = u64::from_le_bytes(counter.try_into().unwrap());
                    let mut cipher = ptr::null_mut();
                    Check::ok(xchacha20::umilib_crypto_chacha20_xchacha20_with_64_bit_counter(
                        key.as_ptr(),
                        32,
                        iv.as_ptr(),
                        24,
                        counter,
                        &mut cipher,
                    ));
                    let status = xchacha20::apply_keystream(cipher, data.as_mut_ptr(), data.len());
                    xchacha20::free(cipher);
                    status
                }
                "ChaCha20-IETF" => {
                    let counter = u32::from_le_bytes(counter.try_into().unwrap());
                    let mut cipher = ptr::null_mut();
                    Check::ok(chacha20::umilib_crypto_chacha20_chacha20_new(
                        key.as_ptr(),
                        32,
                        iv.as_ptr(),
                        12,
                        counter,
                        &mut cipher,
                    ));
                    let mut remaining = U128::default();
                    Check::ok(chacha20::umilib_crypto_chacha20_chacha20_remaining_bytes(cipher, &mut remaining));
                    assert_eq!(u128::from(remaining), 64 * ((1u128 << 32) - counter as u128), "{label}");
                    let status = chacha20::apply_keystream(cipher, data.as_mut_ptr(), data.len());
                    chacha20::free(cipher);
                    status
                }
                algorithm => panic!("{algorithm}"),
            }
        };
        if test.field("result").as_str() == "valid" {
            Check::ok(status);
            assert_eq!(data, test.bytes("ct"), "{label}");
        } else {
            Check::fails(status, "crypto", "LimitExceeded");
        }
    }
}

#[test]
fn xchacha20_follows_the_draft() {
    let key = Vectors::hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let nonce = Vectors::hex("000000090000004a0000000031415927");
    let mut subkey = [0u8; 32];
    unsafe {
        // Section 2.2.1.
        Check::ok(xchacha20::umilib_crypto_chacha20_xchacha20_hchacha20(
            key.as_ptr(),
            32,
            nonce.as_ptr(),
            16,
            subkey.as_mut_ptr(),
            32,
        ));
    }
    assert_eq!(subkey.to_vec(), Vectors::hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"));
    let records = Record::all("crypto/chacha20/draft-irtf-cfrg-xchacha.txt");
    let mut checked = 0;
    for record in records.iter().filter(|record| record.field("Section") != "A.1") {
        let section = record.field("Section");
        let (key, nonce) = (record.bytes("Key"), record.bytes("Nonce"));
        let counter: u32 = record.field("Counter").parse().unwrap();
        let plaintext = record.bytes("Plaintext");
        unsafe {
            let mut cipher = ptr::null_mut();
            Check::ok(xchacha20::umilib_crypto_chacha20_xchacha20_new(
                key.as_ptr(),
                32,
                nonce.as_ptr(),
                24,
                counter,
                &mut cipher,
            ));
            let mut keystream = vec![0u8; plaintext.len()];
            Check::ok(xchacha20::apply_keystream(cipher, keystream.as_mut_ptr(), keystream.len()));
            xchacha20::free(cipher);
            assert_eq!(keystream, record.bytes("Keystream"), "{section}");
            Check::ok(xchacha20::umilib_crypto_chacha20_xchacha20_with_64_bit_counter(
                key.as_ptr(),
                32,
                nonce.as_ptr(),
                24,
                counter as u64,
                &mut cipher,
            ));
            let mut data = plaintext.clone();
            Check::ok(xchacha20::apply_keystream(cipher, data.as_mut_ptr(), data.len()));
            xchacha20::free(cipher);
            assert_eq!(data, record.bytes("Ciphertext"), "{section}");
        }
        checked += 1;
    }
    assert_eq!(checked, 2);
    for record in records.iter().filter(|record| record.field("Section") == "A.1") {
        let (key, nonce) = (record.bytes("Key"), record.bytes("Nonce"));
        let (mut subkey, mut inner) = ([0u8; 32], [0u8; 12]);
        unsafe {
            Check::ok(xchacha20::umilib_crypto_chacha20_xchacha20_derive(
                key.as_ptr(),
                32,
                nonce.as_ptr(),
                24,
                subkey.as_mut_ptr(),
                32,
                inner.as_mut_ptr(),
                12,
            ));
        }
        assert_eq!(inner[..4].to_vec(), record.bytes("Fixed"));
        assert_eq!(inner[4..].to_vec(), nonce[16..].to_vec());
    }
}
