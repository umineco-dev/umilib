//! The MACs of the C ABI: CMAC over every cipher C can name (CMACVS, RFC
//! 4493, Wycheproof), Poly1305 (RFC 8439) and the MACs of AEGIS (its draft).

use std::ptr;

use umilib::ffi::crypto::aegis::{aegis_mac128x, aegis_mac256x};
use umilib::ffi::crypto::{cmac, poly1305};

use super::Cipher;
use crate::Check;
use crate::vectors::{Record, Vectors, Wycheproof};

/// CMAC with the cipher named `cipher` and `key` over `message`, given in pieces of 11 bytes.
fn tag(cipher: &[u8], key: &[u8], message: &[u8]) -> Vec<u8> {
    unsafe {
        let mut state = ptr::null_mut();
        Check::ok(cmac::umilib_crypto_cmac_cmac_new(
            cipher.as_ptr(),
            cipher.len(),
            key.as_ptr(),
            key.len(),
            &mut state,
        ));
        for piece in message.chunks(11) {
            Check::ok(cmac::update(state, piece.as_ptr(), piece.len()));
        }
        let mut size = 0;
        Check::ok(cmac::output_size(state, &mut size));
        let mut tag = vec![0u8; size];
        Check::ok(cmac::finalize(state, tag.as_mut_ptr(), size));
        let mut one_shot = vec![0u8; size];
        Check::ok(cmac::umilib_crypto_cmac_cmac_mac(
            cipher.as_ptr(),
            cipher.len(),
            key.as_ptr(),
            key.len(),
            message.as_ptr(),
            message.len(),
            one_shot.as_mut_ptr(),
            size,
        ));
        assert_eq!(one_shot, tag);
        tag
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn cmac_follows_the_cavp_vectors() {
    let mut checked = 0;
    for (file, family) in
        [("AES128", "aes"), ("AES192", "aes"), ("AES256", "aes"), ("TDES2", "tdes"), ("TDES3", "tdes")]
    {
        for kind in ["Gen", "Ver"] {
            let path = format!("crypto/cmac/CMAC{kind}{file}.rsp");
            for record in Record::all(&path) {
                let length: usize = record.field("Mlen").parse().unwrap();
                let mut message = record.bytes("Msg");
                message.truncate(length);
                let tag_length: usize = record.field("Tlen").parse().unwrap();
                let (cipher, key) = if family == "aes" {
                    let key = record.bytes("Key");
                    (Cipher::name("aes", key.len()).unwrap(), key)
                } else {
                    let key = [record.bytes("Key1"), record.bytes("Key2"), record.bytes("Key3")].concat();
                    (&b"umilib_crypto_des_TDES"[..], key)
                };
                let expected = record.bytes("Mac");
                let label = format!("{path} Count = {}", record.field("Count"));
                if kind == "Gen" {
                    assert_eq!(tag(cipher, &key, &message)[..tag_length], expected[..], "{label}");
                } else {
                    let valid = record.field("Result").starts_with('P');
                    unsafe {
                        let mut state = ptr::null_mut();
                        Check::ok(cmac::umilib_crypto_cmac_cmac_new(
                            cipher.as_ptr(),
                            cipher.len(),
                            key.as_ptr(),
                            key.len(),
                            &mut state,
                        ));
                        Check::ok(cmac::update(state, message.as_ptr(), message.len()));
                        let mut verified = false;
                        Check::ok(cmac::umilib_crypto_cmac_cmac_verify_truncated_with_minimum(
                            state,
                            expected.as_ptr(),
                            expected.len(),
                            tag_length,
                            &mut verified,
                        ));
                        assert_eq!(verified, valid, "{label}");
                    }
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 1176 + 96 + 96 + 360 + 240);
}

#[test]
fn cmac_follows_rfc4493() {
    let key = Vectors::hex("2b7e151628aed2a6abf7158809cf4f3c");
    let message = Vectors::hex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    );
    let aes = Cipher::name("aes", 16).unwrap();
    for (length, expected) in [
        (0, "bb1d6929e95937287fa37d129b756746"),
        (16, "070a16b46b4d4144f79bdd9dd04a287c"),
        (40, "dfa66747de9ae63030ca32611497c827"),
        (64, "51f0bebf7e3b9d92fc49741779363cfe"),
    ] {
        assert_eq!(tag(aes, &key, &message[..length]), Vectors::hex(expected), "{length} bytes");
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn cmac_follows_the_wycheproof_vectors_for_every_cipher() {
    for (path, family) in [
        ("crypto/cmac/aes_cmac_test.json", "aes"),
        ("crypto/aria/aria_cmac_test.json", "aria"),
        ("crypto/camellia/camellia_cmac_test.json", "camellia"),
    ] {
        let tests = Wycheproof::tests(path);
        assert!(tests.len() > 100, "{path}");
        for (group, test) in &tests {
            let label = format!("{path} tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
            let (key, message, expected) = (test.bytes("key"), test.bytes("msg"), test.bytes("tag"));
            let valid = test.field("result").as_str() == "valid";
            let Some(cipher) = Cipher::name(family, key.len()) else {
                assert!(!valid, "{label}");
                continue;
            };
            let tag_length = group.field("tagSize").as_usize() / 8;
            let full = tag(cipher, &key, &message);
            assert_eq!(full[..tag_length] == expected[..], valid, "{label}");
        }
    }
}

#[test]
fn cmac_verifies_whole_and_truncated_tags_and_releases_the_state() {
    let aes = Cipher::name("aes", 16).unwrap();
    let key = [5u8; 16];
    let full = tag(aes, &key, b"message");
    let verify = |tag: &[u8], minimum: Option<usize>| -> bool {
        unsafe {
            let mut state = ptr::null_mut();
            Check::ok(cmac::umilib_crypto_cmac_cmac_new(aes.as_ptr(), aes.len(), key.as_ptr(), 16, &mut state));
            Check::ok(cmac::update(state, b"message".as_ptr(), 7));
            let mut valid = false;
            match minimum {
                None if tag.len() == 16 => Check::ok(cmac::verify(state, tag.as_ptr(), tag.len(), &mut valid)),
                None => Check::ok(cmac::umilib_crypto_cmac_cmac_verify_truncated(
                    state,
                    tag.as_ptr(),
                    tag.len(),
                    &mut valid,
                )),
                Some(minimum) => Check::ok(cmac::umilib_crypto_cmac_cmac_verify_truncated_with_minimum(
                    state,
                    tag.as_ptr(),
                    tag.len(),
                    minimum,
                    &mut valid,
                )),
            }
            valid
        }
    };
    assert!(verify(&full, None));
    // SP 800-38B appendix A.2: at least 64 bits unless the protocol allows fewer.
    assert!(verify(&full[..8], None));
    assert!(!verify(&full[..7], None));
    assert!(verify(&full[..4], Some(4)));
    assert!(!verify(&full[..4], Some(5)));
    let mut wrong = full.clone();
    wrong[3] ^= 1;
    assert!(!verify(&wrong, None));
    unsafe {
        let mut state = ptr::null_mut();
        let unknown = b"umilib_crypto_aes_AES";
        Check::fails(
            cmac::umilib_crypto_cmac_cmac_new(unknown.as_ptr(), unknown.len(), key.as_ptr(), 16, &mut state),
            "ffi",
            "InvalidArgument",
        );
        Check::ok(cmac::umilib_crypto_cmac_cmac_new(aes.as_ptr(), aes.len(), key.as_ptr(), 16, &mut state));
        let mut out = [0u8; 15];
        Check::fails(cmac::finalize(state, out.as_mut_ptr(), 15), "crypto", "TagLength");
        cmac::free(state);
    }
}

#[test]
fn poly1305_follows_rfc8439() {
    let records = Record::all("crypto/chacha20/rfc8439.txt");
    let mut checked = 0;
    for record in records.iter().filter(|record| record.field("Section") == "A.3") {
        let key = match record.get("OneTimeKey") {
            Some(key) => Vectors::hex(key),
            None => Vectors::hex(&format!("{}{}", record.field("R"), record.field("S"))),
        };
        let (text, expected) = (record.bytes("Text"), record.bytes("Tag"));
        unsafe {
            let mut tag = [0u8; 16];
            Check::ok(poly1305::umilib_crypto_poly1305_poly1305_mac(
                key.as_ptr(),
                32,
                text.as_ptr(),
                text.len(),
                tag.as_mut_ptr(),
                16,
            ));
            assert_eq!(tag.to_vec(), expected, "A.3 #{}", record.field("Vector"));
            let mut state = ptr::null_mut();
            Check::ok(poly1305::umilib_crypto_poly1305_poly1305_new(key.as_ptr(), 32, &mut state));
            for piece in text.chunks(5) {
                Check::ok(poly1305::update(state, piece.as_ptr(), piece.len()));
            }
            let mut valid = false;
            Check::ok(poly1305::verify(state, expected.as_ptr(), 16, &mut valid));
            assert!(valid);
        }
        checked += 1;
    }
    assert_eq!(checked, 11);
    unsafe {
        let mut state = ptr::null_mut();
        Check::fails(
            poly1305::umilib_crypto_poly1305_poly1305_new([0u8; 16].as_ptr(), 16, &mut state),
            "crypto",
            "KeyLength",
        );
    }
}

#[test]
fn aegis_mac_follows_the_draft() {
    let records = Record::all("crypto/aegis/draft-irtf-cfrg-aegis-aead.txt");
    let mut checked = 0;
    for record in records.iter().filter(|record| record.field("Group").starts_with("AEGISMAC")) {
        let group = record.field("Group");
        let (key, nonce, data) = (record.bytes("key"), record.bytes("nonce"), record.bytes("data"));
        let degree = match group {
            "AEGISMAC-128L" | "AEGISMAC-256" => 1,
            name if name.ends_with("X2") => 2,
            _ => 4,
        };
        for (tag_size, expected) in [(16, record.bytes("tag128")), (32, record.bytes("tag256"))] {
            unsafe {
                let mut tag = vec![0u8; tag_size];
                if group.starts_with("AEGISMAC-128") {
                    let mut state = ptr::null_mut();
                    Check::ok(aegis_mac128x::new(
                        degree,
                        tag_size,
                        key.as_ptr(),
                        key.len(),
                        nonce.as_ptr(),
                        nonce.len(),
                        &mut state,
                    ));
                    for piece in data.chunks(7) {
                        Check::ok(aegis_mac128x::update(state, piece.as_ptr(), piece.len()));
                    }
                    Check::ok(aegis_mac128x::finalize(state, tag.as_mut_ptr(), tag_size));
                } else {
                    let mut state = ptr::null_mut();
                    Check::ok(aegis_mac256x::new(
                        degree,
                        tag_size,
                        key.as_ptr(),
                        key.len(),
                        nonce.as_ptr(),
                        nonce.len(),
                        &mut state,
                    ));
                    Check::ok(aegis_mac256x::update(state, data.as_ptr(), data.len()));
                    Check::ok(aegis_mac256x::finalize(state, tag.as_mut_ptr(), tag_size));
                }
                assert_eq!(tag, expected, "{group} {tag_size}");
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 6);
}

#[test]
fn a_failed_verification_leaves_the_state_to_the_caller_and_outputs_may_not_overlap() {
    let aes = Cipher::name("aes", 16).unwrap();
    let key = [5u8; 16];
    unsafe {
        let mut state = ptr::null_mut();
        Check::ok(cmac::umilib_crypto_cmac_cmac_new(aes.as_ptr(), aes.len(), key.as_ptr(), 16, &mut state));
        // Without somewhere to write the result, nothing happens to the state: it is still usable and
        // the caller frees it.
        Check::fails(cmac::verify(state, [0u8; 16].as_ptr(), 16, ptr::null_mut()), "ffi", "NullPointer");
        Check::ok(cmac::update(state, b"message".as_ptr(), 7));
        cmac::free(state);
        let mut poly = ptr::null_mut();
        Check::ok(poly1305::umilib_crypto_poly1305_poly1305_new([1u8; 32].as_ptr(), 32, &mut poly));
        Check::fails(poly1305::verify(poly, [0u8; 16].as_ptr(), 16, ptr::null_mut()), "ffi", "NullPointer");
        poly1305::free(poly);
        // The one-shot functions refuse an output that overlaps an input.
        let mut buffer = [7u8; 48];
        let pointer = buffer.as_mut_ptr();
        Check::fails(
            cmac::umilib_crypto_cmac_cmac_mac(
                aes.as_ptr(),
                aes.len(),
                pointer,
                16,
                pointer.add(16),
                32,
                pointer.add(8),
                16,
            ),
            "ffi",
            "InvalidArgument",
        );
        Check::fails(
            poly1305::umilib_crypto_poly1305_poly1305_mac(pointer, 32, pointer.add(32), 16, pointer.add(32), 16),
            "ffi",
            "InvalidArgument",
        );
    }
}
