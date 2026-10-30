//! SIV and S2V against RFC 5297 appendix A and Project Wycheproof.

use umilib::crypto::aes::{AES128, AES192, AES256};
use umilib::crypto::mode::siv::{S2V, SIV};
use umilib::crypto::{AEAD, BlockCipher, CryptoError, KeyInit};

use crate::{Vectors, Wycheproof};

/// V || C of the plaintext under the AES-SIV key `key` and the components `associated`, then its decryption.
fn seal(key: &[u8], associated: &[&[u8]], plaintext: &[u8]) -> Vec<u8> {
    fn with<C: BlockCipher<Block = [u8; 16]> + KeyInit>(key: &[u8], associated: &[&[u8]], plaintext: &[u8]) -> Vec<u8> {
        let siv = SIV::<C>::new_from_slice(key).unwrap();
        let mut buffer = plaintext.to_vec();
        let v = siv.encrypt_vector_in_place(associated, &mut buffer).unwrap();
        let mut decrypted = buffer.clone();
        siv.decrypt_vector_in_place(associated, &mut decrypted, &v).unwrap();
        assert_eq!(decrypted, plaintext);
        [&v[..], &buffer].concat()
    }
    match key.len() {
        32 => with::<AES128>(key, associated, plaintext),
        48 => with::<AES192>(key, associated, plaintext),
        _ => with::<AES256>(key, associated, plaintext),
    }
}

/// The plaintext of V || C, or `None` if it does not authenticate.
fn open(key: &[u8], associated: &[&[u8]], sealed: &[u8]) -> Option<Vec<u8>> {
    fn with<C: BlockCipher<Block = [u8; 16]> + KeyInit>(
        key: &[u8],
        associated: &[&[u8]],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        let siv = SIV::<C>::new_from_slice(key).unwrap();
        let (v, ciphertext) = sealed.split_at(16);
        let mut buffer = ciphertext.to_vec();
        match siv.decrypt_vector_in_place(associated, &mut buffer, v) {
            Ok(()) => Some(buffer),
            Err(error) => {
                assert_eq!(error, CryptoError::AuthenticationFailed);
                assert_eq!(buffer, ciphertext, "a failed decryption restores the ciphertext");
                None
            }
        }
    }
    match key.len() {
        32 => with::<AES128>(key, associated, sealed),
        48 => with::<AES192>(key, associated, sealed),
        _ => with::<AES256>(key, associated, sealed),
    }
}

#[test]
fn siv_follows_rfc5297_appendix_a() {
    // A.1: deterministic authenticated encryption.
    let key = Vectors::hex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let ad = Vectors::hex("101112131415161718191a1b1c1d1e1f2021222324252627");
    let plaintext = Vectors::hex("112233445566778899aabbccddee");
    let expected = Vectors::hex("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");
    assert_eq!(seal(&key, &[&ad], &plaintext), expected);
    // A.2: nonce-based authenticated encryption, with two components and the nonce.
    let key = Vectors::hex("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f");
    let ad1 = Vectors::hex("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100");
    let ad2 = Vectors::hex("102030405060708090a0");
    let nonce = Vectors::hex("09f911029d74e35bd84156c5635688c0");
    let plaintext =
        Vectors::hex("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553");
    let expected = Vectors::hex(
        "7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d",
    );
    assert_eq!(seal(&key, &[&ad1, &ad2, &nonce], &plaintext), expected);
    assert_eq!(open(&key, &[&ad1, &ad2, &nonce], &expected), Some(plaintext));
}

#[test]
fn s2v_follows_the_intermediate_values_of_rfc5297() {
    // A.1 with K1: CMAC(zero) = 0e04dfaf..., and the final output V.
    let k1 = Vectors::hex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0");
    let ad = Vectors::hex("101112131415161718191a1b1c1d1e1f2021222324252627");
    let mut s2v = S2V::new(AES128::new_from_slice(&k1).unwrap());
    s2v.update(&ad);
    assert_eq!(s2v.components(), 1);
    assert_eq!(
        s2v.finalize(&Vectors::hex("112233445566778899aabbccddee")).to_vec(),
        Vectors::hex("85632d07c6e8f37f950acd320a2ecc93")
    );
    // The vector without components is CMAC(K, <one>), by the definition of section 2.4.
    let cipher = AES128::new_from_slice(&k1).unwrap();
    let mut one = [0u8; 16];
    one[15] = 1;
    let expected = umilib::crypto::cmac::CMAC::mac(cipher.clone(), &one);
    assert_eq!(S2V::new(cipher.clone()).finalize_empty(), Some(expected));
    let mut s2v = S2V::new(cipher);
    s2v.update(&ad);
    assert_eq!(s2v.finalize_empty(), None);
}

#[test]
fn siv_follows_the_wycheproof_deterministic_vectors() {
    let tests = Wycheproof::tests("crypto/mode/siv/aes_siv_cmac_test.json");
    assert_eq!(tests.len(), 442);
    for (_, test) in tests {
        let (key, aad, message, ciphertext) =
            (test.bytes("key"), test.bytes("aad"), test.bytes("msg"), test.bytes("ct"));
        let valid = test.field("result").as_str() == "valid";
        let label = format!("tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
        if ![32, 48, 64].contains(&key.len()) {
            assert!(
                SIV::<AES128>::new_from_slice(&key).is_err() && SIV::<AES256>::new_from_slice(&key).is_err(),
                "{label}"
            );
            assert!(!valid, "{label}");
            continue;
        }
        if ciphertext.len() < 16 {
            assert!(!valid, "{label}");
            continue;
        }
        if valid {
            assert_eq!(seal(&key, &[&aad], &message), ciphertext, "{label}");
            assert_eq!(open(&key, &[&aad], &ciphertext), Some(message), "{label}");
        } else {
            assert_eq!(open(&key, &[&aad], &ciphertext), None, "{label}");
        }
    }
}

#[test]
fn siv_follows_the_wycheproof_aead_vectors() {
    let tests = Wycheproof::tests("crypto/mode/siv/aead_aes_siv_cmac_test.json");
    assert_eq!(tests.len(), 900);
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
        let sealed = [&tag[..], &ciphertext].concat();
        let run = |key: &[u8]| -> (Result<Vec<u8>, CryptoError>, Result<Vec<u8>, CryptoError>) {
            fn with<C: BlockCipher<Block = [u8; 16]> + KeyInit>(
                key: &[u8],
                nonce: &[u8],
                aad: &[u8],
                message: &[u8],
                sealed: &[u8],
            ) -> (Result<Vec<u8>, CryptoError>, Result<Vec<u8>, CryptoError>) {
                let siv = SIV::<C>::new_from_slice(key).unwrap();
                (siv.encrypt(nonce, aad, message), siv.decrypt(nonce, aad, sealed))
            }
            match key.len() {
                32 => with::<AES128>(key, &nonce, &aad, &message, &sealed),
                48 => with::<AES192>(key, &nonce, &aad, &message, &sealed),
                _ => with::<AES256>(key, &nonce, &aad, &message, &sealed),
            }
        };
        let (encrypted, decrypted) = run(&key);
        if valid {
            assert_eq!(encrypted, Ok(sealed.clone()), "{label}");
            assert_eq!(decrypted, Ok(message), "{label}");
        } else {
            assert!(decrypted.is_err(), "{label}");
        }
    }
}

#[test]
fn siv_checks_its_inputs() {
    assert!(SIV::<AES128>::new_from_slice(&[0; 16]).is_err());
    assert!(SIV::<AES128>::new_from_slice(&[0; 33]).is_err());
    assert!(SIV::<AES256>::new_from_slice(&[0; 63]).is_err());
    let siv = SIV::<AES128>::new_from_slice(&[7; 32]).unwrap();
    let mut buffer = [1u8; 20];
    // Section 6: the nonce has at least one byte.
    assert!(matches!(siv.encrypt_in_place(&[], &[], &mut buffer), Err(CryptoError::NonceLength { .. })));
    // Section 2.6: at most 126 components of associated data.
    let components = [&[][..]; 127];
    assert_eq!(siv.encrypt_vector_in_place(&components, &mut buffer), Err(CryptoError::InvalidParameter));
    assert!(siv.encrypt_vector_in_place(&components[..126], &mut buffer).is_ok());
    assert!(matches!(siv.decrypt_vector_in_place(&[], &mut buffer, &[0; 15]), Err(CryptoError::TagLength { .. })));
    assert!(matches!(siv.decrypt(&[1], &[], &[0; 15]), Err(CryptoError::InputLength { .. })));
}
