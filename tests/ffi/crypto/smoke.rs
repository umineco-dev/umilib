//! Each operation of the C ABI of `umilib::crypto` on a small input, as a
//! round trip: Miri, which cannot run the vector tests in time, checks the
//! unsafe code of every function through these. The values themselves are
//! checked against the specifications by the vector tests.

use std::ptr;

use umilib::crypto::random::DRBGConfig;
use umilib::ffi::crypto::aegis::{aegis128x, aegis256x};
use umilib::ffi::crypto::chacha20poly1305::{chacha20poly1305, xchacha20poly1305};
use umilib::ffi::crypto::des::tdes;
use umilib::ffi::crypto::mode::{ccm, gcm, gcmsiv, siv, xts};
use umilib::ffi::crypto::random::ctr_drbg;
use umilib::ffi::crypto::{aes, argon2, ascon, idea, kbkdf, kdftree, pbkdf2, rc4, scrypt};

use super::Cipher;
use crate::Check;

/// An AEAD round trip through `encrypt_in_place` and `decrypt_in_place`, and a refused changed tag.
macro_rules! round_trip {
    ($module:ident, $aead:expr, $nonce:expr, $tag:expr) => {{
        let aead = $aead;
        let nonce: &[u8] = $nonce;
        let mut buffer = *b"seventeen bytes!!";
        let mut tag = [0u8; $tag];
        Check::ok($module::encrypt_in_place(
            aead,
            nonce.as_ptr(),
            nonce.len(),
            b"ad".as_ptr(),
            2,
            buffer.as_mut_ptr(),
            17,
            tag.as_mut_ptr(),
            $tag,
        ));
        let mut copy = ptr::null_mut();
        Check::ok($module::clone(aead, &mut copy));
        Check::ok($module::decrypt_in_place(
            copy,
            nonce.as_ptr(),
            nonce.len(),
            b"ad".as_ptr(),
            2,
            buffer.as_mut_ptr(),
            17,
            tag.as_ptr(),
            $tag,
        ));
        assert_eq!(&buffer, b"seventeen bytes!!");
        tag[0] ^= 1;
        Check::fails(
            $module::decrypt_in_place(
                copy,
                nonce.as_ptr(),
                nonce.len(),
                b"ad".as_ptr(),
                2,
                buffer.as_mut_ptr(),
                17,
                tag.as_ptr(),
                $tag,
            ),
            "crypto",
            "AuthenticationFailed",
        );
        $module::free(copy);
        $module::free(aead);
    }};
}

#[test]
fn aeads_round_trip() {
    let aes = Cipher::name("aes", 16).unwrap();
    let key = [3u8; 32];
    unsafe {
        let mut state = ptr::null_mut();
        Check::ok(gcm::umilib_crypto_mode_gcm_gcm_new(aes.as_ptr(), aes.len(), key.as_ptr(), 16, 16, &mut state));
        round_trip!(gcm, state, &[1u8; 12], 16);
        let mut state = ptr::null_mut();
        Check::ok(ccm::umilib_crypto_mode_ccm_ccm_new(aes.as_ptr(), aes.len(), key.as_ptr(), 16, 8, &mut state));
        round_trip!(ccm, state, &[1u8; 13], 8);
        let mut state = ptr::null_mut();
        Check::ok(gcmsiv::umilib_crypto_mode_gcmsiv_gcmsiv_new(aes.as_ptr(), aes.len(), key.as_ptr(), 16, &mut state));
        round_trip!(gcmsiv, state, &[1u8; 12], 16);
        let mut state = ptr::null_mut();
        Check::ok(siv::umilib_crypto_mode_siv_siv_new(
            aes.as_ptr(),
            aes.len(),
            key.as_ptr(),
            16,
            [4u8; 16].as_ptr(),
            16,
            &mut state,
        ));
        let components = [b"one".as_ptr(), b"two".as_ptr()];
        let lengths = [3usize, 3];
        let mut buffer = *b"vector";
        let mut v = [0u8; 16];
        Check::ok(siv::umilib_crypto_mode_siv_siv_encrypt_vector_in_place(
            state,
            components.as_ptr(),
            lengths.as_ptr(),
            2,
            buffer.as_mut_ptr(),
            6,
            v.as_mut_ptr(),
            16,
        ));
        Check::ok(siv::umilib_crypto_mode_siv_siv_decrypt_vector_in_place(
            state,
            components.as_ptr(),
            lengths.as_ptr(),
            2,
            buffer.as_mut_ptr(),
            6,
            v.as_ptr(),
            16,
        ));
        assert_eq!(&buffer, b"vector");
        round_trip!(siv, state, &[1u8; 5], 16);
        let mut state = ptr::null_mut();
        Check::ok(chacha20poly1305::umilib_crypto_chacha20poly1305_chacha20poly1305_new(key.as_ptr(), 32, &mut state));
        round_trip!(chacha20poly1305, state, &[1u8; 12], 16);
        let mut state = ptr::null_mut();
        Check::ok(xchacha20poly1305::umilib_crypto_chacha20poly1305_xchacha20poly1305_new(
            key.as_ptr(),
            32,
            &mut state,
        ));
        round_trip!(xchacha20poly1305, state, &[1u8; 24], 16);
        let mut state = ptr::null_mut();
        Check::ok(aegis128x::new(2, 32, key.as_ptr(), 16, &mut state));
        round_trip!(aegis128x, state, &[1u8; 16], 32);
        let mut state = ptr::null_mut();
        Check::ok(aegis256x::new(1, 16, key.as_ptr(), 32, &mut state));
        round_trip!(aegis256x, state, &[1u8; 32], 16);
        let mut state = ptr::null_mut();
        Check::ok(ascon::umilib_crypto_ascon_ascon_aead128_with_nonce_mask(
            12,
            key.as_ptr(),
            16,
            [5u8; 16].as_ptr(),
            16,
            &mut state,
        ));
        round_trip!(ascon, state, &[1u8; 16], 12);
    }
}

#[test]
fn ciphers_and_xts_round_trip() {
    let aes = Cipher::name("aes", 16).unwrap();
    unsafe {
        let mut block = *b"sixteen byte blk";
        let mut cipher = ptr::null_mut();
        Check::ok(aes::aes128::new([1u8; 16].as_ptr(), 16, &mut cipher));
        Check::ok(aes::aes128::encrypt_blocks(cipher, block.as_mut_ptr(), 16));
        Check::ok(aes::aes128::decrypt_blocks(cipher, block.as_mut_ptr(), 16));
        aes::aes128::free(cipher);
        let mut cipher = ptr::null_mut();
        Check::ok(tdes::new((0..24u8).collect::<Vec<_>>().as_ptr(), 24, &mut cipher));
        Check::ok(tdes::encrypt_blocks(cipher, block.as_mut_ptr(), 16));
        Check::ok(tdes::decrypt_blocks(cipher, block.as_mut_ptr(), 16));
        tdes::free(cipher);
        let mut cipher = ptr::null_mut();
        Check::ok(idea::idea::new([1u8; 16].as_ptr(), 16, &mut cipher));
        Check::ok(idea::idea::encrypt_blocks(cipher, block.as_mut_ptr(), 16));
        Check::ok(idea::idea::decrypt_blocks(cipher, block.as_mut_ptr(), 16));
        idea::idea::free(cipher);
        assert_eq!(&block, b"sixteen byte blk");
        let mut state = ptr::null_mut();
        Check::ok(xts::umilib_crypto_mode_xts_xts_new(
            aes.as_ptr(),
            aes.len(),
            [1u8; 16].as_ptr(),
            16,
            [2u8; 16].as_ptr(),
            16,
            &mut state,
        ));
        let mut unit = *b"a data unit of twenty-one";
        Check::ok(xts::umilib_crypto_mode_xts_xts_encrypt(
            state,
            [3u8; 16].as_ptr(),
            16,
            unit.as_mut_ptr(),
            unit.len(),
        ));
        Check::ok(xts::umilib_crypto_mode_xts_xts_decrypt(
            state,
            [3u8; 16].as_ptr(),
            16,
            unit.as_mut_ptr(),
            unit.len(),
        ));
        assert_eq!(&unit, b"a data unit of twenty-one");
        xts::umilib_crypto_mode_xts_xts_free(state);
        let mut stream = ptr::null_mut();
        Check::ok(rc4::umilib_crypto_rc4_rc4_new(b"key".as_ptr(), 3, &mut stream));
        Check::ok(rc4::apply_keystream(stream, unit.as_mut_ptr(), unit.len()));
        rc4::free(stream);
    }
}

#[test]
fn derivations_and_ctr_drbg_run() {
    let (hmac, sha256, cmac) = (b"umilib_crypto_hmac_HMAC", b"umilib_hash_sha_v2_SHA256", b"umilib_crypto_cmac_CMAC");
    let aes = Cipher::name("aes", 16).unwrap();
    let mut out = [0u8; 40];
    unsafe {
        Check::ok(pbkdf2::umilib_crypto_pbkdf2_pbkdf2_derive(
            sha256.as_ptr(),
            sha256.len(),
            b"p".as_ptr(),
            1,
            b"s".as_ptr(),
            1,
            1,
            out.as_mut_ptr(),
            40,
        ));
        let mut state = ptr::null_mut();
        Check::ok(scrypt::umilib_crypto_scrypt_scrypt_new(2, 1, 1, &mut state));
        Check::ok(scrypt::umilib_crypto_scrypt_scrypt_derive(
            state,
            b"p".as_ptr(),
            1,
            b"s".as_ptr(),
            1,
            out.as_mut_ptr(),
            40,
        ));
        scrypt::umilib_crypto_scrypt_scrypt_free(state);
        let mut state = ptr::null_mut();
        Check::ok(argon2::umilib_crypto_argon2_argon2_new(2, 8, 1, 1, &mut state));
        Check::ok(argon2::umilib_crypto_argon2_argon2_derive(
            state,
            b"p".as_ptr(),
            1,
            b"saltsalt".as_ptr(),
            8,
            ptr::null(),
            0,
            ptr::null(),
            0,
            out.as_mut_ptr(),
            40,
        ));
        argon2::umilib_crypto_argon2_argon2_free(state);
        for (function, primitive, key) in [(&hmac[..], &sha256[..], &[1u8; 5][..]), (&cmac[..], aes, &[1u8; 16][..])] {
            let mut state = ptr::null_mut();
            Check::ok(kbkdf::umilib_crypto_kbkdf_kbkdf_new(
                function.as_ptr(),
                function.len(),
                primitive.as_ptr(),
                primitive.len(),
                key.as_ptr(),
                key.len(),
                32,
                &mut state,
            ));
            Check::ok(kbkdf::umilib_crypto_kbkdf_kbkdf_counter(
                state,
                b"a".as_ptr(),
                1,
                b"b".as_ptr(),
                1,
                out.as_mut_ptr(),
                40,
            ));
            Check::ok(kbkdf::umilib_crypto_kbkdf_kbkdf_feedback(
                state,
                [0u8; 16].as_ptr(),
                16,
                b"f".as_ptr(),
                1,
                1,
                out.as_mut_ptr(),
                40,
            ));
            Check::ok(kbkdf::umilib_crypto_kbkdf_kbkdf_double_pipeline(
                state,
                b"f".as_ptr(),
                1,
                3,
                out.as_mut_ptr(),
                40,
            ));
            kbkdf::umilib_crypto_kbkdf_kbkdf_free(state);
            let mut tree = ptr::null_mut();
            Check::ok(kdftree::umilib_crypto_kdftree_kdftree_new(
                function.as_ptr(),
                function.len(),
                primitive.as_ptr(),
                primitive.len(),
                key.as_ptr(),
                key.len(),
                2,
                &mut tree,
            ));
            Check::ok(kdftree::umilib_crypto_kdftree_kdftree_derive(
                tree,
                b"label".as_ptr(),
                5,
                b"seed".as_ptr(),
                4,
                out.as_mut_ptr(),
                40,
            ));
            kdftree::umilib_crypto_kdftree_kdftree_free(tree);
        }
        let mut drbg = ptr::null_mut();
        Check::ok(ctr_drbg::new(
            aes.as_ptr(),
            aes.len(),
            [1u8; 16].as_ptr(),
            16,
            [2u8; 8].as_ptr(),
            8,
            ptr::null(),
            0,
            &mut drbg,
        ));
        Check::ok(ctr_drbg::generate(drbg, out.as_mut_ptr(), 40, b"additional".as_ptr(), 10));
        Check::ok(ctr_drbg::reseed(drbg, [3u8; 16].as_ptr(), 16, ptr::null(), 0));
        Check::ok(ctr_drbg::fill(drbg, out.as_mut_ptr(), 40));
        ctr_drbg::free(drbg);
        let config = DRBGConfig::default();
        Check::ok(ctr_drbg::umilib_crypto_random_ctr_drbg_instantiate_without_derivation(
            aes.as_ptr(),
            aes.len(),
            &config,
            [4u8; 32].as_ptr(),
            32,
            ptr::null(),
            0,
            &mut drbg,
        ));
        Check::ok(ctr_drbg::generate(drbg, out.as_mut_ptr(), 40, ptr::null(), 0));
        ctr_drbg::free(drbg);
    }
}
