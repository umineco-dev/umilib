//! The modes of `umilib::ffi::crypto::mode` against the files of NIST CAVP
//! (AESAVS, TDES, XTSVS) and SP 800-38A appendix F, with the cipher named.

use std::ptr;

use umilib::ffi::Buffer;
use umilib::ffi::U128;
use umilib::ffi::crypto::mode::cbc::*;
use umilib::ffi::crypto::mode::cfb::*;
use umilib::ffi::crypto::mode::ctr::*;
use umilib::ffi::crypto::mode::ecb::*;
use umilib::ffi::crypto::mode::kw::*;
use umilib::ffi::crypto::mode::ofb::*;
use umilib::ffi::crypto::mode::xts::*;
use umilib::ffi::crypto::mode::*;

use super::Cipher;
use crate::Check;
use crate::vectors::{Record, Vectors};

/// The modes of SP 800-38A under test.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    ECB,
    CBC,
    CFB,
    CFB8,
    CFB1,
    OFB,
}

impl Mode {
    /// Encrypts or decrypts `data` (for CFB1, its first `bits` bits) with a fresh mode object over the
    /// cipher `cipher`, through the C ABI.
    fn run(self, cipher: &[u8], key: &[u8], iv: &[u8], data: &mut [u8], bits: usize, encrypt: bool) {
        unsafe {
            let (c, k, i) = ((cipher.as_ptr(), cipher.len()), (key.as_ptr(), key.len()), (iv.as_ptr(), iv.len()));
            let (d, n) = (data.as_mut_ptr(), data.len());
            match self {
                Mode::ECB => {
                    let mut state = ptr::null_mut();
                    Check::ok(umilib_crypto_mode_ecb_ecb_new(c.0, c.1, k.0, k.1, &mut state));
                    if encrypt {
                        Check::ok(umilib_crypto_mode_ecb_ecb_encrypt(state, d, n));
                    } else {
                        Check::ok(umilib_crypto_mode_ecb_ecb_decrypt(state, d, n));
                    }
                    umilib_crypto_mode_ecb_ecb_free(state);
                }
                Mode::CBC => {
                    let mut state = ptr::null_mut();
                    Check::ok(umilib_crypto_mode_cbc_cbc_new(c.0, c.1, k.0, k.1, i.0, i.1, &mut state));
                    if encrypt {
                        Check::ok(umilib_crypto_mode_cbc_cbc_encrypt(state, d, n));
                    } else {
                        Check::ok(umilib_crypto_mode_cbc_cbc_decrypt(state, d, n));
                    }
                    umilib_crypto_mode_cbc_cbc_free(state);
                }
                Mode::CFB => {
                    let mut state = ptr::null_mut();
                    Check::ok(umilib_crypto_mode_cfb_cfb_new(c.0, c.1, k.0, k.1, i.0, i.1, &mut state));
                    if encrypt {
                        Check::ok(umilib_crypto_mode_cfb_cfb_encrypt(state, d, n));
                    } else {
                        Check::ok(umilib_crypto_mode_cfb_cfb_decrypt(state, d, n));
                    }
                    umilib_crypto_mode_cfb_cfb_free(state);
                }
                Mode::CFB8 => {
                    let mut state = ptr::null_mut();
                    Check::ok(umilib_crypto_mode_cfb_cfb8_new(c.0, c.1, k.0, k.1, i.0, i.1, &mut state));
                    if encrypt {
                        Check::ok(umilib_crypto_mode_cfb_cfb8_encrypt(state, d, n));
                    } else {
                        Check::ok(umilib_crypto_mode_cfb_cfb8_decrypt(state, d, n));
                    }
                    umilib_crypto_mode_cfb_cfb8_free(state);
                }
                Mode::CFB1 => {
                    let mut state = ptr::null_mut();
                    Check::ok(umilib_crypto_mode_cfb_cfb1_new(c.0, c.1, k.0, k.1, i.0, i.1, &mut state));
                    if encrypt {
                        Check::ok(umilib_crypto_mode_cfb_cfb1_encrypt_bits(state, d, n, bits));
                    } else {
                        Check::ok(umilib_crypto_mode_cfb_cfb1_decrypt_bits(state, d, n, bits));
                    }
                    umilib_crypto_mode_cfb_cfb1_free(state);
                }
                Mode::OFB => {
                    let mut state = ptr::null_mut();
                    Check::ok(umilib_crypto_mode_ofb_ofb_new(c.0, c.1, k.0, k.1, i.0, i.1, &mut state));
                    Check::ok(umilib_crypto_mode_ofb_ofb_apply(state, d, n));
                    umilib_crypto_mode_ofb_ofb_free(state);
                }
            }
        }
    }
}

/// The bytes of a field: hexadecimal, or for CFB1 a string of bits, most significant first.
fn field(record: &Record, key: &str, mode: Mode) -> (Vec<u8>, usize) {
    let text = record.field(key);
    if mode != Mode::CFB1 {
        let bytes = Vectors::hex(text);
        let bits = 8 * bytes.len();
        return (bytes, bits);
    }
    let mut bytes = vec![0u8; text.len().div_ceil(8)];
    for (index, character) in text.chars().enumerate() {
        if character == '1' {
            bytes[index / 8] |= 0x80 >> (index % 8);
        }
    }
    (bytes, text.len())
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn modes_follow_the_cavp_known_answers_and_multiblock_tests() {
    let mut checked = 0;
    for (prefix, directory, mode) in [
        ("ECB", "../aes", Mode::ECB),
        ("CBC", "cbc", Mode::CBC),
        ("CFB128", "cfb", Mode::CFB),
        ("CFB8", "cfb", Mode::CFB8),
        ("CFB1", "cfb", Mode::CFB1),
        ("OFB", "ofb", Mode::OFB),
    ] {
        for kind in ["GFSbox", "KeySbox", "VarKey", "VarTxt", "MMT"] {
            for size in [128, 192, 256] {
                let path = format!("crypto/mode/{directory}/{prefix}{kind}{size}.rsp");
                for record in Record::all(&path) {
                    let encrypt = record.header.contains_key("ENCRYPT");
                    let (input, output) =
                        if encrypt { ("PLAINTEXT", "CIPHERTEXT") } else { ("CIPHERTEXT", "PLAINTEXT") };
                    let (mut data, bits) = field(&record, input, mode);
                    let key = record.bytes("KEY");
                    let iv = record.get("IV").map(Vectors::hex).unwrap_or_default();
                    let cipher = Cipher::name("aes", key.len()).unwrap();
                    mode.run(cipher, &key, &iv, &mut data, bits, encrypt);
                    assert_eq!(data, field(&record, output, mode).0, "{path} {:?}", record.fields);
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 8000, "{checked}");
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn tdes_modes_follow_the_cavp_multiblock_tests() {
    let mut checked = 0;
    for (file, mode) in [("TECBMMT3", Mode::ECB), ("TCBCMMT3", Mode::CBC)] {
        let path = format!("crypto/des/{file}.rsp");
        for record in Record::all(&path) {
            let key = [record.bytes("KEY1"), record.bytes("KEY2"), record.bytes("KEY3")].concat();
            let encrypt = record.header.contains_key("ENCRYPT");
            let (input, output) = if encrypt { ("PLAINTEXT", "CIPHERTEXT") } else { ("CIPHERTEXT", "PLAINTEXT") };
            let mut data = record.bytes(input);
            let iv = record.get("IV").map(Vectors::hex).unwrap_or_default();
            let bits = 8 * data.len();
            mode.run(b"umilib_crypto_des_TDES", &key, &iv, &mut data, bits, encrypt);
            assert_eq!(data, record.bytes(output), "{path} {:?}", record.fields);
            checked += 1;
        }
    }
    assert!(checked >= 40, "{checked}");
}

#[test]
fn ctr_follows_sp800_38a_appendix_f5() {
    // F.5.1 CTR-AES128.Encrypt.
    let key = Vectors::hex("2b7e151628aed2a6abf7158809cf4f3c");
    let initial = Vectors::hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let plaintext = Vectors::hex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    );
    let expected = Vectors::hex(
        "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
    );
    let aes = Cipher::name("aes", 16).unwrap();
    unsafe {
        let mut ctr = ptr::null_mut();
        Check::ok(umilib_crypto_mode_ctr_ctr_new(
            aes.as_ptr(),
            aes.len(),
            key.as_ptr(),
            16,
            initial.as_ptr(),
            16,
            &mut ctr,
        ));
        let mut data = plaintext.clone();
        for piece in data.chunks_mut(7) {
            Check::ok(umilib_crypto_mode_ctr_ctr_apply_keystream(ctr, piece.as_mut_ptr(), piece.len()));
        }
        assert_eq!(data, expected);
        umilib_crypto_mode_ctr_ctr_free(ctr);

        // With a 2-bit counter there are 4 blocks of key stream.
        Check::ok(umilib_crypto_mode_ctr_ctr_with_counter_bits(
            aes.as_ptr(),
            aes.len(),
            key.as_ptr(),
            16,
            [0u8; 16].as_ptr(),
            16,
            2,
            &mut ctr,
        ));
        let (mut has_value, mut remaining) = (false, U128::default());
        // Nothing is written unless both outputs can be.
        Check::fails(
            umilib_crypto_mode_ctr_ctr_remaining_bytes(ctr, &mut has_value, ptr::null_mut()),
            "ffi",
            "NullPointer",
        );
        assert!(!has_value);
        Check::ok(umilib_crypto_mode_ctr_ctr_remaining_bytes(ctr, &mut has_value, &mut remaining));
        assert!(has_value);
        assert_eq!(u128::from(remaining), 64);
        let mut block = [0u8; 64];
        Check::ok(umilib_crypto_mode_ctr_ctr_apply_keystream(ctr, block.as_mut_ptr(), 64));
        Check::fails(umilib_crypto_mode_ctr_ctr_apply_keystream(ctr, block.as_mut_ptr(), 1), "crypto", "LimitExceeded");
        umilib_crypto_mode_ctr_ctr_free(ctr);
        Check::fails(
            umilib_crypto_mode_ctr_ctr_with_counter_bits(
                aes.as_ptr(),
                aes.len(),
                key.as_ptr(),
                16,
                [0u8; 16].as_ptr(),
                16,
                129,
                &mut ctr,
            ),
            "crypto",
            "InvalidParameter",
        );
    }
}

#[test]
fn modes_check_the_cipher_the_iv_and_whole_blocks() {
    let aes = Cipher::name("aes", 16).unwrap();
    let unknown = b"umilib_crypto_aes_AES512";
    let key = [1u8; 16];
    unsafe {
        let mut state = ptr::null_mut();
        Check::fails(
            umilib_crypto_mode_cbc_cbc_new(
                unknown.as_ptr(),
                unknown.len(),
                key.as_ptr(),
                16,
                key.as_ptr(),
                16,
                &mut state,
            ),
            "ffi",
            "InvalidArgument",
        );
        Check::fails(
            umilib_crypto_mode_cbc_cbc_new(aes.as_ptr(), aes.len(), key.as_ptr(), 15, key.as_ptr(), 16, &mut state),
            "crypto",
            "KeyLength",
        );
        Check::fails(
            umilib_crypto_mode_cbc_cbc_new(aes.as_ptr(), aes.len(), key.as_ptr(), 16, key.as_ptr(), 8, &mut state),
            "crypto",
            "NonceLength",
        );
        Check::ok(umilib_crypto_mode_cbc_cbc_new(
            aes.as_ptr(),
            aes.len(),
            key.as_ptr(),
            16,
            key.as_ptr(),
            16,
            &mut state,
        ));
        let mut data = [0u8; 17];
        Check::fails(umilib_crypto_mode_cbc_cbc_encrypt(state, data.as_mut_ptr(), 17), "crypto", "InputLength");
        // A copy continues from the same chaining value.
        Check::ok(umilib_crypto_mode_cbc_cbc_encrypt(state, data.as_mut_ptr(), 16));
        let mut copy = ptr::null_mut();
        Check::ok(umilib_crypto_mode_cbc_cbc_clone(state, &mut copy));
        let (mut a, mut b) = ([5u8; 16], [5u8; 16]);
        Check::ok(umilib_crypto_mode_cbc_cbc_encrypt(state, a.as_mut_ptr(), 16));
        Check::ok(umilib_crypto_mode_cbc_cbc_encrypt(copy, b.as_mut_ptr(), 16));
        assert_eq!(a, b);
        umilib_crypto_mode_cbc_cbc_free(state);
        umilib_crypto_mode_cbc_cbc_free(copy);
        // CFB1 takes at most the bits of its data.
        let mut cfb1 = ptr::null_mut();
        Check::ok(umilib_crypto_mode_cfb_cfb1_new(
            aes.as_ptr(),
            aes.len(),
            key.as_ptr(),
            16,
            key.as_ptr(),
            16,
            &mut cfb1,
        ));
        Check::fails(umilib_crypto_mode_cfb_cfb1_encrypt_bits(cfb1, data.as_mut_ptr(), 1, 9), "crypto", "InputLength");
        umilib_crypto_mode_cfb_cfb1_free(cfb1);
        // A 64-bit cipher takes 8-byte IVs.
        let mut ofb = ptr::null_mut();
        let des = b"umilib_crypto_des_DES";
        Check::ok(umilib_crypto_mode_ofb_ofb_new(des.as_ptr(), des.len(), key.as_ptr(), 8, key.as_ptr(), 8, &mut ofb));
        umilib_crypto_mode_ofb_ofb_free(ofb);
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn xts_follows_the_cavp_vectors() {
    let mut checked = 0;
    for file in ["XTSGenAES128", "XTSGenAES256", "XTSGenAES128Sequence", "XTSGenAES256Sequence"] {
        let path = format!("crypto/mode/xts/{file}.rsp");
        for record in Record::all(&path) {
            let bits: usize = record.field("DataUnitLen").parse().unwrap();
            if !bits.is_multiple_of(8) {
                // Data units of bits that do not fill whole bytes are not supported.
                continue;
            }
            let mut tweak = [0u8; 16];
            match record.get("i") {
                Some(value) => tweak.copy_from_slice(&Vectors::hex(value)),
                None => unsafe {
                    let unit: u128 = record.field("DataUnitSeqNumber").parse().unwrap();
                    Check::ok(umilib_crypto_mode_xts_xts_tweak_of(U128::from(unit), tweak.as_mut_ptr(), 16));
                },
            }
            let key = record.bytes("Key");
            let (data_key, tweak_key) = key.split_at(key.len() / 2);
            let cipher = Cipher::name("aes", data_key.len()).unwrap();
            let encrypt = record.header.contains_key("ENCRYPT");
            let (input, output) = if encrypt { ("PT", "CT") } else { ("CT", "PT") };
            let mut data = record.bytes(input);
            unsafe {
                let mut xts = ptr::null_mut();
                Check::ok(umilib_crypto_mode_xts_xts_new(
                    cipher.as_ptr(),
                    cipher.len(),
                    data_key.as_ptr(),
                    data_key.len(),
                    tweak_key.as_ptr(),
                    tweak_key.len(),
                    &mut xts,
                ));
                let run = if encrypt { umilib_crypto_mode_xts_xts_encrypt } else { umilib_crypto_mode_xts_xts_decrypt };
                Check::ok(run(xts, tweak.as_ptr(), 16, data.as_mut_ptr(), data.len()));
                umilib_crypto_mode_xts_xts_free(xts);
            }
            assert_eq!(data, record.bytes(output), "{path} {:?}", record.fields);
            checked += 1;
        }
    }
    assert!(checked > 2000, "{checked}");
}

#[test]
fn xts_rejects_equal_keys_short_units_and_64_bit_ciphers() {
    let aes = Cipher::name("aes", 16).unwrap();
    let des = b"umilib_crypto_des_DES";
    let key = [7u8; 16];
    unsafe {
        let mut xts = ptr::null_mut();
        Check::fails(
            umilib_crypto_mode_xts_xts_new(aes.as_ptr(), aes.len(), key.as_ptr(), 16, key.as_ptr(), 16, &mut xts),
            "crypto",
            "InvalidParameter",
        );
        Check::fails(
            umilib_crypto_mode_xts_xts_new(des.as_ptr(), des.len(), key.as_ptr(), 8, [8u8; 8].as_ptr(), 8, &mut xts),
            "ffi",
            "InvalidArgument",
        );
        Check::ok(umilib_crypto_mode_xts_xts_new(
            aes.as_ptr(),
            aes.len(),
            key.as_ptr(),
            16,
            [8u8; 16].as_ptr(),
            16,
            &mut xts,
        ));
        let mut data = [0u8; 15];
        Check::fails(
            umilib_crypto_mode_xts_xts_encrypt(xts, key.as_ptr(), 16, data.as_mut_ptr(), 15),
            "crypto",
            "InputLength",
        );
        Check::fails(
            umilib_crypto_mode_xts_xts_encrypt(xts, key.as_ptr(), 8, data.as_mut_ptr(), 15),
            "crypto",
            "NonceLength",
        );
        umilib_crypto_mode_xts_xts_free(xts);
    }
}

#[test]
fn pkcs7_pads_to_whole_blocks_and_checks_the_padding() {
    unsafe {
        for length in 0..40usize {
            let data: Vec<u8> = (0..length as u8).collect();
            let mut padded = Buffer::EMPTY;
            Check::ok(umilib_crypto_mode_pkcs7_pad(data.as_ptr(), length, 16, &mut padded));
            let bytes = padded.as_slice().to_vec();
            umilib::ffi::umilib_ffi_buffer_free(&mut padded);
            // RFC 5652 section 6.3: k - (l mod k) bytes, each of that value.
            let count = 16 - length % 16;
            assert_eq!(bytes.len(), length + count);
            assert_eq!(&bytes[..length], &data[..]);
            assert!(bytes[length..].iter().all(|&byte| byte as usize == count));
            let mut unpadded = 0;
            Check::ok(umilib_crypto_mode_pkcs7_unpad_length(bytes.as_ptr(), bytes.len(), 16, &mut unpadded));
            assert_eq!(unpadded, length);
        }
        let mut unpadded = 0;
        for invalid in [&[0u8; 16][..], &[17u8; 16], &[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 2, 3]] {
            Check::fails(
                umilib_crypto_mode_pkcs7_unpad_length(invalid.as_ptr(), invalid.len(), 16, &mut unpadded),
                "crypto",
                "InvalidParameter",
            );
        }
        for partial in [&[][..], &[1u8; 15], &[1u8; 17]] {
            Check::fails(
                umilib_crypto_mode_pkcs7_unpad_length(partial.as_ptr(), partial.len(), 16, &mut unpadded),
                "crypto",
                "InputLength",
            );
        }
        let mut padded = Buffer::EMPTY;
        Check::fails(umilib_crypto_mode_pkcs7_pad([0u8].as_ptr(), 1, 256, &mut padded), "crypto", "InvalidParameter");
    }
}

/// The wrapping (`wrap`) or unwrapping of `data` by KW or KWP (`padding`) over the cipher named
/// `cipher` with `key`, through the C ABI; `None` if it fails.
fn key_wrap(cipher: &[u8], key: &[u8], data: &[u8], padding: bool, wrap: bool) -> Option<Vec<u8>> {
    unsafe {
        let mut out = Buffer::EMPTY;
        let status = if padding {
            let mut state = ptr::null_mut();
            Check::ok(umilib_crypto_mode_kw_kwp_new(
                cipher.as_ptr(),
                cipher.len(),
                key.as_ptr(),
                key.len(),
                &mut state,
            ));
            let function = if wrap { umilib_crypto_mode_kw_kwp_wrap } else { umilib_crypto_mode_kw_kwp_unwrap };
            let status = function(state, data.as_ptr(), data.len(), &mut out);
            umilib_crypto_mode_kw_kwp_free(state);
            status
        } else {
            let mut state = ptr::null_mut();
            Check::ok(umilib_crypto_mode_kw_kw_new(cipher.as_ptr(), cipher.len(), key.as_ptr(), key.len(), &mut state));
            let function = if wrap { umilib_crypto_mode_kw_kw_wrap } else { umilib_crypto_mode_kw_kw_unwrap };
            let status = function(state, data.as_ptr(), data.len(), &mut out);
            umilib_crypto_mode_kw_kw_free(state);
            status
        };
        let result = status.is_null().then(|| out.as_slice().to_vec());
        umilib::ffi::umilib_ffi_buffer_free(&mut out);
        result
    }
}

#[test]
fn key_wrapping_follows_kwvs() {
    // SP 800-38F: KW, KWP and TKW against NIST KWVS, every third record (under Miri, which
    // runs the ciphers thousands of times slower, the first of each file).
    let step = if cfg!(miri) { usize::MAX } else { 3 };
    let files: [(&str, &[u8], bool); 4] = [
        ("KW_AE_256.txt", b"umilib_crypto_aes_AES256", false),
        ("KWP_AD_192.txt", b"umilib_crypto_aes_AES192", true),
        ("TKW_AE.txt", b"umilib_crypto_des_TDES", false),
        ("TKW_AD.txt", b"umilib_crypto_des_TDES", false),
    ];
    for (file, cipher, padding) in files {
        for record in Record::all(&format!("crypto/mode/kw/{file}")).iter().step_by(step) {
            let key = record.bytes("K");
            let wrapped = record.bytes("C");
            if record.get("FAIL").is_some() {
                assert_eq!(key_wrap(cipher, &key, &wrapped, padding, false), None, "{file}");
                continue;
            }
            let plaintext = record.bytes("P");
            assert_eq!(key_wrap(cipher, &key, &plaintext, padding, true), Some(wrapped.clone()), "{file}");
            assert_eq!(key_wrap(cipher, &key, &wrapped, padding, false), Some(plaintext), "{file}");
        }
    }
    // KWP is defined for ciphers of 128-bit blocks only.
    unsafe {
        let (cipher, key) = (b"umilib_crypto_des_TDES", [0u8; 24]);
        let mut state = ptr::null_mut();
        Check::fails(
            umilib_crypto_mode_kw_kwp_new(cipher.as_ptr(), cipher.len(), key.as_ptr(), key.len(), &mut state),
            "ffi",
            "InvalidArgument",
        );
    }
}
