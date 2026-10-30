//! The block ciphers of the C ABI against the known answers of their
//! specifications: FIPS 197 (AESAVS), SP 800-67 (TDES), RFC 2268, NESSIE,
//! RFC 8891, RFC 7801, RFC 4269 and the SM4 draft. ARIA and Camellia are
//! checked through the modes, with the Wycheproof vectors.

use std::ptr;

use umilib::ffi::Status;
use umilib::ffi::crypto::aes::{self, aes128, aes192, aes256};
use umilib::ffi::crypto::des::{self, tdes};
use umilib::ffi::crypto::gost::{kuznyechik, magma};
use umilib::ffi::crypto::{idea, rc2, seed, sm4};

use crate::Check;
use crate::vectors::{Nessie, Record, Vectors};

/// The functions of one block cipher type of the C ABI.
struct Functions<T> {
    new: unsafe extern "C" fn(*const u8, usize, *mut *mut T) -> *const Status,
    encrypt: unsafe extern "C" fn(*const T, *mut u8, usize) -> *const Status,
    decrypt: unsafe extern "C" fn(*const T, *mut u8, usize) -> *const Status,
    free: unsafe extern "C" fn(*mut T),
}

impl<T> Functions<T> {
    /// Encrypts `plaintext` with `key`, checks it against `ciphertext`, and decrypts it back.
    fn check(&self, key: &[u8], plaintext: &[u8], ciphertext: &[u8], label: &str) {
        unsafe {
            let mut cipher = ptr::null_mut();
            Check::ok((self.new)(key.as_ptr(), key.len(), &mut cipher));
            let mut block = plaintext.to_vec();
            Check::ok((self.encrypt)(cipher, block.as_mut_ptr(), block.len()));
            assert_eq!(block, ciphertext, "{label}");
            Check::ok((self.decrypt)(cipher, block.as_mut_ptr(), block.len()));
            assert_eq!(block, plaintext, "{label}");
            (self.free)(cipher);
        }
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn aes_follows_the_aesavs_known_answers() {
    let mut checked = 0;
    for kind in ["GFSbox", "KeySbox", "VarKey", "VarTxt"] {
        for size in [128, 192, 256] {
            let path = format!("crypto/aes/ECB{kind}{size}.rsp");
            for record in Record::all(&path).iter().filter(|record| record.header.contains_key("ENCRYPT")) {
                let (key, plaintext, ciphertext) =
                    (record.bytes("KEY"), record.bytes("PLAINTEXT"), record.bytes("CIPHERTEXT"));
                let label = format!("{path} {:?}", record.fields);
                match size {
                    128 => Functions {
                        new: aes128::new,
                        encrypt: aes128::encrypt_blocks,
                        decrypt: aes128::decrypt_blocks,
                        free: aes128::free,
                    }
                    .check(&key, &plaintext, &ciphertext, &label),
                    192 => Functions {
                        new: aes192::new,
                        encrypt: aes192::encrypt_blocks,
                        decrypt: aes192::decrypt_blocks,
                        free: aes192::free,
                    }
                    .check(&key, &plaintext, &ciphertext, &label),
                    _ => Functions {
                        new: aes256::new,
                        encrypt: aes256::encrypt_blocks,
                        decrypt: aes256::decrypt_blocks,
                        free: aes256::free,
                    }
                    .check(&key, &plaintext, &ciphertext, &label),
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 1000, "{checked}");
}

#[test]
fn block_ciphers_report_their_sizes_and_check_their_inputs() {
    unsafe {
        assert_eq!(aes128::block_size(), 16);
        assert_eq!((aes192::minimum_key_size(), aes192::maximum_key_size()), (24, 24));
        assert_eq!(des::des::block_size(), 8);
        assert_eq!((tdes::minimum_key_size(), tdes::maximum_key_size()), (16, 24));
        let mut cipher = ptr::null_mut();
        Check::fails(aes128::new([0u8; 15].as_ptr(), 15, &mut cipher), "crypto", "KeyLength");
        Check::ok(aes128::new([0u8; 16].as_ptr(), 16, &mut cipher));
        let mut data = [0u8; 33];
        Check::fails(aes128::encrypt_blocks(cipher, data.as_mut_ptr(), 33), "crypto", "InputLength");
        Check::ok(aes128::encrypt_blocks(cipher, data.as_mut_ptr(), 32));
        // Each block is encrypted alone.
        assert_eq!(data[..16], data[16..32]);
        let mut copy = ptr::null_mut();
        Check::ok(aes128::clone(cipher, &mut copy));
        Check::ok(aes128::decrypt_blocks(copy, data.as_mut_ptr(), 32));
        assert_eq!(data[..32], [0u8; 32]);
        aes128::free(copy);
        aes128::free(cipher);
        aes128::free(ptr::null_mut());
    }
}

#[test]
fn aes_round_follows_the_aegis_draft() {
    let records = Record::all("crypto/aegis/draft-irtf-cfrg-aegis-aead.txt");
    let round = records.iter().find(|record| record.field("Group") == "AESRound").unwrap();
    let mut blocks = round.bytes("in");
    let keys = round.bytes("rk");
    unsafe {
        Check::ok(aes::umilib_crypto_aes_aes_bitslice_round(blocks.as_mut_ptr(), keys.as_ptr(), 16));
        assert_eq!(blocks, round.bytes("out"));
        Check::fails(
            aes::umilib_crypto_aes_aes_bitslice_round(blocks.as_mut_ptr(), keys.as_ptr(), 8),
            "crypto",
            "InputLength",
        );
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn des_and_tdes_follow_the_cavp_known_answers() {
    let des = Functions {
        new: des::des::new,
        encrypt: des::des::encrypt_blocks,
        decrypt: des::des::decrypt_blocks,
        free: des::des::free,
    };
    let mut checked = 0;
    for file in ["TECBvartext", "TECBvarkey", "TECBpermop", "TECBsubtab", "TECBinvperm"] {
        let path = format!("crypto/des/{file}.rsp");
        for record in Record::all(&path).iter().filter(|record| record.header.contains_key("ENCRYPT")) {
            // With the three keys equal, TDES is DES with that key.
            let label = format!("{path} {:?}", record.fields);
            des.check(&record.bytes("KEYs"), &record.bytes("PLAINTEXT"), &record.bytes("CIPHERTEXT"), &label);
            checked += 1;
        }
    }
    assert_eq!(checked, 235);
    let tdes =
        Functions { new: tdes::new, encrypt: tdes::encrypt_blocks, decrypt: tdes::decrypt_blocks, free: tdes::free };
    for record in Record::all("crypto/des/TECBMMT3.rsp").iter().filter(|record| record.header.contains_key("ENCRYPT")) {
        let key = [record.bytes("KEY1"), record.bytes("KEY2"), record.bytes("KEY3")].concat();
        tdes.check(&key, &record.bytes("PLAINTEXT"), &record.bytes("CIPHERTEXT"), &format!("{:?}", record.fields));
    }
    unsafe {
        // SP 800-67r2 section 3.1: the keys of a bundle are distinct.
        let mut cipher = ptr::null_mut();
        let bundle = [[1u8; 8], [1u8; 8], [2u8; 8]].concat();
        Check::fails(tdes::new(bundle.as_ptr(), 24, &mut cipher), "crypto", "InvalidParameter");
        // Section 3.3.2: weak, semi-weak and possibly weak keys, whatever the parity bits.
        let mut weak = false;
        for (key, expected) in [
            (Vectors::hex("0101010101010101"), true),
            (Vectors::hex("0000000000000000"), true),
            (Vectors::hex("011f011f010e010e"), true),
            (Vectors::hex("0123456789abcdef"), false),
        ] {
            Check::ok(des::umilib_crypto_des_des_is_weak(key.as_ptr(), 8, &mut weak));
            assert_eq!(weak, expected, "{key:02x?}");
        }
        Check::fails(des::umilib_crypto_des_des_is_weak([0u8; 7].as_ptr(), 7, &mut weak), "crypto", "KeyLength");
    }
}

#[test]
fn rc2_follows_rfc2268_section_5() {
    let records = Record::all("crypto/rc2/rfc2268.txt");
    assert_eq!(records.len(), 8);
    for record in records {
        let bits: usize = record.field("EffectiveBits").parse().unwrap();
        let key = record.bytes("Key");
        let mut block = record.bytes("Plaintext");
        unsafe {
            let mut cipher = ptr::null_mut();
            Check::ok(rc2::umilib_crypto_rc2_rc2_new_with_effective_bits(key.as_ptr(), key.len(), bits, &mut cipher));
            Check::ok(rc2::rc2::encrypt_blocks(cipher, block.as_mut_ptr(), 8));
            assert_eq!(block, record.bytes("Ciphertext"), "{:?}", record.fields);
            Check::ok(rc2::rc2::decrypt_blocks(cipher, block.as_mut_ptr(), 8));
            assert_eq!(block, record.bytes("Plaintext"));
            rc2::rc2::free(cipher);
            // A key of 8 × length effective bits, the default of `_new`.
            if bits == 8 * key.len() {
                Check::ok(rc2::rc2::new(key.as_ptr(), key.len(), &mut cipher));
                Check::ok(rc2::rc2::encrypt_blocks(cipher, block.as_mut_ptr(), 8));
                assert_eq!(block, record.bytes("Ciphertext"));
                rc2::rc2::free(cipher);
            }
        }
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn idea_follows_the_nessie_vectors() {
    let idea = Functions {
        new: idea::idea::new,
        encrypt: idea::idea::encrypt_blocks,
        decrypt: idea::idea::decrypt_blocks,
        free: idea::idea::free,
    };
    let vectors = Nessie::vectors("crypto/idea/Idea-128-64.verified.test-vectors");
    assert!(vectors.len() > 700);
    for (label, fields) in &vectors {
        idea.check(
            &Vectors::hex(&fields["key"]),
            &Vectors::hex(&fields["plain"]),
            &Vectors::hex(&fields["cipher"]),
            label,
        );
    }
}

#[test]
fn gost_ciphers_follow_rfc8891_and_rfc7801() {
    let magma = Functions {
        new: magma::magma::new,
        encrypt: magma::magma::encrypt_blocks,
        decrypt: magma::magma::decrypt_blocks,
        free: magma::magma::free,
    };
    // RFC 8891 appendix A.3 to A.5.
    magma.check(
        &Vectors::hex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        &Vectors::hex("fedcba9876543210"),
        &Vectors::hex("4ee901e5c2d8ca3d"),
        "Magma",
    );
    let kuznyechik = Functions {
        new: kuznyechik::kuznyechik::new,
        encrypt: kuznyechik::kuznyechik::encrypt_blocks,
        decrypt: kuznyechik::kuznyechik::decrypt_blocks,
        free: kuznyechik::kuznyechik::free,
    };
    // RFC 7801 sections 5.5 and 5.6.
    kuznyechik.check(
        &Vectors::hex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
        &Vectors::hex("1122334455667700ffeeddccbbaa9988"),
        &Vectors::hex("7f679d90bebc24305a468d42b9d4edcd"),
        "Kuznyechik",
    );
}

#[test]
fn seed_and_sm4_follow_their_specifications() {
    let seed = Functions {
        new: seed::seed::new,
        encrypt: seed::seed::encrypt_blocks,
        decrypt: seed::seed::decrypt_blocks,
        free: seed::seed::free,
    };
    let mut checked = 0;
    for record in Record::all("crypto/seed/rfc4269.txt").iter().filter(|record| record.field("Name").starts_with("B."))
    {
        seed.check(&record.bytes("Key"), &record.bytes("Plaintext"), &record.bytes("Ciphertext"), record.field("Name"));
        checked += 1;
    }
    assert_eq!(checked, 4);
    let sm4 = Functions {
        new: sm4::sm4::new,
        encrypt: sm4::sm4::encrypt_blocks,
        decrypt: sm4::sm4::decrypt_blocks,
        free: sm4::sm4::free,
    };
    let mut checked = 0;
    for record in Record::all("crypto/sm4/draft-ribose-cfrg-sm4.txt").iter().filter(|record| {
        record.field("Mode") == "SM4" && record.get("Key").is_some() && record.get("Iterations").is_none()
    }) {
        sm4.check(&record.bytes("Key"), &record.bytes("Plaintext"), &record.bytes("Ciphertext"), record.field("Name"));
        checked += 1;
    }
    assert!(checked >= 2, "{checked}");
}
