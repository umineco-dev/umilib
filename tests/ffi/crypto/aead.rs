//! The AEADs of the C ABI against the Project Wycheproof vectors: GCM, CCM,
//! GCM-SIV and SIV over every block cipher C can name, ChaCha20-Poly1305,
//! XChaCha20-Poly1305, AEGIS and Ascon-AEAD128.

use std::ptr;

use umilib::ffi::Status;
use umilib::ffi::crypto::aegis::{aegis128x, aegis256x};
use umilib::ffi::crypto::ascon;
use umilib::ffi::crypto::chacha20poly1305::{chacha20poly1305, xchacha20poly1305};
use umilib::ffi::crypto::mode::{ccm, gcm, gcmsiv, siv};

use super::Cipher;
use crate::Check;
use crate::vectors::{JSON, Wycheproof};

type Encrypt<T> =
    unsafe extern "C" fn(*const T, *const u8, usize, *const u8, usize, *mut u8, usize, *mut u8, usize) -> *const Status;
type Decrypt<T> = unsafe extern "C" fn(
    *const T,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *const u8,
    usize,
) -> *const Status;

/// What an AEAD leaves in the buffer when the tag does not authenticate it.
#[derive(Clone, Copy)]
enum Failure {
    /// The ciphertext, as it was.
    Restores,
    /// Zeros (AEGIS, section 4.3 of its draft).
    Zeroes,
}

/// The functions of one AEAD type of the C ABI.
struct Suite<T> {
    encrypt: Encrypt<T>,
    decrypt: Decrypt<T>,
    free: unsafe extern "C" fn(*mut T),
    failure: Failure,
}

impl<T> Suite<T> {
    /// The handle written by a constructor, or null if it failed.
    fn created(status: *const Status, handle: *mut T) -> *mut T {
        if status.is_null() { handle } else { ptr::null_mut() }
    }

    /// Runs every test of the Wycheproof file `path` with the AEAD `create` makes for the group and the
    /// test (null if it refuses them, which only an invalid test may make it do): a valid test encrypts
    /// to its ciphertext and tag and decrypts back; an invalid one fails to decrypt. Returns the number
    /// of tests.
    fn run(&self, path: &str, create: impl Fn(&JSON, &JSON) -> *mut T) -> usize {
        let tests = Wycheproof::tests(path);
        assert!(!tests.is_empty(), "{path}");
        for (group, test) in &tests {
            let label = format!("{path} tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
            let valid = test.field("result").as_str() == "valid";
            let (iv, aad, message, ciphertext, tag) =
                (test.bytes("iv"), test.bytes("aad"), test.bytes("msg"), test.bytes("ct"), test.bytes("tag"));
            let aead = create(group, test);
            if aead.is_null() {
                assert!(!valid, "{label}: refused");
                continue;
            }
            unsafe {
                let mut buffer = ciphertext.clone();
                let status = (self.decrypt)(
                    aead,
                    iv.as_ptr(),
                    iv.len(),
                    aad.as_ptr(),
                    aad.len(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    tag.as_ptr(),
                    tag.len(),
                );
                if valid {
                    Check::ok(status);
                    assert_eq!(buffer, message, "{label}");
                    let mut buffer = message.clone();
                    let mut computed = vec![0u8; tag.len()];
                    Check::ok((self.encrypt)(
                        aead,
                        iv.as_ptr(),
                        iv.len(),
                        aad.as_ptr(),
                        aad.len(),
                        buffer.as_mut_ptr(),
                        buffer.len(),
                        computed.as_mut_ptr(),
                        computed.len(),
                    ));
                    assert_eq!((buffer, computed), (ciphertext, tag), "{label}");
                } else {
                    let status = status.as_ref().unwrap_or_else(|| panic!("{label}: accepted"));
                    if status.name() == c"AuthenticationFailed" {
                        match self.failure {
                            Failure::Restores => assert_eq!(buffer, ciphertext, "{label}: the ciphertext is kept"),
                            Failure::Zeroes => assert!(buffer.iter().all(|&byte| byte == 0), "{label}: zeroed"),
                        }
                    }
                }
                (self.free)(aead);
            }
        }
        tests.len()
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn gcm_follows_the_wycheproof_vectors_for_every_cipher() {
    let suite = Suite {
        encrypt: gcm::encrypt_in_place,
        decrypt: gcm::decrypt_in_place,
        free: gcm::free,
        failure: Failure::Restores,
    };
    for (path, family) in [
        ("crypto/mode/gcm/aes_gcm_test.json", "aes"),
        ("crypto/aria/aria_gcm_test.json", "aria"),
        ("crypto/seed/seed_gcm_test.json", "seed"),
        ("crypto/sm4/sm4_gcm_test.json", "sm4"),
    ] {
        suite.run(path, |group, test| {
            let key = test.bytes("key");
            let Some(cipher) = Cipher::name(family, key.len()) else { return ptr::null_mut() };
            let mut gcm = ptr::null_mut();
            let tag_size = group.field("tagSize").as_usize() / 8;
            let status = unsafe {
                gcm::umilib_crypto_mode_gcm_gcm_new(
                    cipher.as_ptr(),
                    cipher.len(),
                    key.as_ptr(),
                    key.len(),
                    tag_size,
                    &mut gcm,
                )
            };
            Suite::created(status, gcm)
        });
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn ccm_follows_the_wycheproof_vectors_for_every_cipher() {
    let suite = Suite {
        encrypt: ccm::encrypt_in_place,
        decrypt: ccm::decrypt_in_place,
        free: ccm::free,
        failure: Failure::Restores,
    };
    for (path, family) in [
        ("crypto/mode/ccm/aes_ccm_test.json", "aes"),
        ("crypto/aria/aria_ccm_test.json", "aria"),
        ("crypto/camellia/camellia_ccm_test.json", "camellia"),
        ("crypto/seed/seed_ccm_test.json", "seed"),
        ("crypto/sm4/sm4_ccm_test.json", "sm4"),
    ] {
        suite.run(path, |group, test| {
            let key = test.bytes("key");
            let Some(cipher) = Cipher::name(family, key.len()) else { return ptr::null_mut() };
            let mut ccm = ptr::null_mut();
            let tag_size = group.field("tagSize").as_usize() / 8;
            let status = unsafe {
                ccm::umilib_crypto_mode_ccm_ccm_new(
                    cipher.as_ptr(),
                    cipher.len(),
                    key.as_ptr(),
                    key.len(),
                    tag_size,
                    &mut ccm,
                )
            };
            Suite::created(status, ccm)
        });
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn gcmsiv_follows_the_wycheproof_vectors() {
    let suite = Suite {
        encrypt: gcmsiv::encrypt_in_place,
        decrypt: gcmsiv::decrypt_in_place,
        free: gcmsiv::free,
        failure: Failure::Restores,
    };
    let count = suite.run("crypto/mode/gcmsiv/aes_gcm_siv_test.json", |_, test| {
        let key = test.bytes("key");
        let Some(cipher) = Cipher::name("aes", key.len()) else { return ptr::null_mut() };
        let mut aead = ptr::null_mut();
        let status = unsafe {
            gcmsiv::umilib_crypto_mode_gcmsiv_gcmsiv_new(
                cipher.as_ptr(),
                cipher.len(),
                key.as_ptr(),
                key.len(),
                &mut aead,
            )
        };
        Suite::created(status, aead)
    });
    assert_eq!(count, 202);
}

/// SIV over AES with the key K1 || K2 of a test, or null for another key length.
fn siv(key: &[u8]) -> *mut umilib::crypto::mode::siv::SIV<umilib::ffi::crypto::BlockCipher128> {
    let (k1, k2) = key.split_at(key.len() / 2);
    let Some(cipher) = Cipher::name("aes", k1.len()).filter(|_| key.len().is_multiple_of(2)) else {
        return ptr::null_mut();
    };
    let mut siv = ptr::null_mut();
    let status = unsafe {
        siv::umilib_crypto_mode_siv_siv_new(
            cipher.as_ptr(),
            cipher.len(),
            k1.as_ptr(),
            k1.len(),
            k2.as_ptr(),
            k2.len(),
            &mut siv,
        )
    };
    Suite::created(status, siv)
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn siv_follows_the_wycheproof_aead_vectors() {
    let suite = Suite {
        encrypt: siv::encrypt_in_place,
        decrypt: siv::decrypt_in_place,
        free: siv::free,
        failure: Failure::Restores,
    };
    let count = suite.run("crypto/mode/siv/aead_aes_siv_cmac_test.json", |_, test| siv(&test.bytes("key")));
    assert_eq!(count, 900);
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn siv_follows_the_wycheproof_deterministic_vectors() {
    let tests = Wycheproof::tests("crypto/mode/siv/aes_siv_cmac_test.json");
    assert_eq!(tests.len(), 442);
    for (_, test) in &tests {
        let label = format!("tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
        let valid = test.field("result").as_str() == "valid";
        let (aad, message, sealed) = (test.bytes("aad"), test.bytes("msg"), test.bytes("ct"));
        let state = siv(&test.bytes("key"));
        if state.is_null() || sealed.len() < 16 {
            assert!(!valid, "{label}");
            continue;
        }
        let components = [aad.as_ptr()];
        let lengths = [aad.len()];
        unsafe {
            let (v, ciphertext) = sealed.split_at(16);
            let mut buffer = ciphertext.to_vec();
            let status = siv::umilib_crypto_mode_siv_siv_decrypt_vector_in_place(
                state,
                components.as_ptr(),
                lengths.as_ptr(),
                1,
                buffer.as_mut_ptr(),
                buffer.len(),
                v.as_ptr(),
                16,
            );
            if valid {
                Check::ok(status);
                assert_eq!(buffer, message, "{label}");
                let mut buffer = message.clone();
                let mut computed = [0u8; 16];
                Check::ok(siv::umilib_crypto_mode_siv_siv_encrypt_vector_in_place(
                    state,
                    components.as_ptr(),
                    lengths.as_ptr(),
                    1,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    computed.as_mut_ptr(),
                    16,
                ));
                assert_eq!([&computed[..], &buffer].concat(), sealed, "{label}");
            } else {
                Check::fails(status, "crypto", "AuthenticationFailed");
                assert_eq!(buffer, ciphertext, "{label}");
            }
            siv::free(state);
        }
    }
}

#[test]
fn siv_takes_at_most_126_components_and_16_byte_vs() {
    let state = siv(&[7u8; 32]);
    assert!(!state.is_null());
    let components = [ptr::null::<u8>(); 127];
    let lengths = [0usize; 127];
    let mut buffer = [1u8; 20];
    let mut v = [0u8; 16];
    unsafe {
        Check::fails(
            siv::umilib_crypto_mode_siv_siv_encrypt_vector_in_place(
                state,
                components.as_ptr(),
                lengths.as_ptr(),
                127,
                buffer.as_mut_ptr(),
                20,
                v.as_mut_ptr(),
                16,
            ),
            "crypto",
            "InvalidParameter",
        );
        Check::ok(siv::umilib_crypto_mode_siv_siv_encrypt_vector_in_place(
            state,
            components.as_ptr(),
            lengths.as_ptr(),
            126,
            buffer.as_mut_ptr(),
            20,
            v.as_mut_ptr(),
            16,
        ));
        Check::fails(
            siv::umilib_crypto_mode_siv_siv_encrypt_vector_in_place(
                state,
                components.as_ptr(),
                lengths.as_ptr(),
                0,
                buffer.as_mut_ptr(),
                20,
                v.as_mut_ptr(),
                15,
            ),
            "crypto",
            "TagLength",
        );
        // Section 6: the nonce of the AEAD has at least one byte.
        Check::fails(
            siv::encrypt_in_place(state, ptr::null(), 0, ptr::null(), 0, buffer.as_mut_ptr(), 20, v.as_mut_ptr(), 16),
            "crypto",
            "NonceLength",
        );
        siv::free(state);
    }
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn chacha20_poly1305_follows_the_wycheproof_vectors() {
    let chacha = Suite {
        encrypt: chacha20poly1305::encrypt_in_place,
        decrypt: chacha20poly1305::decrypt_in_place,
        free: chacha20poly1305::free,
        failure: Failure::Restores,
    };
    let count = chacha.run("crypto/chacha20poly1305/chacha20_poly1305_test.json", |_, test| {
        let key = test.bytes("key");
        let mut aead = ptr::null_mut();
        let status = unsafe {
            chacha20poly1305::umilib_crypto_chacha20poly1305_chacha20poly1305_new(key.as_ptr(), key.len(), &mut aead)
        };
        Suite::created(status, aead)
    });
    assert_eq!(count, 325);
    let xchacha = Suite {
        encrypt: xchacha20poly1305::encrypt_in_place,
        decrypt: xchacha20poly1305::decrypt_in_place,
        free: xchacha20poly1305::free,
        failure: Failure::Restores,
    };
    let count = xchacha.run("crypto/chacha20poly1305/xchacha20_poly1305_test.json", |_, test| {
        let key = test.bytes("key");
        let mut aead = ptr::null_mut();
        let status = unsafe {
            xchacha20poly1305::umilib_crypto_chacha20poly1305_xchacha20poly1305_new(key.as_ptr(), key.len(), &mut aead)
        };
        Suite::created(status, aead)
    });
    assert_eq!(count, 315);
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn aegis_follows_the_wycheproof_vectors() {
    let aegis128 = Suite {
        encrypt: aegis128x::encrypt_in_place,
        decrypt: aegis128x::decrypt_in_place,
        free: aegis128x::free,
        failure: Failure::Zeroes,
    };
    let count = aegis128.run("crypto/aegis/aegis128L_test.json", |group, test| {
        let key = test.bytes("key");
        let mut aead = ptr::null_mut();
        let tag_size = group.field("tagSize").as_usize() / 8;
        let status = unsafe { aegis128x::new(1, tag_size, key.as_ptr(), key.len(), &mut aead) };
        Suite::created(status, aead)
    });
    assert_eq!(count, 479);
    let aegis256 = Suite {
        encrypt: aegis256x::encrypt_in_place,
        decrypt: aegis256x::decrypt_in_place,
        free: aegis256x::free,
        failure: Failure::Zeroes,
    };
    let count = aegis256.run("crypto/aegis/aegis256_test.json", |group, test| {
        let key = test.bytes("key");
        let mut aead = ptr::null_mut();
        let tag_size = group.field("tagSize").as_usize() / 8;
        let status = unsafe { aegis256x::new(1, tag_size, key.as_ptr(), key.len(), &mut aead) };
        Suite::created(status, aead)
    });
    assert_eq!(count, 472);
}

#[test]
#[cfg_attr(miri, ignore = "too many vectors for Miri; the other tests reach the same functions")]
fn ascon_aead128_follows_the_wycheproof_vectors() {
    let suite = Suite {
        encrypt: ascon::encrypt_in_place,
        decrypt: ascon::decrypt_in_place,
        free: ascon::free,
        failure: Failure::Restores,
    };
    let count = suite.run("crypto/ascon/ascon_sp800_232_aead128_test.json", |group, test| {
        let key = test.bytes("key");
        let mut aead = ptr::null_mut();
        let tag_size = group.field("tagSize").as_usize() / 8;
        let status =
            unsafe { ascon::umilib_crypto_ascon_ascon_aead128_new(tag_size, key.as_ptr(), key.len(), &mut aead) };
        Suite::created(status, aead)
    });
    assert_eq!(count, 252);
}

#[test]
fn aeads_report_their_sizes_and_refuse_other_choices() {
    let aes = Cipher::name("aes", 16).unwrap();
    let key = [0u8; 32];
    unsafe {
        let mut gcm = ptr::null_mut();
        for tag_size in [0, 3, 5, 9, 11, 17] {
            Check::fails(
                gcm::umilib_crypto_mode_gcm_gcm_new(aes.as_ptr(), aes.len(), key.as_ptr(), 16, tag_size, &mut gcm),
                "crypto",
                "TagLength",
            );
        }
        let des = b"umilib_crypto_des_DES";
        Check::fails(
            gcm::umilib_crypto_mode_gcm_gcm_new(des.as_ptr(), des.len(), key.as_ptr(), 8, 16, &mut gcm),
            "ffi",
            "InvalidArgument",
        );
        Check::ok(gcm::umilib_crypto_mode_gcm_gcm_new(aes.as_ptr(), aes.len(), key.as_ptr(), 16, 12, &mut gcm));
        let mut size = 0;
        Check::ok(gcm::nonce_size(gcm, &mut size));
        assert_eq!(size, 12);
        Check::ok(gcm::tag_size(gcm, &mut size));
        assert_eq!(size, 12);
        let mut copy = ptr::null_mut();
        Check::ok(gcm::clone(gcm, &mut copy));
        let mut buffer = [0u8; 4];
        let mut tag = [0u8; 16];
        Check::fails(
            gcm::encrypt_in_place(copy, key.as_ptr(), 12, ptr::null(), 0, buffer.as_mut_ptr(), 4, tag.as_mut_ptr(), 16),
            "crypto",
            "TagLength",
        );
        // The buffer may not overlap the tag.
        Check::fails(
            gcm::encrypt_in_place(
                copy,
                key.as_ptr(),
                12,
                ptr::null(),
                0,
                tag.as_mut_ptr(),
                4,
                tag.as_mut_ptr().add(2),
                12,
            ),
            "ffi",
            "InvalidArgument",
        );
        gcm::free(copy);
        gcm::free(gcm);

        let mut ccm = ptr::null_mut();
        Check::fails(
            ccm::umilib_crypto_mode_ccm_ccm_new(aes.as_ptr(), aes.len(), key.as_ptr(), 16, 5, &mut ccm),
            "crypto",
            "TagLength",
        );
        let mut aegis = ptr::null_mut();
        Check::fails(aegis128x::new(3, 16, key.as_ptr(), 16, &mut aegis), "crypto", "InvalidParameter");
        Check::fails(aegis128x::new(2, 24, key.as_ptr(), 16, &mut aegis), "crypto", "TagLength");
        Check::fails(aegis256x::new(4, 32, key.as_ptr(), 16, &mut ptr::null_mut()), "crypto", "KeyLength");
        let mut ascon = ptr::null_mut();
        Check::fails(
            ascon::umilib_crypto_ascon_ascon_aead128_new(17, key.as_ptr(), 16, &mut ascon),
            "crypto",
            "TagLength",
        );
        Check::fails(
            ascon::umilib_crypto_ascon_ascon_aead128_new(3, key.as_ptr(), 16, &mut ascon),
            "crypto",
            "TagLength",
        );
    }
}
