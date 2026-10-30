//! The C ABI of `umilib::crypto::sm9` against the examples of GM/T
//! 0044.5-2016 annexes B, C and D.

use std::ptr;

use umilib::ffi::Buffer;
use umilib::ffi::crypto::sm9::*;

use super::{Bytes, Generator};
use crate::Check;
use crate::vectors::GMT;

const CURVE: &[u8] = b"umilib_math_pairing_SM9BN256";
const SM3: &[u8] = b"umilib_hash_sm3_SM3";
const STREAM: &[u8] = b"umilib_crypto_sm9_SM9StreamCipher";
const SM4: &[u8] = b"umilib_crypto_sm4_SM4";
const HID: u8 = 0x03;

type Master = *mut Box<dyn SM9MasterState>;
type User = *mut Box<dyn SM9UserState>;
type Side = *mut Box<dyn SM9KEPState>;

/// The bytes of a buffer the function writes.
fn output(write: impl FnOnce(*mut Buffer) -> *const umilib::ffi::Status) -> Vec<u8> {
    let mut buffer = Buffer::default();
    Check::ok(write(&mut buffer));
    Bytes::take(buffer)
}

/// The master key of an annex: ke and Ppub-e.
fn master(annex: &GMT) -> (Master, Vec<u8>) {
    let secret = annex.padded("The master encryption private key ??:", 32);
    let mut master = ptr::null_mut();
    unsafe {
        Check::ok(umilib_crypto_sm9_sm9_encrypt_master_key_new(
            CURVE.as_ptr(),
            CURVE.len(),
            secret.as_ptr(),
            secret.len(),
            &mut master,
        ));
        assert_eq!(output(|out| umilib_crypto_sm9_sm9_encrypt_master_key_secret(master, out)), secret);
    }
    let public = unsafe { output(|out| umilib_crypto_sm9_sm9_encrypt_master_key_public_key(master, out)) };
    assert_eq!(
        public,
        annex.values("The master encryption public key ????−? = ?? ?1 = (?????−?,?????−?):", 2).concat()
    );
    (master, public)
}

/// The key of `identity` with hid = 03, checked against de of the part of the annex that computes it.
fn user(master: Master, part: &GMT, identity: &[u8]) -> User {
    let mut user = ptr::null_mut();
    unsafe {
        Check::ok(umilib_crypto_sm9_sm9_encrypt_master_key_extract(
            master,
            SM3.as_ptr(),
            SM3.len(),
            identity.as_ptr(),
            identity.len(),
            HID,
            &mut user,
        ));
        let key = output(|out| umilib_crypto_sm9_sm9_encrypt_user_key_key(user, out));
        assert_eq!(key, [&[0x04][..], &part.values("in ??:", 8)[4..8].concat()].concat());
        assert_eq!(output(|out| umilib_crypto_sm9_sm9_encrypt_user_key_identity(user, out)), identity);
        let mut hid = 0;
        Check::ok(umilib_crypto_sm9_sm9_encrypt_user_key_hid(user, &mut hid));
        assert_eq!(hid, HID);
    }
    user
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm9_sizes() {
    let mut sizes = [0usize; 4];
    unsafe {
        Check::ok(umilib_crypto_sm9_sizes(CURVE.as_ptr(), CURVE.len(), SM3.as_ptr(), SM3.len(), sizes.as_mut_ptr()));
        assert_eq!(sizes, [32, 64, 129, 32]);
        let unknown = b"umilib_math_pairing_BN000";
        Check::fails(
            umilib_crypto_sm9_sizes(unknown.as_ptr(), unknown.len(), SM3.as_ptr(), SM3.len(), sizes.as_mut_ptr()),
            "ffi",
            "InvalidArgument",
        );
    }
}

/// Annex B: SK, S_B and S_A of the given r_A and r_B, both sides through the C ABI.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm9_annex_b_key_exchange() {
    let annex = GMT::read("crypto/sm9/gmt-0044.5-2016-annex-b.txt");
    let (master, _) = master(&annex);
    let alice = user(
        master,
        &annex.section("The identity ??? of the entity A: Alice", "The identity ??? of the entity B"),
        b"Alice",
    );
    let bob = user(master, &annex.section("The identity ??? of the entity B: Bob", "The length ????"), b"Bob");
    let initiator_values = annex
        .section("The related values in the steps A1—A4", "The related values in the steps B1—B7")
        .values("(???,???):", 7);
    let responder_values = annex
        .section("The related values in the steps B1—B7", "The related values in the steps A5—A8")
        .values("(???,???):", 49);
    let side = |key: User, role: u8, peer: &[u8], ephemeral: &[u8]| {
        let ephemeral = [vec![0u8; 32 - ephemeral.len()], ephemeral.to_vec()].concat();
        let mut side: Side = ptr::null_mut();
        unsafe {
            Check::ok(umilib_crypto_sm9_sm9kep_new(
                key,
                SM3.as_ptr(),
                SM3.len(),
                role,
                peer.as_ptr(),
                peer.len(),
                ephemeral.as_ptr(),
                ephemeral.len(),
                &mut side,
            ));
        }
        side
    };
    let initiator = side(alice, 0, b"Bob", &initiator_values[4]);
    let responder = side(bob, 1, b"Alice", &responder_values[4]);
    unsafe {
        let r_a = output(|out| umilib_crypto_sm9_sm9kep_ephemeral_public_key(initiator, out));
        let r_b = output(|out| umilib_crypto_sm9_sm9kep_ephemeral_public_key(responder, out));
        assert_eq!(r_a, initiator_values[5..7].concat());
        assert_eq!(r_b, responder_values[5..7].concat());
        let agree = |side: Side, peer: &[u8]| {
            let (mut key, mut s_b, mut s_a) = ([0u8; 16], [0u8; 32], [0u8; 32]);
            Check::ok(umilib_crypto_sm9_sm9kep_agree(
                side,
                peer.as_ptr(),
                peer.len(),
                key.as_mut_ptr(),
                16,
                s_b.as_mut_ptr(),
                32,
                s_a.as_mut_ptr(),
                32,
            ));
            (key, s_b, s_a)
        };
        let (key, s_b, s_a) = agree(responder, &r_a);
        assert_eq!(agree(initiator, &r_b), (key, s_b, s_a));
        assert_eq!(key.to_vec(), responder_values[44]);
        assert_eq!(s_b.to_vec(), responder_values[48]);
        let confirmation = annex.section("The related values in the step B8", "If ?2 = ??");
        assert_eq!(s_a.to_vec(), confirmation.value("\n?2: "));
        // R must be a point of G_1; the confirmations have the bytes of SM3.
        let (mut key, mut s_b, mut s_a) = ([0u8; 16], [0u8; 32], [0u8; 31]);
        Check::fails(
            umilib_crypto_sm9_sm9kep_agree(
                responder,
                [0u8; 64].as_ptr(),
                64,
                key.as_mut_ptr(),
                16,
                s_b.as_mut_ptr(),
                32,
                s_a.as_mut_ptr(),
                31,
            ),
            "crypto",
            "InputLength",
        );
        let mut s_a = [0u8; 32];
        Check::fails(
            umilib_crypto_sm9_sm9kep_agree(
                responder,
                [0u8; 64].as_ptr(),
                64,
                key.as_mut_ptr(),
                16,
                s_b.as_mut_ptr(),
                32,
                s_a.as_mut_ptr(),
                32,
            ),
            "crypto",
            "InvalidKey",
        );
        umilib_crypto_sm9_sm9kep_free(initiator);
        umilib_crypto_sm9_sm9kep_free(responder);
        umilib_crypto_sm9_sm9_encrypt_user_key_free(alice);
        umilib_crypto_sm9_sm9_encrypt_user_key_free(bob);
        umilib_crypto_sm9_sm9_encrypt_master_key_free(master);
    }
}

/// Annex C: K and C of the given r, and the decapsulation.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm9_annex_c_key_encapsulation() {
    let annex = GMT::read("crypto/sm9/gmt-0044.5-2016-annex-c.txt");
    let (master, public) = master(&annex);
    let bob =
        user(master, &annex.section("The identity ??? of the entity B: Bob", "The length of encapsulated key"), b"Bob");
    let values = annex
        .section("The related values in the steps A1—A7", "The related values in the steps B1—B4")
        .values("(???,???):", 33);
    let r = [vec![0u8; 32 - values[4].len()], values[4].clone()].concat();
    let (mut key, mut encapsulated) = ([0u8; 32], [0u8; 64]);
    unsafe {
        Check::ok(umilib_crypto_sm9_sm9kem_encapsulate_with_ephemeral(
            CURVE.as_ptr(),
            CURVE.len(),
            SM3.as_ptr(),
            SM3.len(),
            public.as_ptr(),
            public.len(),
            b"Bob".as_ptr(),
            3,
            HID,
            r.as_ptr(),
            r.len(),
            key.as_mut_ptr(),
            32,
            encapsulated.as_mut_ptr(),
            64,
        ));
        assert_eq!(encapsulated.to_vec(), values[5..7].concat());
        assert_eq!(key.to_vec(), values[32]);
        let mut decapsulated = [0u8; 32];
        Check::ok(umilib_crypto_sm9_sm9kem_decapsulate(
            bob,
            SM3.as_ptr(),
            SM3.len(),
            encapsulated.as_ptr(),
            64,
            decapsulated.as_mut_ptr(),
            32,
        ));
        assert_eq!(decapsulated, key);
        Check::fails(
            umilib_crypto_sm9_sm9kem_decapsulate(
                bob,
                SM3.as_ptr(),
                SM3.len(),
                encapsulated.as_ptr(),
                64,
                decapsulated.as_mut_ptr(),
                0,
            ),
            "crypto",
            "InputLength",
        );

        // A random r: Bob derives the same K.
        let generator = Generator::new(b"sm9");
        Check::ok(umilib_crypto_sm9_sm9kem_encapsulate(
            CURVE.as_ptr(),
            CURVE.len(),
            SM3.as_ptr(),
            SM3.len(),
            public.as_ptr(),
            public.len(),
            b"Bob".as_ptr(),
            3,
            HID,
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            key.as_mut_ptr(),
            32,
            encapsulated.as_mut_ptr(),
            64,
        ));
        Check::ok(umilib_crypto_sm9_sm9kem_decapsulate(
            bob,
            SM3.as_ptr(),
            SM3.len(),
            encapsulated.as_ptr(),
            64,
            decapsulated.as_mut_ptr(),
            32,
        ));
        assert_eq!(decapsulated, key);
        umilib_crypto_sm9_sm9_encrypt_user_key_free(bob);
        umilib_crypto_sm9_sm9_encrypt_master_key_free(master);
    }
}

/// Annex D: the ciphertexts of "Chinese IBE standard" with the stream cipher
/// and with SM4, the decryptions, the key of its encodings, and the rejections.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm9_annex_d_encryption() {
    let annex = GMT::read("crypto/sm9/gmt-0044.5-2016-annex-d.txt");
    let (master, public) = master(&annex);
    let bob =
        user(master, &annex.section("The identity ??? of the entity B: Bob", "The message ? to be encrypted"), b"Bob");
    let message = b"Chinese IBE standard";
    let encryption = annex.section("The related values in the steps A1—A8", "The related values in the steps B1—B5");
    let r = encryption.values("(???,???):", 5).remove(4);
    let r = [vec![0u8; 32 - r.len()], r].concat();
    let label = "a) The encryption is based on the KDF stream cipher:";
    let stream = encryption.section(label, "b) The encryption").values(label, 8).remove(7);
    let block = encryption.values("b) The encryption is based on the block cipher:", 9).remove(8);
    let generator = Generator::new(b"sm9 encryption");
    unsafe {
        for (cipher, expected) in [(STREAM, &stream), (SM4, &block)] {
            let ciphertext = output(|out| {
                umilib_crypto_sm9_sm9pke_encrypt_with_ephemeral(
                    CURVE.as_ptr(),
                    CURVE.len(),
                    SM3.as_ptr(),
                    SM3.len(),
                    cipher.as_ptr(),
                    cipher.len(),
                    public.as_ptr(),
                    public.len(),
                    b"Bob".as_ptr(),
                    3,
                    HID,
                    message.as_ptr(),
                    message.len(),
                    r.as_ptr(),
                    r.len(),
                    out,
                )
            });
            assert_eq!(&ciphertext, expected);
            let decrypt = |ciphertext: &[u8], out| {
                umilib_crypto_sm9_sm9pke_decrypt(
                    bob,
                    SM3.as_ptr(),
                    SM3.len(),
                    cipher.as_ptr(),
                    cipher.len(),
                    ciphertext.as_ptr(),
                    ciphertext.len(),
                    out,
                )
            };
            assert_eq!(output(|out| decrypt(&ciphertext, out)), message);
            let mut changed = ciphertext.clone();
            changed[70] ^= 1;
            let mut buffer = Buffer::default();
            Check::fails(decrypt(&changed, &mut buffer), "crypto", "DecryptionFailed");

            let random = output(|out| {
                umilib_crypto_sm9_sm9pke_encrypt(
                    CURVE.as_ptr(),
                    CURVE.len(),
                    SM3.as_ptr(),
                    SM3.len(),
                    cipher.as_ptr(),
                    cipher.len(),
                    public.as_ptr(),
                    public.len(),
                    b"Bob".as_ptr(),
                    3,
                    HID,
                    message.as_ptr(),
                    message.len(),
                    generator.handle(),
                    Generator::TYPE.as_ptr(),
                    Generator::TYPE.len(),
                    out,
                )
            });
            assert_eq!(output(|out| decrypt(&random, out)), message);
        }

        // An unknown cipher.
        let mut buffer = Buffer::default();
        let unknown = b"umilib_crypto_sm9_SM9Cipher";
        Check::fails(
            umilib_crypto_sm9_sm9pke_decrypt(
                bob,
                SM3.as_ptr(),
                SM3.len(),
                unknown.as_ptr(),
                unknown.len(),
                stream.as_ptr(),
                stream.len(),
                &mut buffer,
            ),
            "ffi",
            "InvalidArgument",
        );

        // The key of its encodings decrypts the same.
        let key = output(|out| umilib_crypto_sm9_sm9_encrypt_user_key_key(bob, out));
        let master_public = output(|out| umilib_crypto_sm9_sm9_encrypt_user_key_master(bob, out));
        assert_eq!(master_public, public);
        let mut copy: User = ptr::null_mut();
        Check::ok(umilib_crypto_sm9_sm9_encrypt_user_key_new(
            CURVE.as_ptr(),
            CURVE.len(),
            b"Bob".as_ptr(),
            3,
            HID,
            key.as_ptr(),
            key.len(),
            master_public.as_ptr(),
            master_public.len(),
            &mut copy,
        ));
        let decrypted = output(|out| {
            umilib_crypto_sm9_sm9pke_decrypt(
                copy,
                SM3.as_ptr(),
                SM3.len(),
                STREAM.as_ptr(),
                STREAM.len(),
                stream.as_ptr(),
                stream.len(),
                out,
            )
        });
        assert_eq!(decrypted, message);
        let mut invalid = key.clone();
        invalid[128] ^= 1;
        let mut rejected: User = ptr::null_mut();
        Check::fails(
            umilib_crypto_sm9_sm9_encrypt_user_key_new(
                CURVE.as_ptr(),
                CURVE.len(),
                b"Bob".as_ptr(),
                3,
                HID,
                invalid.as_ptr(),
                invalid.len(),
                master_public.as_ptr(),
                master_public.len(),
                &mut rejected,
            ),
            "crypto",
            "InvalidKey",
        );
        umilib_crypto_sm9_sm9_encrypt_user_key_free(copy);
        umilib_crypto_sm9_sm9_encrypt_user_key_free(bob);
        umilib_crypto_sm9_sm9_encrypt_master_key_free(master);
    }
}
