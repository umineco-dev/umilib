//! The C ABI of the public-key schemes on small inputs, as a round trip:
//! Miri, which cannot run the vector tests in time, checks the unsafe code of
//! their handles and buffers through these. The values themselves are
//! checked against the specifications by the vector tests.

use std::ptr;

use umilib::ffi::Buffer;
use umilib::ffi::crypto::dh::dh;
use umilib::ffi::crypto::ecdh::xdh;
use umilib::ffi::crypto::hpke::*;
use umilib::ffi::crypto::rsa::*;
use umilib::ffi::crypto::srp::*;

use super::Bytes;
use crate::Check;

#[test]
fn names_and_sizes() {
    let mut sizes = [0usize; 3];
    unsafe {
        let curve = b"umilib_crypto_curve_curve25519_Curve25519";
        Check::ok(xdh::sizes(curve.as_ptr(), curve.len(), sizes.as_mut_ptr()));
        assert_eq!(sizes, [32, 32, 32]);
        let group = b"umilib_crypto_dh_FFDHE2048";
        Check::ok(dh::sizes(group.as_ptr(), group.len(), sizes.as_mut_ptr()));
        assert_eq!(sizes, [256, 256, 256]);
        Check::fails(dh::sizes(curve.as_ptr(), curve.len(), sizes.as_mut_ptr()), "ffi", "InvalidArgument");
        Check::fails(
            xdh::check_public_key(curve.as_ptr(), curve.len(), [9u8; 31].as_ptr(), 31),
            "crypto",
            "InvalidKey",
        );
        Check::fails(
            xdh::check_private_key(curve.as_ptr(), curve.len(), [9u8; 33].as_ptr(), 33),
            "crypto",
            "InvalidKey",
        );
        // An output may share no byte with an input, the names included.
        let mut buffer = curve.to_vec();
        buffer.extend_from_slice(&[0u8; 64]);
        let name = buffer.as_mut_ptr();
        let key = [9u8; 32];
        Check::fails(
            xdh::public_key(name, curve.len(), key.as_ptr(), 32, name.add(curve.len() - 1), 32),
            "ffi",
            "InvalidArgument",
        );
        Check::ok(xdh::public_key(name, curve.len(), key.as_ptr(), 32, name.add(curve.len()), 32));
        Check::fails(
            umilib_crypto_hpke_hpke_derive_key_pair(0x0020, name, 32, name.add(16), 32, name.add(48), 32),
            "ffi",
            "InvalidArgument",
        );
        Check::fails(
            umilib_crypto_hpke_hpke_derive_key_pair(0x0020, name, 8, name.add(16), 32, name.add(40), 32),
            "ffi",
            "InvalidArgument",
        );
        Check::ok(umilib_crypto_hpke_hpke_sizes(0x0020, sizes.as_mut_ptr()));
        assert_eq!(sizes, [32, 32, 32]);
        Check::fails(umilib_crypto_hpke_hpke_sizes(0x0000, sizes.as_mut_ptr()), "ffi", "InvalidArgument");
        Check::fails(umilib_crypto_hpke_hpke_sizes(0x0020, ptr::null_mut()), "ffi", "NullPointer");
        let (srp, sha1) = (b"umilib_crypto_srp_SRP1024", b"umilib_hash_sha_v1_SHA1");
        let mut client = ptr::null_mut();
        Check::fails(
            umilib_crypto_srp_srp_client_new(
                srp.as_ptr(),
                srp.len(),
                sha1.as_ptr(),
                sha1.len(),
                [0u8].as_ptr(),
                1,
                &mut client,
            ),
            "crypto",
            "InvalidKey",
        );
        assert!(client.is_null());
        umilib_crypto_srp_srp_client_free(ptr::null_mut());
    }
}

/// The handles of RSA public keys on a key of 6 bits: creation, its values, DER and release.
#[test]
fn rsa_public_key_handles() {
    unsafe {
        let mut key = ptr::null_mut();
        Check::ok(umilib_crypto_rsa_rsa_public_key_new([0x37].as_ptr(), 1, [0x05].as_ptr(), 1, &mut key));
        let mut size = 0;
        Check::ok(umilib_crypto_rsa_rsa_public_key_size(key, &mut size));
        assert_eq!(size, 1);
        let mut n = Buffer::default();
        Check::ok(umilib_crypto_rsa_rsa_public_key_n(key, &mut n));
        assert_eq!(Bytes::take(n), [0x37]);
        let mut der = Buffer::default();
        Check::ok(pkcs1::umilib_crypto_rsa_rsa_public_key_to_pkcs1_der(key, &mut der));
        let der = Bytes::take(der);
        let mut copy = ptr::null_mut();
        Check::ok(pkcs1::umilib_crypto_rsa_rsa_public_key_from_pkcs1_der(der.as_ptr(), der.len(), &mut copy));
        umilib_crypto_rsa_rsa_public_key_free(copy);
        umilib_crypto_rsa_rsa_public_key_free(key);
        Check::fails(
            umilib_crypto_rsa_rsa_public_key_new([0x36].as_ptr(), 1, [0x05].as_ptr(), 1, &mut key),
            "crypto",
            "InvalidKey",
        );
    }
}

/// An HPKE exchange of X25519 with ChaCha20Poly1305: the contexts behind their handles.
#[test]
fn hpke_contexts() {
    let (kem, kdf, aead) = (0x0020, 0x0001, 0x0003);
    let (mut recipient, mut recipient_public) = ([0u8; 32], [0u8; 32]);
    let (mut ephemeral, mut ephemeral_public) = ([0u8; 32], [0u8; 32]);
    let mut encapsulated = [0u8; 32];
    unsafe {
        Check::ok(umilib_crypto_hpke_hpke_derive_key_pair(
            kem,
            b"r".as_ptr(),
            1,
            recipient.as_mut_ptr(),
            32,
            recipient_public.as_mut_ptr(),
            32,
        ));
        Check::ok(umilib_crypto_hpke_hpke_derive_key_pair(
            kem,
            b"e".as_ptr(),
            1,
            ephemeral.as_mut_ptr(),
            32,
            ephemeral_public.as_mut_ptr(),
            32,
        ));
        let (mut sender, mut receiver) = (ptr::null_mut(), ptr::null_mut());
        Check::ok(umilib_crypto_hpke_hpke_setup_sender_with_ephemeral(
            kem,
            kdf,
            aead,
            recipient_public.as_ptr(),
            32,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ephemeral.as_ptr(),
            32,
            encapsulated.as_mut_ptr(),
            32,
            &mut sender,
        ));
        assert_eq!(encapsulated, ephemeral_public);
        Check::ok(umilib_crypto_hpke_hpke_setup_receiver(
            kem,
            kdf,
            aead,
            encapsulated.as_ptr(),
            32,
            recipient.as_ptr(),
            32,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            &mut receiver,
        ));
        let mut ciphertext = Buffer::default();
        Check::ok(umilib_crypto_hpke_hpke_sender_context_seal(
            sender,
            b"a".as_ptr(),
            1,
            b"message".as_ptr(),
            7,
            &mut ciphertext,
        ));
        let ciphertext = Bytes::take(ciphertext);
        let mut plaintext = Buffer::default();
        Check::ok(umilib_crypto_hpke_hpke_receiver_context_open(
            receiver,
            b"a".as_ptr(),
            1,
            ciphertext.as_ptr(),
            ciphertext.len(),
            &mut plaintext,
        ));
        assert_eq!(Bytes::take(plaintext), b"message");
        let (mut exported_sender, mut exported_receiver) = ([0u8; 16], [0u8; 16]);
        Check::ok(umilib_crypto_hpke_hpke_sender_context_export(
            sender,
            b"x".as_ptr(),
            1,
            exported_sender.as_mut_ptr(),
            16,
        ));
        Check::ok(umilib_crypto_hpke_hpke_receiver_context_export(
            receiver,
            b"x".as_ptr(),
            1,
            exported_receiver.as_mut_ptr(),
            16,
        ));
        assert_eq!(exported_sender, exported_receiver);
        // The output may not overlap the exporter context.
        Check::fails(
            umilib_crypto_hpke_hpke_sender_context_export(
                sender,
                exported_sender.as_ptr(),
                16,
                exported_sender.as_mut_ptr(),
                16,
            ),
            "ffi",
            "InvalidArgument",
        );
        let mut sequence = 0;
        Check::ok(umilib_crypto_hpke_hpke_sender_context_sequence(sender, &mut sequence));
        assert_eq!(sequence, 1);
        umilib_crypto_hpke_hpke_sender_context_free(sender);
        umilib_crypto_hpke_hpke_receiver_context_free(receiver);
    }
}
