//! The exchanges of the C ABI: SRP against the test vectors of RFC 5054
//! appendix B, Dragonfly between two peers, and the key exchange and the
//! encryption of SM2.

use std::ptr;

use umilib::ffi::Buffer;
use umilib::ffi::crypto::dragonfly::*;
use umilib::ffi::crypto::sm2;
use umilib::ffi::crypto::sm2::sm2dsa;
use umilib::ffi::crypto::srp::*;

use super::{Bytes, Generator};
use crate::Check;
use crate::vectors::Vectors;

/// The value after "`name` =" in RFC 5054 appendix B: on the same line or
/// the following ones, in groups of hexadecimal digits.
fn rfc5054(name: &str) -> Vec<u8> {
    let text = Vectors::read("crypto/srp/rfc5054.txt");
    let start = text.find("\nAppendix B.  SRP Test Vectors").unwrap();
    let end = text.find("\nAppendix C.").unwrap();
    let lines: Vec<&str> = text[start..end].lines().map(str::trim).collect();
    let index = lines.iter().position(|line| line.starts_with(&format!("{name} ="))).unwrap();
    let is_hex = |word: &str| !word.is_empty() && word.chars().all(|character| character.is_ascii_hexdigit());
    let mut hex: String = lines[index][name.len() + 2..].split_whitespace().collect();
    // The value may start on the line after a blank one, and ends at the next blank one.
    let starts_empty = hex.is_empty();
    for line in lines[index + 1..].iter().skip_while(|line| starts_empty && line.is_empty()) {
        if line.is_empty() || !line.split_whitespace().all(is_hex) {
            break;
        }
        hex.extend(line.split_whitespace());
    }
    Vectors::hex(&hex)
}

/// The bytes of `bytes` without leading zeros.
fn significant(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().skip_while(|byte| *byte == 0).collect()
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn srp_rfc5054() {
    let (group, hash) = (b"umilib_crypto_srp_SRP1024", b"umilib_hash_sha_v1_SHA1");
    let (identity, password, salt) = (b"alice", b"password123", rfc5054("s"));
    let (secret_a, secret_b) = (rfc5054("a"), rfc5054("b"));
    unsafe {
        let mut buffer = Buffer::default();
        Check::ok(umilib_crypto_srp_srp_verifier(
            group.as_ptr(),
            group.len(),
            hash.as_ptr(),
            hash.len(),
            salt.as_ptr(),
            salt.len(),
            identity.as_ptr(),
            identity.len(),
            password.as_ptr(),
            password.len(),
            &mut buffer,
        ));
        let verifier = Bytes::take(buffer);
        assert_eq!(significant(&verifier), significant(&rfc5054("v")));

        let (mut client, mut server) = (ptr::null_mut(), ptr::null_mut());
        Check::ok(umilib_crypto_srp_srp_client_new(
            group.as_ptr(),
            group.len(),
            hash.as_ptr(),
            hash.len(),
            secret_a.as_ptr(),
            secret_a.len(),
            &mut client,
        ));
        Check::ok(umilib_crypto_srp_srp_server_new(
            group.as_ptr(),
            group.len(),
            hash.as_ptr(),
            hash.len(),
            verifier.as_ptr(),
            verifier.len(),
            secret_b.as_ptr(),
            secret_b.len(),
            &mut server,
        ));
        let mut buffer = Buffer::default();
        Check::ok(umilib_crypto_srp_srp_client_public_value(client, &mut buffer));
        let client_public = Bytes::take(buffer);
        assert_eq!(client_public, rfc5054("A"));
        let mut buffer = Buffer::default();
        Check::ok(umilib_crypto_srp_srp_server_public_value(server, &mut buffer));
        let server_public = Bytes::take(buffer);
        assert_eq!(server_public, rfc5054("B"));

        let expected = rfc5054("<premaster secret>");
        let mut buffer = Buffer::default();
        Check::ok(umilib_crypto_srp_srp_client_premaster_secret(
            client,
            identity.as_ptr(),
            identity.len(),
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            server_public.as_ptr(),
            server_public.len(),
            &mut buffer,
        ));
        assert_eq!(Bytes::take(buffer), expected);
        let mut buffer = Buffer::default();
        Check::ok(umilib_crypto_srp_srp_server_premaster_secret(
            server,
            client_public.as_ptr(),
            client_public.len(),
            &mut buffer,
        ));
        assert_eq!(Bytes::take(buffer), expected);
        // Section 2.5.4: A % N = 0 is refused.
        let mut buffer = Buffer::default();
        Check::fails(
            umilib_crypto_srp_srp_server_premaster_secret(server, [0u8].as_ptr(), 1, &mut buffer),
            "crypto",
            "InvalidKey",
        );
        umilib_crypto_srp_srp_client_free(client);
        umilib_crypto_srp_srp_server_free(server);

        // Generated parties of another group agree.
        let group = b"umilib_crypto_srp_SRP2048";
        let generator = Generator::new(b"srp");
        let mut buffer = Buffer::default();
        Check::ok(umilib_crypto_srp_srp_verifier(
            group.as_ptr(),
            group.len(),
            hash.as_ptr(),
            hash.len(),
            salt.as_ptr(),
            salt.len(),
            identity.as_ptr(),
            identity.len(),
            password.as_ptr(),
            password.len(),
            &mut buffer,
        ));
        let verifier = Bytes::take(buffer);
        Check::ok(umilib_crypto_srp_srp_client_generate(
            group.as_ptr(),
            group.len(),
            hash.as_ptr(),
            hash.len(),
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            &mut client,
        ));
        Check::ok(umilib_crypto_srp_srp_server_generate(
            group.as_ptr(),
            group.len(),
            hash.as_ptr(),
            hash.len(),
            verifier.as_ptr(),
            verifier.len(),
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            &mut server,
        ));
        let (mut a, mut b) = (Buffer::default(), Buffer::default());
        Check::ok(umilib_crypto_srp_srp_client_public_value(client, &mut a));
        Check::ok(umilib_crypto_srp_srp_server_public_value(server, &mut b));
        let (a, b) = (Bytes::take(a), Bytes::take(b));
        let (mut client_secret, mut server_secret) = (Buffer::default(), Buffer::default());
        Check::ok(umilib_crypto_srp_srp_client_premaster_secret(
            client,
            identity.as_ptr(),
            identity.len(),
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            b.as_ptr(),
            b.len(),
            &mut client_secret,
        ));
        Check::ok(umilib_crypto_srp_srp_server_premaster_secret(server, a.as_ptr(), a.len(), &mut server_secret));
        assert_eq!(Bytes::take(client_secret), Bytes::take(server_secret));
        umilib_crypto_srp_srp_client_free(client);
        umilib_crypto_srp_srp_server_free(server);

        let unknown = b"umilib_crypto_srp_SRP512";
        Check::fails(
            umilib_crypto_srp_srp_client_new(
                unknown.as_ptr(),
                unknown.len(),
                hash.as_ptr(),
                hash.len(),
                secret_a.as_ptr(),
                secret_a.len(),
                &mut client,
            ),
            "ffi",
            "InvalidArgument",
        );
    }
}

/// A Dragonfly peer of the C ABI on P-256 with SHA-256.
struct Peer(*mut Box<dyn DragonflyState>);

impl Peer {
    fn new(identity: &[u8], peer_identity: &[u8], password: &[u8], generator: &Generator) -> Peer {
        let (curve, hash) = (b"umilib_crypto_curve_p256_P256", b"umilib_hash_sha_v2_SHA256");
        let config = unsafe { umilib_crypto_dragonfly_dragonfly_config_default() };
        assert_eq!(config.iterations, 40);
        let mut peer = ptr::null_mut();
        Check::ok(unsafe {
            umilib_crypto_dragonfly_dragonfly_peer_new(
                curve.as_ptr(),
                curve.len(),
                hash.as_ptr(),
                hash.len(),
                &config,
                identity.as_ptr(),
                identity.len(),
                peer_identity.as_ptr(),
                peer_identity.len(),
                password.as_ptr(),
                password.len(),
                generator.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                &mut peer,
            )
        });
        Peer(peer)
    }

    fn commit(&self) -> Vec<u8> {
        let mut buffer = Buffer::default();
        Check::ok(unsafe { umilib_crypto_dragonfly_dragonfly_peer_commit(self.0, &mut buffer) });
        Bytes::take(buffer)
    }

    fn process(&self, commit: &[u8]) -> Vec<u8> {
        let mut buffer = Buffer::default();
        Check::ok(unsafe {
            umilib_crypto_dragonfly_dragonfly_peer_process(self.0, commit.as_ptr(), commit.len(), &mut buffer)
        });
        Bytes::take(buffer)
    }

    /// The master key, or the name of the status of the refusal.
    fn finish(&self, confirm: &[u8]) -> Result<Vec<u8>, String> {
        let mut buffer = Buffer::default();
        let status = unsafe {
            umilib_crypto_dragonfly_dragonfly_peer_finish(self.0, confirm.as_ptr(), confirm.len(), &mut buffer)
        };
        match unsafe { status.as_ref() } {
            None => Ok(Bytes::take(buffer)),
            Some(status) => Err(status.name().to_str().unwrap().to_owned()),
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        unsafe { umilib_crypto_dragonfly_dragonfly_peer_free(self.0) };
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn dragonfly_peers_agree() {
    let generator = Generator::new(b"dragonfly");
    let alice = Peer::new(b"alice", b"bob", b"password", &generator);
    let bob = Peer::new(b"bob", b"alice", b"password", &generator);
    assert_eq!(alice.finish(&[0; 32]), Err("InvalidParameter".to_owned()));
    let (commit_a, commit_b) = (alice.commit(), bob.commit());
    assert_eq!(commit_a.len(), 32 + 65);
    let (confirm_a, confirm_b) = (alice.process(&commit_b), bob.process(&commit_a));
    let key = alice.finish(&confirm_b).unwrap();
    assert_eq!(key.len(), 32);
    assert_eq!(bob.finish(&confirm_a).unwrap(), key);
    assert_eq!(alice.finish(&confirm_a), Err("AuthenticationFailed".to_owned()));

    // A peer of another password does not confirm; a reflected commit is refused.
    let eve = Peer::new(b"eve", b"alice", b"guess", &generator);
    let carol = Peer::new(b"alice", b"eve", b"password", &generator);
    let (commit_e, commit_c) = (eve.commit(), carol.commit());
    let confirm_e = eve.process(&commit_c);
    carol.process(&commit_e);
    assert_eq!(carol.finish(&confirm_e), Err("AuthenticationFailed".to_owned()));
    let reflected = Peer::new(b"alice", b"bob", b"password", &generator);
    let commit = reflected.commit();
    let mut buffer = Buffer::default();
    Check::fails(
        unsafe {
            umilib_crypto_dragonfly_dragonfly_peer_process(reflected.0, commit.as_ptr(), commit.len(), &mut buffer)
        },
        "crypto",
        "InvalidKey",
    );
}

const CURVE: &[u8] = b"umilib_crypto_curve_sm2_SM2";
const SM3: &[u8] = b"umilib_hash_sm3_SM3";

/// A key pair of SM2 from the generator: the private key and the uncompressed public key.
fn sm2_key_pair(generator: &Generator) -> (Vec<u8>, Vec<u8>) {
    let (mut private, mut public) = (vec![0u8; 32], vec![0u8; 65]);
    unsafe {
        Check::ok(sm2dsa::generate(
            CURVE.as_ptr(),
            CURVE.len(),
            SM3.as_ptr(),
            SM3.len(),
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            private.as_mut_ptr(),
            32,
        ));
        Check::ok(sm2dsa::verifying_key(
            CURVE.as_ptr(),
            CURVE.len(),
            SM3.as_ptr(),
            SM3.len(),
            private.as_ptr(),
            32,
            public.as_mut_ptr(),
            65,
        ));
    }
    (private, public)
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm2_key_exchange_and_encryption() {
    let generator = Generator::new(b"sm2");
    let (a, public_a) = sm2_key_pair(&generator);
    let (b, public_b) = sm2_key_pair(&generator);
    unsafe {
        let (mut initiator, mut responder) = (ptr::null_mut(), ptr::null_mut());
        Check::ok(sm2::sm2kep_generate(
            0,
            a.as_ptr(),
            32,
            b"alice".as_ptr(),
            5,
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            &mut initiator,
        ));
        Check::ok(sm2::sm2kep_generate(
            1,
            b.as_ptr(),
            32,
            b"bob".as_ptr(),
            3,
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            &mut responder,
        ));
        let (mut ephemeral_a, mut ephemeral_b) = ([0u8; 65], [0u8; 65]);
        Check::ok(sm2::sm2kep_ephemeral_public_key(initiator, ephemeral_a.as_mut_ptr(), 65));
        Check::ok(sm2::sm2kep_ephemeral_public_key(responder, ephemeral_b.as_mut_ptr(), 65));
        let agree = |side, peer: &[u8], identity: &[u8], ephemeral: &[u8; 65]| {
            let (mut key, mut s_b, mut s_a) = ([0u8; 16], [0u8; 32], [0u8; 32]);
            Check::ok(sm2::sm2kep_agree(
                side,
                peer.as_ptr(),
                peer.len(),
                identity.as_ptr(),
                identity.len(),
                ephemeral.as_ptr(),
                65,
                key.as_mut_ptr(),
                16,
                s_b.as_mut_ptr(),
                32,
                s_a.as_mut_ptr(),
                32,
            ));
            (key, s_b, s_a)
        };
        assert_eq!(
            agree(initiator, &public_b, b"bob", &ephemeral_b),
            agree(responder, &public_a, b"alice", &ephemeral_a)
        );
        Check::fails(
            sm2::sm2kep_generate(
                2,
                a.as_ptr(),
                32,
                b"alice".as_ptr(),
                5,
                generator.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                &mut initiator,
            ),
            "ffi",
            "InvalidArgument",
        );
        sm2::sm2kep_free(initiator);
        sm2::sm2kep_free(responder);

        let message = b"encryption standard";
        let overhead = sm2::sm2pke_overhead();
        assert_eq!(overhead, 65 + 32);
        for order in [0u8, 1] {
            let mut ciphertext = vec![0u8; message.len() + overhead];
            Check::ok(sm2::sm2pke_encrypt(
                CURVE.as_ptr(),
                CURVE.len(),
                SM3.as_ptr(),
                SM3.len(),
                public_b.as_ptr(),
                65,
                message.as_ptr(),
                message.len(),
                order,
                generator.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                ciphertext.as_mut_ptr(),
                ciphertext.len(),
            ));
            let mut decrypted = vec![0u8; message.len()];
            Check::ok(sm2::sm2pke_decrypt(
                CURVE.as_ptr(),
                CURVE.len(),
                SM3.as_ptr(),
                SM3.len(),
                b.as_ptr(),
                32,
                ciphertext.as_ptr(),
                ciphertext.len(),
                order,
                decrypted.as_mut_ptr(),
                decrypted.len(),
            ));
            assert_eq!(decrypted, message);
            // The ciphertext of one order is not one of the other.
            Check::fails(
                sm2::sm2pke_decrypt(
                    CURVE.as_ptr(),
                    CURVE.len(),
                    SM3.as_ptr(),
                    SM3.len(),
                    b.as_ptr(),
                    32,
                    ciphertext.as_ptr(),
                    ciphertext.len(),
                    1 - order,
                    decrypted.as_mut_ptr(),
                    decrypted.len(),
                ),
                "crypto",
                "DecryptionFailed",
            );
        }
    }
}
