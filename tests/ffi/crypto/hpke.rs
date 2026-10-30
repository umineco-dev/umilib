//! HPKE through the C ABI against every test vector of RFC 9180 appendix A:
//! seven suites, each in the modes base, PSK, auth and auth-PSK.

use std::collections::BTreeMap;
use std::ptr;

use umilib::ffi::Buffer;
use umilib::ffi::crypto::hpke::*;

use super::{Bytes, Generator};
use crate::Check;
use crate::vectors::Vectors;

/// One setup of appendix A: its fields, its encryptions and its exported values.
#[derive(Default)]
struct Setup {
    name: String,
    fields: BTreeMap<String, String>,
    encryptions: Vec<BTreeMap<String, String>>,
    exports: Vec<BTreeMap<String, String>>,
}

impl Setup {
    /// Every setup of appendix A. A field is "name: value" with the value
    /// on the same line or the following ones, continued on lines without a colon.
    fn all() -> Vec<Setup> {
        let text = Vectors::read("crypto/hpke/rfc9180.txt");
        let start = text.find("\nA.1.  DHKEM(X25519").unwrap();
        let end = text.find("\nAcknowledgements").unwrap_or(text.len());
        let mut setups: Vec<Setup> = Vec::new();
        // Which list the fields go to: 0 the setup, 1 the encryptions, 2 the exports.
        let mut part = 0;
        let mut last: Option<String> = None;
        for line in text[start..end].lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                if part > 0 {
                    last = None;
                }
                continue;
            }
            if line.starts_with("A.") {
                if trimmed.ends_with("Setup Information") {
                    setups.push(Setup { name: trimmed.to_owned(), ..Setup::default() });
                    part = 0;
                } else if trimmed.ends_with("Encryptions") {
                    part = 1;
                } else if trimmed.ends_with("Exported Values") {
                    part = 2;
                }
                last = None;
                continue;
            }
            let Some(setup) = setups.last_mut() else { continue };
            let target = match part {
                0 => &mut setup.fields,
                1 => {
                    if trimmed.starts_with("sequence number:") {
                        setup.encryptions.push(BTreeMap::new());
                    }
                    setup.encryptions.last_mut().unwrap()
                }
                _ => {
                    if trimmed.starts_with("exporter_context:") {
                        setup.exports.push(BTreeMap::new());
                    }
                    setup.exports.last_mut().unwrap()
                }
            };
            if let Some((name, value)) = trimmed.split_once(':') {
                target.insert(name.to_owned(), value.trim().to_owned());
                last = Some(name.to_owned());
            } else if let Some(name) = &last {
                target.get_mut(name).unwrap().push_str(trimmed);
            }
        }
        setups
    }

    fn bytes(&self, name: &str) -> Vec<u8> {
        self.fields.get(name).map(|value| Vectors::hex(value)).unwrap_or_default()
    }

    fn number(&self, name: &str) -> u16 {
        self.fields[name].parse().unwrap()
    }
}

/// Nenc, Npk and Nsk of the KEM `kem`.
fn sizes(kem: u16) -> [usize; 3] {
    let mut sizes = [0; 3];
    Check::ok(unsafe { umilib_crypto_hpke_hpke_sizes(kem, sizes.as_mut_ptr()) });
    sizes
}

/// DeriveKeyPair(ikm) of the KEM `kem`: the private and the public key.
fn derive_key_pair(kem: u16, ikm: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let [_, public_size, private_size] = sizes(kem);
    let (mut private, mut public) = (vec![0; private_size], vec![0; public_size]);
    Check::ok(unsafe {
        umilib_crypto_hpke_hpke_derive_key_pair(
            kem,
            ikm.as_ptr(),
            ikm.len(),
            private.as_mut_ptr(),
            private.len(),
            public.as_mut_ptr(),
            public.len(),
        )
    });
    let mut again = vec![0; public_size];
    Check::ok(unsafe {
        umilib_crypto_hpke_hpke_public_key(kem, private.as_ptr(), private.len(), again.as_mut_ptr(), again.len())
    });
    assert_eq!(again, public);
    (private, public)
}

/// The setup `setup` through the C ABI.
fn check(setup: &Setup) {
    let label = &setup.name;
    let (kem, kdf, aead) = (setup.number("kem_id"), setup.number("kdf_id"), setup.number("aead_id"));
    let (recipient, recipient_public) = derive_key_pair(kem, &setup.bytes("ikmR"));
    assert_eq!(recipient, setup.bytes("skRm"), "{label}");
    assert_eq!(recipient_public, setup.bytes("pkRm"), "{label}");
    let (sender, sender_public) = if setup.fields.contains_key("ikmS") {
        derive_key_pair(kem, &setup.bytes("ikmS"))
    } else {
        (Vec::new(), Vec::new())
    };
    assert_eq!(sender_public, setup.bytes("pkSm"), "{label}");
    let (info, psk, psk_id) = (setup.bytes("info"), setup.bytes("psk"), setup.bytes("psk_id"));
    let (ephemeral, _) = derive_key_pair(kem, &setup.bytes("ikmE"));
    assert_eq!(ephemeral, setup.bytes("skEm"), "{label}");
    let mut encapsulated = vec![0; sizes(kem)[0]];
    let (mut sealing, mut opening) = (ptr::null_mut(), ptr::null_mut());
    unsafe {
        Check::ok(umilib_crypto_hpke_hpke_setup_sender_with_ephemeral(
            kem,
            kdf,
            aead,
            recipient_public.as_ptr(),
            recipient_public.len(),
            info.as_ptr(),
            info.len(),
            psk.as_ptr(),
            psk.len(),
            psk_id.as_ptr(),
            psk_id.len(),
            sender.as_ptr(),
            sender.len(),
            ephemeral.as_ptr(),
            ephemeral.len(),
            encapsulated.as_mut_ptr(),
            encapsulated.len(),
            &mut sealing,
        ));
        assert_eq!(encapsulated, setup.bytes("enc"), "{label}");
        Check::ok(umilib_crypto_hpke_hpke_setup_receiver(
            kem,
            kdf,
            aead,
            encapsulated.as_ptr(),
            encapsulated.len(),
            recipient.as_ptr(),
            recipient.len(),
            info.as_ptr(),
            info.len(),
            psk.as_ptr(),
            psk.len(),
            psk_id.as_ptr(),
            psk_id.len(),
            sender_public.as_ptr(),
            sender_public.len(),
            &mut opening,
        ));

        // The encryptions, at their sequence numbers; the numbers between are used by empty messages.
        for encryption in &setup.encryptions {
            let sequence: u64 = encryption["sequence number"].parse().unwrap();
            loop {
                let mut current = 0;
                Check::ok(umilib_crypto_hpke_hpke_sender_context_sequence(sealing, &mut current));
                if current == sequence {
                    break;
                }
                let mut filler = Buffer::default();
                Check::ok(umilib_crypto_hpke_hpke_sender_context_seal(
                    sealing,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    &mut filler,
                ));
                let filler = Bytes::take(filler);
                let mut opened = Buffer::default();
                Check::ok(umilib_crypto_hpke_hpke_receiver_context_open(
                    opening,
                    ptr::null(),
                    0,
                    filler.as_ptr(),
                    filler.len(),
                    &mut opened,
                ));
                assert!(Bytes::take(opened).is_empty());
            }
            let (plaintext, associated) = (Vectors::hex(&encryption["pt"]), Vectors::hex(&encryption["aad"]));
            let mut ciphertext = Buffer::default();
            Check::ok(umilib_crypto_hpke_hpke_sender_context_seal(
                sealing,
                associated.as_ptr(),
                associated.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                &mut ciphertext,
            ));
            let ciphertext = Bytes::take(ciphertext);
            assert_eq!(ciphertext, Vectors::hex(&encryption["ct"]), "{label} {sequence}");
            let mut changed = ciphertext.clone();
            changed[0] ^= 1;
            let mut opened = Buffer::default();
            Check::fails(
                umilib_crypto_hpke_hpke_receiver_context_open(
                    opening,
                    associated.as_ptr(),
                    associated.len(),
                    changed.as_ptr(),
                    changed.len(),
                    &mut opened,
                ),
                "crypto",
                "AuthenticationFailed",
            );
            Check::ok(umilib_crypto_hpke_hpke_receiver_context_open(
                opening,
                associated.as_ptr(),
                associated.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                &mut opened,
            ));
            assert_eq!(Bytes::take(opened), plaintext, "{label} {sequence}");
        }
        if setup.encryptions.is_empty() {
            // The export-only AEAD neither seals nor opens.
            let mut refused = Buffer::default();
            Check::fails(
                umilib_crypto_hpke_hpke_sender_context_seal(sealing, ptr::null(), 0, ptr::null(), 0, &mut refused),
                "crypto",
                "InvalidParameter",
            );
        }
        for export in &setup.exports {
            let context = Vectors::hex(&export["exporter_context"]);
            let mut value = vec![0u8; export["L"].parse().unwrap()];
            Check::ok(umilib_crypto_hpke_hpke_sender_context_export(
                sealing,
                context.as_ptr(),
                context.len(),
                value.as_mut_ptr(),
                value.len(),
            ));
            assert_eq!(value, Vectors::hex(&export["exported_value"]), "{label}");
            value.fill(0);
            Check::ok(umilib_crypto_hpke_hpke_receiver_context_export(
                opening,
                context.as_ptr(),
                context.len(),
                value.as_mut_ptr(),
                value.len(),
            ));
            assert_eq!(value, Vectors::hex(&export["exported_value"]), "{label}");
        }
        assert_eq!(setup.exports.len(), 3, "{label}");
        umilib_crypto_hpke_hpke_sender_context_free(sealing);
        umilib_crypto_hpke_hpke_receiver_context_free(opening);
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn rfc9180_test_vectors() {
    let setups = Setup::all();
    assert_eq!(setups.len(), 7 * 4);
    for setup in &setups {
        check(setup);
    }
}

/// Unknown identifiers, inconsistent pre-shared keys and a random ephemeral key.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn suites_and_inputs() {
    let (kem, kdf, aead) = (0x0020, 0x0001, 0x0003);
    let mut sizes = [0usize; 3];
    unsafe {
        Check::fails(umilib_crypto_hpke_hpke_sizes(0x0030, sizes.as_mut_ptr()), "ffi", "InvalidArgument");
    }
    let (recipient, recipient_public) = derive_key_pair(kem, b"recipient");
    // Section 7.1.1: a public key of another length is refused, the compressed form of P-256 too.
    unsafe {
        Check::ok(umilib_crypto_hpke_hpke_check_public_key(kem, recipient_public.as_ptr(), 32));
        Check::ok(umilib_crypto_hpke_hpke_check_private_key(kem, recipient.as_ptr(), 32));
        Check::fails(umilib_crypto_hpke_hpke_check_private_key(kem, recipient.as_ptr(), 31), "crypto", "InvalidKey");
        // P-256 refuses the private key 0 (SEC 1 section 2.3.6 through DeserializePrivateKey).
        Check::fails(umilib_crypto_hpke_hpke_check_private_key(0x0010, [0u8; 32].as_ptr(), 32), "crypto", "InvalidKey");
        Check::fails(
            umilib_crypto_hpke_hpke_check_public_key(kem, recipient_public.as_ptr(), 31),
            "crypto",
            "InvalidKey",
        );
        let (_, p256) = derive_key_pair(0x0010, b"p256");
        let mut compressed = vec![2 + (p256[64] & 1)];
        compressed.extend_from_slice(&p256[1..33]);
        Check::fails(umilib_crypto_hpke_hpke_check_public_key(0x0010, compressed.as_ptr(), 33), "crypto", "InvalidKey");
        Check::ok(umilib_crypto_hpke_hpke_check_public_key(0x0010, p256.as_ptr(), 65));
    }
    let generator = Generator::new(b"hpke");
    let setup = |kem: u16, kdf: u16, aead: u16, psk: &[u8], psk_id: &[u8], out: &mut *mut Box<dyn HPKESenderState>| {
        let mut encapsulated = [0u8; 32];
        let status = unsafe {
            umilib_crypto_hpke_hpke_setup_sender(
                kem,
                kdf,
                aead,
                recipient_public.as_ptr(),
                recipient_public.len(),
                b"info".as_ptr(),
                4,
                psk.as_ptr(),
                psk.len(),
                psk_id.as_ptr(),
                psk_id.len(),
                ptr::null(),
                0,
                generator.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                encapsulated.as_mut_ptr(),
                encapsulated.len(),
                out,
            )
        };
        (status, encapsulated)
    };
    let mut context = ptr::null_mut();
    Check::fails(setup(kem, 0x0004, aead, &[], &[], &mut context).0, "ffi", "InvalidArgument");
    Check::fails(setup(kem, kdf, 0x0004, &[], &[], &mut context).0, "ffi", "InvalidArgument");
    Check::fails(setup(kem, kdf, aead, &[1; 32], &[], &mut context).0, "crypto", "InvalidParameter");
    let (status, encapsulated) = setup(kem, kdf, aead, &[], &[], &mut context);
    Check::ok(status);
    let mut opening = ptr::null_mut();
    unsafe {
        Check::ok(umilib_crypto_hpke_hpke_setup_receiver(
            kem,
            kdf,
            aead,
            encapsulated.as_ptr(),
            32,
            recipient.as_ptr(),
            recipient.len(),
            b"info".as_ptr(),
            4,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            &mut opening,
        ));
        let mut ciphertext = Buffer::default();
        Check::ok(umilib_crypto_hpke_hpke_sender_context_seal(
            context,
            b"ad".as_ptr(),
            2,
            b"message".as_ptr(),
            7,
            &mut ciphertext,
        ));
        let ciphertext = Bytes::take(ciphertext);
        let mut opened = Buffer::default();
        Check::ok(umilib_crypto_hpke_hpke_receiver_context_open(
            opening,
            b"ad".as_ptr(),
            2,
            ciphertext.as_ptr(),
            ciphertext.len(),
            &mut opened,
        ));
        assert_eq!(Bytes::take(opened), b"message");
        let mut sequence = 0;
        Check::ok(umilib_crypto_hpke_hpke_receiver_context_sequence(opening, &mut sequence));
        assert_eq!(sequence, 1);
        umilib_crypto_hpke_hpke_sender_context_free(context);
        umilib_crypto_hpke_hpke_receiver_context_free(opening);
        // Null handles are ignored by the functions that free them.
        umilib_crypto_hpke_hpke_sender_context_free(ptr::null_mut());
    }
}
