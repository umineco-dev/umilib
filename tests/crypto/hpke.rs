//! HPKE (RFC 9180) against every test vector of its appendix A: seven
//! suites, each in the modes base, PSK, auth and auth-PSK.

use std::collections::BTreeMap;

use umilib::crypto::CryptoError;
use umilib::crypto::aes::{AES128, AES256};
use umilib::crypto::chacha20poly1305::ChaCha20Poly1305;
use umilib::crypto::curve::p256::P256;
use umilib::crypto::curve::p521::P521;
use umilib::crypto::ecdh::{ECDH, X25519};
use umilib::crypto::hpke::{DHKEM, HPKE, HPKEAEAD, HPKEExportOnly, HPKEKDF, HPKEKEM, HPKEMode};
use umilib::crypto::mode::gcm::GCM;
use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::{SHA256, SHA512};

use crate::Vectors;

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
        Vectors::hex(self.fields.get(name).unwrap_or_else(|| panic!("{}: no {name}", self.name)))
    }

    fn number(&self, name: &str) -> u64 {
        self.fields[name].parse().unwrap()
    }
}

/// The setup `setup` with the suite (K, F, A).
fn check<K: HPKEKEM, F: HPKEKDF, A: HPKEAEAD>(setup: &Setup) {
    let label = &setup.name;
    let mode = setup.number("mode") as u8;
    let info = setup.bytes("info");
    let (recipient, recipient_public) = K::derive_key_pair(&setup.bytes("ikmR")).unwrap();
    assert_eq!(K::serialize_private_key(&recipient), setup.bytes("skRm"), "{label}");
    assert_eq!(K::serialize_public_key(&recipient_public), setup.bytes("pkRm"), "{label}");
    let (ephemeral, ephemeral_public) = K::derive_key_pair(&setup.bytes("ikmE")).unwrap();
    assert_eq!(K::serialize_private_key(&ephemeral), setup.bytes("skEm"), "{label}");
    assert_eq!(K::serialize_public_key(&ephemeral_public), setup.bytes("pkEm"), "{label}");
    let sender = setup.fields.contains_key("ikmS").then(|| {
        let (sender, sender_public) = K::derive_key_pair(&setup.bytes("ikmS")).unwrap();
        assert_eq!(K::serialize_private_key(&sender), setup.bytes("skSm"), "{label}");
        assert_eq!(K::serialize_public_key(&sender_public), setup.bytes("pkSm"), "{label}");
        sender
    });
    let (psk, psk_id) = if setup.fields.contains_key("psk") {
        (setup.bytes("psk"), setup.bytes("psk_id"))
    } else {
        (Vec::new(), Vec::new())
    };
    let psk = (!psk.is_empty()).then_some((&psk[..], &psk_id[..]));
    assert_eq!(HPKEMode::of(psk.is_some(), sender.is_some()) as u8, mode, "{label}");

    // The KEM alone: enc and the shared secret, both ways.
    let (shared, encapsulated) = K::encapsulate(&recipient_public, &ephemeral, sender.as_ref()).unwrap();
    assert_eq!(encapsulated, setup.bytes("enc"), "{label}");
    assert_eq!(shared, setup.bytes("shared_secret"), "{label}");
    let sender_public = sender.as_ref().map(K::public_key);
    assert_eq!(K::decapsulate(&encapsulated, &recipient, sender_public.as_ref()).unwrap(), shared, "{label}");

    let (encapsulated, mut sealing) =
        HPKE::<K, F, A>::setup_sender_with_ephemeral(&recipient_public, &info, psk, sender.as_ref(), &ephemeral)
            .unwrap();
    let mut opening =
        HPKE::<K, F, A>::setup_receiver(&encapsulated, &recipient, &info, psk, sender_public.as_ref()).unwrap();
    for context in [sealing.context(), opening.context()] {
        assert_eq!(context.key(), &setup.bytes("key")[..], "{label}");
        assert_eq!(context.base_nonce(), &setup.bytes("base_nonce")[..], "{label}");
        assert_eq!(context.exporter_secret(), &setup.bytes("exporter_secret")[..], "{label}");
    }

    // The encryptions, at their sequence numbers; the numbers between are used by empty messages.
    for encryption in &setup.encryptions {
        let sequence: u64 = encryption["sequence number"].parse().unwrap();
        while sealing.context().sequence() < sequence {
            let filler = sealing.seal(b"", b"").unwrap();
            opening.open(b"", &filler).unwrap();
        }
        assert_eq!(sealing.context().nonce(), Vectors::hex(&encryption["nonce"]), "{label} {sequence}");
        let (plaintext, associated) = (Vectors::hex(&encryption["pt"]), Vectors::hex(&encryption["aad"]));
        let ciphertext = sealing.seal(&associated, &plaintext).unwrap();
        assert_eq!(ciphertext, Vectors::hex(&encryption["ct"]), "{label} {sequence}");
        let mut changed = ciphertext.clone();
        changed[0] ^= 1;
        assert_eq!(opening.open(&associated, &changed), Err(CryptoError::AuthenticationFailed), "{label}");
        assert_eq!(opening.open(&associated, &ciphertext).unwrap(), plaintext, "{label} {sequence}");
    }
    for export in &setup.exports {
        let length: usize = export["L"].parse().unwrap();
        let mut value = vec![0u8; length];
        sealing.export(&Vectors::hex(&export["exporter_context"]), &mut value).unwrap();
        assert_eq!(value, Vectors::hex(&export["exported_value"]), "{label}");
        opening.export(&Vectors::hex(&export["exporter_context"]), &mut value).unwrap();
        assert_eq!(value, Vectors::hex(&export["exported_value"]), "{label}");
    }
    assert!(setup.exports.len() == 3, "{label}");
}

type AES128GCM = GCM<AES128, 16>;
type AES256GCM = GCM<AES256, 16>;

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn rfc9180_test_vectors() {
    let setups = Setup::all();
    assert_eq!(setups.len(), 7 * 4);
    for setup in &setups {
        let suite = (setup.number("kem_id"), setup.number("kdf_id"), setup.number("aead_id"));
        match suite {
            (32, 1, 1) => check::<DHKEM<X25519, SHA256>, SHA256, AES128GCM>(setup),
            (32, 1, 3) => check::<DHKEM<X25519, SHA256>, SHA256, ChaCha20Poly1305>(setup),
            (16, 1, 1) => check::<DHKEM<ECDH<P256>, SHA256>, SHA256, AES128GCM>(setup),
            (16, 3, 1) => check::<DHKEM<ECDH<P256>, SHA256>, SHA512, AES128GCM>(setup),
            (16, 1, 3) => check::<DHKEM<ECDH<P256>, SHA256>, SHA256, ChaCha20Poly1305>(setup),
            (18, 3, 2) => check::<DHKEM<ECDH<P521>, SHA512>, SHA512, AES256GCM>(setup),
            (32, 1, 65535) => check::<DHKEM<X25519, SHA256>, SHA256, HPKEExportOnly>(setup),
            other => panic!("{}: {other:?}", setup.name),
        }
    }
}

/// Section 5.1: the PSK inputs must be both given or both absent, and the
/// contexts of other parameters do not open each other's messages.
#[test]
fn modes_and_inputs() {
    type Suite = HPKE<DHKEM<X25519, SHA256>, SHA256, ChaCha20Poly1305>;
    type KEM = DHKEM<X25519, SHA256>;
    let mut random = HMACDRBG::<SHA256>::new(&[7; 32], &[8; 16], b"hpke").unwrap();
    let (recipient, recipient_public) = KEM::generate_key_pair(&mut random).unwrap();
    let (sender, sender_public) = KEM::generate_key_pair(&mut random).unwrap();
    let psk = (&[1u8; 32][..], &b"id"[..]);
    for (psk, auth) in [(None, false), (Some(psk), false), (None, true), (Some(psk), true)] {
        let sender_key = auth.then_some(&sender);
        let sender_key_public = auth.then_some(&sender_public);
        let (encapsulated, ciphertext) =
            Suite::seal(&recipient_public, b"info", b"aad", b"message", psk, sender_key, &mut random).unwrap();
        assert_eq!(
            Suite::open(&encapsulated, &recipient, b"info", b"aad", &ciphertext, psk, sender_key_public).unwrap(),
            b"message"
        );
        assert!(Suite::open(&encapsulated, &recipient, b"other", b"aad", &ciphertext, psk, sender_key_public).is_err());
        if psk.is_some() {
            assert!(
                Suite::open(&encapsulated, &recipient, b"info", b"aad", &ciphertext, None, sender_key_public).is_err()
            );
        }
    }
    let inconsistent = Some((&[1u8; 32][..], &b""[..]));
    assert_eq!(
        Suite::seal(&recipient_public, b"", b"", b"", inconsistent, None, &mut random).err(),
        Some(CryptoError::InvalidParameter)
    );
    // The export-only AEAD neither seals nor opens.
    let (_, mut context) =
        HPKE::<KEM, SHA256, HPKEExportOnly>::setup_sender(&recipient_public, b"", None, None, &mut random).unwrap();
    assert_eq!(context.seal(b"", b"m"), Err(CryptoError::InvalidParameter));
    // A public key of another length is refused (section 7.1.1).
    assert_eq!(KEM::deserialize_public_key(&[9; 31]).err(), Some(CryptoError::InvalidKey));
    assert_eq!(<DHKEM<ECDH<P256>, SHA256>>::deserialize_public_key(&[2; 33]).err(), Some(CryptoError::InvalidKey));
}
