//! CMAC against NIST CAVP (CMACVS), RFC 4493 and Project Wycheproof.

use umilib::crypto::aes::{AES128, AES192, AES256};
use umilib::crypto::cmac::CMAC;
#[cfg(umilib_feature = "crypto-des")]
use umilib::crypto::des::TDES;
use umilib::crypto::{BlockCipher, KeyInit};

use crate::{Record, Vectors, wycheproof};

/// The full tag of `message` under the AES key `key`.
fn tag(key: &[u8], message: &[u8]) -> Vec<u8> {
    fn with<C: BlockCipher + KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut cmac = CMAC::<C>::new_from_slice(key).unwrap();
        for piece in message.chunks(11) {
            cmac.update(piece);
        }
        let mut copy = cmac.clone();
        copy.reset();
        copy.update(message);
        let tag = cmac.finalize().as_ref().to_vec();
        assert_eq!(copy.finalize().as_ref(), tag);
        tag
    }
    match key.len() {
        16 => with::<AES128>(key, message),
        24 => with::<AES192>(key, message),
        _ => with::<AES256>(key, message),
    }
}

#[test]
fn cmac_follows_the_cavp_vectors() {
    let mut checked = 0;
    for kind in ["Gen", "Ver"] {
        for size in [128, 192, 256] {
            let path = format!("crypto/cmac/CMAC{kind}AES{size}.rsp");
            for record in Record::all(&path) {
                let length: usize = record.field("Mlen").parse().unwrap();
                let mut message = record.bytes("Msg");
                message.truncate(length);
                let tag_length: usize = record.field("Tlen").parse().unwrap();
                let computed = tag(&record.bytes("Key"), &message);
                let expected = record.bytes("Mac");
                let label = format!("{path} Count = {}", record.field("Count"));
                if kind == "Gen" {
                    assert_eq!(computed[..tag_length], expected[..], "{label}");
                } else {
                    let valid = record.field("Result").starts_with('P');
                    assert_eq!(computed[..tag_length] == expected[..], valid, "{label}");
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 1176);
}

/// The TDES files hold the bundle as Key1, Key2 and Key3 (Key3 = Key1 for two keys) and tags of 1 to 8 bytes.
#[cfg(umilib_feature = "crypto-des")]
#[test]
fn cmac_with_tdes_follows_the_cavp_vectors() {
    let mut checked = 0;
    for kind in ["Gen", "Ver"] {
        for keys in [2, 3] {
            let path = format!("crypto/cmac/CMAC{kind}TDES{keys}.rsp");
            for record in Record::all(&path) {
                let length: usize = record.field("Mlen").parse().unwrap();
                let mut message = record.bytes("Msg");
                message.truncate(length);
                let tag_length: usize = record.field("Tlen").parse().unwrap();
                let key = |name: &str| -> [u8; 8] { record.bytes(name).try_into().unwrap() };
                let tdes = TDES::new(&key("Key1"), &key("Key2"), &key("Key3")).unwrap();
                let mut cmac = CMAC::new(tdes);
                cmac.update(&message);
                let expected = record.bytes("Mac");
                let label = format!("{path} Count = {}", record.field("Count"));
                if kind == "Gen" {
                    assert_eq!(cmac.finalize()[..tag_length], expected[..], "{label}");
                } else {
                    let valid = record.field("Result").starts_with('P');
                    assert_eq!(cmac.verify_truncated_with_minimum(&expected, tag_length), valid, "{label}");
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 96 + 96 + 360 + 240);
}

#[test]
fn cmac_follows_rfc4493() {
    // Section 4: AES-128 with the key 2b7e1516..., messages of 0, 16, 40 and 64 bytes.
    let key = Vectors::hex("2b7e151628aed2a6abf7158809cf4f3c");
    let message = Vectors::hex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    );
    for (length, expected) in [
        (0, "bb1d6929e95937287fa37d129b756746"),
        (16, "070a16b46b4d4144f79bdd9dd04a287c"),
        (40, "dfa66747de9ae63030ca32611497c827"),
        (64, "51f0bebf7e3b9d92fc49741779363cfe"),
    ] {
        assert_eq!(tag(&key, &message[..length]), Vectors::hex(expected), "{length} bytes");
    }
    // The subkeys of section 2.3 example.
    let mut k1 = [0u8; 16];
    AES128::new_from_slice(&key).unwrap().encrypt_block(&mut k1);
    assert_eq!(k1.to_vec(), Vectors::hex("7df76b0c1ab899b33e42f047b91b546f"));
    CMAC::<AES128>::double(&mut k1);
    assert_eq!(k1.to_vec(), Vectors::hex("fbeed618357133667c85e08f7236a8de"));
    CMAC::<AES128>::double(&mut k1);
    assert_eq!(k1.to_vec(), Vectors::hex("f7ddac306ae266ccf90bc11ee46d513b"));
}

#[test]
fn cmac_follows_the_wycheproof_vectors() {
    assert!(wycheproof!("crypto/cmac/aes_cmac_test.json", cmac, { 16 => AES128, 24 => AES192, 32 => AES256 }) > 200);
}

#[test]
fn cmac_verifies_truncated_tags() {
    let key = [5u8; 16];
    let full = tag(&key, b"message");
    let mut cmac = CMAC::<AES128>::new_from_slice(&key).unwrap();
    cmac.update(b"message");
    assert!(cmac.clone().verify_truncated(&full[..8]));
    assert!(!cmac.clone().verify_truncated(&full[..7]));
    assert!(cmac.clone().verify_truncated_with_minimum(&full[..4], 4));
    assert!(!cmac.clone().verify_truncated_with_minimum(&full[..4], 5));
    assert!(!cmac.clone().verify_truncated_with_minimum(&[], 0));
    let mut wrong = full.clone();
    wrong[3] ^= 1;
    assert!(!cmac.verify_truncated(&wrong));
}
