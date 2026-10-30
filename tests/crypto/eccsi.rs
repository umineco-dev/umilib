//! ECCSI (RFC 6507) against the test data of its appendix A, on NIST P-256
//! with SHA-256.

use umilib::crypto::CryptoError;
use umilib::crypto::curve::p256::{P256, P256Scalar};
use umilib::crypto::eccsi::{ECCSI, ECCSIKMS, ECCSIUserKey};
use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;
use umilib::math::ec::{AffinePoint, FieldElement};

use crate::Vectors;

/// The value "name := 0x ...;" of appendix A, or for a hash "name := hash(
/// ... ), = 0x ...;" the value after "=", across lines.
fn appendix_a(name: &str) -> Vec<u8> {
    let text = Vectors::read("crypto/eccsi/rfc6507.txt");
    let start = text.find("\nAppendix A.  Test Data").unwrap();
    let section = &text[start..];
    let at = section.find(&format!("\n      {name} ")).unwrap_or_else(|| panic!("no {name}"));
    let mut value = &section[at + 1..];
    if value[..value.find('\n').unwrap()].contains("hash(") {
        value = &value[value.find("),").unwrap()..];
    }
    let from = value.find("0x").unwrap() + 2;
    let to = from + value[from..].find(';').unwrap();
    let hex: String = value[from..to].split_whitespace().collect();
    let padded = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex };
    Vectors::hex(&padded)
}

fn scalar(bytes: &[u8]) -> FieldElement<P256Scalar> {
    let mut padded = vec![0u8; 32 - bytes.len().min(32)];
    padded.extend_from_slice(bytes);
    FieldElement::from_be_bytes(&padded).unwrap()
}

fn point(bytes: &[u8]) -> AffinePoint<P256> {
    AffinePoint::from_encoded(bytes).unwrap()
}

#[test]
fn rfc6507_test_data() {
    let identity = appendix_a("ID");
    assert_eq!(identity, b"2011-02\0tel:+447700900123\0");
    let kms = ECCSIKMS::<P256>::new(scalar(&appendix_a("KSAK"))).unwrap();
    assert_eq!(*kms.public_key(), point(&appendix_a("KPAK")));
    let key: ECCSIUserKey<P256, SHA256> = kms.issue_with_ephemeral(&identity, &scalar(&appendix_a("v"))).unwrap();
    assert_eq!(*key.token(), point(&appendix_a("PVT")));
    assert_eq!(*key.hash(), scalar(&appendix_a("HS")));
    assert_eq!(*key.secret(), scalar(&appendix_a("SSK")));

    let message = appendix_a("M");
    assert_eq!(message, b"message\0");
    let signature = ECCSI::<P256, SHA256>::sign_with_ephemeral(&key, &message, &scalar(&appendix_a("j"))).unwrap();
    assert_eq!(signature, appendix_a("Sig"));
    assert_eq!(&signature[..32], &appendix_a("r")[..]);
    assert_eq!(&signature[32..64], &appendix_a("s")[..]);
    assert_eq!(
        ECCSI::<P256, SHA256>::message_hash(key.hash(), &signature[..32], &message).unwrap(),
        scalar(&appendix_a("HE"))
    );
    assert_eq!(ECCSI::<P256, SHA256>::verify(kms.public_key(), &identity, &message, &signature), Ok(()));
}

#[test]
fn signatures_bind_identity_message_and_kms() {
    let mut random = HMACDRBG::<SHA256>::new(&[5; 32], &[6; 16], b"eccsi").unwrap();
    let kms = ECCSIKMS::<P256>::generate(&mut random).unwrap();
    let key: ECCSIUserKey<P256, SHA256> = kms.issue(b"alice", &mut random).unwrap();
    let signature = ECCSI::<P256, SHA256>::sign(&key, b"message", &mut random).unwrap();
    assert_eq!(ECCSI::<P256, SHA256>::verify(kms.public_key(), b"alice", b"message", &signature), Ok(()));
    let invalid = Err(CryptoError::InvalidSignature);
    assert_eq!(ECCSI::<P256, SHA256>::verify(kms.public_key(), b"bob", b"message", &signature), invalid);
    assert_eq!(ECCSI::<P256, SHA256>::verify(kms.public_key(), b"alice", b"massage", &signature), invalid);
    let other = ECCSIKMS::<P256>::generate(&mut random).unwrap();
    assert_eq!(ECCSI::<P256, SHA256>::verify(other.public_key(), b"alice", b"message", &signature), invalid);
    for index in [0, 40, 70, signature.len() - 1] {
        let mut changed = signature.clone();
        changed[index] ^= 1;
        assert_eq!(ECCSI::<P256, SHA256>::verify(kms.public_key(), b"alice", b"message", &changed), invalid);
    }
    assert_eq!(ECCSI::<P256, SHA256>::verify(kms.public_key(), b"alice", b"message", &signature[1..]), invalid);
    // An SSK of another identity, or another KPAK, does not validate (section 5.1.2).
    assert_eq!(
        ECCSIUserKey::<P256, SHA256>::new(kms.public_key(), b"bob", *key.secret(), *key.token()).err(),
        Some(CryptoError::InvalidKey)
    );
    assert_eq!(
        ECCSIUserKey::<P256, SHA256>::new(other.public_key(), b"alice", *key.secret(), *key.token()).err(),
        Some(CryptoError::InvalidKey)
    );
    assert!(format!("{key:?}").ends_with(", ..)"));
}
