//! SM2 (GB/T 32918) against the examples of draft-shen-sm2-ecdsa over E(Fp),
//! on the test curve the draft defines, and on the recommended curve.

use umilib::crypto::CryptoError;
use umilib::crypto::curve::sm2::SM2;
use umilib::crypto::random::HMACDRBG;
use umilib::crypto::sm2::{
    SM2CiphertextOrder, SM2DSA, SM2KEP, SM2PKE, SM2PrivateKey, SM2PublicKey, SM2Role, SM2Signature,
};
use umilib::hash::sha::v2::SHA256;
use umilib::hash::sm3::SM3;
use umilib::math::bigint::U256;
use umilib::math::ec::{AffinePoint, CoefficientA, FieldElement, PrimeField, WeierstrassCurve};
use umilib::math::modular::Modulus;

use crate::Vectors;

/// The values of an appendix of the draft: each label line followed by
/// lines of hexadecimal groups.
struct Example {
    text: String,
}

impl Example {
    fn new(start: &str, end: &str) -> Example {
        let text = Vectors::read("crypto/sm2/draft-shen-sm2-ecdsa-02.txt");
        let from = text.find(&format!("\n{start}")).unwrap();
        let to = from + text[from..].find(&format!("\n{end}")).unwrap();
        Example { text: text[from..to].to_owned() }
    }

    /// The value after the first line that is `label` after `after`.
    fn value_after(&self, after: &str, label: &str) -> Vec<u8> {
        let start = self.text.find(after).unwrap_or_else(|| panic!("no {after}"));
        let mut lines = self.text[start..].lines().map(str::trim).skip_while(|line| *line != label);
        assert!(lines.next().is_some(), "no {label}");
        let is_group = |word: &str| !word.is_empty() && word.chars().all(|character| character.is_ascii_hexdigit());
        let hex: String = lines
            .filter(|line| !line.is_empty() && !line.starts_with("Shen") && !line.starts_with("Internet-Draft"))
            .take_while(|line| line.split_whitespace().all(is_group))
            .flat_map(str::split_whitespace)
            .collect();
        Vectors::hex(&hex)
    }

    fn value(&self, label: &str) -> Vec<u8> {
        self.value_after("", label)
    }
}

/// The 256-bit test curve of the draft's examples (y^2 = x^3 + ax + b).
#[derive(Clone, Copy, Debug)]
struct TestField;

impl PrimeField for TestField {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "8542d69e4c044f18e8b92435bf6ff7de457283915c45517d722edb8b08f1dfc3",
    ));
    const BYTES: usize = 32;
}

#[derive(Clone, Copy, Debug)]
struct TestScalar;

impl PrimeField for TestScalar {
    type Modulus = Modulus<{ U256::LIMBS }>;
    const MODULUS: Modulus<{ U256::LIMBS }> = Modulus::new_vartime_or_panic(U256::from_hex_vartime_or_panic(
        "8542d69e4c044f18e8b92435bf6ff7dd297720630485628d5ae74ee7c32e79b7",
    ));
    const BYTES: usize = 32;
}

const fn element(hex: &str) -> FieldElement<TestField> {
    FieldElement::from_residue(TestField::MODULUS.residue_vartime(&U256::from_hex_vartime_or_panic(hex)))
}

#[derive(Clone, Copy, Debug)]
struct TestCurve;

impl WeierstrassCurve for TestCurve {
    type Field = TestField;
    type Scalar = TestScalar;
    const A: FieldElement<TestField> = element("787968b4fa32c3fd2417842e73bbfeff2f3c848b6831d7e0ec65228b3937e498");
    const B: FieldElement<TestField> = element("63e4c6d3b23b0c849cf84241484bfe48f61d59a5b16ba06e6e12d1da27c5249a");
    const SHAPE: CoefficientA = CoefficientA::General;
    const GENERATOR_X: FieldElement<TestField> =
        element("421debd61b62eab6746434ebc3cc315e32220b3badd50bdc4c4e6c147fedd43d");
    const GENERATOR_Y: FieldElement<TestField> =
        element("0680512bcbb42c07d47349d2153b70c4e5d7fdfcbfa36ea1a85841b9e46e09a2");
    const COFACTOR: u128 = 1;
}

/// The public key of the coordinates of `labels` in `example`, after `after`.
fn point(example: &Example, after: &str, x: &str, y: &str) -> AffinePoint<TestCurve> {
    let (x, y) = (example.value_after(after, x), example.value_after(after, y));
    AffinePoint::new(FieldElement::from_be_bytes(&x).unwrap(), FieldElement::from_be_bytes(&y).unwrap()).unwrap()
}

/// Appendix A.2: the key pair, Z, e and the signature of "message digest".
#[test]
fn signature_example() {
    let example = Example::new("A.2.  Digital Signature", "A.3.  Digital Signature");
    let key = SM2PrivateKey::<TestCurve>::from_bytes(&example.value("The private key dA:")).unwrap();
    let public = point(&example, "The public key PA", "x-coordinate xA:", "y-coordinate yA:");
    assert_eq!(*key.public_key().point(), public);
    // The draft's IDA is cut short; the identity is the text it spells.
    let identity = b"ALICE123@YAHOO.COM";
    let z = key.public_key().identity_hash::<SM3>(identity).unwrap();
    assert_eq!(z.as_ref(), &example.value("ZA:")[..]);
    let message = b"message digest";
    let e = SM2DSA::<TestCurve, SM3>::digest_scalar(key.public_key(), identity, message).unwrap();
    assert_eq!(e, FieldElement::from_be_bytes_reduced(&example.value("hash value e=H256(M):")));
    let signature = SM2Signature::<TestCurve>::new(
        FieldElement::from_be_bytes(&example.value_after("Digital Signature of the message M", "r:")).unwrap(),
        FieldElement::from_be_bytes(&example.value_after("Digital Signature of the message M", "s:")).unwrap(),
    )
    .unwrap();
    assert_eq!(SM2DSA::<TestCurve, SM3>::verify(key.public_key(), identity, message, &signature), Ok(()));
    let invalid = Err(CryptoError::InvalidSignature);
    assert_eq!(SM2DSA::<TestCurve, SM3>::verify(key.public_key(), b"BILL456@YAHOO.COM", message, &signature), invalid);
    assert_eq!(SM2DSA::<TestCurve, SM3>::verify(key.public_key(), identity, b"message digesT", &signature), invalid);
    // Our own signatures verify.
    let own = SM2DSA::<TestCurve, SM3>::sign(&key, identity, message).unwrap();
    assert_eq!(SM2DSA::<TestCurve, SM3>::verify(key.public_key(), identity, message, &own), Ok(()));
    assert_eq!(SM2DSA::<TestCurve, SM3>::sign(&key, identity, message).unwrap(), own);
}

/// Appendix B.2: A and B agree on KA = KB with the given ephemeral keys,
/// and on the confirmation SB.
#[test]
fn key_exchange_example() {
    let example = Example::new("B.2.  Key Exchange", "B.3.  Key Exchange");
    let key_a = SM2PrivateKey::<TestCurve>::from_bytes(&example.value("The private key dA:")).unwrap();
    let key_b = SM2PrivateKey::<TestCurve>::from_bytes(&example.value("The private key dB:")).unwrap();
    assert_eq!(
        *key_a.public_key().point(),
        point(&example, "The public key PA", "x-coordinate xA:", "y-coordinate yA:")
    );
    assert_eq!(
        *key_b.public_key().point(),
        point(&example, "The public key PB", "x-coordinate xB:", "y-coordinate yB:")
    );
    let r_a = SM2PrivateKey::from_bytes(&example.value("random number rA:")).unwrap();
    let r_b = SM2PrivateKey::from_bytes(&example.value("random number rB:")).unwrap();
    let (identity_a, identity_b) = (b"ALICE123@YAHOO.COM", b"BILL456@YAHOO.COM");
    let a = SM2KEP::<TestCurve, SM3>::new(SM2Role::Initiator, key_a.clone(), identity_a, r_a).unwrap();
    let b = SM2KEP::<TestCurve, SM3>::new(SM2Role::Responder, key_b.clone(), identity_b, r_b).unwrap();
    assert_eq!(a.identity_hash(), &example.value("ZA:")[..]);
    assert_eq!(b.identity_hash(), &example.value("ZB:")[..]);
    assert_eq!(*a.ephemeral_public_key().point(), point(&example, "point RA", "x-coordinate x1:", "y-coordinate y1:"));
    assert_eq!(*b.ephemeral_public_key().point(), point(&example, "point RB", "x-coordinate x2:", "y-coordinate y2:"));
    let reduced = SM2KEP::<TestCurve, SM3>::reduced_coordinate(b.ephemeral_public_key().point()).unwrap();
    let mut expected = vec![0u8; 16];
    expected.extend(example.value("x2~=2^127+(x2 AND (2^127-1)):"));
    assert_eq!(reduced, FieldElement::from_be_bytes(&expected).unwrap());

    let (mut shared_a, mut shared_b) = ([0u8; 16], [0u8; 16]);
    let confirmation_b = b.agree(key_a.public_key(), identity_a, a.ephemeral_public_key(), &mut shared_b).unwrap();
    let confirmation_a = a.agree(key_b.public_key(), identity_b, b.ephemeral_public_key(), &mut shared_a).unwrap();
    assert_eq!(&shared_b[..], &example.value("shared secret key KB:")[..]);
    assert_eq!(shared_a, shared_b);
    assert_eq!(confirmation_b.responder(), &example.value("option SB:")[..]);
    assert_eq!(confirmation_a.responder(), confirmation_b.responder());
    assert_eq!(confirmation_a.initiator(), confirmation_b.initiator());
    assert!(a.confirm(&confirmation_a, confirmation_b.responder()));
    assert!(b.confirm(&confirmation_b, confirmation_a.initiator()));
    assert!(!a.confirm(&confirmation_a, confirmation_a.initiator()));
    // Another identity gives another key.
    let mut other = [0u8; 16];
    a.agree(key_b.public_key(), b"MALLORY", b.ephemeral_public_key(), &mut other).unwrap();
    assert_ne!(other, shared_a);
}

/// Appendix C.2: the ciphertext of "encryption standard" (C1 || C2 || C3)
/// decrypts; our own encryptions decrypt in both orders.
#[test]
fn encryption_example() {
    let example = Example::new("C.2.  Encryption and Decryption", "C.3.  Encryption and Decryption");
    let key = SM2PrivateKey::<TestCurve>::from_bytes(&example.value("The private key dB:")).unwrap();
    assert_eq!(*key.public_key().point(), point(&example, "The public key PB", "x-coordinate xB:", "y-coordinate yB:"));
    let ciphertext = example.value("ciphertext C=C1 || C2 || C3:");
    let message = b"encryption standard";
    let order = SM2CiphertextOrder::C1C2C3;
    assert_eq!(SM2PKE::<TestCurve, SM3>::decrypt(&key, &ciphertext, order).unwrap(), message);
    assert_eq!(
        SM2PKE::<TestCurve, SM3>::decrypt(&key, &ciphertext, SM2CiphertextOrder::C1C3C2),
        Err(CryptoError::DecryptionFailed)
    );
    for index in [1, 70, ciphertext.len() - 1] {
        let mut changed = ciphertext.clone();
        changed[index] ^= 1;
        assert_eq!(SM2PKE::<TestCurve, SM3>::decrypt(&key, &changed, order), Err(CryptoError::DecryptionFailed));
    }
    assert_eq!(SM2PKE::<TestCurve, SM3>::decrypt(&key, &ciphertext[..96], order), Err(CryptoError::DecryptionFailed));
    let mut random = HMACDRBG::<SHA256>::new(&[6; 32], &[7; 16], b"sm2").unwrap();
    for order in [SM2CiphertextOrder::C1C3C2, SM2CiphertextOrder::C1C2C3] {
        let own = SM2PKE::<TestCurve, SM3>::encrypt(key.public_key(), message, order, &mut random).unwrap();
        assert_eq!(own.len(), message.len() + SM2PKE::<TestCurve, SM3>::OVERHEAD);
        assert_eq!(SM2PKE::<TestCurve, SM3>::decrypt(&key, &own, order).unwrap(), message);
    }
}

/// The recommended curve with SM3, through every interface.
#[test]
fn recommended_curve() {
    super::ecdsa::check_scheme::<SM2DSA>();
    let mut random = HMACDRBG::<SHA256>::new(&[8; 32], &[9; 16], b"sm2").unwrap();
    let key = SM2PrivateKey::<SM2>::generate(&mut random).unwrap();
    let ciphertext =
        SM2PKE::<SM2, SM3>::encrypt(key.public_key(), b"plaintext", SM2CiphertextOrder::C1C3C2, &mut random).unwrap();
    assert_eq!(SM2PKE::<SM2, SM3>::decrypt(&key, &ciphertext, SM2CiphertextOrder::C1C3C2).unwrap(), b"plaintext");
    let hedged = SM2DSA::<SM2, SM3>::sign_hedged(&key, b"id", b"m", &mut random).unwrap();
    assert_eq!(SM2DSA::<SM2, SM3>::verify(key.public_key(), b"id", b"m", &hedged), Ok(()));
    #[cfg(umilib_feature = "codec-asn1-der")]
    assert_eq!(SM2Signature::<SM2>::from_der(&hedged.to_der()).unwrap(), hedged);
    // 0 and n - 1 are not private keys.
    assert_eq!(SM2PrivateKey::<SM2>::new(FieldElement::zero()).err(), Some(CryptoError::InvalidKey));
    assert_eq!(SM2PrivateKey::<SM2>::new(FieldElement::one().neg()).err(), Some(CryptoError::InvalidKey));
    assert!(SM2PublicKey::<SM2>::from_encoded(&[0]).is_err());
    let (a, b) =
        (SM2PrivateKey::<SM2>::generate(&mut random).unwrap(), SM2PrivateKey::<SM2>::generate(&mut random).unwrap());
    let initiator = SM2KEP::<SM2, SM3>::generate(SM2Role::Initiator, a.clone(), b"a", &mut random).unwrap();
    let responder = SM2KEP::<SM2, SM3>::generate(SM2Role::Responder, b.clone(), b"b", &mut random).unwrap();
    let (mut key_a, mut key_b) = ([0u8; 48], [0u8; 48]);
    initiator.agree(b.public_key(), b"b", responder.ephemeral_public_key(), &mut key_a).unwrap();
    responder.agree(a.public_key(), b"a", initiator.ephemeral_public_key(), &mut key_b).unwrap();
    assert_eq!(key_a, key_b);
}
