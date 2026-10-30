//! Identity-based signatures: Hess and Cha–Cheon on BLS12_381 and BN254,
//! whose papers give no test vectors (the tests check the equations that
//! define the schemes and the rejections a verifier must make), and SM9
//! against the example of GM/T 0044.5-2016 annex A.

use umilib::crypto::CryptoError;
use umilib::crypto::ibs::chacheon::{ChaCheon, ChaCheonSignature};
use umilib::crypto::ibs::hess::{Hess, HessSignature};
use umilib::crypto::ibs::sm9::{SM9, SM9Signature};
use umilib::crypto::ibs::{IBSHash, IBSMasterKey, IBSSignature, IdentityBasedSignature};
use umilib::crypto::random::HMACDRBG;
use umilib::crypto::sm9::{SM9Encoding, SM9Hash};
use umilib::hash::sha::v2::SHA256;
use umilib::hash::sm3::SM3;
use umilib::math::ec::{AffinePoint, FieldElement};
use umilib::math::pairing::{BLS12381, BN254, G2Affine, Pairing, PairingCurve, SM9BN256, SM9BN256Scalar};

use crate::GMT;

fn random(seed: u8) -> HMACDRBG<SHA256> {
    HMACDRBG::new(&[seed; 32], &[seed; 16], b"ibs").unwrap()
}

/// What every identity-based signature must do on the curve `C`.
fn check_scheme<S: IdentityBasedSignature<Curve = C>, C: PairingCurve>(
    encode: fn(&S::Signature) -> Vec<u8>,
    decode: fn(&[u8]) -> Result<S::Signature, CryptoError>,
) {
    let mut random = random(1);
    let master = S::setup(&mut random).unwrap();
    let alice = S::extract(&master, b"alice@example.com").unwrap();
    assert_eq!(alice.identity(), b"alice@example.com");
    assert_eq!(alice.master(), master.public_key());
    let signature = S::sign(&alice, b"message", &mut random).unwrap();
    let public = master.public_key();
    assert_eq!(S::verify(public, b"alice@example.com", b"message", &signature), Ok(()));
    let invalid = Err(CryptoError::InvalidSignature);
    assert_eq!(S::verify(public, b"bob@example.com", b"message", &signature), invalid);
    assert_eq!(S::verify(public, b"alice@example.com", b"massage", &signature), invalid);
    let other = S::setup(&mut random).unwrap();
    assert_eq!(S::verify(other.public_key(), b"alice@example.com", b"message", &signature), invalid);
    // The encoding round-trips and every changed byte is refused.
    let bytes = encode(&signature);
    assert_eq!(S::verify(public, b"alice@example.com", b"message", &decode(&bytes).unwrap()), Ok(()));
    for index in [1, bytes.len() / 2, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        if let Ok(changed) = decode(&changed) {
            assert_eq!(S::verify(public, b"alice@example.com", b"message", &changed), invalid);
        }
    }
    assert!(decode(&bytes[1..]).is_err());
    // Signatures are randomized and all verify.
    let again = S::sign(&alice, b"message", &mut random).unwrap();
    assert_ne!(encode(&again), bytes);
    assert_eq!(S::verify(public, b"alice@example.com", b"message", &again), Ok(()));
    assert!(format!("{alice:?}").ends_with(", ..)"));
    assert!(format!("{master:?}").ends_with(", ..)"));
}

/// H1 gives points of G_1 of the identity alone.
fn check_hash<C: PairingCurve>() {
    let point = IBSHash::<C, SHA256>::hash_to_g1(b"tag", b"alice").unwrap();
    assert!(point.is_on_curve().into_bool());
    assert!(point.is_in_subgroup().into_bool());
    assert!(!point.is_identity().into_bool());
    use umilib::math::ec::{PrimeField, ProjectivePoint};
    use umilib::math::modular::ModularArithmetic;
    let order = *<C::Scalar as PrimeField>::MODULUS.value();
    assert!(ProjectivePoint::from_affine(&point).mul_value_vartime(&order).is_identity().into_bool());
    assert_eq!(IBSHash::<C, SHA256>::hash_to_g1(b"tag", b"alice").unwrap(), point);
    assert_ne!(IBSHash::<C, SHA256>::hash_to_g1(b"tag", b"bob").unwrap(), point);
    assert_ne!(IBSHash::<C, SHA256>::hash_to_g1(b"other", b"alice").unwrap(), point);
}

/// The Extract of the schemes whose key of an identity is s H1(ID), H1 of
/// the domain tag `tag`: e(s Q_ID, P) = e(Q_ID, P_pub).
fn check_extract<S: IdentityBasedSignature<Curve = C>, C: PairingCurve>(tag: &[u8]) {
    let master = S::setup(&mut random(2)).unwrap();
    let alice = S::extract(&master, b"alice@example.com").unwrap();
    let point = IBSHash::<C, SHA256>::hash_to_g1(tag, b"alice@example.com").unwrap();
    assert_eq!(
        Pairing::<C>::pairing(alice.key(), &G2Affine::generator()).unwrap(),
        Pairing::<C>::pairing(&point, master.public_key()).unwrap()
    );
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn hess() {
    check_scheme::<Hess<BLS12381, SHA256>, BLS12381>(HessSignature::to_bytes, HessSignature::from_bytes);
    check_scheme::<Hess<BN254, SHA256>, BN254>(HessSignature::to_bytes, HessSignature::from_bytes);
    check_extract::<Hess<BN254, SHA256>, BN254>(Hess::<BN254, SHA256>::IDENTITY_TAG);
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn cha_cheon() {
    check_scheme::<ChaCheon<BLS12381, SHA256>, BLS12381>(ChaCheonSignature::to_bytes, ChaCheonSignature::from_bytes);
    check_scheme::<ChaCheon<BN254, SHA256>, BN254>(ChaCheonSignature::to_bytes, ChaCheonSignature::from_bytes);
    check_extract::<ChaCheon<BN254, SHA256>, BN254>(ChaCheon::<BN254, SHA256>::IDENTITY_TAG);
}

#[test]
fn hash_to_g1() {
    check_hash::<BLS12381>();
    check_hash::<BN254>();
}

/// An integer of the scalars of SM9BN256 after `label` in `annex`.
fn scalar(annex: &GMT, label: &str) -> FieldElement<SM9BN256Scalar> {
    FieldElement::from_be_bytes(&annex.padded(label, 32)).unwrap()
}

/// The bytes of an element of G_T after `label` in `annex`: its twelve coefficients in the order of the annex.
fn gt(annex: &GMT, label: &str) -> Vec<u8> {
    annex.values(label, 12).concat()
}

/// GM/T 0044.5-2016 annex A: the keys, the signature of "Chinese IBS
/// standard" by Alice with the given r, every intermediate value and the
/// verification.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm9_annex_a() {
    type Scheme = SM9<SM9BN256, SM3>;
    let annex = GMT::read("crypto/ibs/gmt-0044.5-2016-annex-a.txt");
    let master = IBSMasterKey::new(scalar(&annex, "The master signature private key ??:")).unwrap();
    let public = annex.values("The master signature public key ????−? = ?? ?2 = (?????−?, ?????−?):", 4);
    let mut encoded = vec![0x04];
    encoded.extend(public.concat());
    assert_eq!(Scheme::master_public_key_to_bytes(master.public_key()), encoded);
    assert_eq!(Scheme::master_public_key_from_bytes(&encoded).unwrap(), *master.public_key());
    assert_eq!(SM9Hash::<SM9BN256, SM3>::hash_bits(), 320);

    let identity = b"Alice";
    let extract = annex.values("Compute ?1 = ?1(??? ∥ ℎ??,?) + ?? in ??:", 3);
    assert_eq!(extract[0], [identity.as_slice(), &[0x01]].concat());
    let h1 = SM9Hash::<SM9BN256, SM3>::hash(0x01, &[identity, &[Scheme::SIGNATURE_IDENTIFIER]]).unwrap();
    assert_eq!(h1.value().to_be_bytes().to_vec(), extract[1]);
    let key = Scheme::extract(&master, identity).unwrap();
    let key_point = annex.values("The signature private key ??? = ?2 ?1 = ????,???? :", 2);
    let mut expected = vec![0x04];
    expected.extend(key_point.concat());
    let mut written = vec![0u8; 65];
    key.key().write_encoded(&mut written, false).unwrap();
    assert_eq!(written, expected);

    let message = annex.value("The hexadecimal representation of ?:");
    assert_eq!(message, b"Chinese IBS standard");
    let g = Pairing::<SM9BN256>::pairing(&AffinePoint::generator(), master.public_key()).unwrap();
    assert_eq!(SM9Encoding::<SM9BN256>::gt(&g), gt(&annex, "Compute the element ? = ?(?1,????−?) in ??:"));
    let r = scalar(&annex, "Generate random number ?:");
    assert_eq!(SM9Encoding::<SM9BN256>::gt(&g.pow(&r)), gt(&annex, "Compute the element ? = ?? in ??:"));
    let signature = Scheme::sign_with_ephemeral(&key, &message, &r).unwrap();
    let hashed = annex.values("Compute ℎ = ?2(? ∥ ?,?):", 2);
    assert_eq!(hashed[0], [message.as_slice(), &SM9Encoding::<SM9BN256>::gt(&g.pow(&r))].concat());
    assert_eq!(signature.h().value().to_be_bytes().to_vec(), hashed[1]);
    assert_eq!(r.sub(signature.h()).value().to_be_bytes().to_vec(), annex.value("Compute ? = (? − ℎ) mod ? :"));
    let output = annex.values("The signature (ℎ, ?) of the message ?:", 2);
    assert_eq!(signature.to_bytes(), output.concat());

    // The verification, with its intermediate values.
    assert_eq!(Scheme::verify(master.public_key(), identity, &message, &signature), Ok(()));
    let t = g.pow(signature.h());
    assert_eq!(SM9Encoding::<SM9BN256>::gt(&t), gt(&annex, "Compute the element ? = ?ℎ'"));
    let point = annex.values("ℎ1 ?2 + ????−? = (??,??) of ?2:", 4);
    let mut combined = vec![0x04];
    combined.extend(point.concat());
    let p = Scheme::master_public_key_from_bytes(&combined).unwrap();
    let u = Pairing::<SM9BN256>::pairing(signature.s(), &p).unwrap();
    assert_eq!(SM9Encoding::<SM9BN256>::gt(&u), gt(&annex, "Compute the element ? = ?(?',?) of ??:"));
    assert_eq!(SM9Encoding::<SM9BN256>::gt(&u.mul(&t)), gt(&annex, "Compute the element ?' = ? ⋅ ? of ??:"));
    let decoded = SM9Signature::<SM9BN256>::from_bytes(&output.concat()).unwrap();
    assert_eq!(Scheme::verify(master.public_key(), identity, &message, &decoded), Ok(()));
    let invalid = Err(CryptoError::InvalidSignature);
    assert_eq!(Scheme::verify(master.public_key(), b"Bob", &message, &decoded), invalid);
    assert_eq!(Scheme::verify_with_identifier(master.public_key(), identity, 0x02, &message, &decoded), invalid);
}

/// SM9 as every identity-based signature, and its rejections: h outside
/// [1, N - 1], S off the curve or the identity, other encodings.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm9() {
    type Scheme = SM9<SM9BN256, SM3>;
    check_scheme::<Scheme, SM9BN256>(SM9Signature::to_bytes, SM9Signature::from_bytes);
    let master = Scheme::setup(&mut random(3)).unwrap();
    let key = Scheme::extract(&master, b"alice").unwrap();
    let signature = Scheme::sign(&key, b"message", &mut random(4)).unwrap().to_bytes();
    let invalid = Some(CryptoError::InvalidSignature);
    let mut zero = signature.clone();
    zero[..32].fill(0);
    assert_eq!(SM9Signature::<SM9BN256>::from_bytes(&zero).err(), invalid);
    let mut order = signature.clone();
    order[..32].copy_from_slice(&Pairing::<SM9BN256>::order().to_be_bytes());
    assert_eq!(SM9Signature::<SM9BN256>::from_bytes(&order).err(), invalid);
    let mut off = signature.clone();
    off[96] ^= 1;
    assert_eq!(SM9Signature::<SM9BN256>::from_bytes(&off).err(), invalid);
    let mut compressed = signature[..65].to_vec();
    compressed[32] = 0x02 | (signature[96] & 1);
    assert_eq!(SM9Signature::<SM9BN256>::from_bytes(&compressed).err(), invalid);
    assert_eq!(SM9Signature::<SM9BN256>::from_bytes(&signature[..96]).err(), invalid);
    // The master public key: 04, then x and y of GF(p^2) with the u-coefficient first.
    let bytes = Scheme::master_public_key_to_bytes(master.public_key());
    assert_eq!(bytes.len(), 129);
    let mut wrong = bytes.clone();
    wrong[0] = 0x03;
    assert_eq!(Scheme::master_public_key_from_bytes(&wrong).err(), Some(CryptoError::InvalidKey));
    assert_eq!(Scheme::master_public_key_from_bytes(&bytes[..128]).err(), Some(CryptoError::InvalidKey));
}
