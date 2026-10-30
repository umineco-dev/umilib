//! SM9 key exchange, key encapsulation and public key encryption (GM/T
//! 0044.3-2016 and 0044.4-2016) against the examples of GM/T 0044.5-2016
//! annexes B, C and D, and the rejections the standard requires.

use umilib::crypto::CryptoError;
use umilib::crypto::random::HMACDRBG;
use umilib::crypto::sm4::SM4;
use umilib::crypto::sm9::{
    SM9BlockCipher, SM9Encoding, SM9EncryptMasterKey, SM9EncryptUserKey, SM9Hash, SM9KEM, SM9KEP, SM9PKE, SM9Role,
};
use umilib::hash::sha::v2::SHA256;
use umilib::hash::sm3::SM3;
use umilib::math::ec::{AffinePoint, FieldElement};
use umilib::math::pairing::{G2Affine, Pairing, SM9BN256, SM9BN256Scalar};

use crate::GMT;

type Hash = SM9Hash<SM9BN256, SM3>;
type Encoding = SM9Encoding<SM9BN256>;
type Exchange = SM9KEP<SM9BN256, SM3>;
type Encapsulation = SM9KEM<SM9BN256, SM3>;
type StreamEncryption = SM9PKE<SM9BN256, SM3>;
type BlockEncryption = SM9PKE<SM9BN256, SM3, SM9BlockCipher<SM4>>;

/// The identifier of the encryption keys of the annexes: hid = 03.
const HID: u8 = 0x03;

fn random(seed: u8) -> HMACDRBG<SHA256> {
    HMACDRBG::new(&[seed; 32], &[seed; 16], b"sm9").unwrap()
}

/// An integer of the scalars of SM9BN256.
fn scalar(bytes: &[u8]) -> FieldElement<SM9BN256Scalar> {
    let mut padded = vec![0u8; 32 - bytes.len()];
    padded.extend(bytes);
    FieldElement::from_be_bytes(&padded).unwrap()
}

/// 04 || x || y of a point of G_2 printed as the coordinates `values`.
fn g2(values: &[Vec<u8>]) -> Vec<u8> {
    [&[0x04][..], &values.concat()].concat()
}

/// The master encryption key of an annex, checked against Ppub-e.
fn master(annex: &GMT) -> SM9EncryptMasterKey<SM9BN256> {
    let master = SM9EncryptMasterKey::new(scalar(&annex.value("The master encryption private key ??:"))).unwrap();
    let public = annex.values("The master encryption public key ????−? = ?? ?1 = (?????−?,?????−?):", 2);
    assert_eq!(Encoding::g1(master.public_key()).unwrap(), public.concat());
    master
}

/// The encryption key of `identity` in the part of an annex that computes
/// it: ID || hid, H1(ID || hid, N), t1, t2 and de.
fn user(annex: &GMT, master: &SM9EncryptMasterKey<SM9BN256>, identity: &[u8]) -> SM9EncryptUserKey<SM9BN256> {
    let values = annex.values("in ??:", 8);
    assert_eq!(values[0], [identity, &[HID]].concat());
    assert_eq!(Hash::hash(Hash::H1, &[identity, &[HID]]).unwrap().value().to_be_bytes().to_vec(), values[1]);
    let t1 = Hash::hash(Hash::H1, &[identity, &[HID]]).unwrap().add(master.secret());
    assert_eq!(t1.value().to_be_bytes().to_vec(), values[2]);
    assert_eq!(master.secret().mul(&t1.invert().unwrap()).value().to_be_bytes().to_vec(), values[3]);
    let key = master.extract::<SM3>(identity, HID).unwrap();
    assert_eq!(Encoding::g2(key.key()).unwrap(), g2(&values[4..8]));
    assert_eq!(key.identity(), identity);
    assert_eq!(key.hid(), HID);
    key
}

/// GM/T 0044.5-2016 annex B: the keys of Alice and Bob, R_A and R_B of the
/// given r_A and r_B, g1, g2 and g3 of both sides, SK of 128 bits and the
/// confirmations S_B and S_A.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm9_annex_b() {
    let annex = GMT::read("crypto/sm9/gmt-0044.5-2016-annex-b.txt");
    let master = master(&annex);
    let alice = user(
        &annex.section("The identity ??? of the entity A: Alice", "The identity ??? of the entity B"),
        &master,
        b"Alice",
    );
    let bob = user(&annex.section("The identity ??? of the entity B: Bob", "The length ????"), &master, b"Bob");

    // A1 to A4 (the annex prints IDB || hid with hid 02, and H1 of hid 03: see tests/vectors/crypto/sm9/SOURCE).
    let steps = annex.section("The related values in the steps A1—A4", "The related values in the steps B1—B7");
    let values = steps.values("(???,???):", 7);
    assert_eq!(values[0], b"Bob\x02");
    assert_eq!(Hash::hash(Hash::H1, &[b"Bob", &[HID]]).unwrap().value().to_be_bytes().to_vec(), values[1]);
    let peer = Hash::identity_point(master.public_key(), b"Bob", HID).unwrap();
    assert_eq!(Encoding::g1(&peer).unwrap(), values[2..4].concat());
    let initiator = Exchange::new(SM9Role::Initiator, alice, b"Bob", scalar(&values[4])).unwrap();
    assert_eq!(Encoding::g1(initiator.ephemeral_public_key()).unwrap(), values[5..7].concat());

    // B1 to B7.
    let steps = annex.section("The related values in the steps B1—B7", "The related values in the steps A5—A8");
    let values = steps.values("(???,???):", 7 + 36 + 6);
    assert_eq!(values[0], b"Alice\x02");
    let peer = Hash::identity_point(master.public_key(), b"Alice", HID).unwrap();
    assert_eq!(Encoding::g1(&peer).unwrap(), values[2..4].concat());
    let responder = Exchange::new(SM9Role::Responder, bob, b"Alice", scalar(&values[4])).unwrap();
    assert_eq!(Encoding::g1(responder.ephemeral_public_key()).unwrap(), values[5..7].concat());
    let (g1, g2, g3) = (values[7..19].concat(), values[19..31].concat(), values[31..43].concat());
    let bob = master.extract::<SM3>(b"Bob", HID).unwrap();
    let pairing = Pairing::<SM9BN256>::pairing(initiator.ephemeral_public_key(), bob.key()).unwrap();
    assert_eq!(Encoding::gt(&pairing), g1);
    let own = Pairing::<SM9BN256>::pairing(master.public_key(), &G2Affine::generator()).unwrap();
    assert_eq!(Encoding::gt(&own.pow(&scalar(&values[4]))), g2);
    assert_eq!(Encoding::gt(&pairing.pow(&scalar(&values[4]))), g3);
    let identities_and_points = [
        b"Alice".as_slice(),
        b"Bob",
        &Encoding::g1(initiator.ephemeral_public_key()).unwrap(),
        &Encoding::g1(responder.ephemeral_public_key()).unwrap(),
    ]
    .concat();
    assert_eq!(values[43], [identities_and_points.as_slice(), &g1, &g2, &g3].concat());
    let mut responder_key = [0u8; 16];
    let responder_confirmation = responder.agree(initiator.ephemeral_public_key(), &mut responder_key).unwrap();
    assert_eq!(responder_key.to_vec(), values[44]);
    assert_eq!(values[45], [g2.as_slice(), &g3, &identities_and_points].concat());
    assert_eq!(responder_confirmation.responder(), values[48]);

    // A5 to A8: S1 = S_B, SK_A = SK_B and S_A.
    let steps = annex.section("The related values in the steps A5—A8", "The related values in the step B8");
    let mut initiator_key = [0u8; 16];
    let initiator_confirmation = initiator.agree(responder.ephemeral_public_key(), &mut initiator_key).unwrap();
    assert_eq!(initiator_confirmation.responder(), steps.value("\n?1: "));
    assert_eq!(initiator_key.to_vec(), steps.value("\n???: "));
    assert_eq!(initiator_key, responder_key);
    assert!(initiator.confirm(&initiator_confirmation, responder_confirmation.responder()));
    assert_eq!(initiator_confirmation.initiator(), steps.value("\n??: "));

    // B8: S2 = S_A.
    let steps = annex.section("The related values in the step B8", "If ?2 = ??");
    assert_eq!(responder_confirmation.initiator(), steps.value("\n?2: "));
    assert!(responder.confirm(&responder_confirmation, initiator_confirmation.initiator()));
    assert!(!responder.confirm(&responder_confirmation, responder_confirmation.responder()));
    assert!(!initiator.confirm(&initiator_confirmation, initiator_confirmation.initiator()));
}

/// GM/T 0044.5-2016 annex C: Bob's key, C of the given r, g, w and K of 256
/// bits, and the decapsulation.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm9_annex_c() {
    let annex = GMT::read("crypto/sm9/gmt-0044.5-2016-annex-c.txt");
    let master = master(&annex);
    let bob = user(
        &annex.section("The identity ??? of the entity B: Bob", "The length of encapsulated key"),
        &master,
        b"Bob",
    );
    assert_eq!(annex.value("The length of encapsulated key:"), [0x01, 0x00]);
    let steps = annex.section("The related values in the steps A1—A7", "The related values in the steps B1—B4");
    let values = steps.values("(???,???):", 4 + 1 + 2 + 24 + 2);
    assert_eq!(values[0], b"Bob\x03");
    let peer = Hash::identity_point(master.public_key(), b"Bob", HID).unwrap();
    assert_eq!(Encoding::g1(&peer).unwrap(), values[2..4].concat());
    let r = scalar(&values[4]);
    let g = Pairing::<SM9BN256>::pairing(master.public_key(), &G2Affine::generator()).unwrap();
    assert_eq!(Encoding::gt(&g), values[7..19].concat());
    let w = values[19..31].concat();
    assert_eq!(Encoding::gt(&g.pow(&r)), w);
    let mut key = [0u8; 32];
    let encapsulated =
        Encapsulation::encapsulate_with_ephemeral(master.public_key(), b"Bob", HID, &r, &mut key).unwrap();
    let c = Encoding::g1(&encapsulated).unwrap();
    assert_eq!(c, values[5..7].concat());
    assert_eq!(values[31], [c.as_slice(), &w, b"Bob"].concat());
    assert_eq!(key.to_vec(), values[32]);

    let steps = annex.after("The related values in the steps B1—B4");
    let w_prime = Pairing::<SM9BN256>::pairing(&encapsulated, bob.key()).unwrap();
    assert_eq!(Encoding::gt(&w_prime), steps.values("(?',???):", 12).concat());
    let mut decapsulated = [0u8; 32];
    Encapsulation::decapsulate(&bob, &Encoding::g1_from_bytes(&c).unwrap(), &mut decapsulated).unwrap();
    assert_eq!(decapsulated, key);
    assert_eq!(decapsulated.to_vec(), steps.value("\n?': "));
}

/// GM/T 0044.5-2016 annex D: the encryption of "Chinese IBE standard" for
/// Bob with the given r, with the KDF stream cipher (a) and with SM4 in CBC
/// mode (b), and the decryptions.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm9_annex_d() {
    let annex = GMT::read("crypto/sm9/gmt-0044.5-2016-annex-d.txt");
    let master = master(&annex);
    let bob =
        user(&annex.section("The identity ??? of the entity B: Bob", "The message ? to be encrypted"), &master, b"Bob");
    let message = annex.value("The hexadecimal representation of ?:");
    assert_eq!(message, b"Chinese IBE standard");
    let encryption = annex.section("The related values in the steps A1—A8", "The related values in the steps B1—B5");
    let values = encryption.values("(???,???):", 4 + 1 + 2 + 24);
    let r = scalar(&values[4]);
    let w = values[19..31].concat();

    // a) The stream cipher: klen = mlen + K2_len, C2 = M ⊕ K1, C3 = MAC(K2, C2).
    let label = "a) The encryption is based on the KDF stream cipher:";
    let parts = encryption.section(label, "b) The encryption").values(label, 8);
    assert_eq!(parts[0], [0x01, 0xA0]);
    assert_eq!(parts[1], [values[5..7].concat().as_slice(), &w, b"Bob"].concat());
    assert_eq!(parts[2], [parts[3].as_slice(), &parts[5]].concat());
    let ciphertext = StreamEncryption::encrypt_with_ephemeral(master.public_key(), b"Bob", HID, &message, &r).unwrap();
    assert_eq!(ciphertext, parts[7]);
    assert_eq!(ciphertext, [values[5..7].concat().as_slice(), &parts[6], &parts[4]].concat());
    assert_eq!(StreamEncryption::mac(&parts[5], &parts[4]).as_ref(), parts[6].as_slice());
    assert_eq!(StreamEncryption::decrypt(&bob, &ciphertext).unwrap(), message);

    // b) SM4-CBC: klen = K1_len + K2_len, M padded to 128 bits, C3 = MAC(K2, C2).
    let label = "b) The encryption is based on the block cipher:";
    let parts = encryption.values(label, 9);
    assert_eq!(parts[0], [0x01, 0x80]);
    assert_eq!(parts[2], [parts[3].as_slice(), &parts[6]].concat());
    assert_eq!(parts[4], [message.as_slice(), &[0x0C; 12]].concat());
    let ciphertext = BlockEncryption::encrypt_with_ephemeral(master.public_key(), b"Bob", HID, &message, &r).unwrap();
    assert_eq!(ciphertext, parts[8]);
    assert_eq!(ciphertext, [values[5..7].concat().as_slice(), &parts[7], &parts[5]].concat());
    assert_eq!(BlockEncryption::decrypt(&bob, &ciphertext).unwrap(), message);

    // B1 to B5: w' and the message of each ciphertext.
    let decryption = annex.after("The related values in the steps B1—B5");
    assert_eq!(decryption.values("Compute ?' = ?(?1", 12).concat(), w);
    let label = "a) The encryption is based on the KDF stream cipher:";
    assert_eq!(decryption.values(label, 5)[4], message);
    let label = "b) The encryption is based on the block cipher:";
    assert_eq!(decryption.values(label, 5)[4], [message.as_slice(), &[0x0C; 12]].concat());
}

/// Two users agree on the same key with random r_A and r_B, the
/// confirmations match, and other keys, roles or points disagree or fail.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm9_key_exchange() {
    let master = SM9EncryptMasterKey::<SM9BN256>::generate(&mut random(1)).unwrap();
    let alice = || master.extract::<SM3>(b"alice", HID).unwrap();
    let bob = || master.extract::<SM3>(b"bob", HID).unwrap();
    let initiator = Exchange::generate(SM9Role::Initiator, alice(), b"bob", &mut random(2)).unwrap();
    let responder = Exchange::generate(SM9Role::Responder, bob(), b"alice", &mut random(3)).unwrap();
    assert_eq!(initiator.role(), SM9Role::Initiator);
    let (mut a, mut b) = ([0u8; 48], [0u8; 48]);
    let from_b = responder.agree(initiator.ephemeral_public_key(), &mut b).unwrap();
    let from_a = initiator.agree(responder.ephemeral_public_key(), &mut a).unwrap();
    assert_eq!(a, b);
    assert!(initiator.confirm(&from_a, from_b.responder()));
    assert!(responder.confirm(&from_b, from_a.initiator()));

    // Both as initiators, or a third user in Bob's place: other keys.
    let other = Exchange::generate(SM9Role::Initiator, bob(), b"alice", &mut random(4)).unwrap();
    let mut c = [0u8; 48];
    other.agree(initiator.ephemeral_public_key(), &mut c).unwrap();
    assert_ne!(a, c);
    let carol =
        Exchange::generate(SM9Role::Responder, master.extract::<SM3>(b"carol", HID).unwrap(), b"alice", &mut random(5))
            .unwrap();
    carol.agree(initiator.ephemeral_public_key(), &mut c).unwrap();
    assert_ne!(a, c);

    // R must be a point of G_1 other than the identity; r must not be zero.
    assert_eq!(initiator.agree(&AffinePoint::identity(), &mut c).err(), Some(CryptoError::InvalidKey));
    assert_eq!(
        Exchange::new(SM9Role::Initiator, alice(), b"bob", FieldElement::zero()).err(),
        Some(CryptoError::InvalidKey)
    );
    assert!(Encoding::g1_from_bytes(&[0u8; 64]).is_err());
    let mut off = Encoding::g1(initiator.ephemeral_public_key()).unwrap();
    off[63] ^= 1;
    assert_eq!(Encoding::g1_from_bytes(&off).err(), Some(CryptoError::InvalidKey));
}

/// Encapsulation and decapsulation with random r, and the rejections of C.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm9_key_encapsulation() {
    let master = SM9EncryptMasterKey::<SM9BN256>::generate(&mut random(6)).unwrap();
    let bob = master.extract::<SM3>(b"bob", HID).unwrap();
    let mut key = [0u8; 40];
    let encapsulated = Encapsulation::encapsulate(master.public_key(), b"bob", HID, &mut key, &mut random(7)).unwrap();
    let mut decapsulated = [0u8; 40];
    Encapsulation::decapsulate(&bob, &encapsulated, &mut decapsulated).unwrap();
    assert_eq!(key, decapsulated);
    // Another user's key, or another identifier, derives another K.
    let carol = master.extract::<SM3>(b"carol", HID).unwrap();
    Encapsulation::decapsulate(&carol, &encapsulated, &mut decapsulated).unwrap();
    assert_ne!(key, decapsulated);
    let other = master.extract::<SM3>(b"bob", 0x02).unwrap();
    Encapsulation::decapsulate(&other, &encapsulated, &mut decapsulated).unwrap();
    assert_ne!(key, decapsulated);
    assert_eq!(
        Encapsulation::decapsulate(&bob, &AffinePoint::identity(), &mut decapsulated).err(),
        Some(CryptoError::InvalidKey)
    );
    assert_eq!(
        Encapsulation::encapsulate_with_ephemeral(master.public_key(), b"bob", HID, &FieldElement::zero(), &mut key)
            .err(),
        Some(CryptoError::InvalidParameter)
    );
    // klen = 0: K is empty and the encapsulation is refused, not retried.
    let empty = Some(CryptoError::InputLength { length: 0 });
    assert_eq!(Encapsulation::encapsulate(master.public_key(), b"bob", HID, &mut [], &mut random(10)).err(), empty);
    assert_eq!(Encapsulation::decapsulate(&bob, &encapsulated, &mut []).err(), empty);
}

/// Encryption and decryption of messages of every length up to a few
/// blocks with both ciphers, and the rejection of every changed ciphertext.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn sm9_encryption() {
    let master = SM9EncryptMasterKey::<SM9BN256>::generate(&mut random(8)).unwrap();
    let bob = master.extract::<SM3>(b"bob", HID).unwrap();
    let carol = master.extract::<SM3>(b"carol", HID).unwrap();
    let mut random = random(9);
    let failed = Some(CryptoError::DecryptionFailed);
    for length in [0, 1, 15, 16, 17, 33] {
        let message: Vec<u8> = (0..length as u8).collect();
        let stream = StreamEncryption::encrypt(master.public_key(), b"bob", HID, &message, &mut random).unwrap();
        assert_eq!(stream.len(), StreamEncryption::overhead() + length);
        assert_eq!(StreamEncryption::decrypt(&bob, &stream).unwrap(), message);
        let block = BlockEncryption::encrypt(master.public_key(), b"bob", HID, &message, &mut random).unwrap();
        assert_eq!(block.len(), BlockEncryption::overhead() + (length / 16 + 1) * 16);
        assert_eq!(BlockEncryption::decrypt(&bob, &block).unwrap(), message);
        assert_eq!(StreamEncryption::decrypt(&carol, &stream).err(), failed);
        assert_eq!(BlockEncryption::decrypt(&carol, &block).err(), failed);
        for ciphertext in [&stream, &block] {
            for index in [0, 63, 64, 95, ciphertext.len() - 1] {
                let mut changed = ciphertext.clone();
                changed[index] ^= 0x01;
                assert_eq!(StreamEncryption::decrypt(&bob, &changed).err(), failed);
                assert_eq!(BlockEncryption::decrypt(&bob, &changed).err(), failed);
            }
            assert_eq!(StreamEncryption::decrypt(&bob, &ciphertext[..95]).err(), failed);
        }
        assert_eq!(BlockEncryption::decrypt(&bob, &block[..block.len() - 1]).err(), failed);
    }
}
