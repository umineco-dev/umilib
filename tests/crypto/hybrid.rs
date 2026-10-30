//! The hybrid groups of RFC 10024 (which gives no test vectors): the sizes
//! and codepoints of its tables, the order of the parts in the shares and
//! the secret checked against ML-KEM and ECDH separately (whose own vectors
//! are tested in their modules), and the checks of section 3.

use umilib::crypto::hybrid::{HybridKEM, HybridKEMParameters, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519MLKEM768};
use umilib::crypto::random::HMACDRBG;
use umilib::crypto::{CryptoError, KeyAgreement, KeyEncapsulation};
use umilib::hash::sha::v2::SHA256;

/// The encoding of `key` by `write`, of `size` bytes.
fn encoded<K>(key: &K, size: usize, write: fn(&K, &mut [u8]) -> Result<(), CryptoError>) -> Vec<u8> {
    let mut out = vec![0; size];
    write(key, &mut out).unwrap();
    out
}

/// The client's share, the server's share and the secret of a run of the
/// group, and each part checked against the KEM and the key agreement
/// alone: `kem_first` tells the order, `sizes` the client's share, the
/// server's share and the secret (RFC 10024 section 3 and table 1).
fn check_group<P: HybridKEMParameters>(codepoint: u16, kem_first: bool, sizes: [usize; 3]) {
    type Group<P> = HybridKEM<P>;
    assert_eq!(P::CODEPOINT, codepoint);
    assert_eq!(
        [Group::<P>::ENCAPSULATION_KEY_SIZE, Group::<P>::CIPHERTEXT_SIZE, Group::<P>::SHARED_SECRET_SIZE],
        sizes
    );
    let mut random = HMACDRBG::<SHA256>::new(&[9; 32], &[8; 16], P::NAME.as_bytes()).unwrap();
    let client = Group::<P>::generate(&mut random).unwrap();
    let share = encoded(&Group::<P>::encapsulation_key(&client), sizes[0], Group::<P>::write_encapsulation_key);
    let kem_key = encoded(
        &P::KEM::encapsulation_key(client.kem()),
        P::KEM::ENCAPSULATION_KEY_SIZE,
        P::KEM::write_encapsulation_key,
    );
    let agreement_key = encoded(
        &P::KeyAgreement::public_key(client.agreement()),
        P::KeyAgreement::PUBLIC_KEY_SIZE,
        P::KeyAgreement::write_public_key,
    );
    let order =
        |kem: &[u8], agreement: &[u8]| if kem_first { [kem, agreement].concat() } else { [agreement, kem].concat() };
    assert_eq!(share, order(&kem_key, &agreement_key));

    // The server encapsulates to the share it receives.
    let received = Group::<P>::encapsulation_key_from_bytes(&share).unwrap();
    let (mut ciphertext, mut sent) = (vec![0; sizes[1]], vec![0; sizes[2]]);
    Group::<P>::encapsulate(&received, &mut random, &mut ciphertext, &mut sent).unwrap();
    let mut decapsulated = vec![0; sizes[2]];
    Group::<P>::decapsulate(&client, &ciphertext, &mut decapsulated).unwrap();
    assert_eq!(decapsulated, sent);

    // The secret is the KEM's secret and the key agreement's, in the order of the group.
    let kem_length = P::KEM::CIPHERTEXT_SIZE;
    let (kem_ciphertext, server_share) = if kem_first {
        ciphertext.split_at(kem_length)
    } else {
        let (agreement, kem) = ciphertext.split_at(ciphertext.len() - kem_length);
        (kem, agreement)
    };
    let mut kem_secret = vec![0; P::KEM::SHARED_SECRET_SIZE];
    P::KEM::decapsulate(client.kem(), kem_ciphertext, &mut kem_secret).unwrap();
    let mut agreement_secret = vec![0; P::KeyAgreement::SHARED_SECRET_SIZE];
    let server = P::KeyAgreement::public_key_from_bytes(server_share).unwrap();
    P::KeyAgreement::agree(client.agreement(), &server, &mut agreement_secret).unwrap();
    assert_eq!(sent, order(&kem_secret, &agreement_secret));

    // Keys survive their encodings.
    let secret = encoded(&client, Group::<P>::DECAPSULATION_KEY_SIZE, Group::<P>::write_decapsulation_key);
    let decoded = Group::<P>::decapsulation_key_from_bytes(&secret).unwrap();
    assert_eq!(Group::<P>::encapsulation_key(&decoded), received);

    // Section 3: the ML-KEM encapsulation key is checked (a coefficient of q), and the length of the ciphertext.
    let mut overflow = share.clone();
    let kem_start = if kem_first { 0 } else { P::KeyAgreement::PUBLIC_KEY_SIZE };
    overflow[kem_start] = 0x01;
    overflow[kem_start + 1] = (overflow[kem_start + 1] & 0xF0) | 0x0D;
    assert_eq!(Group::<P>::encapsulation_key_from_bytes(&overflow).err(), Some(CryptoError::InvalidKey));
    for length in [sizes[1] - 1, sizes[1] + 1] {
        let error = Some(CryptoError::InputLength { length });
        assert_eq!(Group::<P>::decapsulate(&client, &vec![0; length], &mut decapsulated).err(), error);
    }
    assert_eq!(Group::<P>::encapsulation_key_from_bytes(&share[1..]).err(), Some(CryptoError::InvalidKey));
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn hybrid_groups_follow_rfc_10024() {
    check_group::<X25519MLKEM768>(0x11EC, true, [1216, 1120, 64]);
    check_group::<SecP256r1MLKEM768>(0x11EB, false, [1249, 1153, 64]);
    check_group::<SecP384r1MLKEM1024>(0x11ED, false, [1665, 1665, 80]);
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn hybrid_groups_refuse_invalid_traditional_shares() {
    let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"hybrid").unwrap();
    // X25519 of a point of small order is zero, which TLS refuses (RFC 8446 section 7.4.2).
    let client = HybridKEM::<X25519MLKEM768>::generate(&mut random).unwrap();
    let mut ciphertext = vec![0; 1120];
    let public = HybridKEM::<X25519MLKEM768>::encapsulation_key(&client);
    let mut shared = vec![0; 64];
    HybridKEM::<X25519MLKEM768>::encapsulate(&public, &mut random, &mut ciphertext, &mut shared).unwrap();
    ciphertext[1088..].fill(0);
    assert_eq!(
        HybridKEM::<X25519MLKEM768>::decapsulate(&client, &ciphertext, &mut shared).err(),
        Some(CryptoError::InvalidKey)
    );
    assert_eq!(shared, vec![0; 64]);
    // A secp256r1 share that is not a point of the curve.
    let client = HybridKEM::<SecP256r1MLKEM768>::generate(&mut random).unwrap();
    let mut ciphertext = vec![0; 1153];
    let public = HybridKEM::<SecP256r1MLKEM768>::encapsulation_key(&client);
    HybridKEM::<SecP256r1MLKEM768>::encapsulate(&public, &mut random, &mut ciphertext, &mut shared).unwrap();
    ciphertext[64] ^= 1;
    assert_eq!(
        HybridKEM::<SecP256r1MLKEM768>::decapsulate(&client, &ciphertext, &mut shared).err(),
        Some(CryptoError::InvalidKey)
    );
}
