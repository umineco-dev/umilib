//! The Dragonfly key exchange (RFC 7664) on NIST P-256 with SHA-256: the
//! exchange of section 3, the rejections it requires and the properties of
//! the password element of section 3.2. RFC 7664 has no test vectors; the
//! functions of the profile are checked against their definitions.

use umilib::crypto::CryptoError;
use umilib::crypto::curve::p256::P256;
use umilib::crypto::dragonfly::{Dragonfly, DragonflyCommit, DragonflyConfig, DragonflyPeer};
use umilib::crypto::hmac::HMAC;
use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;

type Peer = DragonflyPeer<P256, SHA256>;

fn random(seed: u8) -> HMACDRBG<SHA256> {
    HMACDRBG::new(&[seed; 32], &[seed; 16], b"dragonfly").unwrap()
}

#[test]
fn peers_with_the_same_password_agree() {
    let config = DragonflyConfig::default();
    let mut alice = Peer::new(&config, b"alice", b"bob", b"password", &mut random(1)).unwrap();
    let mut bob = Peer::new(&config, b"bob", b"alice", b"password", &mut random(2)).unwrap();
    let (commit_a, commit_b) = (alice.commit().to_bytes(), bob.commit().to_bytes());
    assert_eq!(commit_a.len(), DragonflyCommit::<P256>::BYTES);
    let confirm_a = alice.process(DragonflyCommit::from_bytes(&commit_b).unwrap()).unwrap();
    let confirm_b = bob.process(DragonflyCommit::from_bytes(&commit_a).unwrap()).unwrap();
    let key_a = alice.finish(&confirm_b).unwrap().to_vec();
    let key_b = bob.finish(&confirm_a).unwrap().to_vec();
    assert_eq!(key_a, key_b);
    assert_eq!(key_a.len(), 32);
    // A confirm is bound to its sender: Bob's under another name is refused, and so is Alice's own.
    let commit_a = DragonflyCommit::from_bytes(&commit_a).unwrap();
    let renamed = bob.confirm(bob.commit(), &commit_a, b"carol");
    assert_eq!(alice.finish(&renamed).err(), Some(CryptoError::AuthenticationFailed));
    assert_eq!(alice.finish(&confirm_a).err(), Some(CryptoError::AuthenticationFailed));
}

#[test]
fn peers_with_other_passwords_fail_to_confirm() {
    let config = DragonflyConfig::default();
    let mut alice = Peer::new(&config, b"alice", b"bob", b"password", &mut random(3)).unwrap();
    let mut bob = Peer::new(&config, b"bob", b"alice", b"passw0rd", &mut random(4)).unwrap();
    let commit_a = DragonflyCommit::from_bytes(&alice.commit().to_bytes()).unwrap();
    let commit_b = DragonflyCommit::from_bytes(&bob.commit().to_bytes()).unwrap();
    let confirm_a = alice.process(commit_b).unwrap();
    let confirm_b = bob.process(commit_a).unwrap();
    assert_eq!(alice.finish(&confirm_b).err(), Some(CryptoError::AuthenticationFailed));
    assert_eq!(bob.finish(&confirm_a).err(), Some(CryptoError::AuthenticationFailed));
    assert!(format!("{alice:?}").ends_with(", ..)"));
}

/// Section 3.3: a reflected commit is refused, and so are scalars outside
/// 1 < scalar < q and elements that are not points of the subgroup.
#[test]
fn commits_are_validated() {
    let config = DragonflyConfig::default();
    let mut alice = Peer::new(&config, b"alice", b"bob", b"password", &mut random(5)).unwrap();
    let own = alice.commit().to_bytes();
    assert_eq!(alice.process(DragonflyCommit::from_bytes(&own).unwrap()).err(), Some(CryptoError::InvalidKey));
    assert_eq!(alice.finish(&[0; 32]).err(), Some(CryptoError::InvalidParameter));
    let invalid = Some(CryptoError::InvalidKey);
    for scalar in [
        [0u8; 32],
        {
            let mut one = [0u8; 32];
            one[31] = 1;
            one
        },
        [0xFF; 32],
    ] {
        let mut changed = own.clone();
        changed[..32].copy_from_slice(&scalar);
        assert_eq!(DragonflyCommit::<P256>::from_bytes(&changed).err(), invalid);
    }
    let mut off_curve = own.clone();
    *off_curve.last_mut().unwrap() ^= 1;
    assert_eq!(DragonflyCommit::<P256>::from_bytes(&off_curve).err(), invalid);
    assert_eq!(DragonflyCommit::<P256>::from_bytes(&own[1..]).err(), invalid);
}

/// Section 3.2: the password element depends on the password and the pair
/// of identities, in either order, not on the number of rounds run.
#[test]
fn password_elements() {
    type Scheme = Dragonfly<P256, SHA256>;
    let config = DragonflyConfig::default();
    let element = Scheme::password_element(&config, b"alice", b"bob", b"password").unwrap();
    assert!(element.is_on_curve().into_bool());
    assert_eq!(Scheme::password_element(&config, b"bob", b"alice", b"password").unwrap(), element);
    assert_ne!(Scheme::password_element(&config, b"alice", b"bob", b"passwort").unwrap(), element);
    assert_ne!(Scheme::password_element(&config, b"alice", b"carol", b"password").unwrap(), element);
    let few = DragonflyConfig { iterations: 1 };
    assert_eq!(Scheme::password_element(&few, b"alice", b"bob", b"password").unwrap(), element);
}

/// The KDF of the profile is SP 800-108 counter mode: block i is
/// HMAC(k, [i]_32 || label || 0x00 || [L]_32).
#[test]
fn kdf_is_the_counter_mode_of_sp800_108() {
    let mut out = [0u8; 40];
    Dragonfly::<P256, SHA256>::kdf(b"key", b"label", &mut out).unwrap();
    for block in 0..2u32 {
        let mut mac = HMAC::<SHA256>::new(b"key");
        mac.update(&(block + 1).to_be_bytes());
        mac.update(b"label\0");
        mac.update(&320u32.to_be_bytes());
        let expected = mac.finalize();
        let start = 32 * block as usize;
        let end = (start + 32).min(40);
        assert_eq!(&out[start..end], &expected[..end - start]);
    }
}
