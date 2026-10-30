//! Finite field Diffie–Hellman (SP 800-56A section 5.7.1.1) in the groups of
//! RFC 7919 and RFC 3526: the constants against the RFC texts, exchanges
//! against an oracle of Python's integers, and the validation of keys.

use umilib::crypto::dh::{
    DH, DHGroup, FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192, MODP1536, MODP2048, MODP3072, MODP4096,
    MODP6144, MODP8192,
};
use umilib::crypto::random::HMACDRBG;
use umilib::crypto::{CryptoError, KeyAgreement};
use umilib::hash::sha::v2::SHA256;
use umilib::math::bigint::BoxedUint;
use umilib::math::modular::BoxedModulus;

use crate::Vectors;

/// The prime of the section of `path` from `start` to `end`: its groups of
/// eight hexadecimal digits, page breaks removed.
fn rfc_prime(path: &str, start: &str, from: &str, to: &str) -> String {
    let text = Vectors::read(path);
    let section = &text[text.find(start).unwrap()..];
    let from = section.find(from).unwrap();
    let to = from + section[from..].find(to).unwrap();
    section[from..to]
        .lines()
        .filter(|line| !line.starts_with("RFC ") && !line.contains("[Page"))
        .flat_map(str::split_whitespace)
        .filter(|word| word.len() == 8 && word.chars().all(|character| character.is_ascii_hexdigit()))
        .collect::<String>()
        .to_ascii_lowercase()
}

/// The checks of the group `G` named `name`, whose prime the RFC gives.
fn check_group<G: DHGroup>(name: &str, prime: &str) {
    assert_eq!(G::PRIME, prime, "{name}");
    let modulus = G::modulus().unwrap();
    assert_eq!(modulus.value().bit_length(), G::BITS);
    // p and q = (p - 1) / 2 pass Miller–Rabin, and 2 generates the subgroup of order q.
    let base = BoxedUint::from_u64(3, 64).unwrap();
    assert!(modulus.miller_rabin(&base).unwrap().into_bool(), "{name}");
    let order = G::order().unwrap();
    assert!(BoxedModulus::new(order.clone()).unwrap().miller_rabin(&base).unwrap().into_bool(), "{name}");
    let generator = modulus.residue(&BoxedUint::from_u64(2, 64).unwrap());
    assert_eq!(modulus.pow_vartime(&generator, &order).unwrap(), modulus.one(), "{name}");

    // The exchanges of the oracle.
    let lines: Vec<String> = Vectors::read("crypto/dh/python.txt")
        .lines()
        .filter(|line| line.starts_with(&format!("{name} ")))
        .map(str::to_owned)
        .collect();
    assert_eq!(lines.len(), 3, "{name}");
    for line in &lines {
        let values: Vec<Vec<u8>> = line.split_whitespace().skip(1).map(Vectors::hex).collect();
        let (a, b) = (
            DH::<G>::private_key_from_bytes(&values[0]).unwrap(),
            DH::<G>::private_key_from_bytes(&values[1]).unwrap(),
        );
        let mut encoded = vec![0; DH::<G>::PUBLIC_KEY_SIZE];
        DH::<G>::write_public_key(&DH::<G>::public_key(&a), &mut encoded).unwrap();
        assert_eq!(encoded, values[2], "{name}");
        let public_b = DH::<G>::public_key_from_bytes(&values[3]).unwrap();
        assert_eq!(DH::<G>::public_key(&b), public_b);
        let mut shared = vec![0; DH::<G>::SHARED_SECRET_SIZE];
        DH::<G>::agree(&a, &public_b, &mut shared).unwrap();
        assert_eq!(shared, values[4], "{name}");
    }
}

/// SP 800-56A sections 5.6.1.1.4 and 5.6.2.3.1: generated keys have twice
/// the strength in bits; public keys outside 2..p - 2 or the subgroup and
/// private keys outside 1..q are refused.
fn check_keys<G: DHGroup>() {
    let mut random = HMACDRBG::<SHA256>::new(&[9; 32], &[8; 16], b"dh").unwrap();
    let (a, b) = (DH::<G>::generate(&mut random).unwrap(), DH::<G>::generate(&mut random).unwrap());
    assert!(a.exponent().bit_length() <= G::PRIVATE_KEY_BITS);
    let (mut shared_a, mut shared_b) = (vec![0; DH::<G>::SHARED_SECRET_SIZE], vec![0; DH::<G>::SHARED_SECRET_SIZE]);
    DH::<G>::agree(&a, &DH::<G>::public_key(&b), &mut shared_a).unwrap();
    DH::<G>::agree(&b, &DH::<G>::public_key(&a), &mut shared_b).unwrap();
    assert_eq!(shared_a, shared_b);
    assert!(format!("{a:?}").ends_with("(..)"));

    let size = G::bytes();
    let modulus = G::modulus().unwrap();
    let encode = |value: &BoxedUint| {
        let mut bytes = vec![0; size];
        value.resize(G::BITS).unwrap().write_be_bytes(&mut bytes).unwrap();
        bytes
    };
    let one = BoxedUint::one(64).unwrap();
    let p = modulus.value().clone();
    let p_minus_1 = p.wrapping_sub(&one);
    for invalid in [BoxedUint::zero(64).unwrap(), one.clone(), p_minus_1.clone(), p.clone()] {
        assert_eq!(DH::<G>::public_key_from_bytes(&encode(&invalid)).err(), Some(CryptoError::InvalidKey));
    }
    // -2 = -1 × 2 is outside the subgroup of order q: 2 is a quadratic residue and -1 is not.
    let minus_two = p.wrapping_sub(&BoxedUint::from_u64(2, 64).unwrap());
    assert_eq!(DH::<G>::public_key_from_bytes(&encode(&minus_two)).err(), Some(CryptoError::InvalidKey));
    let two = BoxedUint::from_u64(2, 64).unwrap();
    assert!(DH::<G>::public_key_from_bytes(&encode(&two)).is_ok());
    let order = G::order().unwrap();
    assert_eq!(
        DH::<G>::private_key_from_bytes(&encode(&BoxedUint::zero(64).unwrap())).err(),
        Some(CryptoError::InvalidKey)
    );
    assert_eq!(DH::<G>::private_key_from_bytes(&encode(&order)).err(), Some(CryptoError::InvalidKey));
    assert!(DH::<G>::private_key_from_bytes(&encode(&order.wrapping_sub(&one))).is_ok());
    for length in [0, size - 1, size + 1] {
        assert_eq!(DH::<G>::public_key_from_bytes(&vec![2; length]).err(), Some(CryptoError::InvalidKey));
        assert_eq!(DH::<G>::private_key_from_bytes(&vec![2; length]).err(), Some(CryptoError::InvalidKey));
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn ffdhe() {
    let path = "crypto/dh/rfc7919.txt";
    let prime = |index: usize, bits: u32| {
        rfc_prime(path, &format!("\nA.{index}.  ffdhe{bits}\n"), "representation of p is:", "The generator is")
    };
    check_group::<FFDHE2048>("ffdhe2048", &prime(1, 2048));
    check_keys::<FFDHE2048>();
    check_group::<FFDHE3072>("ffdhe3072", &prime(2, 3072));
    check_group::<FFDHE4096>("ffdhe4096", &prime(3, 4096));
    check_group::<FFDHE6144>("ffdhe6144", &prime(4, 6144));
    check_group::<FFDHE8192>("ffdhe8192", &prime(5, 8192));
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn modp() {
    let path = "math/modular/rfc3526.txt";
    let prime = |bits: u32| {
        rfc_prime(path, &format!("{bits}-bit MODP Group\n"), "Its hexadecimal value is:", "The generator is")
    };
    check_group::<MODP1536>("modp1536", &prime(1536));
    check_keys::<MODP1536>();
    check_group::<MODP2048>("modp2048", &prime(2048));
    check_group::<MODP3072>("modp3072", &prime(3072));
    check_group::<MODP4096>("modp4096", &prime(4096));
    check_group::<MODP6144>("modp6144", &prime(6144));
    check_group::<MODP8192>("modp8192", &prime(8192));
}
