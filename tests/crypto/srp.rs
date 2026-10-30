//! SRP (RFC 5054) against the groups of its appendix A and the test vectors
//! of its appendix B.

use umilib::crypto::CryptoError;
use umilib::crypto::random::HMACDRBG;
use umilib::crypto::srp::{
    SRP, SRP1024, SRP1536, SRP2048, SRP3072, SRP4096, SRP6144, SRP8192, SRPClient, SRPGroup, SRPServer,
};
use umilib::hash::sha::v1::SHA1;
use umilib::hash::sha::v2::SHA256;
use umilib::math::bigint::BoxedUint;

use crate::Vectors;

/// The value after "`name` =" in appendix B: on the same line or the
/// following ones, in groups of hexadecimal digits.
fn appendix_b(name: &str) -> Vec<u8> {
    let text = Vectors::read("crypto/srp/rfc5054.txt");
    let start = text.find("\nAppendix B.  SRP Test Vectors").unwrap();
    let end = text.find("\nAppendix C.").unwrap();
    let lines: Vec<&str> = text[start..end].lines().map(str::trim).collect();
    let index = lines.iter().position(|line| line.starts_with(&format!("{name} ="))).unwrap();
    let is_hex = |word: &str| !word.is_empty() && word.chars().all(|character| character.is_ascii_hexdigit());
    let mut hex: String = lines[index][name.len() + 2..].split_whitespace().collect();
    // The value may start on the line after a blank one, and ends at the next blank one.
    let starts_empty = hex.is_empty();
    for line in lines[index + 1..].iter().skip_while(|line| starts_empty && line.is_empty()) {
        if line.is_empty() || !line.split_whitespace().all(is_hex) {
            break;
        }
        hex.extend(line.split_whitespace());
    }
    Vectors::hex(&hex)
}

fn integer(bytes: &[u8]) -> BoxedUint {
    BoxedUint::from_be_bytes(bytes, (bytes.len().max(1) * 8) as u32).unwrap()
}

/// Appendix B: k, x, v, A, B, u and the premaster secret of "alice".
#[test]
fn rfc5054_vectors() {
    type Scheme = SRP<SRP1024, SHA1>;
    let (identity, password, salt) = (b"alice", b"password123", appendix_b("s"));
    assert!(Scheme::multiplier().unwrap().compare_vartime(&integer(&appendix_b("k"))).is_eq());
    assert!(
        Scheme::private_key(&salt, identity, password).unwrap().compare_vartime(&integer(&appendix_b("x"))).is_eq()
    );
    let verifier = Scheme::verifier(&salt, identity, password).unwrap();
    assert_eq!(verifier.len(), 128);
    assert!(integer(&verifier).compare_vartime(&integer(&appendix_b("v"))).is_eq());

    let client = SRPClient::<SRP1024, SHA1>::new(&appendix_b("a")).unwrap();
    let server = SRPServer::<SRP1024, SHA1>::new(&verifier, &appendix_b("b")).unwrap();
    assert_eq!(client.public_value(), appendix_b("A"));
    assert_eq!(server.public_value(), appendix_b("B"));
    let u = Scheme::scrambling(&integer(&appendix_b("A")), &integer(&appendix_b("B"))).unwrap();
    assert!(u.compare_vartime(&integer(&appendix_b("u"))).is_eq());
    let expected = appendix_b("<premaster secret>");
    assert_eq!(client.premaster_secret(identity, password, &salt, &server.public_value()).unwrap(), expected);
    assert_eq!(server.premaster_secret(&client.public_value()).unwrap(), expected);
    // A wrong password gives another secret.
    assert_ne!(client.premaster_secret(identity, b"password124", &salt, &server.public_value()).unwrap(), expected);
}

/// Sections 2.5.3 and 2.5.4: A % N = 0 and B % N = 0 are refused.
#[test]
fn zero_public_values_are_refused() {
    let verifier = SRP::<SRP1024>::verifier(b"salt", b"user", b"secret").unwrap();
    let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"srp").unwrap();
    let client = SRPClient::<SRP1024>::generate(&mut random).unwrap();
    let server = SRPServer::<SRP1024>::generate(&verifier, &mut random).unwrap();
    let n = SRP1024::modulus().unwrap().value().to_be_bytes();
    for invalid in [vec![0u8], n.clone(), vec![0u8; 128]] {
        assert_eq!(server.premaster_secret(&invalid).err(), Some(CryptoError::InvalidKey));
        assert_eq!(client.premaster_secret(b"user", b"secret", b"salt", &invalid).err(), Some(CryptoError::InvalidKey));
    }
    let longer = [&[1u8][..], &n[..]].concat();
    assert_eq!(server.premaster_secret(&longer).err(), Some(CryptoError::InvalidKey));
    assert!(SRPClient::<SRP1024>::new(&[0; 32]).is_err());
    assert!(format!("{client:?}").ends_with(", ..)"));
}

/// The groups of appendix A: the primes of the RFC, generators of order
/// N - 1, and an exchange in each.
fn check_group<G: SRPGroup>(index: usize) {
    let text = Vectors::read("crypto/srp/rfc5054.txt");
    let start = text.find(&format!("   {index}.  {}-bit Group", G::BITS)).unwrap();
    let section = &text[start..];
    let from = section.find("hexadecimal value").unwrap();
    let to = section.find("The generator is:").unwrap();
    let prime: String = section[from..to]
        .lines()
        .filter(|line| !line.starts_with("RFC ") && !line.contains("[Page"))
        .flat_map(str::split_whitespace)
        .filter(|word| word.len() == 8 && word.chars().all(|character| character.is_ascii_hexdigit()))
        .collect::<String>()
        .to_ascii_lowercase();
    assert_eq!(G::PRIME, prime);
    // "2." or "19 (decimal).".
    let digits: String =
        section[to + "The generator is:".len()..].trim_start().chars().take_while(char::is_ascii_digit).collect();
    let generator: u64 = digits.parse().unwrap();
    assert_eq!(G::GENERATOR, generator);
    // g^((N-1)/2) = -1: g generates the whole group (N is a safe prime).
    let modulus = G::modulus().unwrap();
    let q = modulus.value().shr(1);
    let g = modulus.residue(&BoxedUint::from_u64(generator, 64).unwrap());
    assert_eq!(modulus.pow_vartime(&g, &q).unwrap(), modulus.neg(&modulus.one()).unwrap());

    let mut random = HMACDRBG::<SHA256>::new(&[index as u8; 32], &[3; 16], b"srp").unwrap();
    let verifier = SRP::<G, SHA256>::verifier(b"salt", b"carol", b"pass").unwrap();
    let client = SRPClient::<G, SHA256>::generate(&mut random).unwrap();
    let server = SRPServer::<G, SHA256>::generate(&verifier, &mut random).unwrap();
    assert_eq!(
        client.premaster_secret(b"carol", b"pass", b"salt", &server.public_value()).unwrap(),
        server.premaster_secret(&client.public_value()).unwrap()
    );
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn groups() {
    check_group::<SRP1024>(1);
    check_group::<SRP1536>(2);
    check_group::<SRP2048>(3);
    check_group::<SRP3072>(4);
    check_group::<SRP4096>(5);
    check_group::<SRP6144>(6);
    check_group::<SRP8192>(7);
}
