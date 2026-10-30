//! Argon2 against RFC 9106 and the reference implementation.

use umilib::crypto::CryptoError;
use umilib::crypto::argon2::{Argon2, Argon2Type};

use crate::Record;

fn variant(record: &Record) -> Argon2Type {
    match record.field("Type") {
        "Argon2d" => Argon2Type::Argon2d,
        "Argon2i" => Argon2Type::Argon2i,
        "Argon2id" => Argon2Type::Argon2id,
        other => panic!("{other}"),
    }
}

fn parameters(record: &Record) -> Argon2 {
    let number = |name: &str| record.field(name).parse::<u32>().unwrap();
    Argon2::new(variant(record), number("Memory"), number("Passes"), number("Lanes")).unwrap()
}

#[test]
fn argon2_follows_rfc9106_section_5() {
    let records = Record::all("crypto/argon2/rfc9106.txt");
    assert_eq!(records.len(), 3);
    for record in records {
        let label = record.field("Type");
        let argon2 = parameters(&record);
        let (password, salt, secret, associated) =
            (record.bytes("Password"), record.bytes("Salt"), record.bytes("Secret"), record.bytes("Associated"));
        let tag_length: usize = record.field("TagLength").parse().unwrap();
        let h0 = argon2.initial_hash(tag_length, &password, &salt, &secret, &associated).unwrap();
        assert_eq!(h0.to_vec(), record.bytes("H0"), "{label} H0");
        // The memory after each pass: the words printed for its first and last blocks.
        let mut memory = argon2.allocate().unwrap();
        argon2.initialize(&h0, &mut memory).unwrap();
        for pass in 0..record.field("Passes").parse::<u32>().unwrap() {
            argon2.fill_pass(&mut memory, pass);
            for entry in record.field(&format!("Pass{pass}")).split(',') {
                let parts: Vec<&str> = entry.split(':').collect();
                let (block, word) = (parts[0].parse::<usize>().unwrap(), parts[1].parse::<usize>().unwrap());
                assert_eq!(
                    memory[block][word],
                    u64::from_str_radix(parts[2], 16).unwrap(),
                    "{label} pass {pass} block {block} word {word}"
                );
            }
        }
        let mut tag = vec![0u8; tag_length];
        argon2.tag(&memory, &mut tag).unwrap();
        assert_eq!(tag, record.bytes("Tag"), "{label}");
        let mut derived = vec![0u8; tag_length];
        argon2.derive(&password, &salt, &secret, &associated, &mut derived).unwrap();
        assert_eq!(derived, tag, "{label}");
    }
}

fn reference(record: &Record) -> Vec<u8> {
    let mut tag = vec![0u8; 32];
    parameters(record).derive(&record.bytes("Password"), &record.bytes("Salt"), &[], &[], &mut tag).unwrap();
    tag
}

#[test]
fn argon2_follows_the_reference_implementation() {
    let records = Record::all("crypto/argon2/reference.txt");
    assert_eq!(records.len(), 17);
    for record in records.iter().filter(|record| record.field("Large") == "no") {
        assert_eq!(reference(record), record.bytes("Tag"), "{:?}", record.fields);
    }
}

#[test]
#[ignore = "m = 2^20 KiB allocates 1 GiB"]
fn argon2_follows_the_reference_implementation_with_1_gib() {
    for record in Record::all("crypto/argon2/reference.txt").iter().filter(|record| record.field("Large") == "yes") {
        assert_eq!(reference(record), record.bytes("Tag"), "{:?}", record.fields);
    }
}

#[test]
fn argon2_checks_its_parameters() {
    // Section 3.1: p from 1 to 2^24 - 1, m ≥ 8p, t ≥ 1, T ≥ 4.
    for (memory, passes, lanes) in [(8, 1, 0), (8, 0, 1), (15, 1, 2), (1 << 24, 1, 1 << 24)] {
        assert_eq!(
            Argon2::new(Argon2Type::Argon2id, memory, passes, lanes),
            Err(CryptoError::InvalidParameter),
            "m = {memory}, t = {passes}, p = {lanes}"
        );
    }
    let argon2 = Argon2::new(Argon2Type::Argon2id, 37, 1, 2).unwrap();
    // m' = 4p ⌊m / 4p⌋.
    assert_eq!(argon2.blocks(), 32);
    assert!(matches!(
        argon2.derive(b"password", b"somesalt", &[], &[], &mut [0; 3]),
        Err(CryptoError::InputLength { .. })
    ));
    // A tag of more than 64 bytes uses the chain of H' (section 3.3); its first bytes differ from the shorter tag.
    let (mut long, mut short) = ([0u8; 100], [0u8; 64]);
    argon2.derive(b"password", b"somesalt", &[], &[], &mut long).unwrap();
    argon2.derive(b"password", b"somesalt", &[], &[], &mut short).unwrap();
    assert_ne!(long[..64], short);
}
