//! The Ascon permutation, Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128
//! against NIST SP 800-232, its ACVP vectors and the reference implementation.

use umilib::hash::ascon::{AsconCXOF128, AsconHash256, AsconPermutation, AsconSponge, AsconXOF128};
use umilib::hash::{Digest, ExtendableOutput, HashError, XOFReader};

use crate::Record;

/// The S-box by equations (7) of section 3.3, on (x0, ..., x4) with x0 the most significant bit of `x`.
fn sbox_by_equations(x: u8) -> u8 {
    let bit = |index: u8| (x >> (4 - index)) & 1;
    let (x0, x1, x2, x3, x4) = (bit(0), bit(1), bit(2), bit(3), bit(4));
    let y = [
        (x4 & x1) ^ x3 ^ (x2 & x1) ^ x2 ^ (x1 & x0) ^ x1 ^ x0,
        x4 ^ (x3 & x2) ^ (x3 & x1) ^ x3 ^ (x2 & x1) ^ x2 ^ x1 ^ x0,
        (x4 & x3) ^ x4 ^ x2 ^ x1 ^ 1,
        (x4 & x0) ^ x4 ^ (x3 & x0) ^ x3 ^ x2 ^ x1 ^ x0,
        (x4 & x1) ^ x4 ^ x3 ^ (x1 & x0) ^ x1,
    ];
    y.iter().fold(0, |value, bit| (value << 1) | bit)
}

#[test]
fn ascon_substitution_follows_section_3_3() {
    // Table 6.
    const TABLE: [u8; 32] = [
        0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02, 0x1b, 0x05, 0x08, 0x12, 0x1d, 0x03, 0x06, 0x1c, 0x1e, 0x13,
        0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18, 0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a, 0x0f, 0x17,
    ];
    for x in 0..32u8 {
        assert_eq!(sbox_by_equations(x), TABLE[x as usize], "SBOX({x:#04x}) by the equations");
        // The bits of x in column 5 of the state: s(i, 5) = x_i.
        let words: [u64; 5] = core::array::from_fn(|i| (((x >> (4 - i)) & 1) as u64) << 5);
        let mut permutation = AsconPermutation::from_words(words);
        permutation.substitute();
        let y = permutation.words().iter().fold(0u8, |value, word| (value << 1) | ((word >> 5) & 1) as u8);
        assert_eq!(y, TABLE[x as usize], "SBOX({x:#04x}) by the circuit");
        // The other columns hold SBOX(0) = 4: only x2 is set.
        assert_eq!(permutation.words().map(|word| word & !(1 << 5)), [0, 0, !(1u64 << 5), 0, 0]);
    }
}

#[test]
fn ascon_initial_values_follow_appendix_b() {
    // IV = v || 0^8 || a || b || t || r/8 || 0^16 as bitstrings (table 13), printed as integers (table 14).
    let iv = |v: u64, a: u64, b: u64, t: u64, rate: u64| v | (a << 16) | (b << 20) | (t << 24) | (rate << 40);
    assert_eq!(iv(1, 12, 8, 128, 16), 0x0000_1000_808c_0001);
    assert_eq!(iv(2, 12, 12, 256, 8), AsconHash256::IV);
    assert_eq!(iv(3, 12, 12, 0, 8), AsconXOF128::IV);
    assert_eq!(iv(4, 12, 12, 0, 8), AsconCXOF128::IV);
    // Table 12: the states after the initialization.
    let expected = [
        (
            AsconHash256::IV,
            [0x9b1e5494e934d681, 0x4bc3a01e333751d2, 0xae65396c6b34b81a, 0x3c7fd4a4d56a4db3, 0x1a5c464906c5976d],
        ),
        (
            AsconXOF128::IV,
            [0xda82ce768d9447eb, 0xcc7ce6c75f1ef969, 0xe7508fd780085631, 0x0ee0ea53416b58cc, 0xe0547524db6f0bde],
        ),
        (
            AsconCXOF128::IV,
            [0x675527c2a0e8de03, 0x43d12d7dc0377bbc, 0xe9901dec426e81b5, 0x2ab14907720780b6, 0x8f3f1d02d432bc46],
        ),
    ];
    for (iv, words) in expected {
        assert_eq!(*AsconSponge::new(iv).permutation().words(), words, "{iv:#018x}");
    }
    // Ascon-p[rnd] adds const_(16 - rnd + i) in round i: p[16] then p[12] agree with p[16 + 12] in pieces.
    let mut a = AsconPermutation::from_words([1, 2, 3, 4, 5]);
    a.permute(12);
    let mut b = AsconPermutation::from_words([1, 2, 3, 4, 5]);
    for &constant in &AsconPermutation::CONSTANTS[4..] {
        b.round(constant);
    }
    assert_eq!(a, b);
}

#[test]
fn ascon_hash256_follows_the_reference_known_answers() {
    let records = Record::all("hash/ascon/LWC_HASH_KAT_128_256.txt");
    assert_eq!(records.len(), 1025);
    for record in records {
        let message = record.bytes("Msg");
        let expected = record.bytes("MD");
        assert_eq!(AsconHash256::digest(&message).to_vec(), expected, "Count = {}", record.field("Count"));
        let mut hash = AsconHash256::new();
        for piece in message.chunks(3) {
            hash.update(piece);
        }
        assert_eq!(hash.finalize_reset().to_vec(), expected);
        hash.update(&message);
        assert_eq!(hash.finalize().to_vec(), expected);
    }
}

#[test]
fn ascon_xof128_follows_the_reference_known_answers() {
    let records = Record::all("hash/ascon/LWC_XOF_KAT_128_512.txt");
    assert_eq!(records.len(), 1025);
    for record in records {
        let (message, expected) = (record.bytes("Msg"), record.bytes("MD"));
        let mut out = vec![0u8; expected.len()];
        AsconXOF128::digest_xof(&message, &mut out);
        assert_eq!(out, expected, "Count = {}", record.field("Count"));
        // Reads of any sizes continue each other.
        let mut xof = AsconXOF128::new();
        for piece in message.chunks(5) {
            xof.update(piece);
        }
        let mut reader = xof.finalize_xof();
        let mut pieces = vec![0u8; expected.len()];
        for piece in pieces.chunks_mut(7) {
            reader.read(piece);
        }
        assert_eq!(pieces, expected);
    }
}

#[test]
fn ascon_cxof128_follows_the_reference_known_answers() {
    let records = Record::all("hash/ascon/LWC_CXOF_KAT_128_512.txt");
    assert_eq!(records.len(), 1089);
    for record in records {
        let (message, customization, expected) = (record.bytes("Msg"), record.bytes("Z"), record.bytes("MD"));
        let mut cxof = AsconCXOF128::new(&customization).unwrap();
        cxof.update(&message);
        let mut out = vec![0u8; expected.len()];
        cxof.clone().finalize_xof().read(&mut out);
        assert_eq!(out, expected, "Count = {}", record.field("Count"));
        // Reset returns to the state after the customization.
        cxof.reset();
        cxof.update(&message);
        cxof.finalize_xof().read(&mut out);
        assert_eq!(out, expected);
    }
}

#[test]
fn ascon_hashes_follow_the_acvp_vectors() {
    let records = Record::all("hash/ascon/acvp.txt");
    assert_eq!(records.len(), 16);
    for record in records {
        let (message, expected) = (record.bytes("msg"), record.bytes("md"));
        let mut out = vec![0u8; expected.len()];
        match record.field("Mode") {
            "Hash256" => out.copy_from_slice(&AsconHash256::digest(&message)),
            "XOF128" => AsconXOF128::digest_xof(&message, &mut out),
            "CXOF128" => {
                let mut cxof = AsconCXOF128::new(&record.bytes("cs")).unwrap();
                cxof.update(&message);
                cxof.finalize_xof().read(&mut out);
            }
            mode => panic!("{mode}"),
        }
        assert_eq!(out, expected, "tcId {}", record.field("tcId"));
    }
}

#[test]
fn ascon_xofs_follow_section_5() {
    // A shorter output of Ascon-XOF128 is a prefix of a longer one (section 5).
    let (mut short, mut long) = ([0u8; 10], [0u8; 100]);
    AsconXOF128::digest_xof(b"umilib", &mut short);
    AsconXOF128::digest_xof(b"umilib", &mut long);
    assert_eq!(short, long[..10]);
    // The customization string has at most 2048 bits (section 5.3).
    assert!(AsconCXOF128::new(&[0; 256]).is_ok());
    assert_eq!(AsconCXOF128::new(&[0; 257]).err(), Some(HashError::InvalidParameter));
    // Ascon-CXOF128 with an empty customization differs from Ascon-XOF128.
    let mut customized = [0u8; 16];
    AsconCXOF128::new(&[]).unwrap().finalize_xof().read(&mut customized);
    assert_ne!(customized, long[..16]);
}
