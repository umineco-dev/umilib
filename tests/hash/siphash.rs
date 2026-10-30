use core::hash::Hasher;

use umilib::hash::Digest;
use umilib::hash::siphash::*;

use crate::Vectors;

/// The 64 outputs of the array `name` in the reference vectors.h, for the
/// messages 0x00, 0x00 0x01, ... of 0 to 63 bytes.
fn reference(name: &str) -> Vec<Vec<u8>> {
    let text = Vectors::read("hash/siphash/vectors.h");
    let start = text.find(&format!("{name}[64]")).unwrap();
    let body = &text[start..start + text[start..].find("};").unwrap()];
    let body = &body[body.find('{').unwrap() + 1..];
    let outputs: Vec<Vec<u8>> = body
        .split('}')
        .filter(|entry| entry.contains("0x"))
        .map(|entry| {
            entry
                .split(',')
                .filter_map(|item| item.trim().trim_start_matches('{').trim().strip_prefix("0x"))
                .map(|digits| u8::from_str_radix(digits, 16).unwrap())
                .collect()
        })
        .collect();
    assert_eq!(outputs.len(), 64);
    outputs
}

/// Checks `hash` (created from the key 0x00, 0x01, ...) against `name`,
/// feeding the message at once and byte by byte.
fn check<H: Digest>(name: &str, new: impl Fn() -> H) {
    for (length, expected) in reference(name).into_iter().enumerate() {
        let message: Vec<u8> = (0..length as u8).collect();
        let mut hash = new();
        hash.update(&message);
        assert_eq!(hash.finalize().as_ref(), expected, "{name}, {length} bytes");
        let mut hash = new();
        message.iter().for_each(|byte| hash.update(&[*byte]));
        assert_eq!(hash.finalize_reset().as_ref(), expected, "{name}, {length} bytes one at a time");
        assert_eq!(hash.finalize().as_ref(), reference(name)[0], "{name} after reset");
    }
}

fn key<const N: usize>() -> [u8; N] {
    core::array::from_fn(|index| index as u8)
}

#[test]
fn siphash_follows_the_reference_vectors() {
    check("vectors_sip64", || SipHash24::new(&key()));
    check("vectors_sip128", || SipHash128::<2, 4>::new(&key()));
    check("vectors_hsip32", || HalfSipHash::<2, 4>::new(&key()));
    check("vectors_hsip64", || HalfSipHash64::<2, 4>::new(&key()));
}

#[test]
fn siphash_follows_the_example_of_the_paper() {
    // Appendix A of the SipHash paper: the key 00..0f and the 15-byte message 00..0e.
    let mut hash = SipHash24::new(&key());
    hash.update(&(0..15).collect::<Vec<u8>>());
    assert_eq!(hash.finish(), 0xA129CA6149BE45E5);
}

#[test]
fn siphash_rounds_are_parameters() {
    // SipHash-1-3 and SipHash-2-4 differ only in their numbers of rounds.
    let mut one = SipHash13::new(&key());
    let mut two = SipHash24::new(&key());
    one.write(b"abc");
    two.write(b"abc");
    assert_ne!(one.finish(), two.finish());
    assert_eq!(format!("{one:?}"), "SipHash-1-3(..)");
    assert_eq!((SipHash24::KEY_SIZE, HalfSipHash::<2, 4>::KEY_SIZE, SipHash128::<2, 4>::OUTPUT_SIZE), (16, 8, 16));
}

/// SipHash-2-4 against `core::hash::SipHasher`, an implementation of its
/// own, for inputs past 255 bytes, where only the low byte of the length is
/// hashed.
#[test]
#[allow(deprecated)]
fn siphash_agrees_with_the_core_library() {
    for length in [64usize, 255, 256, 257, 300, 1000] {
        let message: Vec<u8> = (0..length).map(|index| (index * 7) as u8).collect();
        let mut core = core::hash::SipHasher::new_with_keys(0x0706050403020100, 0x0f0e0d0c0b0a0908);
        core.write(&message);
        assert_eq!(u64::from_le_bytes(SipHash24::hash(&key(), &message)), core.finish(), "{length} bytes");
    }
}
