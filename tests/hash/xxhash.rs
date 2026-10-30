use umilib::hash::Digest;
use umilib::hash::xxhash::*;

use crate::Vectors;

/// The reference outputs of tools/xxhash_vectors.py, with its inputs and secrets.
struct Reference {
    input: Vec<u8>,
    secrets: Vec<(String, Vec<u8>)>,
    /// function, length, key and value.
    lines: Vec<(String, usize, String, String)>,
}

impl Reference {
    fn read() -> Reference {
        let text = Vectors::read("hash/xxhash/xxhash.txt");
        let mut secrets = Vec::new();
        let mut lines = Vec::new();
        for line in text.lines().filter(|line| !line.starts_with('#')) {
            let words: Vec<&str> = line.split(' ').collect();
            if words[0] == "secret" {
                secrets.push((words[1].to_string(), Vectors::hex(words[2])));
            } else {
                assert_eq!(words[3], "=");
                lines.push((
                    words[0].to_string(),
                    words[1].parse().unwrap(),
                    words[2].to_string(),
                    words[4].to_string(),
                ));
            }
        }
        let largest = lines.iter().map(|line| line.1).max().unwrap();
        Reference { input: Reference::generate(largest, 0x9E3779B9), secrets, lines }
    }

    /// The bytes of the script: the top bytes of a linear congruential sequence.
    fn generate(length: usize, mut state: u32) -> Vec<u8> {
        (0..length)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 24) as u8
            })
            .collect()
    }

    fn secret(&self, name: &str) -> Option<&[u8]> {
        self.secrets.iter().find(|secret| secret.0 == name).map(|secret| secret.1.as_slice())
    }
}

/// Feeds `input` to `hash` whole and in pieces of several sizes, and checks
/// that every way gives `expected`.
fn check<H: Digest>(new: impl Fn() -> H, input: &[u8], expected: &[u8], label: &str) {
    for piece in [usize::MAX, 1, 7, 63, 64, 65, 255, 256, 257, 1000] {
        let mut hash = new();
        input.chunks(piece.min(input.len().max(1))).for_each(|chunk| hash.update(chunk));
        assert_eq!(hash.finalize_reset().as_ref(), expected, "{label}, pieces of {piece}");
        hash.update(input);
        assert_eq!(hash.finalize().as_ref(), expected, "{label}, after reset");
    }
    // Irregular pieces, empty ones and intermediate results along the way.
    let mut hash = new();
    let (mut rest, mut state) = (input, input.len() as u32 | 1);
    while !rest.is_empty() {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        let size = ((state >> 16) as usize % 600).min(rest.len());
        hash.update(&[]);
        hash.update(&rest[..size]);
        rest = &rest[size..];
        if state & 1 == 0 {
            let _ = hash.clone().finalize();
        }
    }
    assert_eq!(hash.finalize().as_ref(), expected, "{label}, irregular pieces");
}

#[test]
fn xxhash_follows_the_reference_implementation() {
    let reference = Reference::read();
    assert_eq!(reference.secrets.len(), 4);
    assert_eq!(reference.lines.len(), 16 * 409);
    for (function, length, key, value) in &reference.lines {
        let input = &reference.input[..*length];
        let expected = Vectors::hex(value);
        let label = format!("{function} of {length} bytes with {key}");
        let seed = u64::from_str_radix(key, 16).ok();
        match (function.as_str(), reference.secret(key)) {
            ("xxh32", None) => {
                let seed = seed.unwrap() as u32;
                check(|| xxh32::XXH32::with_seed(seed), input, &expected, &label);
                assert_eq!(xxh32::XXH32::hash(seed, input).to_be_bytes().to_vec(), expected);
            }
            ("xxh64", None) => {
                let seed = seed.unwrap();
                check(|| xxh64::XXH64::with_seed(seed), input, &expected, &label);
                assert_eq!(xxh64::XXH64::hash(seed, input).to_be_bytes().to_vec(), expected);
            }
            ("xxh3_64", None) => {
                let seed = seed.unwrap();
                check(|| xxh3::XXH3_64::with_seed(seed), input, &expected, &label);
                assert_eq!(xxh3::XXH3_64::hash(seed, input).to_be_bytes().to_vec(), expected);
            }
            ("xxh3_64", Some(secret)) => {
                check(|| xxh3::XXH3_64::with_secret(secret).unwrap(), input, &expected, &label)
            }
            ("xxh3_128", None) => {
                let seed = seed.unwrap();
                check(|| xxh3::XXH3_128::with_seed(seed), input, &expected, &label);
                assert_eq!(xxh3::XXH3_128::hash(seed, input).to_be_bytes().to_vec(), expected);
            }
            ("xxh3_128", Some(secret)) => {
                check(|| xxh3::XXH3_128::with_secret(secret).unwrap(), input, &expected, &label)
            }
            other => panic!("unknown line {other:?}"),
        }
    }
}

#[test]
fn xxhash_defaults_are_the_seed_zero() {
    let input = Reference::generate(1000, 5);
    assert_eq!(xxh32::XXH32::digest(&input), xxh32::XXH32::hash(0, &input).to_be_bytes());
    assert_eq!(xxh64::XXH64::digest(&input), xxh64::XXH64::hash(0, &input).to_be_bytes());
    assert_eq!(xxh3::XXH3_64::digest(&input), xxh3::XXH3_64::hash(0, &input).to_be_bytes());
    assert_eq!(xxh3::XXH3_128::digest(&input), xxh3::XXH3_128::hash(0, &input).to_be_bytes());
    // The seed 0 derives the default secret, so it equals the default secret given explicitly.
    let mut explicit = xxh3::XXH3_64::with_secret(&xxh3::XXH3::DEFAULT_SECRET).unwrap();
    explicit.update(&input);
    assert_eq!(explicit.value(), xxh3::XXH3_64::hash(0, &input));
    assert_eq!(xxh3::XXH3Secret::with_seed(0).secret(), xxh3::XXH3::DEFAULT_SECRET);
}

#[test]
fn xxh3_rejects_short_secrets() {
    assert!(xxh3::XXH3_64::with_secret(&[0; 135]).is_err());
    assert!(xxh3::XXH3_128::with_secret(&[0; 135]).is_err());
    assert!(xxh3::XXH3_64::with_secret(&[0; 136]).is_ok());
}
