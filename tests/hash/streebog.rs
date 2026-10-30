use umilib::hash::Digest;
use umilib::hash::streebog::{Streebog256, Streebog512};

use crate::Vectors;

/// The hexadecimal number that starts after `label` at line `index` and
/// continues on the indented lines below, as a byte string read in reverse
/// (the first byte least significant), which is how messages and hash codes
/// are exchanged.
fn number(lines: &[&str], index: usize, label: &str) -> Vec<u8> {
    let mut digits = lines[index].trim().strip_prefix(label).unwrap().trim().to_string();
    for line in &lines[index + 1..] {
        let line = line.trim();
        if line.is_empty() || !line.chars().all(|c| c.is_ascii_hexdigit()) {
            break;
        }
        digits.push_str(line);
    }
    let mut bytes = Vectors::hex(&digits);
    bytes.reverse();
    bytes
}

#[test]
fn streebog_follows_the_examples_of_rfc6986() {
    let text = Vectors::read("hash/streebog/rfc6986.txt");
    let lines: Vec<&str> = text.lines().collect();
    let find = |label: &str, occurrence: usize| {
        lines.iter().enumerate().filter(|(_, line)| line.trim().starts_with(label)).nth(occurrence).unwrap().0
    };
    let m1 = number(&lines, find("M1 = ", 0), "M1 =");
    let m2 = number(&lines, find("M2 = ", 0), "M2 =");
    // M1 is the ASCII text "0123456789" repeated, 63 characters.
    assert_eq!(m1, b"012345678901234567890123456789012345678901234567890123456789012");
    assert_eq!(m2.len(), 72);
    let check512 = |message: &[u8], expected: Vec<u8>| {
        assert_eq!(Streebog512::digest(message).to_vec(), expected);
        let mut hash = Streebog512::new();
        message.chunks(5).for_each(|piece| hash.update(piece));
        assert_eq!(hash.finalize_reset().to_vec(), expected);
    };
    check512(&m1, number(&lines, find("H(M1) = ", 0), "H(M1) ="));
    check512(&m2, number(&lines, find("H(M2) = ", 0), "H(M2) ="));
    assert_eq!(Streebog256::digest(&m1).to_vec(), number(&lines, find("H(M1) = ", 1), "H(M1) ="));
    assert_eq!(Streebog256::digest(&m2).to_vec(), number(&lines, find("H(M2) = ", 1), "H(M2) ="));
    assert_eq!((Streebog512::OUTPUT_SIZE, Streebog256::OUTPUT_SIZE, Streebog512::BLOCK_SIZE), (64, 32, 64));
}

#[test]
fn streebog_handles_whole_blocks() {
    // A message of exactly one block is padded with a block of its own
    // (step 3.1 with |M| = 0); streaming in pieces gives the same result.
    for length in [0usize, 63, 64, 65, 128, 200] {
        let message: Vec<u8> = (0..length as u8).collect();
        let mut hash = Streebog256::new();
        message.chunks(64).for_each(|piece| hash.update(piece));
        assert_eq!(hash.finalize(), Streebog256::digest(&message), "{length}");
    }
}
