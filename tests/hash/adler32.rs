//! Adler-32 against the definition of RFC 1950 section 8.

use umilib::hash::Digest;
use umilib::hash::adler32::Adler32;

/// A = 1 + D1 + ... + Dn and B = (1 + D1) + ... + (1 + D1 + ... + Dn), both modulo 65521, by the definition.
fn definition(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u64, 0u64);
    for byte in data {
        a = (a + *byte as u64) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16 | a) as u32
}

#[test]
fn adler32_follows_rfc1950() {
    assert_eq!(Adler32::checksum(b""), 1);
    // "a": A = 1 + 97 = 98, B = 98.
    assert_eq!(Adler32::checksum(b"a"), 98 << 16 | 98);
    // Long runs of 0xFF reach the modulus many times within and across blocks.
    for data in [
        vec![0xFFu8; 5552],
        vec![0xFF; 5553],
        vec![0xFF; 100_000],
        (0..70_000u32).map(|index| (index * 31 % 256) as u8).collect(),
    ] {
        assert_eq!(Adler32::checksum(&data), definition(&data));
        let mut pieces = Adler32::new();
        for piece in data.chunks(777) {
            pieces.update(piece);
        }
        assert_eq!(pieces.value(), definition(&data));
        assert_eq!(Adler32::digest(&data), definition(&data).to_be_bytes());
        // A checksum continues from its value.
        let (first, second) = data.split_at(data.len() / 3);
        let mut continued = Adler32::with_value(Adler32::checksum(first));
        continued.update(second);
        assert_eq!(continued.value(), definition(&data));
    }
}
