//! scrypt against RFC 7914.

use umilib::crypto::CryptoError;
use umilib::crypto::pbkdf2::PBKDF2;
use umilib::crypto::scrypt::Scrypt;
use umilib::hash::sha::v2::SHA256;

use crate::Record;

fn words(bytes: &[u8]) -> Vec<[u32; 16]> {
    bytes
        .chunks(64)
        .map(|block| {
            core::array::from_fn(|index| u32::from_le_bytes(block[4 * index..4 * index + 4].try_into().unwrap()))
        })
        .collect()
}

fn scrypt(record: &Record) -> Vec<u8> {
    let parameter = |name: &str| record.field(name).parse::<u64>().unwrap();
    let scrypt = Scrypt::new(parameter("N"), parameter("r") as u32, parameter("p") as u32).unwrap();
    let mut out = vec![0u8; record.bytes("DK").len()];
    scrypt.derive(&record.bytes("P"), &record.bytes("S"), &mut out).unwrap();
    out
}

#[test]
fn scrypt_follows_rfc7914() {
    let records = Record::all("crypto/scrypt/rfc7914.txt");
    assert_eq!(records.len(), 9);
    for record in records.iter().filter(|record| record.get("N") != Some("1048576")) {
        let function = record.field("Function");
        match function {
            "Salsa20/8" => {
                let mut block = words(&record.bytes("Input"))[0];
                Scrypt::salsa20_8(&mut block);
                assert_eq!(vec![block], words(&record.bytes("Output")));
            }
            "BlockMix" => {
                let input = words(&record.bytes("Input"));
                let mut output = vec![[0u32; 16]; input.len()];
                Scrypt::block_mix(&input, &mut output);
                assert_eq!(output, words(&record.bytes("Output")));
            }
            "ROMix" => {
                let mut block = words(&record.bytes("Input"));
                let mut memory = vec![[0u32; 16]; 16 * block.len()];
                let mut scratch = vec![[0u32; 16]; block.len()];
                Scrypt::ro_mix(&mut block, &mut memory, &mut scratch);
                assert_eq!(block, words(&record.bytes("Output")));
            }
            "PBKDF2-HMAC-SHA-256" => {
                let expected = record.bytes("DK");
                let mut out = vec![0u8; expected.len()];
                PBKDF2::<SHA256>::derive(
                    &record.bytes("P"),
                    &record.bytes("S"),
                    record.field("c").parse().unwrap(),
                    &mut out,
                )
                .unwrap();
                assert_eq!(out, expected);
            }
            "scrypt" => assert_eq!(scrypt(record), record.bytes("DK"), "N = {}", record.field("N")),
            function => panic!("{function}"),
        }
    }
}

/// The last vector of section 12 needs 1 GiB of memory.
#[test]
#[ignore = "N = 2^20 allocates 1 GiB"]
fn scrypt_follows_rfc7914_with_n_2_to_the_20() {
    let record =
        Record::all("crypto/scrypt/rfc7914.txt").into_iter().find(|record| record.get("N") == Some("1048576")).unwrap();
    assert_eq!(scrypt(&record), record.bytes("DK"));
}

#[test]
fn scrypt_checks_its_parameters() {
    // Section 6: N > 1 a power of two, below 2^(16 r); r, p > 0 with r × p < 2^30.
    for (n, r, p) in [(0, 1, 1), (1, 1, 1), (3, 1, 1), (1 << 16, 1, 1), (16, 0, 1), (16, 1, 0), (16, 1 << 15, 1 << 15)]
    {
        assert_eq!(Scrypt::new(n, r, p), Err(CryptoError::InvalidParameter), "N = {n}, r = {r}, p = {p}");
    }
    assert!(Scrypt::new(1 << 15, 1, 1).is_ok());
    let scrypt = Scrypt::new(1024, 8, 16).unwrap();
    assert_eq!(scrypt.memory(), 128 * 8 * (1024 + 16));
    assert!(matches!(scrypt.derive(b"p", b"s", &mut []), Err(CryptoError::InputLength { .. })));
    // Valid parameters whose memory (128 × r × N bytes) no machine has: the derivation cannot be
    // computed and must fail rather than return another value.
    for (n, r) in [(1u64 << 61, 8), (1 << 62, 4), (1 << 59, 16), (1 << 40, 8)] {
        let scrypt = Scrypt::new(n, r, 1).unwrap();
        assert_eq!(scrypt.derive(b"p", b"s", &mut [0; 32]), Err(CryptoError::Allocation), "N = {n}, r = {r}");
    }
}
