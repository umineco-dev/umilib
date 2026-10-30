//! DES and TDES against NIST SP 800-67r2 and the NIST CAVP (SP 800-20).

use umilib::crypto::des::{DES, TDES};
use umilib::crypto::mode::cbc::CBC;
use umilib::crypto::mode::cfb::{CFB, CFB1, CFB8};
use umilib::crypto::mode::ecb::ECB;
use umilib::crypto::mode::ofb::OFB;
use umilib::crypto::{BlockCipher, CryptoError, KeyInit};

use crate::{Record, Vectors};

const MODES: [&str; 6] = ["ECB", "CBC", "CFB64", "CFB8", "CFB1", "OFB"];
const PARITY: u64 = 0x0101_0101_0101_0101;

/// The bytes of a field: hexadecimal, or for CFB1 a string of bits, most significant first.
fn field(record: &Record, key: &str, mode: &str) -> (Vec<u8>, usize) {
    let text = record.field(key);
    if mode != "CFB1" {
        let bytes = Vectors::hex(text);
        let bits = 8 * bytes.len();
        return (bytes, bits);
    }
    let mut bytes = vec![0u8; text.len().div_ceil(8)];
    for (index, character) in text.chars().enumerate() {
        if character == '1' {
            bytes[index / 8] |= 0x80 >> (index % 8);
        }
    }
    (bytes, text.len())
}

/// Encrypts or decrypts `data` (for CFB1, its first `bits` bits) in `mode` with a fresh mode object.
fn run<C: BlockCipher<Block = [u8; 8]>>(
    mode: &str,
    cipher: C,
    iv: &[u8; 8],
    data: &mut [u8],
    bits: usize,
    encrypt: bool,
) {
    match mode {
        "ECB" => {
            let ecb = ECB::new(cipher);
            if encrypt { ecb.encrypt(data).unwrap() } else { ecb.decrypt(data).unwrap() }
        }
        "CBC" => {
            let mut cbc = CBC::new(cipher, iv);
            if encrypt { cbc.encrypt(data).unwrap() } else { cbc.decrypt(data).unwrap() }
        }
        "CFB64" => {
            let mut cfb = CFB::new(cipher, iv);
            if encrypt { cfb.encrypt(data) } else { cfb.decrypt(data) }
        }
        "CFB8" => {
            let mut cfb = CFB8::new(cipher, iv);
            if encrypt { cfb.encrypt(data) } else { cfb.decrypt(data) }
        }
        "CFB1" => {
            let mut cfb = CFB1::new(cipher, iv);
            if encrypt { cfb.encrypt_bits(data, bits).unwrap() } else { cfb.decrypt_bits(data, bits).unwrap() }
        }
        "OFB" => OFB::new(cipher, iv).apply(data),
        other => panic!("{other}"),
    }
}

/// Runs one record in both directions with `cipher` made by `make`.
fn check<C: BlockCipher<Block = [u8; 8]>>(record: &Record, mode: &str, make: impl Fn() -> C, label: &str) {
    let iv: [u8; 8] = record.get("IV").map_or([0; 8], |_| record.bytes("IV").try_into().unwrap());
    let (plaintext, bits) = field(record, "PLAINTEXT", mode);
    let (ciphertext, _) = field(record, "CIPHERTEXT", mode);
    let mut data = plaintext.clone();
    run(mode, make(), &iv, &mut data, bits, true);
    assert_eq!(data, ciphertext, "{label}");
    run(mode, make(), &iv, &mut data, bits, false);
    assert_eq!(data, plaintext, "{label}");
}

#[test]
fn des_follows_the_cavp_known_answer_tests() {
    let mut checked = 0;
    for mode in MODES {
        for kind in ["invperm", "permop", "subtab", "varkey", "vartext"] {
            let path = format!("crypto/des/T{mode}{kind}.rsp");
            for record in Record::all(&path) {
                let label =
                    format!("{path} {:?} COUNT = {}", record.header.keys().collect::<Vec<_>>(), record.field("COUNT"));
                let key: [u8; 8] = record.bytes("KEYs").try_into().unwrap();
                check(&record, mode, || DES::new(&key), &label);
                // Key1 = Key2 = Key3 is single DES, which a TDES bundle may not be.
                assert_eq!(TDES::new(&key, &key, &key).err(), Some(CryptoError::InvalidParameter), "{label}");
                checked += 1;
            }
        }
    }
    assert!(checked > 2000, "{checked}");
}

#[test]
fn tdes_follows_the_cavp_multiblock_message_tests() {
    let mut checked = 0;
    for mode in MODES {
        for keys in [2, 3] {
            let path = format!("crypto/des/T{mode}MMT{keys}.rsp");
            for record in Record::all(&path) {
                let label =
                    format!("{path} {:?} COUNT = {}", record.header.keys().collect::<Vec<_>>(), record.field("COUNT"));
                let key = |name: &str| -> [u8; 8] { record.bytes(name).try_into().unwrap() };
                check(&record, mode, || TDES::new(&key("KEY1"), &key("KEY2"), &key("KEY3")).unwrap(), &label);
                if keys == 2 {
                    // A two-key bundle from 16 bytes.
                    let bundle = [key("KEY1"), key("KEY2")].concat();
                    check(&record, mode, || TDES::new_from_slice(&bundle).unwrap(), &label);
                }
                checked += 1;
            }
        }
    }
    // Two-key bundles are tested in decryption only, which SP 800-131A still allows; three-key in both directions.
    assert_eq!(checked, 6 * (10 + 20));
}

/// The Monte Carlo tests of SP 800-20 for TECB (tables 6 and 12) and TCBC
/// (tables 18 and 24) on the first records of each file.
#[test]
fn tdes_follows_the_cavp_monte_carlo_tests() {
    const RECORDS: usize = 4;
    for mode in ["ECB", "CBC"] {
        for keys in [2, 3] {
            let path = format!("crypto/des/T{mode}Monte{keys}.rsp");
            let records = Record::all(&path);
            for encrypt in [true, false] {
                let section: Vec<&Record> =
                    records.iter().filter(|record| record.header.contains_key("ENCRYPT") == encrypt).collect();
                // The two-key files test decryption only.
                if section.is_empty() && keys == 2 && encrypt {
                    continue;
                }
                assert_eq!(section.len(), 400, "{path}");
                for (index, record) in section.iter().take(RECORDS).enumerate() {
                    let label = format!("{path} encrypt = {encrypt} COUNT = {index}");
                    let words = |name: &str| u64::from_str_radix(record.field(name), 16).unwrap();
                    let (k1, k2, k3) = (words("KEY1"), words("KEY2"), words("KEY3"));
                    let tdes = TDES::new(&k1.to_be_bytes(), &k2.to_be_bytes(), &k3.to_be_bytes()).unwrap();
                    let (input, output) =
                        if encrypt { ("PLAINTEXT", "CIPHERTEXT") } else { ("CIPHERTEXT", "PLAINTEXT") };
                    // The outputs of the last three iterations: [j - 2, j - 1, j].
                    let mut last = [0u64; 3];
                    let mut text = words(input);
                    let mut cv = if mode == "CBC" { words("IV") } else { 0 };
                    let mut previous = cv;
                    for j in 0..10_000 {
                        let out = if mode == "ECB" {
                            let mut block = text.to_be_bytes();
                            if encrypt {
                                tdes.encrypt_block(&mut block)
                            } else {
                                tdes.decrypt_block(&mut block)
                            }
                            let out = u64::from_be_bytes(block);
                            text = out;
                            out
                        } else if encrypt {
                            let mut block = (text ^ cv).to_be_bytes();
                            tdes.encrypt_block(&mut block);
                            let out = u64::from_be_bytes(block);
                            // P_{j+1} is CV_0 after the first iteration and C_{j-1} after the others.
                            text = if j == 0 { cv } else { previous };
                            previous = out;
                            cv = out;
                            out
                        } else {
                            let mut block = text.to_be_bytes();
                            tdes.decrypt_block(&mut block);
                            let out = u64::from_be_bytes(block) ^ cv;
                            cv = text;
                            text = out;
                            out
                        };
                        last = [last[1], last[2], out];
                    }
                    assert_eq!(last[2], words(output), "{label}");
                    // The keys of the next record (section 5.1.1.6 e).
                    let next = section[index + 1];
                    let next_words = |name: &str| u64::from_str_radix(next.field(name), 16).unwrap();
                    let three_keys = k1 & !PARITY != k3 & !PARITY;
                    let (n1, n2, n3) =
                        (k1 ^ last[2], k2 ^ last[1], if three_keys { k3 ^ last[0] } else { k3 ^ last[2] });
                    for (computed, name) in [(n1, "KEY1"), (n2, "KEY2"), (n3, "KEY3")] {
                        assert_eq!(computed & !PARITY, next_words(name) & !PARITY, "{label} {name}");
                    }
                    let (next_input, next_cv) = if mode == "ECB" {
                        (last[2], None)
                    } else if encrypt {
                        (last[1], Some(last[2]))
                    } else {
                        (last[2], Some(cv))
                    };
                    assert_eq!(next_input, next_words(input), "{label} next {input}");
                    if let Some(cv) = next_cv {
                        assert_eq!(cv, next_words("IV"), "{label} next IV");
                    }
                }
            }
        }
    }
}

#[test]
fn des_follows_the_definitions_of_sp800_67() {
    // Section 2.3: S1(011011) = 0101.
    assert_eq!(DES::SELECTION_TABLES[0].get(0b011011), 0b0101);
    // IP^-1 is the inverse of IP.
    for bit in 0..64 {
        let input = 1u64 << bit;
        let permuted = DES::permute(input, 64, &DES::INITIAL_PERMUTATION);
        assert_eq!(DES::permute(permuted, 64, &DES::FINAL_PERMUTATION), input);
    }
    let plaintext = *b"umilib\x00\x01";
    // A weak key makes encryption an involution; a pair of semi-weak keys undo each other (section 3.3.2).
    for key in DES::WEAK_KEYS {
        let des = DES::new(&key.to_be_bytes());
        let mut block = plaintext;
        des.encrypt_block(&mut block);
        des.encrypt_block(&mut block);
        assert_eq!(block, plaintext, "{key:016x}");
        assert!(DES::is_weak(&key.to_be_bytes()));
        // The parity bits do not matter.
        assert!(DES::is_weak(&(key ^ PARITY).to_be_bytes()));
    }
    for pair in DES::SEMI_WEAK_KEYS.chunks(2) {
        let (first, second) = (DES::new(&pair[0].to_be_bytes()), DES::new(&pair[1].to_be_bytes()));
        let mut block = plaintext;
        first.encrypt_block(&mut block);
        second.encrypt_block(&mut block);
        assert_eq!(block, plaintext, "{:016x} {:016x}", pair[0], pair[1]);
    }
    // A possibly weak key gives only four distinct subkeys.
    for key in DES::POSSIBLY_WEAK_KEYS {
        let des = DES::new(&key.to_be_bytes());
        let mut subkeys = des.subkeys().to_vec();
        subkeys.sort();
        subkeys.dedup();
        assert_eq!(subkeys.len(), 4, "{key:016x}");
    }
    assert!(!DES::is_weak(b"umilib\x00\x01"));
}

#[test]
fn tdes_refuses_degenerate_bundles() {
    let (a, b, c) = (
        *b"\x01\x23\x45\x67\x89\xab\xcd\xef",
        *b"\x23\x45\x67\x89\xab\xcd\xef\x01",
        *b"\x45\x67\x89\xab\xcd\xef\x01\x23",
    );
    assert!(TDES::new(&a, &b, &c).is_ok());
    assert!(TDES::new(&a, &b, &a).is_ok());
    assert_eq!(TDES::new(&a, &a, &c).err(), Some(CryptoError::InvalidParameter));
    assert_eq!(TDES::new(&a, &b, &b).err(), Some(CryptoError::InvalidParameter));
    // Keys that differ only in their parity bits are the same DES key.
    let mut parity = a;
    parity[0] ^= 1;
    assert_eq!(TDES::new(&a, &parity, &c).err(), Some(CryptoError::InvalidParameter));
    assert!(matches!(TDES::new_from_slice(&[0; 8]), Err(CryptoError::KeyLength { .. })));
    assert!(matches!(TDES::new_from_slice(&[0; 32]), Err(CryptoError::KeyLength { .. })));
    assert!(DES::new_from_slice(&[0; 7]).is_err());
}
