//! The modes of SP 800-38A against the AESAVS files of NIST CAVP.

use umilib::crypto::aes::{AES128, AES192, AES256};
use umilib::crypto::mode::PKCS7;
use umilib::crypto::mode::cbc::CBC;
use umilib::crypto::mode::cfb::{CFB, CFB1, CFB8};
use umilib::crypto::mode::ctr::CTR;
use umilib::crypto::mode::ecb::ECB;
use umilib::crypto::mode::ofb::OFB;
use umilib::crypto::{BlockCipher, CryptoError, KeyInit, StreamCipher};

use crate::{Record, Vectors, wycheproof};

/// The modes under test, each a direction of one mode over one cipher.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    CBC,
    CFB,
    CFB8,
    CFB1,
    OFB,
}

impl Mode {
    /// Encrypts or decrypts `data` (for CFB1, its first `bits` bits) with a fresh mode object.
    fn run<C: BlockCipher<Block = [u8; 16]> + KeyInit>(
        self,
        key: &[u8],
        iv: &[u8; 16],
        data: &mut [u8],
        bits: usize,
        encrypt: bool,
    ) {
        let cipher = C::new_from_slice(key).unwrap();
        match self {
            Mode::CBC => {
                let mut mode = CBC::new(cipher, iv);
                if encrypt { mode.encrypt(data).unwrap() } else { mode.decrypt(data).unwrap() }
            }
            Mode::CFB => {
                let mut mode = CFB::new(cipher, iv);
                if encrypt { mode.encrypt(data) } else { mode.decrypt(data) }
            }
            Mode::CFB8 => {
                let mut mode = CFB8::new(cipher, iv);
                if encrypt { mode.encrypt(data) } else { mode.decrypt(data) }
            }
            Mode::CFB1 => {
                let mut mode = CFB1::new(cipher, iv);
                if encrypt { mode.encrypt_bits(data, bits).unwrap() } else { mode.decrypt_bits(data, bits).unwrap() }
            }
            Mode::OFB => {
                let mut mode = OFB::new(cipher, iv);
                mode.apply_keystream(data).unwrap();
            }
        }
    }

    fn dispatch(self, key: &[u8], iv: &[u8; 16], data: &mut [u8], bits: usize, encrypt: bool) {
        match key.len() {
            16 => self.run::<AES128>(key, iv, data, bits, encrypt),
            24 => self.run::<AES192>(key, iv, data, bits, encrypt),
            _ => self.run::<AES256>(key, iv, data, bits, encrypt),
        }
    }
}

/// The bytes of a field: hexadecimal, or for CFB1 a string of bits, most significant first.
fn field(record: &Record, key: &str, mode: Mode) -> (Vec<u8>, usize) {
    let text = record.field(key);
    if mode != Mode::CFB1 {
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

#[test]
fn modes_follow_the_cavp_known_answers_and_multiblock_tests() {
    let mut checked = 0;
    for (prefix, directory, mode) in [
        ("CBC", "cbc", Mode::CBC),
        ("CFB128", "cfb", Mode::CFB),
        ("CFB8", "cfb", Mode::CFB8),
        ("CFB1", "cfb", Mode::CFB1),
        ("OFB", "ofb", Mode::OFB),
    ] {
        for kind in ["GFSbox", "KeySbox", "VarKey", "VarTxt", "MMT"] {
            for size in [128, 192, 256] {
                let path = format!("crypto/mode/{directory}/{prefix}{kind}{size}.rsp");
                for record in Record::all(&path) {
                    let encrypt = record.header.contains_key("ENCRYPT");
                    let (input, output) =
                        if encrypt { ("PLAINTEXT", "CIPHERTEXT") } else { ("CIPHERTEXT", "PLAINTEXT") };
                    let (mut data, bits) = field(&record, input, mode);
                    let iv: [u8; 16] = record.bytes("IV").try_into().unwrap();
                    mode.dispatch(&record.bytes("KEY"), &iv, &mut data, bits, encrypt);
                    assert_eq!(data, field(&record, output, mode).0, "{path} {:?}", record.fields);
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 7000, "{checked}");
}

/// The Monte Carlo tests of AESAVS section 6.4 for CBC, OFB and the three
/// CFB segment sizes, each run with one mode object per outer iteration.
#[test]
fn modes_follow_the_cavp_monte_carlo_tests() {
    for (prefix, directory, mode) in [
        ("CBC", "cbc", Mode::CBC),
        ("OFB", "ofb", Mode::OFB),
        ("CFB128", "cfb", Mode::CFB),
        ("CFB8", "cfb", Mode::CFB8),
        ("CFB1", "cfb", Mode::CFB1),
    ] {
        for size in [128usize, 192, 256] {
            let path = format!("crypto/mode/{directory}/{prefix}MCT{size}.rsp");
            let records = Record::all(&path);
            for encrypt in [true, false] {
                let section: Vec<&Record> =
                    records.iter().filter(|record| record.header.contains_key("ENCRYPT") == encrypt).collect();
                let (input, output) = if encrypt { ("PLAINTEXT", "CIPHERTEXT") } else { ("CIPHERTEXT", "PLAINTEXT") };
                let mut key = section[0].bytes("KEY");
                let mut iv: [u8; 16] = section[0].bytes("IV").try_into().unwrap();
                // The segments: whole blocks, bytes or bits, each held in its own vector.
                let (segment_bits, segments) = match mode {
                    Mode::CFB1 => (1, 128usize),
                    Mode::CFB8 => (8, 16),
                    _ => (128, 1),
                };
                let bytes_of = |segment: &[u8]| segment.to_vec();
                let mut text = field(section[0], input, mode).0;
                for record in &section {
                    assert_eq!(key, record.bytes("KEY"), "{path} {}", record.field("COUNT"));
                    assert_eq!(iv.to_vec(), record.bytes("IV"), "{path} {}", record.field("COUNT"));
                    let mut outputs: Vec<Vec<u8>> = Vec::new();
                    // One mode object, fed one segment at a time: running the segments through a
                    // fresh object each would restart the chaining.
                    let mut runner = Runner::start(mode, &key, &iv);
                    for j in 0..1000 {
                        let mut segment = text.clone();
                        runner.step(&mut segment, encrypt);
                        outputs.push(bytes_of(&segment));
                        // The next input: segment j of the IV for the first segments, then the
                        // output `segments` steps back.
                        text = if j < segments {
                            Runner::segment_of(&iv, j, segment_bits)
                        } else {
                            outputs[j - segments].clone()
                        };
                    }
                    assert_eq!(outputs[999], field(record, output, mode).0, "{path} {}", record.field("COUNT"));
                    // The last outputs as one bit string, from which the next key and IV come.
                    let tail = Runner::concatenate(&outputs, segment_bits, 256);
                    let material = &tail[32 - key.len()..];
                    for (byte, value) in key.iter_mut().zip(material) {
                        *byte ^= value;
                    }
                    iv.copy_from_slice(&tail[16..]);
                    text = outputs[999 - segments].clone();
                }
            }
        }
    }
}

/// A mode object fed one segment at a time: a block, a byte, or a bit (in
/// the most significant bit of a byte).
trait Segmenter {
    fn step(&mut self, segment: &mut [u8], encrypt: bool);
}

impl<C: BlockCipher<Block = [u8; 16]>> Segmenter for CBC<C> {
    fn step(&mut self, segment: &mut [u8], encrypt: bool) {
        if encrypt { self.encrypt(segment).unwrap() } else { self.decrypt(segment).unwrap() }
    }
}

impl<C: BlockCipher<Block = [u8; 16]>> Segmenter for CFB<C> {
    fn step(&mut self, segment: &mut [u8], encrypt: bool) {
        if encrypt { self.encrypt(segment) } else { self.decrypt(segment) }
    }
}

impl<C: BlockCipher<Block = [u8; 16]>> Segmenter for CFB8<C> {
    fn step(&mut self, segment: &mut [u8], encrypt: bool) {
        if encrypt { self.encrypt(segment) } else { self.decrypt(segment) }
    }
}

impl<C: BlockCipher<Block = [u8; 16]>> Segmenter for CFB1<C> {
    fn step(&mut self, segment: &mut [u8], encrypt: bool) {
        if encrypt { self.encrypt_bits(segment, 1).unwrap() } else { self.decrypt_bits(segment, 1).unwrap() }
    }
}

impl<C: BlockCipher<Block = [u8; 16]>> Segmenter for OFB<C> {
    fn step(&mut self, segment: &mut [u8], _: bool) {
        self.apply(segment);
    }
}

struct Runner;

impl Runner {
    fn mode<C: BlockCipher<Block = [u8; 16]> + KeyInit + 'static>(
        mode: Mode,
        key: &[u8],
        iv: &[u8; 16],
    ) -> Box<dyn Segmenter> {
        let cipher = C::new_from_slice(key).unwrap();
        match mode {
            Mode::CBC => Box::new(CBC::new(cipher, iv)),
            Mode::CFB => Box::new(CFB::new(cipher, iv)),
            Mode::CFB8 => Box::new(CFB8::new(cipher, iv)),
            Mode::CFB1 => Box::new(CFB1::new(cipher, iv)),
            Mode::OFB => Box::new(OFB::new(cipher, iv)),
        }
    }

    fn start(mode: Mode, key: &[u8], iv: &[u8; 16]) -> Box<dyn Segmenter> {
        match key.len() {
            16 => Runner::mode::<AES128>(mode, key, iv),
            24 => Runner::mode::<AES192>(mode, key, iv),
            _ => Runner::mode::<AES256>(mode, key, iv),
        }
    }

    /// Bit strings of one bit per byte (0 or 0x80) packed into bytes.
    fn pack(bits: &[u8]) -> Vec<u8> {
        let mut packed = vec![0u8; bits.len().div_ceil(8)];
        for (index, &bit) in bits.iter().enumerate() {
            if bit != 0 {
                packed[index / 8] |= 0x80 >> (index % 8);
            }
        }
        packed
    }

    /// Segment `index` of the IV.
    fn segment_of(iv: &[u8; 16], index: usize, bits: usize) -> Vec<u8> {
        match bits {
            1 => vec![(iv[index / 8] << (index % 8)) & 0x80],
            8 => vec![iv[index]],
            _ => iv.to_vec(),
        }
    }

    /// The last `length_bits` bits of the outputs, as bytes.
    fn concatenate(outputs: &[Vec<u8>], bits: usize, length_bits: usize) -> Vec<u8> {
        if bits == 1 {
            let bits: Vec<u8> = outputs[outputs.len() - length_bits..].iter().map(|segment| segment[0]).collect();
            return Runner::pack(&bits);
        }
        outputs[outputs.len() - length_bits / bits..].concat()
    }
}

#[test]
fn ctr_follows_sp800_38a_appendix_f5() {
    // F.5.1 CTR-AES128.Encrypt.
    let key = Vectors::hex("2b7e151628aed2a6abf7158809cf4f3c");
    let initial: [u8; 16] = Vectors::hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").try_into().unwrap();
    let plaintext = Vectors::hex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    );
    let expected = Vectors::hex(
        "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
    );
    let mut data = plaintext.clone();
    let mut ctr = CTR::new(AES128::new_from_slice(&key).unwrap(), &initial);
    for piece in data.chunks_mut(7) {
        ctr.apply_keystream(piece).unwrap();
    }
    assert_eq!(data, expected);
    let mut ctr = CTR::new(AES128::new_from_slice(&key).unwrap(), &initial);
    ctr.apply_keystream(&mut data).unwrap();
    assert_eq!(data, plaintext);
}

#[test]
fn ctr_counts_within_its_bits_and_stops_before_repeating() {
    let mut block = [0xFFu8; 16];
    CTR::<AES128>::increment(&mut block, 8);
    assert_eq!(block[15], 0x00);
    assert_eq!(block[14], 0xFF);
    let mut block = [0u8; 16];
    block[15] = 0xFF;
    block[14] = 0x0F;
    CTR::<AES128>::increment(&mut block, 12);
    assert_eq!((block[14], block[15]), (0x00, 0x00));
    let mut block = [0xA5u8; 16];
    block[15] = 0xFF;
    CTR::<AES128>::increment(&mut block, 3);
    assert_eq!(block[15], 0xF8);
    // With a 2-bit counter there are 4 blocks of key stream.
    let mut ctr = CTR::with_counter_bits(AES128::new(&[0; 16]), &[0; 16], 2).unwrap();
    let mut data = [0u8; 64];
    ctr.apply_keystream(&mut data[..40]).unwrap();
    assert_eq!(ctr.apply_keystream(&mut data[40..]), Ok(()));
    assert_eq!(ctr.apply_keystream(&mut [0u8; 1]), Err(CryptoError::LimitExceeded));
    assert!(CTR::with_counter_bits(AES128::new(&[0; 16]), &[0; 16], 129).is_err());
    // A counter of c bits has 2^c values, each a block of key stream (SP 800-38A appendix B.1).
    for bits in [32, 63, 64, 100, 123] {
        let ctr = CTR::with_counter_bits(AES128::new(&[0; 16]), &[0; 16], bits).unwrap();
        assert_eq!(ctr.remaining_bytes(), Some(16 << bits), "{bits} bits");
    }
    let mut ctr = CTR::with_counter_bits(AES128::new(&[0; 16]), &[0; 16], 32).unwrap();
    ctr.apply_keystream(&mut [0u8; 100]).unwrap();
    assert_eq!(ctr.remaining_bytes(), Some((16 << 32) - 100));
}

#[test]
fn ecb_and_cbc_need_whole_blocks_and_pkcs7_pads() {
    let ecb = ECB::new(AES128::new(&[1; 16]));
    assert_eq!(ecb.encrypt(&mut [0u8; 15]), Err(CryptoError::InputLength { length: 15 }));
    let mut cbc = CBC::new(AES128::new(&[1; 16]), &[2; 16]);
    assert!(cbc.decrypt(&mut [0u8; 17]).is_err());
    for length in 0..40 {
        let mut data: Vec<u8> = (0..length as u8).collect();
        PKCS7::pad(&mut data, 16).unwrap();
        assert!(data.len().is_multiple_of(16) && data.len() > length);
        PKCS7::unpad(&mut data, 16).unwrap();
        assert_eq!(data, (0..length as u8).collect::<Vec<_>>());
    }
    for invalid in [&[0u8; 16][..], &[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 2, 3], &[17u8; 16], &[]] {
        assert!(PKCS7::unpad_length(invalid, 16).is_err(), "{invalid:?}");
    }
    let mut full = vec![16u8; 16];
    PKCS7::unpad(&mut full, 16).unwrap();
    assert!(full.is_empty());
}

#[test]
fn cbc_with_pkcs7_follows_the_wycheproof_vectors() {
    assert_eq!(
        wycheproof!("crypto/mode/cbc/aes_cbc_pkcs5_test.json", cbc_pkcs5, { 16 => AES128, 24 => AES192, 32 => AES256 }),
        216
    );
}
