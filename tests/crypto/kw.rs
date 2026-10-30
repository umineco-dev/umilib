//! Key wrapping against SP 800-38F: KW, TKW and KWP against RFC 3394 §4,
//! RFC 5649 §6, the KWVS files of NIST CAVP and Project Wycheproof.

use umilib::crypto::aes::{AES128, AES192, AES256};
use umilib::crypto::des::TDES;
use umilib::crypto::mode::kw::{KW, KWP, Wrapping};
use umilib::crypto::{BlockCipher, CryptoError, KeyInit};

use crate::{Record, Vectors, Wycheproof};

/// The modes under test.
#[derive(Clone, Copy, Debug)]
enum Mode {
    KW,
    KWP,
}

impl Mode {
    /// The wrapping of `data` under the AES key `key`.
    fn wrap(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        fn with<C: BlockCipher + KeyInit>(mode: Mode, key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let cipher = C::new_from_slice(key).unwrap();
            match mode {
                Mode::KW => {
                    let mut out = vec![0; KW::<C>::wrapped_length(data.len())?];
                    KW::new(cipher)?.wrap(data, &mut out)?;
                    Ok(out)
                }
                Mode::KWP => {
                    let mut out = vec![0; KWP::<C>::wrapped_length(data.len())?];
                    KWP::new(cipher)?.wrap(data, &mut out)?;
                    Ok(out)
                }
            }
        }
        match key.len() {
            16 => with::<AES128>(self, key, data),
            24 => with::<AES192>(self, key, data),
            _ => with::<AES256>(self, key, data),
        }
    }

    /// The data `wrapped` holds under the AES key `key`.
    fn unwrap(self, key: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
        fn with<C: BlockCipher + KeyInit>(mode: Mode, key: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let cipher = C::new_from_slice(key).unwrap();
            let mut out = vec![0xFF; wrapped.len().saturating_sub(8)];
            let result = match mode {
                Mode::KW => KW::new(cipher)?.unwrap(wrapped, &mut out).map(|()| out.len()),
                Mode::KWP => KWP::new(cipher)?.unwrap(wrapped, &mut out),
            };
            match result {
                Ok(length) => Ok(out[..length].to_vec()),
                Err(error) => {
                    assert!(out.iter().all(|&byte| byte == 0) || error != CryptoError::AuthenticationFailed);
                    Err(error)
                }
            }
        }
        match key.len() {
            16 => with::<AES128>(self, key, wrapped),
            24 => with::<AES192>(self, key, wrapped),
            _ => with::<AES256>(self, key, wrapped),
        }
    }
}

/// TKW over the three-key TDEA bundle `key`.
fn tkw(key: &[u8]) -> KW<TDES> {
    let part = |index: usize| -> [u8; 8] { key[8 * index..8 * index + 8].try_into().unwrap() };
    KW::new(TDES::new(&part(0), &part(1), &part(2)).unwrap()).unwrap()
}

/// The examples of an RFC appendix: each section's values of `labels`,
/// written in hexadecimal groups that may continue on the following lines.
fn examples(path: &str, heading: &str, labels: &[&str]) -> Vec<Vec<Vec<u8>>> {
    let text = Vectors::read(path);
    let mut sections: Vec<Vec<Vec<u8>>> = Vec::new();
    let is_hex = |line: &str| {
        let line = line.trim().trim_start_matches(':').trim();
        !line.is_empty() && line.chars().all(|c| c.is_ascii_hexdigit() || c == ' ')
    };
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index].trim();
        if line.starts_with(heading) {
            sections.push(vec![Vec::new(); labels.len()]);
        }
        if let Some(position) = labels.iter().position(|label| line.starts_with(label))
            && let Some(section) = sections.last_mut()
            && section[position].is_empty()
        {
            let mut value = line[labels[position].len()..].trim().trim_start_matches(':').to_string();
            while index + 1 < lines.len() && is_hex(lines[index + 1]) {
                index += 1;
                value.push_str(lines[index].trim().trim_start_matches(':'));
            }
            if is_hex(&value) {
                section[position] = Vectors::hex(&value);
            }
        }
        index += 1;
    }
    sections.retain(|section| section.iter().all(|value| !value.is_empty()));
    sections
}

#[test]
fn rfc_3394_section_4() {
    let sections = examples("crypto/mode/kw/rfc3394.txt", "4.", &["KEK", "Key Data", "Ciphertext"]);
    assert_eq!(sections.len(), 6, "the six examples of RFC 3394 §4");
    for section in sections {
        let (kek, data, ciphertext) = (&section[0], &section[1], &section[2]);
        assert_eq!(Mode::KW.wrap(kek, data).unwrap(), *ciphertext);
        assert_eq!(Mode::KW.unwrap(kek, ciphertext).unwrap(), *data);
    }
}

#[test]
fn rfc_5649_section_6() {
    let sections = examples("crypto/mode/kw/rfc5649.txt", "The ", &["KEK", "Key", "Wrap"]);
    assert_eq!(sections.len(), 2, "the two examples of RFC 5649 §6");
    for section in sections {
        let (kek, data, ciphertext) = (&section[0], &section[1], &section[2]);
        assert_eq!(Mode::KWP.wrap(kek, data).unwrap(), *ciphertext);
        assert_eq!(Mode::KWP.unwrap(kek, ciphertext).unwrap(), *data);
    }
}

#[test]
fn kwvs_of_nist_cavp() {
    let mut count = 0;
    for (mode, prefix) in [(Mode::KW, "KW"), (Mode::KWP, "KWP")] {
        for bits in [128, 192, 256] {
            for record in Record::all(&format!("crypto/mode/kw/{prefix}_AE_{bits}.txt")) {
                let (key, plaintext, ciphertext) = (record.bytes("K"), record.bytes("P"), record.bytes("C"));
                assert_eq!(
                    mode.wrap(&key, &plaintext).unwrap(),
                    ciphertext,
                    "{prefix} AE {bits} {}",
                    record.field("COUNT")
                );
                count += 1;
            }
            for record in Record::all(&format!("crypto/mode/kw/{prefix}_AD_{bits}.txt")) {
                let (key, ciphertext) = (record.bytes("K"), record.bytes("C"));
                let unwrapped = mode.unwrap(&key, &ciphertext);
                match record.get("P") {
                    Some(plaintext) => assert_eq!(unwrapped.unwrap(), Vectors::hex(plaintext)),
                    None => assert_eq!(
                        unwrapped,
                        Err(CryptoError::AuthenticationFailed),
                        "{prefix} AD {bits} {}",
                        record.field("COUNT")
                    ),
                }
                count += 1;
            }
        }
    }
    for record in Record::all("crypto/mode/kw/TKW_AE.txt") {
        let kw = tkw(&record.bytes("K"));
        let plaintext = record.bytes("P");
        let mut out = vec![0; KW::<TDES>::wrapped_length(plaintext.len()).unwrap()];
        kw.wrap(&plaintext, &mut out).unwrap();
        assert_eq!(out, record.bytes("C"), "TKW AE {}", record.field("COUNT"));
        count += 1;
    }
    for record in Record::all("crypto/mode/kw/TKW_AD.txt") {
        let kw = tkw(&record.bytes("K"));
        let ciphertext = record.bytes("C");
        let mut out = vec![0; ciphertext.len() - 4];
        let unwrapped = kw.unwrap(&ciphertext, &mut out);
        match record.get("P") {
            Some(plaintext) => {
                unwrapped.unwrap();
                assert_eq!(out, Vectors::hex(plaintext));
            }
            None => {
                assert_eq!(unwrapped, Err(CryptoError::AuthenticationFailed), "TKW AD {}", record.field("COUNT"));
                assert!(out.iter().all(|&byte| byte == 0));
            }
        }
        count += 1;
    }
    // Every record of the files (KW, KWP and TKW, encryptions and decryptions).
    assert!(count >= 7000, "{count} records");
}

#[test]
fn wycheproof() {
    for (mode, file) in [(Mode::KW, "aes_wrap_test.json"), (Mode::KWP, "aes_kwp_test.json")] {
        for (_, test) in Wycheproof::tests(&format!("crypto/mode/kw/{file}")) {
            let (key, message, ciphertext) = (test.bytes("key"), test.bytes("msg"), test.bytes("ct"));
            let id = test.field("tcId").as_usize();
            if Wycheproof::valid(&test) {
                assert_eq!(mode.wrap(&key, &message).unwrap(), ciphertext, "{file} {id}");
                assert_eq!(mode.unwrap(&key, &ciphertext).unwrap(), message, "{file} {id}");
            } else {
                // Invalid tests are wrappings that must not unwrap, or data the mode cannot wrap.
                assert!(mode.unwrap(&key, &ciphertext).is_err(), "{file} {id}");
                if mode.wrap(&key, &message).is_ok_and(|wrapped| wrapped == ciphertext) {
                    panic!("{file} {id}: an invalid wrapping was produced");
                }
            }
        }
    }
}

#[test]
fn lengths_follow_sp_800_38f() {
    // KW: whole semiblocks, at least two (§5.3.1); the wrapping adds one.
    assert_eq!(KW::<AES128>::wrapped_length(16), Ok(24));
    for length in [0, 8, 15, 17] {
        assert!(KW::<AES128>::wrapped_length(length).is_err(), "{length}");
    }
    // TKW: semiblocks of 32 bits.
    assert_eq!(KW::<TDES>::wrapped_length(8), Ok(12));
    assert!(KW::<TDES>::wrapped_length(4).is_err());
    assert_eq!(Wrapping::<TDES>::SEMIBLOCK, 4);
    // KWP: 1 to 2^32 − 1 bytes, padded to a semiblock; not defined for 64-bit ciphers.
    assert_eq!(KWP::<AES128>::wrapped_length(1), Ok(16));
    assert_eq!(KWP::<AES128>::wrapped_length(8), Ok(16));
    assert_eq!(KWP::<AES128>::wrapped_length(9), Ok(24));
    assert!(KWP::<AES128>::wrapped_length(0).is_err());
    let tdes = TDES::new(&[1; 8], &[2; 8], &[4; 8]).unwrap();
    assert_eq!(KWP::new(tdes).map(|_| ()), Err(CryptoError::InvalidParameter));
    // A KWP wrapping whose length field or padding is wrong does not unwrap (RFC 5649 §3).
    let key = [7u8; 16];
    for length in 1..=24 {
        let data: Vec<u8> = (0..length as u8).collect();
        let wrapped = Mode::KWP.wrap(&key, &data).unwrap();
        assert_eq!(Mode::KWP.unwrap(&key, &wrapped).unwrap(), data);
        let mut tampered = wrapped.clone();
        tampered[0] ^= 1;
        assert_eq!(Mode::KWP.unwrap(&key, &tampered), Err(CryptoError::AuthenticationFailed), "{length}");
    }
    // The checks of RFC 5649 §3 on what W⁻¹ gives: 8(n − 1) < MLI ≤ 8n, and zero padding.
    let raw = |length: u32, padded: &[u8]| {
        let mut data = [&[0xA6, 0x59, 0x59, 0xA6][..], &length.to_be_bytes(), padded].concat();
        Wrapping::wrap(&AES128::new_from_slice(&key).unwrap(), &mut data).unwrap();
        Mode::KWP.unwrap(&key, &data)
    };
    let padded = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0];
    assert_eq!(raw(12, &padded), Ok(padded[..12].to_vec()));
    assert_eq!(raw(16, &[1; 16]), Ok(vec![1; 16]));
    for length in [0, 8, 17, 100] {
        assert_eq!(raw(length, &padded), Err(CryptoError::AuthenticationFailed), "MLI {length}");
    }
    let mut dirty = padded;
    dirty[15] = 1;
    assert_eq!(raw(12, &dirty), Err(CryptoError::AuthenticationFailed), "padding not zero");
    assert_eq!(raw(15, &dirty), Err(CryptoError::AuthenticationFailed), "the 16th byte is padding");
    assert_eq!(raw(16, &dirty), Ok(dirty.to_vec()));
}

/// A cipher of 256-bit blocks, which SP 800-38F does not define key wrapping for.
#[derive(Clone)]
struct Wide;

impl umilib::secret::Zeroize for Wide {
    fn zeroize(&mut self) {}
}

impl BlockCipher for Wide {
    const BLOCK_SIZE: usize = 32;
    type Block = [u8; 32];

    fn encrypt_block(&self, _: &mut [u8; 32]) {}

    fn decrypt_block(&self, _: &mut [u8; 32]) {}
}

#[test]
fn key_wrapping_is_defined_for_64_and_128_bit_blocks() {
    // SP 800-38F §5.1: KW and KWP for 128-bit ciphers, TKW for 64-bit ones.
    assert!(matches!(KW::new(Wide), Err(CryptoError::InvalidParameter)));
    assert!(matches!(KWP::new(Wide), Err(CryptoError::InvalidParameter)));
    assert!(matches!(KWP::new(tkw_cipher()), Err(CryptoError::InvalidParameter)));
    // RFC 5649 §3: keys of 1 to 2^32 − 1 bytes.
    assert_eq!(KWP::<AES128>::wrapped_length(0), Err(CryptoError::InputLength { length: 0 }));
    assert_eq!(KWP::<AES128>::wrapped_length(9), Ok(24));
    if let Ok(length) = usize::try_from(u64::from(u32::MAX) + 1) {
        assert_eq!(KWP::<AES128>::wrapped_length(length), Err(CryptoError::InputLength { length }));
    }
}

/// A TDEA cipher, with the key of the first record of TKW_AE.txt.
fn tkw_cipher() -> TDES {
    let key = Vectors::hex("12b84c663120c196f8fc17428bc86a110d92cc7c4d3cb695");
    let part = |index: usize| -> [u8; 8] { key[8 * index..8 * index + 8].try_into().unwrap() };
    TDES::new(&part(0), &part(1), &part(2)).unwrap()
}
