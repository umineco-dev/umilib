//! The Project Wycheproof suites of the modes and MACs of 128-bit block
//! ciphers, run on any cipher: a test file names the cipher of each key size
//! with [`wycheproof!`](crate::wycheproof).

use umilib::crypto::cmac::CMAC;
use umilib::crypto::mode::PKCS7;
use umilib::crypto::mode::cbc::CBC;
use umilib::crypto::mode::ccm::CCM;
use umilib::crypto::mode::gcm::GCM;
use umilib::crypto::{AEAD, BlockCipher, CryptoError, KeyInit};

use crate::Json;

/// Runs the Wycheproof file `$path` with the `Suite` function `$suite` and
/// the cipher of each key size; a test with another key size must be
/// invalid. Evaluates to the number of tests.
#[macro_export]
macro_rules! wycheproof {
    ($path:expr, $suite:ident, { $($size:literal => $cipher:ty),* $(,)? }) => {{
        let tests = $crate::Wycheproof::tests($path);
        assert!(!tests.is_empty(), "{}", $path);
        for (group, test) in &tests {
            match test.bytes("key").len() {
                $($size => $crate::suite::Suite::$suite::<$cipher>(group, test),)*
                _ => assert_eq!(test.field("result").as_str(), "invalid", "{}", $crate::suite::Suite::label(test)),
            }
        }
        tests.len()
    }};
}

pub struct Suite;

impl Suite {
    pub fn label(test: &Json) -> String {
        format!("tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str())
    }

    pub fn is_valid(test: &Json) -> bool {
        test.field("result").as_str() == "valid"
    }

    /// Encrypts `data` (without `tag`) or decrypts it (with `tag`) under the
    /// AEAD `A`; the result is the output and the tag of an encryption. A
    /// failed decryption must leave `data` as it was.
    pub fn aead<A: AEAD + KeyInit>(
        key: &[u8],
        nonce: &[u8],
        associated: &[u8],
        data: &[u8],
        tag: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let aead = A::new_from_slice(key)?;
        let mut buffer = data.to_vec();
        match tag {
            None => {
                let tag = aead.encrypt_in_place(nonce, associated, &mut buffer)?;
                Ok((buffer, tag.as_ref().to_vec()))
            }
            Some(tag) => {
                let result = aead.decrypt_in_place(nonce, associated, &mut buffer, tag);
                if result.is_err() {
                    assert_eq!(buffer, data, "a failed decryption restores the ciphertext");
                }
                result.map(|()| (buffer, Vec::new()))
            }
        }
    }

    /// Checks an AEAD test: a valid one encrypts to its ciphertext and tag and
    /// decrypts back; an invalid one fails to decrypt.
    pub fn check_aead(test: &Json, run: impl Fn(&[u8], Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), CryptoError>) {
        let (message, ciphertext, tag) = (test.bytes("msg"), test.bytes("ct"), test.bytes("tag"));
        let label = Suite::label(test);
        let decrypted = run(&ciphertext, Some(&tag));
        if Suite::is_valid(test) {
            assert_eq!(run(&message, None), Ok((ciphertext.clone(), tag.clone())), "{label}");
            assert_eq!(decrypted.map(|result| result.0), Ok(message), "{label}");
        } else {
            assert!(decrypted.is_err(), "{label}");
        }
    }

    /// A test of aead_*_gcm_test.json (SP 800-38D).
    pub fn gcm<C: BlockCipher<Block = [u8; 16]> + KeyInit>(group: &Json, test: &Json) {
        let (key, iv, aad) = (test.bytes("key"), test.bytes("iv"), test.bytes("aad"));
        Suite::check_aead(test, |data, tag| match group.field("tagSize").as_usize() / 8 {
            16 => Suite::aead::<GCM<C, 16>>(&key, &iv, &aad, data, tag),
            15 => Suite::aead::<GCM<C, 15>>(&key, &iv, &aad, data, tag),
            14 => Suite::aead::<GCM<C, 14>>(&key, &iv, &aad, data, tag),
            13 => Suite::aead::<GCM<C, 13>>(&key, &iv, &aad, data, tag),
            12 => Suite::aead::<GCM<C, 12>>(&key, &iv, &aad, data, tag),
            8 => Suite::aead::<GCM<C, 8>>(&key, &iv, &aad, data, tag),
            4 => Suite::aead::<GCM<C, 4>>(&key, &iv, &aad, data, tag),
            length => Err(CryptoError::TagLength { length, minimum: 4, maximum: 16 }),
        });
    }

    /// A test of *_ccm_test.json (SP 800-38C).
    pub fn ccm<C: BlockCipher<Block = [u8; 16]> + KeyInit>(group: &Json, test: &Json) {
        let (key, iv, aad) = (test.bytes("key"), test.bytes("iv"), test.bytes("aad"));
        Suite::check_aead(test, |data, tag| match group.field("tagSize").as_usize() / 8 {
            4 => Suite::aead::<CCM<C, 4>>(&key, &iv, &aad, data, tag),
            6 => Suite::aead::<CCM<C, 6>>(&key, &iv, &aad, data, tag),
            8 => Suite::aead::<CCM<C, 8>>(&key, &iv, &aad, data, tag),
            10 => Suite::aead::<CCM<C, 10>>(&key, &iv, &aad, data, tag),
            12 => Suite::aead::<CCM<C, 12>>(&key, &iv, &aad, data, tag),
            14 => Suite::aead::<CCM<C, 14>>(&key, &iv, &aad, data, tag),
            16 => Suite::aead::<CCM<C, 16>>(&key, &iv, &aad, data, tag),
            length => Err(CryptoError::TagLength { length, minimum: 4, maximum: 16 }),
        });
    }

    /// A test of *_cbc_pkcs5_test.json: CBC with the padding of PKCS #7; an
    /// invalid test has a ciphertext whose padding is wrong.
    pub fn cbc_pkcs5<C: BlockCipher<Block = [u8; 16]> + KeyInit>(_: &Json, test: &Json) {
        let (key, iv, message, ciphertext) = (test.bytes("key"), test.bytes("iv"), test.bytes("msg"), test.bytes("ct"));
        let label = Suite::label(test);
        let iv: [u8; 16] = iv.try_into().expect("16-byte IVs");
        let decrypt = || -> Result<Vec<u8>, CryptoError> {
            let mut buffer = ciphertext.clone();
            CBC::new(C::new_from_slice(&key)?, &iv).decrypt(&mut buffer)?;
            PKCS7::unpad(&mut buffer, 16)?;
            Ok(buffer)
        };
        if Suite::is_valid(test) {
            let mut buffer = message.clone();
            PKCS7::pad(&mut buffer, 16).unwrap();
            CBC::new(C::new_from_slice(&key).unwrap(), &iv).encrypt(&mut buffer).unwrap();
            assert_eq!(buffer, ciphertext, "{label}");
            assert_eq!(decrypt(), Ok(message), "{label}");
        } else {
            assert!(decrypt().is_err(), "{label}");
        }
    }

    /// A test of *_cmac_test.json (SP 800-38B): the tag may be truncated.
    pub fn cmac<C: BlockCipher<Block = [u8; 16]> + KeyInit>(group: &Json, test: &Json) {
        let (key, message, tag) = (test.bytes("key"), test.bytes("msg"), test.bytes("tag"));
        let tag_length = group.field("tagSize").as_usize() / 8;
        let full = CMAC::mac(C::new_from_slice(&key).unwrap(), &message);
        assert_eq!(full[..tag_length] == tag[..], Suite::is_valid(test), "{}", Suite::label(test));
    }
}
