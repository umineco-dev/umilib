//! The C ABI of `umilib::crypto` against the test vectors of the
//! specifications, through the functions C calls.

#[cfg(umilib_all_features)]
mod aead;
#[cfg(umilib_all_features)]
mod block_cipher;
#[cfg(umilib_all_features)]
mod exchange;
#[cfg(umilib_all_features)]
mod hpke;
#[cfg(umilib_all_features)]
mod kdf;
#[cfg(umilib_all_features)]
mod key_agreement;
#[cfg(umilib_all_features)]
mod mac;
#[cfg(umilib_all_features)]
mod mode;
#[cfg(umilib_all_features)]
mod pqc;
#[cfg(umilib_all_features)]
mod public_key_smoke;
#[cfg(umilib_all_features)]
mod signature;
#[cfg(umilib_all_features)]
mod sm9;
#[cfg(umilib_all_features)]
mod smoke;
#[cfg(umilib_all_features)]
mod stream_cipher;

use std::ptr;

use umilib::crypto::random::DRBGConfig;
use umilib::ffi::crypto::hmac::*;
use umilib::ffi::crypto::random::*;

use super::Check;

const SHA256: &[u8] = b"umilib_hash_sha_v2_SHA256";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
}

#[test]
fn hmac_through_the_c_abi() {
    // RFC 4231 test case 2.
    let expected = hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    let (key, data) = (b"Jefe", b"what do ya want for nothing?");
    unsafe {
        let mut out = [0u8; 32];
        Check::ok(umilib_crypto_hmac_hmac_mac(
            SHA256.as_ptr(),
            SHA256.len(),
            key.as_ptr(),
            4,
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            32,
        ));
        assert_eq!(out.to_vec(), expected);
        let mut state = ptr::null_mut();
        let unknown = b"umilib_hash_sha_v2_SHA999";
        Check::fails(
            umilib_crypto_hmac_hmac_new(unknown.as_ptr(), unknown.len(), key.as_ptr(), 4, &mut state),
            "ffi",
            "InvalidArgument",
        );
        Check::ok(umilib_crypto_hmac_hmac_new(SHA256.as_ptr(), SHA256.len(), key.as_ptr(), 4, &mut state));
        let mut size = 0;
        Check::ok(umilib_crypto_hmac_hmac_output_size(state, &mut size));
        assert_eq!(size, 32);
        Check::ok(umilib_crypto_hmac_hmac_minimum_truncated_length(state, &mut size));
        assert_eq!(size, 16);
        Check::ok(umilib_crypto_hmac_hmac_update(state, data.as_ptr(), data.len()));
        let mut copy = ptr::null_mut();
        Check::ok(umilib_crypto_hmac_hmac_clone(state, &mut copy));
        let mut valid = false;
        Check::ok(umilib_crypto_hmac_hmac_verify(copy, expected.as_ptr(), 32, &mut valid));
        assert!(valid);
        Check::ok(umilib_crypto_hmac_hmac_clone(state, &mut copy));
        Check::ok(umilib_crypto_hmac_hmac_verify_truncated(copy, expected.as_ptr(), 15, &mut valid));
        assert!(!valid);
        Check::fails(umilib_crypto_hmac_hmac_finalize(state, out.as_mut_ptr(), 31), "hash", "OutputLength");
        Check::ok(umilib_crypto_hmac_hmac_finalize_reset(state, out.as_mut_ptr(), 32));
        assert_eq!(out.to_vec(), expected);
        Check::ok(umilib_crypto_hmac_hmac_update(state, data.as_ptr(), data.len()));
        Check::ok(umilib_crypto_hmac_hmac_finalize(state, out.as_mut_ptr(), 32));
        assert_eq!(out.to_vec(), expected);
    }
}

#[test]
fn drbgs_through_the_c_abi() {
    unsafe {
        assert_eq!(umilib_crypto_random_drbg_config_default(), DRBGConfig::default());
        let loose = DRBGConfig { reseed_interval: 0, maximum_request: usize::MAX };
        assert_eq!(
            umilib_crypto_random_drbg_config_clamped(loose),
            DRBGConfig { reseed_interval: 1, maximum_request: 1 << 16 }
        );
        let (entropy, nonce) = ([1u8; 32], [2u8; 16]);
        let mut state = ptr::null_mut();
        Check::fails(
            hmac_drbg::new(
                SHA256.as_ptr(),
                SHA256.len(),
                entropy.as_ptr(),
                31,
                ptr::null(),
                0,
                ptr::null(),
                0,
                &mut state,
            ),
            "crypto.random",
            "EntropyLength",
        );
        let config = DRBGConfig { reseed_interval: 1, maximum_request: 64 };
        let mut state = ptr::null_mut();
        Check::ok(hash_drbg::with_config(
            SHA256.as_ptr(),
            SHA256.len(),
            &config,
            entropy.as_ptr(),
            32,
            nonce.as_ptr(),
            16,
            ptr::null(),
            0,
            &mut state,
        ));
        let mut strength = 0;
        Check::ok(hash_drbg::security_strength(state, &mut strength));
        assert_eq!(strength, 256);
        let mut out = [0u8; 65];
        Check::fails(
            hash_drbg::generate(state, out.as_mut_ptr(), 65, ptr::null(), 0),
            "crypto.random",
            "RequestLength",
        );
        Check::ok(hash_drbg::generate(state, out.as_mut_ptr(), 64, ptr::null(), 0));
        Check::fails(
            hash_drbg::generate(state, out.as_mut_ptr(), 1, ptr::null(), 0),
            "crypto.random",
            "ReseedRequired",
        );
        Check::ok(hash_drbg::reseed(state, entropy.as_ptr(), 32, ptr::null(), 0));
        let mut read = DRBGConfig::default();
        Check::ok(hash_drbg::config(state, &mut read));
        assert_eq!(read, config);
        let mut instantiated = false;
        Check::ok(hash_drbg::is_instantiated(state, &mut instantiated));
        assert!(instantiated);
        Check::fails(
            hmac_drbg::new(
                SHA256.as_ptr(),
                SHA256.len(),
                entropy.as_ptr(),
                32,
                nonce.as_ptr(),
                15,
                ptr::null(),
                0,
                &mut ptr::null_mut(),
            ),
            "crypto.random",
            "NonceLength",
        );
        Check::ok(hash_drbg::uninstantiate(state));
        Check::ok(hash_drbg::is_instantiated(state, &mut instantiated));
        assert!(!instantiated);
        Check::fails(
            hash_drbg::generate(state, out.as_mut_ptr(), 1, ptr::null(), 0),
            "crypto.random",
            "Uninstantiated",
        );
        hash_drbg::free(state);
        // The C ABI generates the same bytes as the Rust generator.
        let mut state = ptr::null_mut();
        Check::ok(hmac_drbg::new(
            SHA256.as_ptr(),
            SHA256.len(),
            entropy.as_ptr(),
            32,
            nonce.as_ptr(),
            16,
            ptr::null(),
            0,
            &mut state,
        ));
        Check::ok(hmac_drbg::fill(state, out.as_mut_ptr(), 65));
        let mut rust =
            umilib::crypto::random::HMACDRBG::<umilib::hash::sha::v2::SHA256>::new(&entropy, &nonce, &[]).unwrap();
        let mut expected = [0u8; 65];
        umilib::crypto::random::Random::fill(&mut rust, &mut expected).unwrap();
        assert_eq!(out, expected);
        hmac_drbg::free(state);
    }
}

/// The C type names of the block ciphers, by family and key length.
#[cfg(umilib_all_features)]
struct Cipher;

#[cfg(umilib_all_features)]
impl Cipher {
    /// The C type name of the cipher of `family` (`aes`, `aria`, `camellia`, `seed`, `sm4`) with a key of
    /// `length` bytes, if there is one.
    fn name(family: &str, length: usize) -> Option<&'static [u8]> {
        Some(match (family, length) {
            ("aes", 16) => b"umilib_crypto_aes_AES128",
            ("aes", 24) => b"umilib_crypto_aes_AES192",
            ("aes", 32) => b"umilib_crypto_aes_AES256",
            ("aria", 16) => b"umilib_crypto_aria_ARIA128",
            ("aria", 24) => b"umilib_crypto_aria_ARIA192",
            ("aria", 32) => b"umilib_crypto_aria_ARIA256",
            ("camellia", 16) => b"umilib_crypto_camellia_Camellia128",
            ("camellia", 24) => b"umilib_crypto_camellia_Camellia192",
            ("camellia", 32) => b"umilib_crypto_camellia_Camellia256",
            ("seed", 16) => b"umilib_crypto_seed_SEED",
            ("sm4", 16) => b"umilib_crypto_sm4_SM4",
            _ => return None,
        })
    }
}

/// A generator of the C ABI for the functions that draw random values: an
/// HMAC_DRBG over SHA-256 of a fixed seed, released when dropped.
#[cfg(umilib_all_features)]
struct Generator {
    state: *mut umilib::ffi::crypto::random::HMACDRBGState,
}

#[cfg(umilib_all_features)]
impl Generator {
    /// The C type name of the handle.
    const TYPE: &'static [u8] = b"umilib_crypto_random_HMACDRBG";

    /// A generator of the seed `label`.
    fn new(label: &[u8]) -> Generator {
        let mut state = ptr::null_mut();
        unsafe {
            Check::ok(hmac_drbg::new(
                SHA256.as_ptr(),
                SHA256.len(),
                [7u8; 32].as_ptr(),
                32,
                [8u8; 16].as_ptr(),
                16,
                label.as_ptr(),
                label.len(),
                &mut state,
            ))
        };
        Generator { state }
    }

    /// The handle, as the functions take it.
    fn handle(&self) -> *mut core::ffi::c_void {
        self.state.cast()
    }
}

#[cfg(umilib_all_features)]
impl Drop for Generator {
    fn drop(&mut self) {
        unsafe { hmac_drbg::free(self.state) };
    }
}

/// The bytes of a buffer of the C ABI, which is released.
#[cfg(umilib_all_features)]
struct Bytes;

#[cfg(umilib_all_features)]
impl Bytes {
    fn take(mut buffer: umilib::ffi::Buffer) -> Vec<u8> {
        let bytes = buffer.as_slice().to_vec();
        unsafe { umilib::ffi::umilib_ffi_buffer_free(&mut buffer) };
        bytes
    }
}
