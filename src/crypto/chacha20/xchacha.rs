use core::fmt;

use super::ChaCha20;
use crate::crypto::{CryptoError, StreamCipher};
use crate::secret::Zeroize;

/// XChaCha20 (draft-irtf-cfrg-xchacha section 2.3): ChaCha20 with a 192-bit
/// nonce, long enough to be chosen at random. HChaCha20 derives a subkey
/// from the key and the first 16 bytes of the nonce; ChaCha20 then runs with
/// the subkey and the last 8 bytes, prefixed by four zero bytes, and a 32-bit
/// counter ([`XChaCha20::new`]), or with the last 8 bytes as the nonce of a
/// 64-bit counter ([`XChaCha20::with_64_bit_counter`], as in libsodium). The
/// two agree while the counter is below 2^32.
#[derive(Clone)]
pub struct XChaCha20 {
    inner: ChaCha20,
}

impl XChaCha20 {
    pub const KEY_SIZE: usize = 32;
    pub const NONCE_SIZE: usize = 24;

    pub fn new(key: &[u8; 32], nonce: &[u8; 24], counter: u32) -> XChaCha20 {
        let (mut subkey, inner_nonce) = XChaCha20::derive(key, nonce);
        let inner = ChaCha20::new(&subkey, &inner_nonce, counter);
        subkey.zeroize();
        XChaCha20 { inner }
    }

    /// The inner ChaCha20 with a 64-bit counter.
    pub fn with_64_bit_counter(key: &[u8; 32], nonce: &[u8; 24], counter: u64) -> XChaCha20 {
        let mut subkey = XChaCha20::hchacha20(key, nonce[..16].try_into().expect("16 bytes"));
        let inner = ChaCha20::with_64_bit_counter(&subkey, nonce[16..].try_into().expect("eight bytes"), counter);
        subkey.zeroize();
        XChaCha20 { inner }
    }

    /// The subkey and the 96-bit nonce of the inner ChaCha20.
    pub fn derive(key: &[u8; 32], nonce: &[u8; 24]) -> ([u8; 32], [u8; 12]) {
        let subkey = XChaCha20::hchacha20(key, nonce[..16].try_into().expect("16 bytes"));
        let mut inner_nonce = [0u8; 12];
        inner_nonce[4..].copy_from_slice(&nonce[16..]);
        (subkey, inner_nonce)
    }

    /// HChaCha20 (section 2.2): the ChaCha20 rounds on the state whose last
    /// four words are the 128-bit nonce, without the final addition; the
    /// subkey is the first and the last row.
    pub fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
        let mut state = ChaCha20::initial_state(
            key,
            u32::from_le_bytes(nonce[..4].try_into().expect("four bytes")),
            nonce[4..].try_into().expect("12 bytes"),
        );
        ChaCha20::rounds(&mut state);
        let mut subkey = [0u8; 32];
        for (bytes, word) in subkey.as_chunks_mut::<4>().0.iter_mut().zip(state[..4].iter().chain(&state[12..])) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        state.zeroize();
        subkey
    }

    /// The bytes of key stream left before the counter wraps.
    pub fn remaining_bytes(&self) -> u128 {
        self.inner.remaining_bytes()
    }
}

impl StreamCipher for XChaCha20 {
    fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        self.inner.apply_keystream(data)
    }
}

impl Zeroize for XChaCha20 {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl fmt::Debug for XChaCha20 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XChaCha20(..)")
    }
}
