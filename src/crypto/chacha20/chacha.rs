use core::fmt;

use crate::crypto::{CryptoError, StreamCipher};
use crate::secret::Zeroize;

/// ChaCha20: the stream cipher of RFC 8439 section 2.4, with a 256-bit key,
/// a 96-bit nonce and a 32-bit block counter ([`ChaCha20::new`]), or the
/// original layout of Bernstein with a 64-bit nonce and a 64-bit counter in
/// words 12 and 13 ([`ChaCha20::with_64_bit_counter`], as in libsodium and
/// OpenSSH). It uses only additions, xors and rotations, so it takes the
/// same time for every key and input.
///
/// The key stream ends when the counter would wrap (2^32 or 2^64 blocks of
/// 64 bytes from the initial counter); further key stream fails with
/// [`CryptoError::LimitExceeded`] instead of repeating.
#[derive(Clone)]
pub struct ChaCha20 {
    /// The input state: constants, key, the next block counter and nonce.
    state: [u32; 16],
    keystream: [u8; 64],
    /// The bytes of `keystream` used; 64 when it is used up.
    position: usize,
    /// Whether the counter has 64 bits (words 12 and 13) instead of 32.
    wide: bool,
    /// The blocks left before the counter wraps.
    blocks: u128,
}

impl ChaCha20 {
    pub const KEY_SIZE: usize = 32;
    pub const NONCE_SIZE: usize = 12;
    /// The first four words of the state: "expand 32-byte k" (section 2.3).
    pub const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574];

    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> ChaCha20 {
        ChaCha20 {
            state: ChaCha20::initial_state(key, counter, nonce),
            keystream: [0; 64],
            position: 64,
            wide: false,
            blocks: (1u128 << 32) - counter as u128,
        }
    }

    /// The original layout: words 12 and 13 hold a 64-bit counter, words 14 and 15 a 64-bit nonce.
    pub fn with_64_bit_counter(key: &[u8; 32], nonce: &[u8; 8], counter: u64) -> ChaCha20 {
        let mut words = [0u8; 12];
        words[..4].copy_from_slice(&((counter >> 32) as u32).to_le_bytes());
        words[4..].copy_from_slice(nonce);
        ChaCha20 {
            state: ChaCha20::initial_state(key, counter as u32, &words),
            keystream: [0; 64],
            position: 64,
            wide: true,
            blocks: (1u128 << 64) - counter as u128,
        }
    }

    /// The state of section 2.3: constants, key, block counter, nonce, as little-endian words.
    pub fn initial_state(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u32; 16] {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&ChaCha20::CONSTANTS);
        for (index, word) in key.as_chunks::<4>().0.iter().enumerate() {
            state[4 + index] = u32::from_le_bytes(*word);
        }
        state[12] = counter;
        for (index, word) in nonce.as_chunks::<4>().0.iter().enumerate() {
            state[13 + index] = u32::from_le_bytes(*word);
        }
        state
    }

    /// The quarter round on the words `a`, `b`, `c` and `d` of the state (sections 2.1 and 2.2).
    pub fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[d] ^ state[a]).rotate_left(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(12);
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[d] ^ state[a]).rotate_left(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(7);
    }

    /// The 20 rounds: ten column rounds alternating with ten diagonal rounds.
    pub fn rounds(state: &mut [u32; 16]) {
        for _ in 0..10 {
            ChaCha20::quarter_round(state, 0, 4, 8, 12);
            ChaCha20::quarter_round(state, 1, 5, 9, 13);
            ChaCha20::quarter_round(state, 2, 6, 10, 14);
            ChaCha20::quarter_round(state, 3, 7, 11, 15);
            ChaCha20::quarter_round(state, 0, 5, 10, 15);
            ChaCha20::quarter_round(state, 1, 6, 11, 12);
            ChaCha20::quarter_round(state, 2, 7, 8, 13);
            ChaCha20::quarter_round(state, 3, 4, 9, 14);
        }
    }

    /// The block function (section 2.3): the rounds, the addition of the input state, serialized little-endian.
    pub fn block(state: &[u32; 16]) -> [u8; 64] {
        let mut working = *state;
        ChaCha20::rounds(&mut working);
        let mut out = [0u8; 64];
        for ((bytes, word), input) in out.as_chunks_mut::<4>().0.iter_mut().zip(&working).zip(state) {
            bytes.copy_from_slice(&word.wrapping_add(*input).to_le_bytes());
        }
        working.zeroize();
        out
    }

    /// The bytes of key stream left before the counter wraps.
    pub fn remaining_bytes(&self) -> u128 {
        64 * self.blocks + (64 - self.position) as u128
    }
}

impl StreamCipher for ChaCha20 {
    fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        if data.len() as u128 > self.remaining_bytes() {
            return Err(CryptoError::LimitExceeded);
        }
        let mut data = data;
        while !data.is_empty() {
            if self.position == 64 {
                self.keystream = ChaCha20::block(&self.state);
                self.state[12] = self.state[12].wrapping_add(1);
                if self.wide && self.state[12] == 0 {
                    self.state[13] = self.state[13].wrapping_add(1);
                }
                self.blocks -= 1;
                self.position = 0;
            }
            let take = (64 - self.position).min(data.len());
            for (byte, key) in data[..take].iter_mut().zip(&self.keystream[self.position..]) {
                *byte ^= key;
            }
            self.position += take;
            data = &mut data[take..];
        }
        Ok(())
    }
}

impl Zeroize for ChaCha20 {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.keystream.zeroize();
        self.position = 64;
        self.blocks = 0;
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for ChaCha20 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChaCha20(..)")
    }
}
