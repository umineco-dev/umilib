//! RC4 (Arcfour): the stream cipher of Rivest. Its key stream is biased,
//! and RFC 7465 prohibits it in TLS; it is here for legacy formats only.

use core::fmt;

use crate::crypto::{CryptoError, KeyInit, StreamCipher};
use crate::secret::{ConstantTimeTable, Zeroize};

/// RC4 with a key of 1 to 256 bytes.
///
/// The state permutation is a [`ConstantTimeTable`]: every read and write
/// touches the whole table, so no memory access depends on the secret index
/// j. Each byte of key stream costs several passes over the table.
#[derive(Clone)]
pub struct RC4 {
    state: ConstantTimeTable<32, 8>,
    i: u8,
    j: u8,
}

impl RC4 {
    pub const MAXIMUM_KEY_SIZE: usize = 256;

    /// The key-scheduling algorithm.
    pub fn new(key: &[u8]) -> Result<RC4, CryptoError> {
        if key.is_empty() || key.len() > RC4::MAXIMUM_KEY_SIZE {
            return Err(CryptoError::KeyLength { length: key.len(), minimum: 1, maximum: RC4::MAXIMUM_KEY_SIZE });
        }
        let mut entries = [0u8; 256];
        for (index, entry) in entries.iter_mut().enumerate() {
            *entry = index as u8;
        }
        let mut state = ConstantTimeTable::<32, 8>::from_bytes(&entries);
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(state.get(i) as u8).wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }
        j.zeroize();
        Ok(RC4 { state, i: 0, j: 0 })
    }

    /// The next byte of the key stream (the pseudo-random generation algorithm).
    pub fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        let a = self.state.get(self.i as usize) as u8;
        self.j = self.j.wrapping_add(a);
        let b = self.state.get(self.j as usize) as u8;
        self.state.set(self.i as usize, b as u32);
        self.state.set(self.j as usize, a as u32);
        self.state.get(a.wrapping_add(b) as usize) as u8
    }
}

impl StreamCipher for RC4 {
    fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        for byte in data {
            *byte ^= self.next_byte();
        }
        Ok(())
    }
}

impl KeyInit for RC4 {
    const MINIMUM_KEY_SIZE: usize = 1;
    const MAXIMUM_KEY_SIZE: usize = 256;

    fn new_from_slice(key: &[u8]) -> Result<RC4, CryptoError> {
        RC4::new(key)
    }
}

impl Zeroize for RC4 {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.i.zeroize();
        self.j.zeroize();
    }
}

impl Drop for RC4 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for RC4 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RC4(..)")
    }
}
