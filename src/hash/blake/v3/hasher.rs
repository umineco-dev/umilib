use core::fmt;

use super::{BLAKE3Chunk, BLAKE3Output, BLAKE3Reader};
use crate::hash::{CryptographicDigest, Digest, ExtendableOutput, XOFReader};
use crate::secret::Zeroize;

/// BLAKE3 in one of its three modes: hashing ([`BLAKE3::new`]), keyed hashing
/// ([`BLAKE3::with_key`]) and key derivation ([`BLAKE3::with_context`]).
///
/// The input is split into chunks whose chaining values are merged into
/// parent nodes as soon as both children are known, so the state holds one
/// chaining value per level of the tree (specification section 5.1.2).
/// [`Digest`] gives the default 32 bytes of output and [`ExtendableOutput`]
/// any length; the first 32 bytes are the same.
#[derive(Clone)]
pub struct BLAKE3 {
    chunk: BLAKE3Chunk,
    key: [u32; 8],
    /// The chaining values of the complete subtrees, from the largest.
    stack: [[u32; 8]; BLAKE3::MAXIMUM_DEPTH],
    depth: usize,
    flags: u32,
}

impl BLAKE3 {
    pub const BLOCK_SIZE: usize = 64;
    pub const CHUNK_SIZE: usize = 1024;
    pub const KEY_SIZE: usize = 32;
    /// The default output length, in bytes.
    pub const OUTPUT_SIZE: usize = 32;
    /// The largest number of subtree chaining values: 2^54 chunks are 2^64 bytes.
    pub const MAXIMUM_DEPTH: usize = 54;
    pub const ROUNDS: usize = 7;
    /// The initialization vector, the one of SHA-256 (section 2.2).
    pub const IV: [u32; 8] =
        [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
    /// The permutation of the message words between rounds (section 2.2).
    pub const MESSAGE_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
    /// The domain separation flags (section 2.1).
    pub const CHUNK_START: u32 = 1 << 0;
    pub const CHUNK_END: u32 = 1 << 1;
    pub const PARENT: u32 = 1 << 2;
    pub const ROOT: u32 = 1 << 3;
    pub const KEYED_HASH: u32 = 1 << 4;
    pub const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
    pub const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

    /// The hash mode.
    pub fn new() -> BLAKE3 {
        BLAKE3::with_key_words(&BLAKE3::IV, 0)
    }

    /// The keyed hash mode, a MAC.
    pub fn with_key(key: &[u8; BLAKE3::KEY_SIZE]) -> BLAKE3 {
        let mut words = BLAKE3::key_words(key);
        let state = BLAKE3::with_key_words(&words, BLAKE3::KEYED_HASH);
        words.zeroize();
        state
    }

    /// The key derivation mode for the application-specific `context`; the
    /// input is the key material.
    pub fn with_context(context: &[u8]) -> BLAKE3 {
        let mut hash = BLAKE3::with_key_words(&BLAKE3::IV, BLAKE3::DERIVE_KEY_CONTEXT);
        hash.update(context);
        let mut key = hash.finalize();
        let mut words = BLAKE3::key_words(&key);
        let state = BLAKE3::with_key_words(&words, BLAKE3::DERIVE_KEY_MATERIAL);
        key.zeroize();
        words.zeroize();
        state
    }

    /// The state with the key words `key` and the mode flags `flags`.
    pub fn with_key_words(key: &[u32; 8], flags: u32) -> BLAKE3 {
        BLAKE3 {
            chunk: BLAKE3Chunk::new(key, 0, flags),
            key: *key,
            stack: [[0; 8]; BLAKE3::MAXIMUM_DEPTH],
            depth: 0,
            flags,
        }
    }

    /// The keyed hash of `data` under `key`, 32 bytes.
    pub fn keyed_hash(key: &[u8; BLAKE3::KEY_SIZE], data: &[u8]) -> [u8; 32] {
        let mut hash = BLAKE3::with_key(key);
        hash.update(data);
        hash.finalize()
    }

    /// The 32-byte key derived from `material` for `context`.
    pub fn derive_key(context: &[u8], material: &[u8]) -> [u8; 32] {
        let mut hash = BLAKE3::with_context(context);
        hash.update(material);
        hash.finalize()
    }

    /// The key as eight little-endian words.
    pub fn key_words(key: &[u8; BLAKE3::KEY_SIZE]) -> [u32; 8] {
        let mut words = [0u32; 8];
        for (word, bytes) in words.iter_mut().zip(key.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        words
    }

    /// A block as sixteen little-endian words.
    pub fn words(block: &[u8; BLAKE3::BLOCK_SIZE]) -> [u32; 16] {
        let mut words = [0u32; 16];
        for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        words
    }

    /// The compression function (section 2.2): the full 16-word state, whose
    /// first half is the new chaining value.
    pub fn compress(
        chaining_value: &[u32; 8],
        block: &[u32; 16],
        counter: u64,
        block_length: u32,
        flags: u32,
    ) -> [u32; 16] {
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(chaining_value);
        v[8..12].copy_from_slice(&BLAKE3::IV[..4]);
        v[12] = counter as u32;
        v[13] = (counter >> 32) as u32;
        v[14] = block_length;
        v[15] = flags;
        let mix = |v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32| {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(12);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(8);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(7);
        };
        let mut m = *block;
        for round in 0..BLAKE3::ROUNDS {
            mix(&mut v, 0, 4, 8, 12, m[0], m[1]);
            mix(&mut v, 1, 5, 9, 13, m[2], m[3]);
            mix(&mut v, 2, 6, 10, 14, m[4], m[5]);
            mix(&mut v, 3, 7, 11, 15, m[6], m[7]);
            mix(&mut v, 0, 5, 10, 15, m[8], m[9]);
            mix(&mut v, 1, 6, 11, 12, m[10], m[11]);
            mix(&mut v, 2, 7, 8, 13, m[12], m[13]);
            mix(&mut v, 3, 4, 9, 14, m[14], m[15]);
            if round + 1 < BLAKE3::ROUNDS {
                let previous = m;
                for (word, &index) in m.iter_mut().zip(&BLAKE3::MESSAGE_PERMUTATION) {
                    *word = previous[index];
                }
            }
        }
        for index in 0..8 {
            v[index] ^= v[index + 8];
            v[index + 8] ^= chaining_value[index];
        }
        m.zeroize();
        v
    }

    /// Adds `data` to the input.
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.chunk.len() == BLAKE3::CHUNK_SIZE {
                let value = self.chunk.output().chaining_value();
                let chunks = self.chunk.counter() + 1;
                self.push_chunk(value, chunks);
                self.chunk = BLAKE3Chunk::new(&self.key, chunks, self.flags);
            }
            let take = (BLAKE3::CHUNK_SIZE - self.chunk.len()).min(data.len());
            self.chunk.update(&data[..take]);
            data = &data[take..];
        }
    }

    /// Adds the chaining value of a completed chunk, after which `chunks`
    /// chunks are complete, merging every subtree it completes.
    ///
    /// # Panics
    ///
    /// If `chunks` is not one more than the chunks added so far.
    pub fn push_chunk(&mut self, mut value: [u32; 8], mut chunks: u64) {
        while chunks & 1 == 0 {
            self.depth -= 1;
            value = BLAKE3Output::parent(&self.stack[self.depth], &value, &self.key, self.flags).chaining_value();
            self.stack[self.depth].zeroize();
            chunks >>= 1;
        }
        self.stack[self.depth] = value;
        self.depth += 1;
        value.zeroize();
    }

    /// The root node of the input so far.
    pub fn root(&self) -> BLAKE3Output {
        let mut output = self.chunk.output();
        for value in self.stack[..self.depth].iter().rev() {
            let mut chaining = output.chaining_value();
            output = BLAKE3Output::parent(value, &chaining, &self.key, self.flags);
            chaining.zeroize();
        }
        output
    }

    /// The default 32 bytes of output; [`BLAKE3::root`] gives the output
    /// without consuming the state.
    pub fn finalize(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.root().reader().read(&mut out);
        out
    }

    /// The output of any length.
    pub fn finalize_xof(self) -> BLAKE3Reader {
        self.root().reader()
    }

    /// Returns to the empty input, keeping the mode and the key.
    pub fn reset(&mut self) {
        self.chunk = BLAKE3Chunk::new(&self.key, 0, self.flags);
        self.stack.zeroize();
        self.depth = 0;
    }
}

impl Digest for BLAKE3 {
    const OUTPUT_SIZE: usize = BLAKE3::OUTPUT_SIZE;
    const BLOCK_SIZE: usize = BLAKE3::BLOCK_SIZE;
    type Output = [u8; 32];

    fn update(&mut self, data: &[u8]) {
        BLAKE3::update(self, data);
    }

    fn finalize(self) -> [u8; 32] {
        BLAKE3::finalize(self)
    }

    fn reset(&mut self) {
        BLAKE3::reset(self);
    }
}

impl ExtendableOutput for BLAKE3 {
    const BLOCK_SIZE: usize = BLAKE3::BLOCK_SIZE;
    type Reader = BLAKE3Reader;

    fn update(&mut self, data: &[u8]) {
        BLAKE3::update(self, data);
    }

    fn finalize_xof(self) -> BLAKE3Reader {
        BLAKE3::finalize_xof(self)
    }

    fn reset(&mut self) {
        BLAKE3::reset(self);
    }
}

impl Default for BLAKE3 {
    fn default() -> BLAKE3 {
        BLAKE3::new()
    }
}

impl CryptographicDigest for BLAKE3 {}

impl Zeroize for BLAKE3 {
    fn zeroize(&mut self) {
        self.chunk.zeroize();
        self.key.zeroize();
        self.stack.zeroize();
        self.depth.zeroize();
    }
}

impl Drop for BLAKE3 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for BLAKE3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BLAKE3(..)")
    }
}
