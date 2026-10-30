use core::fmt;

use super::BLAKE3;
use crate::hash::XOFReader;
use crate::secret::Zeroize;

/// A node whose compression is still to be done: the chaining value of a
/// chunk or parent node, or, with `ROOT`, the output of the hash
/// (specification section 2.6).
#[derive(Clone)]
pub struct BLAKE3Output {
    chaining_value: [u32; 8],
    block: [u32; 16],
    counter: u64,
    block_length: u32,
    flags: u32,
}

impl BLAKE3Output {
    pub fn new(
        chaining_value: [u32; 8],
        block: [u32; 16],
        counter: u64,
        block_length: u32,
        flags: u32,
    ) -> BLAKE3Output {
        BLAKE3Output { chaining_value, block, counter, block_length, flags }
    }

    /// The parent node of the chaining values `left` and `right`.
    pub fn parent(left: &[u32; 8], right: &[u32; 8], key: &[u32; 8], flags: u32) -> BLAKE3Output {
        let mut block = [0u32; 16];
        block[..8].copy_from_slice(left);
        block[8..].copy_from_slice(right);
        BLAKE3Output::new(*key, block, 0, BLAKE3::BLOCK_SIZE as u32, flags | BLAKE3::PARENT)
    }

    /// The chaining value of the node, as a non-root node.
    pub fn chaining_value(&self) -> [u32; 8] {
        let mut state =
            BLAKE3::compress(&self.chaining_value, &self.block, self.counter, self.block_length, self.flags);
        let mut value = [0u32; 8];
        value.copy_from_slice(&state[..8]);
        state.zeroize();
        value
    }

    /// Output block `index` of the node as the root (64 bytes).
    pub fn root_block(&self, index: u64) -> [u8; BLAKE3::BLOCK_SIZE] {
        let mut state =
            BLAKE3::compress(&self.chaining_value, &self.block, index, self.block_length, self.flags | BLAKE3::ROOT);
        let mut bytes = [0u8; BLAKE3::BLOCK_SIZE];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(&state) {
            *chunk = word.to_le_bytes();
        }
        state.zeroize();
        bytes
    }

    /// Reads the root output from its start.
    pub fn reader(self) -> BLAKE3Reader {
        BLAKE3Reader { output: self, position: 0 }
    }
}

impl Zeroize for BLAKE3Output {
    fn zeroize(&mut self) {
        self.chaining_value.zeroize();
        self.block.zeroize();
        self.counter.zeroize();
        self.block_length.zeroize();
    }
}

impl Drop for BLAKE3Output {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for BLAKE3Output {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BLAKE3Output(..)")
    }
}

/// The output of BLAKE3, read in order from any position up to 2^64 bytes.
#[derive(Clone, Debug)]
pub struct BLAKE3Reader {
    output: BLAKE3Output,
    position: u64,
}

impl BLAKE3Reader {
    /// The number of bytes before the next one read.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Moves to byte `position` of the output.
    pub fn set_position(&mut self, position: u64) {
        self.position = position;
    }
}

impl XOFReader for BLAKE3Reader {
    /// Reads the next bytes; panics past 2^64 - 1 bytes, where the position
    /// ends (the last byte of the 2^64 the block counter allows is out of reach).
    fn read(&mut self, mut out: &mut [u8]) {
        let end = self.position.checked_add(out.len() as u64);
        assert!(end.is_some(), "the output of BLAKE3 ends at 2^64 bytes");
        while !out.is_empty() {
            let offset = (self.position % BLAKE3::BLOCK_SIZE as u64) as usize;
            let mut block = self.output.root_block(self.position / BLAKE3::BLOCK_SIZE as u64);
            let take = (BLAKE3::BLOCK_SIZE - offset).min(out.len());
            out[..take].copy_from_slice(&block[offset..offset + take]);
            block.zeroize();
            out = &mut out[take..];
            self.position += take as u64;
        }
    }
}
