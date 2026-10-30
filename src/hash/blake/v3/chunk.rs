use core::fmt;

use super::{BLAKE3, BLAKE3Output};
use crate::secret::Zeroize;

/// The state of one chunk: up to [`BLAKE3::CHUNK_SIZE`] bytes, compressed one
/// block at a time into a chaining value (specification section 2.4).
#[derive(Clone)]
pub struct BLAKE3Chunk {
    chaining_value: [u32; 8],
    counter: u64,
    block: [u8; BLAKE3::BLOCK_SIZE],
    block_length: usize,
    blocks_compressed: usize,
    flags: u32,
}

impl BLAKE3Chunk {
    /// The chunk with index `counter`, starting from the key words `key`.
    pub fn new(key: &[u32; 8], counter: u64, flags: u32) -> BLAKE3Chunk {
        BLAKE3Chunk {
            chaining_value: *key,
            counter,
            block: [0; BLAKE3::BLOCK_SIZE],
            block_length: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    /// The number of bytes added so far.
    pub fn len(&self) -> usize {
        BLAKE3::BLOCK_SIZE * self.blocks_compressed + self.block_length
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The index of the chunk in the input.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// `CHUNK_START` for the first block of the chunk, none for the others.
    pub fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 { BLAKE3::CHUNK_START } else { 0 }
    }

    /// Adds `data`. The last block is kept, because it is compressed with
    /// `CHUNK_END` by [`BLAKE3Chunk::output`].
    ///
    /// # Panics
    ///
    /// If `data` does not fit in the rest of the chunk.
    pub fn update(&mut self, mut data: &[u8]) {
        assert!(data.len() <= BLAKE3::CHUNK_SIZE - self.len(), "the input exceeds the chunk");
        while !data.is_empty() {
            if self.block_length == BLAKE3::BLOCK_SIZE {
                let mut words = BLAKE3::words(&self.block);
                let mut state = BLAKE3::compress(
                    &self.chaining_value,
                    &words,
                    self.counter,
                    BLAKE3::BLOCK_SIZE as u32,
                    self.flags | self.start_flag(),
                );
                self.chaining_value.copy_from_slice(&state[..8]);
                words.zeroize();
                state.zeroize();
                self.blocks_compressed += 1;
                self.block.zeroize();
                self.block_length = 0;
            }
            let take = (BLAKE3::BLOCK_SIZE - self.block_length).min(data.len());
            self.block[self.block_length..self.block_length + take].copy_from_slice(&data[..take]);
            self.block_length += take;
            data = &data[take..];
        }
    }

    /// The output node of the chunk: its last block with `CHUNK_END`.
    pub fn output(&self) -> BLAKE3Output {
        BLAKE3Output::new(
            self.chaining_value,
            BLAKE3::words(&self.block),
            self.counter,
            self.block_length as u32,
            self.flags | self.start_flag() | BLAKE3::CHUNK_END,
        )
    }
}

impl Zeroize for BLAKE3Chunk {
    fn zeroize(&mut self) {
        self.chaining_value.zeroize();
        self.counter.zeroize();
        self.block.zeroize();
        self.block_length.zeroize();
        self.blocks_compressed.zeroize();
    }
}

impl Drop for BLAKE3Chunk {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for BLAKE3Chunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BLAKE3Chunk(..)")
    }
}
