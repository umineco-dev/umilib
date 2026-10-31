use alloc::vec::Vec;

use super::{CanonicalHuffmanConfig, CanonicalHuffmanFormat, HuffmanCode};
use crate::bytes::BitWriter;
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};

/// Compresses into the format of [`CanonicalHuffmanFormat`]: each block of
/// at most [`CanonicalHuffmanConfig::block_size`] bytes with the canonical
/// code of the frequencies of its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalHuffmanCompressor {
    config: CanonicalHuffmanConfig,
    block: Vec<u8>,
    pending: PendingOutput,
    finished: bool,
}

impl CanonicalHuffmanCompressor {
    /// A compressor of the parameters `config`; fails with `InvalidParameter`
    /// for a block size of 0.
    pub fn new(config: CanonicalHuffmanConfig) -> Result<CanonicalHuffmanCompressor, CompressionError> {
        if config.block_size == 0 {
            return Err(CompressionError::InvalidParameter);
        }
        Ok(CanonicalHuffmanCompressor { config, block: Vec::new(), pending: PendingOutput::new(), finished: false })
    }

    pub fn config(&self) -> CanonicalHuffmanConfig {
        self.config
    }

    /// The encoding of a block of `data`, last of its stream if `last`.
    pub fn encode_block(data: &[u8], last: bool) -> Vec<u8> {
        let mut frequencies = [0u32; CanonicalHuffmanFormat::SYMBOLS];
        for byte in data {
            frequencies[*byte as usize] = frequencies[*byte as usize].saturating_add(1);
        }
        frequencies[CanonicalHuffmanFormat::END as usize] = 1;
        // 257 used symbols at most fit 15 bits, so the frequencies always have a code.
        let code = HuffmanCode::from_frequencies(&frequencies, CanonicalHuffmanFormat::MAXIMUM_LENGTH)
            .expect("257 symbols fit codes of 15 bits");
        let mut writer = BitWriter::new();
        writer.write(last as u64, 1);
        for length in code.lengths() {
            writer.write(*length as u64, CanonicalHuffmanFormat::LENGTH_BITS);
        }
        for symbol in data.iter().map(|byte| *byte as usize).chain([CanonicalHuffmanFormat::END as usize]) {
            writer.write(code.reversed_code(symbol) as u64, code.length(symbol));
        }
        writer.finish()
    }
}

impl Default for CanonicalHuffmanCompressor {
    fn default() -> CanonicalHuffmanCompressor {
        CanonicalHuffmanCompressor::new(CanonicalHuffmanConfig::default()).expect("the default parameters are valid")
    }
}

impl Compressor for CanonicalHuffmanCompressor {
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        let (mut consumed, mut produced) = (0, 0);
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() || self.finished {
                break;
            }
            let take = (input.len() - consumed).min(self.config.block_size - self.block.len());
            self.block.extend_from_slice(&input[consumed..consumed + take]);
            consumed += take;
            // Input is left only when the block is full.
            let input_left = consumed < input.len();
            let full = self.block.len() == self.config.block_size;
            let last = !input_left && flush == Flush::Finish;
            let sync = !input_left && flush == Flush::Sync && !self.block.is_empty();
            if !(full || last || sync) {
                break;
            }
            self.pending.extend(&CanonicalHuffmanCompressor::encode_block(&self.block, last));
            self.block.clear();
            self.finished = last;
        }
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.block.clear();
        self.pending.clear();
        self.finished = false;
    }
}
