use alloc::vec::Vec;

use super::{LZSSConfig, LZSSFormat};
use crate::codec::lz77::{LZ77MatchFinder, LZ77MatchFinderConfig};
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};

/// Compresses into the format of [`LZSSFormat`], greedily, with matches
/// reaching N - F bytes back as the reference's encoder does (the spaces
/// the ring buffer starts with included).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZSSCompressor {
    config: LZSSConfig,
    finder: LZ77MatchFinder,
    position: usize,
    /// The bits of a byte not yet complete, most significant first, and their number.
    bits: u32,
    count: u32,
    pending: PendingOutput,
    finished: bool,
}

impl LZSSCompressor {
    /// The input taken before encoding.
    pub const BLOCK: usize = 1 << 14;

    /// A compressor of the parameters `config`; fails with `InvalidParameter` outside their ranges.
    pub fn new(config: LZSSConfig) -> Result<LZSSCompressor, CompressionError> {
        config.check()?;
        let window_bits = config.position_bits.max(8);
        let finder = LZ77MatchFinder::new(LZ77MatchFinderConfig {
            window_bits,
            chain_bits: window_bits,
            hash_bits: window_bits.min(16),
            maximum_distance: config.ring_size() - config.maximum_length(),
            minimum_length: LZSSFormat::MINIMUM_LENGTH,
            maximum_length: config.maximum_length(),
            chain_limit: 256,
            nice_length: config.maximum_length(),
        })?;
        let mut compressor = LZSSCompressor {
            config,
            finder,
            position: 0,
            bits: 0,
            count: 0,
            pending: PendingOutput::new(),
            finished: false,
        };
        compressor.reset();
        Ok(compressor)
    }

    pub fn config(&self) -> LZSSConfig {
        self.config
    }

    /// Appends the low `count` bits of `value`, most significant first.
    pub fn write_bits(&mut self, value: u32, count: u32, out: &mut Vec<u8>) {
        for bit in (0..count).rev() {
            self.bits = self.bits << 1 | (value >> bit) & 1;
            self.count += 1;
            if self.count == 8 {
                out.push(self.bits as u8);
                self.bits = 0;
                self.count = 0;
            }
        }
    }

    /// The ring position of the byte at `position` of the finder's data:
    /// the data start with the N bytes of the initial ring before the first
    /// byte, which goes to N - F.
    pub fn ring_position(&self, position: usize) -> u32 {
        let n = self.config.ring_size();
        ((position + n - self.config.maximum_length()) % n) as u32
    }

    /// Encodes the buffered data, all of it if `all`, otherwise up to where
    /// a match could still grow with more input.
    pub fn encode(&mut self, all: bool) {
        let mut out = Vec::new();
        let maximum = self.config.maximum_length();
        loop {
            let available = self.finder.data().len() - self.position;
            if available == 0 || (!all && available < maximum) {
                break;
            }
            match self.finder.find(self.position, maximum) {
                Some(found) => {
                    let position = self.ring_position(self.position - found.distance);
                    self.write_bits(0, 1, &mut out);
                    self.write_bits(position, self.config.position_bits, &mut out);
                    self.write_bits((found.length - 2) as u32, self.config.length_bits, &mut out);
                    self.position += found.length;
                }
                None => {
                    let byte = self.finder.data()[self.position];
                    self.write_bits(1 << 8 | byte as u32, 9, &mut out);
                    self.position += 1;
                }
            }
        }
        self.pending.extend(&out);
        // Positions stay congruent modulo N, as the finder drops whole windows of at least N bytes.
        self.position -= self.finder.discard(self.position);
    }
}

impl Default for LZSSCompressor {
    fn default() -> LZSSCompressor {
        LZSSCompressor::new(LZSSConfig::default()).expect("the default parameters are valid")
    }
}

impl Compressor for LZSSCompressor {
    /// The format cannot pad a byte in the middle of a stream (its padding
    /// is only allowed at the end), so [`Flush::Sync`] fails with `InvalidParameter`.
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        if flush == Flush::Sync {
            return Err(CompressionError::InvalidParameter);
        }
        let (mut consumed, mut produced) = (0, 0);
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() || self.finished {
                break;
            }
            let buffered = self.finder.data().len() - self.position;
            let take = (input.len() - consumed).min(LZSSCompressor::BLOCK.saturating_sub(buffered));
            self.finder.append(&input[consumed..consumed + take]);
            consumed += take;
            let input_left = consumed < input.len();
            self.encode(!input_left && flush == Flush::Finish);
            if !input_left && flush == Flush::Finish {
                if self.count > 0 {
                    let padding = 8 - self.count;
                    let mut out = Vec::new();
                    self.write_bits(0, padding, &mut out);
                    self.pending.extend(&out);
                }
                self.finished = true;
            } else if !input_left && self.pending.is_empty() {
                break;
            }
        }
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.finder.clear();
        self.finder.append(&self.config.dictionary());
        self.position = self.config.ring_size();
        self.bits = 0;
        self.count = 0;
        self.pending.clear();
        self.finished = false;
    }
}
