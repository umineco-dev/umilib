use alloc::vec::Vec;

use super::{DeflateBlock, DeflateConfig, DeflateFormat, DeflateLevel, DeflateSymbol};
use crate::bytes::BitWriter;
use crate::codec::lz77::{LZ77Match, LZ77MatchFinder, LZ77MatchFinderConfig};
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};

/// Compresses into raw Deflate streams (RFC 1951) with the search of a
/// [`DeflateConfig::level`]: greedy matching for the levels 1 to 3, lazy
/// matching for 4 to 9, and for each block the kind (stored, fixed or
/// dynamic codes) that takes the fewest bits. Level 0 writes stored blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeflateCompressor {
    config: DeflateConfig,
    level: DeflateLevel,
    finder: LZ77MatchFinder,
    /// The position in the finder's data of the next byte to encode, and of the first byte of the block.
    position: usize,
    block_start: usize,
    symbols: Vec<DeflateSymbol>,
    block: DeflateBlock,
    writer: BitWriter,
    pending: PendingOutput,
    /// Whether bytes were taken since the last block that a flush ended.
    unflushed: bool,
    finished: bool,
}

impl DeflateCompressor {
    /// The input buffered ahead of the position being encoded.
    pub const LOOKAHEAD: usize = 1 << 16;
    /// The most symbols of a block.
    pub const BLOCK_SYMBOLS: usize = 16383;
    /// A match of 3 bytes farther back than this is not worth its distance (zlib's TOO_FAR).
    pub const TOO_FAR: usize = 4096;

    /// A compressor of the parameters `config`; fails with `InvalidParameter` outside their ranges.
    pub fn new(config: DeflateConfig) -> Result<DeflateCompressor, CompressionError> {
        config.check()?;
        let level = DeflateLevel::LEVELS[config.level as usize];
        let finder = LZ77MatchFinder::new(LZ77MatchFinderConfig {
            window_bits: config.window_bits,
            chain_bits: config.window_bits,
            hash_bits: 15,
            maximum_distance: 1 << config.window_bits,
            minimum_length: DeflateFormat::MINIMUM_MATCH,
            maximum_length: DeflateFormat::MAXIMUM_MATCH,
            chain_limit: level.chain_limit.max(1),
            nice_length: level.nice_length.max(DeflateFormat::MINIMUM_MATCH),
        })?;
        Ok(DeflateCompressor {
            config,
            level,
            finder,
            position: 0,
            block_start: 0,
            symbols: Vec::new(),
            block: DeflateBlock::new(),
            writer: BitWriter::new(),
            pending: PendingOutput::new(),
            unflushed: false,
            finished: false,
        })
    }

    pub fn config(&self) -> DeflateConfig {
        self.config
    }

    /// Makes `dictionary` (its last window) the history before the data
    /// (the preset dictionary of zlib), before the first call of `compress`.
    pub fn set_dictionary(&mut self, dictionary: &[u8]) {
        let window = 1usize << self.config.window_bits;
        let dictionary = &dictionary[dictionary.len().saturating_sub(window)..];
        self.finder.append(dictionary);
        self.position = self.finder.data().len();
        self.block_start = self.position;
        self.finder.insert(self.position);
    }

    /// The match the level accepts at `position`, if any, examining at most `chain_limit` candidates.
    pub fn find(&mut self, position: usize, available: usize, chain_limit: usize) -> Option<LZ77Match> {
        let found = self.finder.find_within(position, available, chain_limit)?;
        // A short match far back costs more than its literals (as zlib judges it).
        if found.length == DeflateFormat::MINIMUM_MATCH && found.distance > DeflateCompressor::TOO_FAR {
            return None;
        }
        Some(found)
    }

    /// Turns the buffered data into symbols, all of it if `all`, otherwise
    /// up to where a match could still grow with more input; ends a block
    /// whenever it is full.
    pub fn encode(&mut self, all: bool) {
        let margin = if all { 0 } else { DeflateFormat::MAXIMUM_MATCH + 1 };
        while self.position + margin < self.finder.data().len() {
            let available = self.finder.data().len() - self.position;
            if self.level.chain_limit == 0 {
                self.symbols.push(DeflateSymbol::Literal(self.finder.data()[self.position]));
                self.position += 1;
            } else {
                let chain_limit = self.level.chain_limit;
                let mut found = self.find(self.position, available, chain_limit);
                if self.level.lazy && found.is_some_and(|found| found.length < self.level.lazy_length) && available > 1
                {
                    // A longer match one byte later wins over this one; after a good match, a shorter search suffices.
                    let good = found.is_some_and(|found| found.length >= self.level.good_length);
                    let limit = if good { (chain_limit / 4).max(1) } else { chain_limit };
                    let next = self.find(self.position + 1, available - 1, limit);
                    if next.is_some_and(|next| next.length > found.map_or(0, |found| found.length)) {
                        found = None;
                    }
                }
                match found {
                    Some(found) => {
                        self.symbols.push(DeflateSymbol::Match {
                            length: found.length as u16,
                            distance: found.distance as u16,
                        });
                        self.position += found.length;
                    }
                    None => {
                        self.symbols.push(DeflateSymbol::Literal(self.finder.data()[self.position]));
                        self.position += 1;
                    }
                }
            }
            if self.symbols.len() >= DeflateCompressor::BLOCK_SYMBOLS {
                self.end_block(false);
            }
        }
    }

    /// Writes the symbols since the last block as a block, the last of the
    /// stream if `last`, and moves the complete bytes to the pending output.
    pub fn end_block(&mut self, last: bool) {
        let bytes = &self.finder.data()[self.block_start..self.position];
        self.block.write(&mut self.writer, &self.symbols, bytes, last, self.config.level == 0);
        self.symbols.clear();
        let dropped = self.finder.discard(self.position);
        self.position -= dropped;
        self.block_start = self.position;
        self.pending.extend(self.writer.completed());
        self.writer.clear_completed();
    }
}

impl Default for DeflateCompressor {
    fn default() -> DeflateCompressor {
        DeflateCompressor::new(DeflateConfig::default()).expect("the default parameters are valid")
    }
}

impl Compressor for DeflateCompressor {
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        let (mut consumed, mut produced) = (0, 0);
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() || self.finished {
                break;
            }
            let buffered = self.finder.data().len() - self.position;
            let take = (input.len() - consumed).min(DeflateCompressor::LOOKAHEAD.saturating_sub(buffered));
            self.finder.append(&input[consumed..consumed + take]);
            consumed += take;
            self.unflushed |= take > 0;
            if consumed < input.len() || flush == Flush::None {
                self.encode(false);
                if consumed == input.len() && self.pending.is_empty() {
                    break;
                }
                continue;
            }
            self.encode(true);
            if flush == Flush::Finish {
                self.end_block(true);
                self.writer.align();
                self.pending.extend(self.writer.completed());
                self.writer.clear_completed();
                self.finished = true;
            } else if self.unflushed {
                // A sync flush: the block, then an empty stored block that ends at a byte boundary.
                if !self.symbols.is_empty() || self.position > self.block_start {
                    self.end_block(false);
                }
                DeflateBlock::write_stored_chunk(&mut self.writer, &[], false);
                self.pending.extend(self.writer.completed());
                self.writer.clear_completed();
                self.unflushed = false;
            } else {
                break;
            }
        }
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.finder.clear();
        self.position = 0;
        self.block_start = 0;
        self.symbols.clear();
        self.writer = BitWriter::new();
        self.pending.clear();
        self.unflushed = false;
        self.finished = false;
    }
}
