use alloc::vec::Vec;

use super::{ZstandardBlockEncoder, ZstandardConfig, ZstandardFormat, ZstandardLevel, ZstandardOffsets};
use crate::codec::lz77::{LZ77MatchFinder, LZ77MatchFinderConfig};
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};
use crate::hash::xxhash::xxh64::XXH64;

/// Compresses into a Zstandard frame (RFC 8878): a header with a window
/// descriptor (and the content size and dictionary identifier if known),
/// blocks of at most 128 KiB, each compressed (Huffman literals and FSE
/// sequences), raw or RLE, whichever is smallest, and the content checksum.
#[derive(Clone, Debug)]
pub struct ZstandardCompressor {
    config: ZstandardConfig,
    encoder: ZstandardBlockEncoder,
    /// The position in the finder's data of the first byte not yet in a block.
    position: usize,
    /// The bytes before `position` the decoder holds (history and dictionary).
    history: usize,
    window_log: u32,
    pending: PendingOutput,
    checksum: XXH64,
    size: u64,
    started: bool,
    finished: bool,
}

impl ZstandardCompressor {
    /// A compressor of the parameters `config`; fails with `InvalidParameter` outside their ranges.
    pub fn new(config: ZstandardConfig) -> Result<ZstandardCompressor, CompressionError> {
        let level = *config
            .level
            .checked_sub(1)
            .and_then(|index| ZstandardLevel::LEVELS.get(index as usize))
            .ok_or(CompressionError::InvalidParameter)?;
        let window_log = config.window_log.unwrap_or(level.window_log);
        if !(10..=30).contains(&window_log) {
            return Err(CompressionError::InvalidParameter);
        }
        let finder = LZ77MatchFinder::new(LZ77MatchFinderConfig {
            window_bits: window_log.max(8),
            chain_bits: window_log.clamp(8, 22),
            hash_bits: 17,
            maximum_distance: 1 << window_log,
            minimum_length: ZstandardBlockEncoder::MINIMUM_MATCH,
            maximum_length: ZstandardBlockEncoder::MAXIMUM_MATCH,
            chain_limit: level.chain_limit,
            nice_length: level.nice_length,
        })?;
        let level = ZstandardLevel { window_log, ..level };
        let mut compressor = ZstandardCompressor {
            config,
            encoder: ZstandardBlockEncoder { finder, level, offsets: ZstandardOffsets::new() },
            position: 0,
            history: 0,
            window_log,
            pending: PendingOutput::new(),
            checksum: XXH64::new(),
            size: 0,
            started: false,
            finished: false,
        };
        compressor.reset();
        Ok(compressor)
    }

    pub fn config(&self) -> &ZstandardConfig {
        &self.config
    }

    /// The largest block: the window, at most 128 KiB.
    pub fn block_size(&self) -> usize {
        (1usize << self.window_log).min(ZstandardFormat::MAXIMUM_BLOCK)
    }

    /// The magic number and the frame header.
    pub fn header_bytes(&self) -> Vec<u8> {
        let identifier = self.config.dictionary.as_ref().map_or(0, |dictionary| dictionary.identifier);
        let (identifier_flag, identifier_bytes) = match identifier {
            0 => (0u8, 0usize),
            1..=0xFF => (1, 1),
            0x100..=0xFFFF => (2, 2),
            _ => (3, 4),
        };
        let (size_flag, size_bytes) = match self.config.content_size {
            None => (0u8, 0usize),
            Some(size) if (256..=65791).contains(&size) => (1, 2),
            Some(size) if size <= u32::MAX as u64 => (2, 4),
            Some(_) => (3, 8),
        };
        let descriptor = size_flag << 6 | (self.config.content_checksum as u8) << 2 | identifier_flag;
        let mut bytes = ZstandardFormat::MAGIC.to_le_bytes().to_vec();
        bytes.push(descriptor);
        bytes.push(((self.window_log - 10) as u8) << 3);
        bytes.extend_from_slice(&identifier.to_le_bytes()[..identifier_bytes]);
        if let Some(size) = self.config.content_size {
            let value = if size_bytes == 2 { size - 256 } else { size };
            bytes.extend_from_slice(&value.to_le_bytes()[..size_bytes]);
        }
        bytes
    }

    /// Encodes the buffered data into blocks: whole blocks only, unless `all`.
    pub fn encode(&mut self, all: bool, last: bool) {
        let block = self.block_size();
        let mut out = Vec::new();
        loop {
            let available = self.encoder.finder.data().len() - self.position;
            if available == 0 || (!all && available < block) {
                break;
            }
            let length = available.min(block);
            let is_last = last && length == available;
            self.encoder.encode(self.position, self.position + length, self.history, is_last, &mut out);
            self.position += length;
            self.history = (self.history + length).min(1 << self.window_log);
            if is_last {
                self.finished = true;
            }
        }
        self.pending.extend(&out);
        let dropped = self.encoder.finder.discard(self.position);
        self.position -= dropped;
    }
}

impl Compressor for ZstandardCompressor {
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        if !self.started {
            let header = self.header_bytes();
            self.pending.extend(&header);
            self.started = true;
        }
        let (mut consumed, mut produced) = (0, 0);
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() || self.finished {
                break;
            }
            let buffered = self.encoder.finder.data().len() - self.position;
            let take = (input.len() - consumed).min((2 * self.block_size()).saturating_sub(buffered));
            self.encoder.finder.append(&input[consumed..consumed + take]);
            self.checksum.update(&input[consumed..consumed + take]);
            self.size += take as u64;
            consumed += take;
            if consumed < input.len() || flush == Flush::None {
                self.encode(false, false);
                if consumed == input.len() && self.pending.is_empty() {
                    break;
                }
                continue;
            }
            if flush == Flush::Sync {
                self.encode(true, false);
                if self.pending.is_empty() {
                    break;
                }
                continue;
            }
            if self.config.content_size.is_some_and(|size| size != self.size) {
                return Err(CompressionError::InvalidParameter);
            }
            self.encode(true, true);
            if !self.finished {
                // No data left for a last block: an empty one ends the frame.
                let mut out = Vec::new();
                ZstandardBlockEncoder::empty_last_block(&mut out);
                self.pending.extend(&out);
                self.finished = true;
            }
            if self.config.content_checksum {
                self.pending.extend(&(self.checksum.value() as u32).to_le_bytes());
            }
        }
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.encoder.finder.clear();
        self.encoder.offsets = ZstandardOffsets::new();
        self.position = 0;
        self.history = 0;
        if let Some(dictionary) = &self.config.dictionary {
            let content = &dictionary.content[dictionary.content.len().saturating_sub(1 << self.window_log)..];
            self.encoder.finder.append(content);
            self.encoder.offsets = dictionary.offsets;
            self.position = content.len();
            self.history = content.len();
        }
        self.pending.clear();
        self.checksum.reset();
        self.size = 0;
        self.started = false;
        self.finished = false;
    }
}
