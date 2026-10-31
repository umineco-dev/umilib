use super::{LZMAConfig, LZMAEncoder, LZMAFormat, LZMALevel, LZMAModel, LZMARangeEncoder};
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};

/// Compresses into raw LZMA2 streams: chunks of at most 2 MiB of data and
/// 64 KiB compressed, each LZMA-compressed or, when that is not smaller,
/// stored uncompressed, ended by 0. The decompressor must be given the
/// dictionary size ([`LZMA2Compressor::dictionary_size`]), which containers
/// such as xz record (as [`LZMAFormat::lzma2_dictionary_byte`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZMA2Compressor {
    config: LZMAConfig,
    encoder: LZMAEncoder,
    /// The position in the finder's data of the first byte of the chunk being encoded.
    chunk_start: usize,
    /// What the next LZMA chunk must reset: the dictionary (the first chunk),
    /// the properties (after an uncompressed first chunk), the state.
    reset_dictionary: bool,
    reset_properties: bool,
    reset_state: bool,
    pending: PendingOutput,
    unflushed: bool,
    finished: bool,
}

impl LZMA2Compressor {
    /// The input buffered ahead of the position being encoded.
    pub const LOOKAHEAD: usize = 1 << 20;
    /// The most compressed bytes a symbol adds, kept free in a chunk.
    pub const SYMBOL_MARGIN: u64 = 64;

    /// A compressor of the parameters `config` (lc + lp at most 4); fails
    /// with `InvalidParameter` outside their ranges.
    pub fn new(config: LZMAConfig) -> Result<LZMA2Compressor, CompressionError> {
        config.properties.check(true)?;
        let level = *LZMALevel::LEVELS.get(config.level as usize).ok_or(CompressionError::InvalidParameter)?;
        let dictionary_size = config.dictionary_size.unwrap_or(level.dictionary_size);
        let encoder = LZMAEncoder::new(config.properties, dictionary_size, &level)?;
        Ok(LZMA2Compressor {
            config,
            encoder,
            chunk_start: 0,
            reset_dictionary: true,
            reset_properties: true,
            reset_state: true,
            pending: PendingOutput::new(),
            unflushed: false,
            finished: false,
        })
    }

    pub fn config(&self) -> &LZMAConfig {
        &self.config
    }

    /// The dictionary size the decompressor needs.
    pub fn dictionary_size(&self) -> usize {
        self.encoder.dictionary_size
    }

    /// Encodes the buffered data into chunks, all of it if `all`, otherwise
    /// up to where matches could still grow with more input.
    pub fn encode(&mut self, all: bool) {
        let margin = if all { 0 } else { LZMAModel::MAXIMUM_MATCH as usize + 1 };
        while self.encoder.position + margin < self.encoder.finder.data().len() {
            let full_data =
                self.encoder.position - self.chunk_start + LZMAModel::MAXIMUM_MATCH as usize > LZMAFormat::CHUNK_DATA;
            let full_code = self.encoder.range.pending_size() + LZMA2Compressor::SYMBOL_MARGIN
                > LZMAFormat::CHUNK_COMPRESSED as u64;
            if full_data || full_code {
                self.end_chunk();
            }
            self.encoder.encode_next();
        }
        let dropped = self.encoder.finder.discard(self.chunk_start);
        self.encoder.position -= dropped;
        self.chunk_start -= dropped;
    }

    /// Writes the data since the last chunk as a chunk (nothing if there is none).
    pub fn end_chunk(&mut self) {
        let length = self.encoder.position - self.chunk_start;
        if length == 0 {
            return;
        }
        self.encoder.range.flush();
        let compressed = self.encoder.range.take();
        self.encoder.range = LZMARangeEncoder::new();
        if compressed.len() >= length {
            // Stored: the decoder's model never saw the symbols, so the next LZMA chunk resets it.
            let data = &self.encoder.finder.data()[self.chunk_start..self.encoder.position];
            for piece in data.chunks(LZMAFormat::CHUNK_COMPRESSED) {
                let control =
                    if self.reset_dictionary { LZMAFormat::UNCOMPRESSED_RESET } else { LZMAFormat::UNCOMPRESSED };
                let size = (piece.len() - 1) as u16;
                self.pending.extend(&[control, (size >> 8) as u8, size as u8]);
                self.pending.extend(piece);
                self.reset_dictionary = false;
            }
            self.encoder.model.reset(self.config.properties);
            self.reset_state = true;
        } else {
            let control = if self.reset_dictionary {
                LZMAFormat::LZMA_DICTIONARY_RESET
            } else if self.reset_properties {
                LZMAFormat::LZMA_PROPERTIES
            } else if self.reset_state {
                LZMAFormat::LZMA_STATE_RESET
            } else {
                LZMAFormat::LZMA
            };
            let (data, code) = (length - 1, compressed.len() - 1);
            self.pending.extend(&[
                control | (data >> 16) as u8,
                (data >> 8) as u8,
                data as u8,
                (code >> 8) as u8,
                code as u8,
            ]);
            if control >= LZMAFormat::LZMA_PROPERTIES {
                self.pending.extend(&[self.config.properties.to_byte()]);
            }
            self.pending.extend(&compressed);
            self.reset_dictionary = false;
            self.reset_properties = false;
            self.reset_state = false;
        }
        self.chunk_start = self.encoder.position;
    }
}

impl Default for LZMA2Compressor {
    fn default() -> LZMA2Compressor {
        LZMA2Compressor::new(LZMAConfig::default()).expect("the default parameters are valid")
    }
}

impl Compressor for LZMA2Compressor {
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        let (mut consumed, mut produced) = (0, 0);
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() || self.finished {
                break;
            }
            let buffered = self.encoder.finder.data().len() - self.encoder.position;
            let take = (input.len() - consumed).min(LZMA2Compressor::LOOKAHEAD.saturating_sub(buffered));
            self.encoder.finder.append(&input[consumed..consumed + take]);
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
            self.end_chunk();
            if flush == Flush::Finish {
                self.pending.extend(&[LZMAFormat::END]);
                self.finished = true;
            } else if self.unflushed {
                self.unflushed = false;
            } else {
                break;
            }
        }
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.encoder.clear();
        self.encoder.model.reset(self.config.properties);
        self.encoder.range = LZMARangeEncoder::new();
        self.chunk_start = 0;
        self.reset_dictionary = true;
        self.reset_properties = true;
        self.reset_state = true;
        self.pending.clear();
        self.unflushed = false;
        self.finished = false;
    }
}
