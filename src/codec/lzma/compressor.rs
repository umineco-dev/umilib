use super::{LZMAConfig, LZMAEncoder, LZMAFormat, LZMALevel, LZMAModel};
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};

/// Compresses into the .lzma file format: the header, then one LZMA stream,
/// ended by its end marker (or by the size the header gives).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZMACompressor {
    config: LZMAConfig,
    encoder: LZMAEncoder,
    pending: PendingOutput,
    started: bool,
    finished: bool,
}

impl LZMACompressor {
    /// The input buffered ahead of the position being encoded.
    pub const LOOKAHEAD: usize = 1 << 20;

    /// A compressor of the parameters `config`; fails with `InvalidParameter` outside their ranges.
    pub fn new(config: LZMAConfig) -> Result<LZMACompressor, CompressionError> {
        config.properties.check(false)?;
        let level = *LZMALevel::LEVELS.get(config.level as usize).ok_or(CompressionError::InvalidParameter)?;
        let dictionary_size = config.dictionary_size.unwrap_or(level.dictionary_size);
        let encoder = LZMAEncoder::new(config.properties, dictionary_size, &level)?;
        Ok(LZMACompressor { config, encoder, pending: PendingOutput::new(), started: false, finished: false })
    }

    pub fn config(&self) -> &LZMAConfig {
        &self.config
    }

    /// The 13 bytes of the header.
    pub fn header_bytes(&self) -> [u8; LZMAFormat::HEADER_SIZE] {
        let mut header = [0u8; LZMAFormat::HEADER_SIZE];
        header[0] = self.config.properties.to_byte();
        header[1..5].copy_from_slice(&(self.encoder.dictionary_size as u32).to_le_bytes());
        header[5..].copy_from_slice(&self.config.uncompressed_size.unwrap_or(LZMAFormat::UNKNOWN_SIZE).to_le_bytes());
        header
    }

    /// Encodes the buffered data, all of it if `all`, otherwise up to where
    /// matches could still grow with more input.
    pub fn encode(&mut self, all: bool) {
        let margin = if all { 0 } else { LZMAModel::MAXIMUM_MATCH as usize + 1 };
        while self.encoder.position + margin < self.encoder.finder.data().len() {
            self.encoder.encode_next();
        }
        let out = self.encoder.range.take();
        self.pending.extend(&out);
        let dropped = self.encoder.finder.discard(self.encoder.position);
        self.encoder.position -= dropped;
    }
}

impl Compressor for LZMACompressor {
    /// LZMA streams cannot be flushed without ending them, so [`Flush::Sync`]
    /// fails with `InvalidParameter`.
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        if flush == Flush::Sync {
            return Err(CompressionError::InvalidParameter);
        }
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
            let buffered = self.encoder.finder.data().len() - self.encoder.position;
            let take = (input.len() - consumed).min(LZMACompressor::LOOKAHEAD.saturating_sub(buffered));
            self.encoder.finder.append(&input[consumed..consumed + take]);
            consumed += take;
            if consumed < input.len() || flush == Flush::None {
                self.encode(false);
                if consumed == input.len() && self.pending.is_empty() {
                    break;
                }
                continue;
            }
            self.encode(true);
            match self.config.uncompressed_size {
                None => self.encoder.encode_end_marker(),
                Some(size) if size != self.encoder.total => return Err(CompressionError::InvalidParameter),
                Some(_) => {}
            }
            self.encoder.range.flush();
            let out = self.encoder.range.take();
            self.pending.extend(&out);
            self.finished = true;
        }
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.encoder.clear();
        self.encoder.model.reset(self.config.properties);
        self.encoder.range = super::LZMARangeEncoder::new();
        self.pending.clear();
        self.started = false;
        self.finished = false;
    }
}
