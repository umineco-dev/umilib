use super::{LZ77Config, LZ77Format, LZ77MatchFinder, LZ77MatchFinderConfig};
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};

/// Compresses into the format of [`LZ77Format`], greedily: each token takes
/// the longest match at its position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZ77Compressor {
    config: LZ77Config,
    finder: LZ77MatchFinder,
    /// The position in the finder's data of the next byte to encode.
    position: usize,
    pending: PendingOutput,
    finished: bool,
}

impl LZ77Compressor {
    /// The input taken before encoding: tokens are made once this much is
    /// buffered, so that matches may be as long as the format allows.
    pub const BLOCK: usize = 1 << 14;

    /// A compressor of the parameters `config`; fails with `InvalidParameter`
    /// for a chain limit of 0.
    pub fn new(config: LZ77Config) -> Result<LZ77Compressor, CompressionError> {
        let finder = LZ77MatchFinder::new(LZ77MatchFinderConfig {
            window_bits: 12,
            chain_bits: 12,
            hash_bits: 12,
            maximum_distance: LZ77Format::WINDOW,
            minimum_length: 2,
            maximum_length: LZ77Format::MAXIMUM_LENGTH,
            chain_limit: config.chain_limit,
            nice_length: LZ77Format::MAXIMUM_LENGTH,
        })?;
        Ok(LZ77Compressor { config, finder, position: 0, pending: PendingOutput::new(), finished: false })
    }

    pub fn config(&self) -> LZ77Config {
        self.config
    }

    /// Encodes the buffered data into tokens, all of it if `all`, otherwise
    /// up to where a match could still grow with more input.
    pub fn encode(&mut self, all: bool) {
        let mut tokens = alloc::vec::Vec::new();
        loop {
            let available = self.finder.data().len() - self.position;
            if available == 0 || (!all && available <= LZ77Format::MAXIMUM_LENGTH) {
                break;
            }
            // A match leaves the byte that follows it in the data.
            let found = self.finder.find(self.position, available - 1);
            let (field, length) = match found {
                Some(found) => ((found.distance - 1) as u16, found.length),
                None => (0, 0),
            };
            let next = self.finder.data()[self.position + length];
            let header = field << 4 | length as u16;
            tokens.extend_from_slice(&[(header >> 8) as u8, header as u8, next]);
            self.position += length + 1;
        }
        self.pending.extend(&tokens);
        self.position -= self.finder.discard(self.position);
    }
}

impl Compressor for LZ77Compressor {
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        let (mut consumed, mut produced) = (0, 0);
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() || self.finished {
                break;
            }
            let buffered = self.finder.data().len() - self.position;
            let take = (input.len() - consumed).min(LZ77Compressor::BLOCK.saturating_sub(buffered));
            self.finder.append(&input[consumed..consumed + take]);
            consumed += take;
            if consumed < input.len() {
                self.encode(false);
            } else if flush == Flush::None {
                self.encode(false);
                if self.pending.is_empty() {
                    break;
                }
            } else {
                self.encode(true);
                if flush == Flush::Finish {
                    let end = LZ77Format::END << 4;
                    self.pending.extend(&[(end >> 8) as u8, end as u8]);
                    self.finished = true;
                } else if self.pending.is_empty() {
                    break;
                }
            }
        }
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.finder.clear();
        self.position = 0;
        self.pending.clear();
        self.finished = false;
    }
}
