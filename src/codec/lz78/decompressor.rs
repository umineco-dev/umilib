use alloc::vec::Vec;

use super::{LZ78DecompressorConfig, LZ78Dictionary, LZ78Format};
use crate::bytes::BitQueue;
use crate::codec::{CompressionError, Decompressor, PendingOutput, Progress};

/// Where an [`LZ78Decompressor`] is in its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LZ78State {
    /// Before the byte of the dictionary size.
    Header,
    /// Before the first field of a token.
    Token,
    /// After the phrase `phrase` of a token, before its byte.
    Byte { phrase: u32 },
    /// After the first field of a marker, before its phrase and its bit.
    Marker,
    /// After the stream.
    End,
}

/// Decompresses the format of [`LZ78Format`]. The bytes of a phrase wait in
/// a buffer of at most the longest phrase when the output is full.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZ78Decompressor {
    config: LZ78DecompressorConfig,
    dictionary: LZ78Dictionary,
    queue: BitQueue,
    pending: PendingOutput,
    phrase: Vec<u8>,
    state: LZ78State,
}

impl LZ78Decompressor {
    pub fn new(config: LZ78DecompressorConfig) -> LZ78Decompressor {
        LZ78Decompressor {
            config,
            dictionary: LZ78Dictionary::new(0, false),
            queue: BitQueue::new(),
            pending: PendingOutput::new(),
            phrase: Vec::new(),
            state: LZ78State::Header,
        }
    }

    pub fn state(&self) -> LZ78State {
        self.state
    }

    /// Queues the bytes of `phrase`, then `byte` if any.
    pub fn emit(&mut self, phrase: u32, byte: Option<u8>) {
        self.phrase.resize(self.dictionary.length(phrase), 0);
        self.dictionary.write(phrase, &mut self.phrase);
        self.phrase.extend(byte);
        self.pending.extend(&self.phrase);
    }
}

impl Default for LZ78Decompressor {
    fn default() -> LZ78Decompressor {
        LZ78Decompressor::new(LZ78DecompressorConfig::default())
    }
}

impl Decompressor for LZ78Decompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let mut rest = input;
        let mut produced = 0;
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() {
                break;
            }
            let width = LZ78Format::width(self.dictionary.len());
            match self.state {
                LZ78State::Header => {
                    let Some(bits) = self.queue.read_from(8, &mut rest) else { break };
                    let bits = bits as u32;
                    if !(1..=LZ78Format::MAXIMUM_BITS).contains(&bits) {
                        return Err(CompressionError::InvalidData { reason: "invalid dictionary size" });
                    }
                    if bits > self.config.maximum_dictionary_bits {
                        return Err(CompressionError::LimitExceeded {
                            limit: 1 << self.config.maximum_dictionary_bits,
                        });
                    }
                    self.dictionary = LZ78Dictionary::new(1 << bits, false);
                    self.state = LZ78State::Token;
                }
                LZ78State::Token => {
                    let Some(value) = self.queue.read_from(width, &mut rest) else { break };
                    let phrases = self.dictionary.len() as u64;
                    self.state = match value {
                        value if value <= phrases => LZ78State::Byte { phrase: value as u32 },
                        value if value == phrases + 1 => LZ78State::Marker,
                        _ => return Err(CompressionError::InvalidData { reason: "phrase beyond the dictionary" }),
                    };
                }
                LZ78State::Byte { phrase } => {
                    let Some(byte) = self.queue.read_from(8, &mut rest) else { break };
                    self.emit(phrase, Some(byte as u8));
                    self.dictionary.add(phrase, byte as u8);
                    self.state = LZ78State::Token;
                }
                LZ78State::Marker => {
                    let Some(fields) = self.queue.read_from(width + 1, &mut rest) else { break };
                    let phrase = fields & BitQueue::mask(width);
                    if phrase > self.dictionary.len() as u64 {
                        return Err(CompressionError::InvalidData { reason: "phrase beyond the dictionary" });
                    }
                    self.emit(phrase as u32, None);
                    if self.queue.align() != 0 {
                        return Err(CompressionError::InvalidData { reason: "nonzero padding" });
                    }
                    self.state = if fields >> width == 1 { LZ78State::End } else { LZ78State::Token };
                }
                LZ78State::End => break,
            }
        }
        let finished = self.state == LZ78State::End && self.pending.is_empty();
        Ok(Progress { consumed: input.len() - rest.len(), produced, finished })
    }

    fn finish(&mut self) -> Result<(), CompressionError> {
        if self.state == LZ78State::End && self.pending.is_empty() {
            Ok(())
        } else {
            Err(CompressionError::UnexpectedEnd)
        }
    }

    fn reset(&mut self) {
        self.dictionary = LZ78Dictionary::new(0, false);
        self.queue.clear();
        self.pending.clear();
        self.state = LZ78State::Header;
    }
}
