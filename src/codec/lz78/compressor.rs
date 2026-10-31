use super::{LZ78Config, LZ78Dictionary, LZ78Format};
use crate::bytes::BitWriter;
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};

/// Compresses into the format of [`LZ78Format`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZ78Compressor {
    config: LZ78Config,
    dictionary: LZ78Dictionary,
    /// The phrase the input since the last token matches.
    phrase: u32,
    writer: BitWriter,
    pending: PendingOutput,
    started: bool,
    unflushed: bool,
    finished: bool,
}

impl LZ78Compressor {
    /// A compressor of the parameters `config`; fails with `InvalidParameter`
    /// for a dictionary size outside 1 to [`LZ78Format::MAXIMUM_BITS`] bits.
    pub fn new(config: LZ78Config) -> Result<LZ78Compressor, CompressionError> {
        if !(1..=LZ78Format::MAXIMUM_BITS).contains(&config.dictionary_bits) {
            return Err(CompressionError::InvalidParameter);
        }
        Ok(LZ78Compressor {
            config,
            dictionary: LZ78Dictionary::new(1 << config.dictionary_bits, true),
            phrase: 0,
            writer: BitWriter::new(),
            pending: PendingOutput::new(),
            started: false,
            unflushed: false,
            finished: false,
        })
    }

    pub fn config(&self) -> LZ78Config {
        self.config
    }

    /// Takes `byte` into the current phrase, writing a token when the phrase leaves the dictionary.
    pub fn write_byte(&mut self, byte: u8) {
        match self.dictionary.child(self.phrase, byte) {
            Some(child) => self.phrase = child,
            None => {
                let width = LZ78Format::width(self.dictionary.len());
                self.writer.write(self.phrase as u64, width);
                self.writer.write(byte as u64, 8);
                self.dictionary.add(self.phrase, byte);
                self.phrase = 0;
            }
        }
    }

    /// Writes the marker token with the current phrase, ending the stream if `last`.
    pub fn write_marker(&mut self, last: bool) {
        let phrases = self.dictionary.len();
        let width = LZ78Format::width(phrases);
        self.writer.write(phrases as u64 + 1, width);
        self.writer.write(self.phrase as u64, width);
        self.writer.write(last as u64, 1);
        self.writer.align();
        self.phrase = 0;
    }
}

impl Default for LZ78Compressor {
    fn default() -> LZ78Compressor {
        LZ78Compressor::new(LZ78Config::default()).expect("the default parameters are valid")
    }
}

impl Compressor for LZ78Compressor {
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        if !self.started {
            self.writer.write(self.config.dictionary_bits as u64, 8);
            self.started = true;
        }
        let (mut consumed, mut produced) = (0, 0);
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() || self.finished {
                break;
            }
            // Encodes no more than the output has room for.
            let room = output.len() - produced;
            while consumed < input.len() && self.writer.completed().len() < room.max(1) {
                self.write_byte(input[consumed]);
                consumed += 1;
                self.unflushed = true;
            }
            if consumed == input.len() {
                if flush == Flush::Finish {
                    self.write_marker(true);
                    self.finished = true;
                } else if flush == Flush::Sync && self.unflushed {
                    self.write_marker(false);
                    self.unflushed = false;
                }
            }
            self.pending.extend(self.writer.completed());
            self.writer.clear_completed();
            if self.pending.is_empty() && (consumed == input.len() || room == 0) {
                break;
            }
        }
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.dictionary.clear();
        self.phrase = 0;
        self.writer = BitWriter::new();
        self.pending.clear();
        self.started = false;
        self.unflushed = false;
        self.finished = false;
    }
}
