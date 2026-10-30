use super::{LZMADecoder, LZMADecompressorConfig, LZMAFormat, LZMAProperties, LZMASymbol};
use crate::codec::{CompressionError, Decompressor, Progress};

/// Where an [`LZMADecompressor`] is in its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LZMAState {
    /// Reading the 13 bytes of the header.
    Header,
    /// Reading the 5 bytes that start the range decoder.
    Start,
    /// Decoding symbols.
    Symbols,
    /// Writing a decoded literal, or the `remaining` bytes of a match `distance` back.
    Literal {
        byte: u8,
    },
    Copy {
        distance: usize,
        remaining: usize,
    },
    /// After the stream.
    End,
}

/// Decompresses the .lzma file format, with the checks of the
/// specification: the properties, the first byte of the range coder, the
/// distances, the uncompressed size of the header (with or without an end
/// marker) and the range decoder's final state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZMADecompressor {
    config: LZMADecompressorConfig,
    header: [u8; LZMAFormat::HEADER_SIZE],
    filled: usize,
    decoder: Option<LZMADecoder>,
    size: u64,
    state: LZMAState,
}

impl LZMADecompressor {
    pub fn new(config: LZMADecompressorConfig) -> LZMADecompressor {
        LZMADecompressor {
            config,
            header: [0; LZMAFormat::HEADER_SIZE],
            filled: 0,
            decoder: None,
            size: 0,
            state: LZMAState::Header,
        }
    }

    pub fn state(&self) -> LZMAState {
        self.state
    }

    /// The properties, the dictionary size (at least 4 KiB) and the uncompressed size of the header read.
    pub fn header(&self) -> Option<(LZMAProperties, usize, Option<u64>)> {
        let decoder = self.decoder.as_ref()?;
        Some((
            decoder.model.properties,
            decoder.dictionary_size,
            (self.size != LZMAFormat::UNKNOWN_SIZE).then_some(self.size),
        ))
    }

    /// Reads the header: the properties, the dictionary within the limit.
    pub fn read_header(&mut self) -> Result<(), CompressionError> {
        let properties = LZMAProperties::from_byte(self.header[0])?;
        let dictionary = u32::from_le_bytes(self.header[1..5].try_into().expect("4 bytes")) as usize;
        let dictionary = dictionary.max(LZMAFormat::MINIMUM_DICTIONARY);
        if dictionary > self.config.maximum_dictionary_size {
            return Err(CompressionError::LimitExceeded { limit: self.config.maximum_dictionary_size as u64 });
        }
        self.size = u64::from_le_bytes(self.header[5..].try_into().expect("8 bytes"));
        self.decoder = Some(LZMADecoder::new(properties, dictionary));
        Ok(())
    }
}

impl Default for LZMADecompressor {
    fn default() -> LZMADecompressor {
        LZMADecompressor::new(LZMADecompressorConfig::default())
    }
}

impl Decompressor for LZMADecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let mut rest = input;
        let mut produced = 0;
        loop {
            match self.state {
                LZMAState::Header => {
                    let count = (LZMAFormat::HEADER_SIZE - self.filled).min(rest.len());
                    self.header[self.filled..self.filled + count].copy_from_slice(&rest[..count]);
                    self.filled += count;
                    rest = &rest[count..];
                    if self.filled < LZMAFormat::HEADER_SIZE {
                        break;
                    }
                    self.read_header()?;
                    self.state = LZMAState::Start;
                }
                LZMAState::Start => {
                    if !self.decoder.as_mut().expect("read with the header").start(&mut rest)? {
                        break;
                    }
                    self.state = LZMAState::Symbols;
                }
                LZMAState::Symbols => {
                    let decoder = self.decoder.as_mut().expect("read with the header");
                    let total = decoder.window.total();
                    let known = self.size != LZMAFormat::UNKNOWN_SIZE;
                    // With a known size, the stream may end there without an end marker.
                    if known
                        && total == self.size
                        && decoder.range.is_some_and(|range| range.is_finished())
                        && !decoder.holds_input()
                    {
                        self.state = LZMAState::End;
                        continue;
                    }
                    let Some(symbol) = decoder.decode(&mut rest)? else { break };
                    let remaining = self.size.wrapping_sub(total);
                    self.state = match symbol {
                        LZMASymbol::End => {
                            if known && remaining != 0 {
                                return Err(CompressionError::InvalidData {
                                    reason: "end marker before the uncompressed size",
                                });
                            }
                            if !decoder.range.is_some_and(|range| range.is_finished()) || decoder.holds_input() {
                                return Err(CompressionError::InvalidData { reason: "range decoder not finished" });
                            }
                            LZMAState::End
                        }
                        _ if known && remaining == 0 => {
                            return Err(CompressionError::InvalidData { reason: "data beyond the uncompressed size" });
                        }
                        LZMASymbol::Literal(byte) => LZMAState::Literal { byte },
                        LZMASymbol::Match { length, .. } if known && length as u64 > remaining => {
                            return Err(CompressionError::InvalidData { reason: "data beyond the uncompressed size" });
                        }
                        LZMASymbol::Match { distance, length } => LZMAState::Copy { distance, remaining: length },
                    };
                }
                LZMAState::Literal { byte } => {
                    if produced == output.len() {
                        break;
                    }
                    let decoder = self.decoder.as_mut().expect("read with the header");
                    produced += decoder.write(LZMASymbol::Literal(byte), &mut output[produced..])?;
                    self.state = LZMAState::Symbols;
                }
                LZMAState::Copy { distance, remaining } => {
                    let decoder = self.decoder.as_mut().expect("read with the header");
                    let copied = decoder.window.copy(distance, remaining, &mut output[produced..])?;
                    produced += copied;
                    if copied < remaining {
                        self.state = LZMAState::Copy { distance, remaining: remaining - copied };
                        break;
                    }
                    self.state = LZMAState::Symbols;
                }
                LZMAState::End => break,
            }
        }
        Ok(Progress { consumed: input.len() - rest.len(), produced, finished: self.state == LZMAState::End })
    }

    fn finish(&mut self) -> Result<(), CompressionError> {
        if self.state == LZMAState::End { Ok(()) } else { Err(CompressionError::UnexpectedEnd) }
    }

    fn reset(&mut self) {
        self.filled = 0;
        self.decoder = None;
        self.size = 0;
        self.state = LZMAState::Header;
    }
}
