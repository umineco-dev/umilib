use super::{LZMA2DecompressorConfig, LZMADecoder, LZMAFormat, LZMAProperties, LZMASymbol};
use crate::codec::{CompressionError, Decompressor, Progress};

/// Where an [`LZMA2Decompressor`] is in its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LZMA2State {
    /// Before the control byte of a chunk.
    Control,
    /// Reading the sizes (and properties) of a chunk: `count` of its `length` header bytes so far.
    Header {
        control: u8,
        count: usize,
        length: usize,
    },
    /// Copying the `remaining` bytes of an uncompressed chunk.
    Uncompressed {
        remaining: usize,
    },
    /// Starting the range decoder of an LZMA chunk.
    Start,
    /// Decoding the symbols of an LZMA chunk.
    Symbols,
    Literal {
        byte: u8,
    },
    Copy {
        distance: usize,
        remaining: usize,
    },
    /// After the end byte.
    End,
}

/// Decompresses raw LZMA2 streams, with the checks of liblzma: the first
/// chunk resets the dictionary, an LZMA chunk after a dictionary reset sets
/// properties (lc + lp at most 4), control bytes 3 to 0x7F are invalid,
/// and each LZMA chunk holds exactly its sizes, decodes without an end marker
/// and leaves the range decoder finished.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZMA2Decompressor {
    config: LZMA2DecompressorConfig,
    decoder: LZMADecoder,
    header: [u8; 5],
    need_dictionary_reset: bool,
    need_properties: bool,
    /// The data and compressed bytes left in the chunk.
    data_remaining: usize,
    code_remaining: usize,
    state: LZMA2State,
}

impl LZMA2Decompressor {
    /// A decompressor of streams of a dictionary of `config.dictionary_size`
    /// bytes; fails with `InvalidParameter` below 4 KiB.
    pub fn new(config: LZMA2DecompressorConfig) -> Result<LZMA2Decompressor, CompressionError> {
        if config.dictionary_size < LZMAFormat::MINIMUM_DICTIONARY {
            return Err(CompressionError::InvalidParameter);
        }
        Ok(LZMA2Decompressor {
            config,
            decoder: LZMADecoder::new(LZMAProperties::default(), config.dictionary_size),
            header: [0; 5],
            need_dictionary_reset: true,
            need_properties: true,
            data_remaining: 0,
            code_remaining: 0,
            state: LZMA2State::Control,
        })
    }

    pub fn state(&self) -> LZMA2State {
        self.state
    }

    /// Starts the chunk of the header read: its sizes, properties and resets.
    pub fn start_chunk(&mut self, control: u8) -> Result<LZMA2State, CompressionError> {
        let header = self.header;
        if control < LZMAFormat::LZMA {
            self.data_remaining = (header[0] as usize) << 8 | header[1] as usize;
            self.data_remaining += 1;
            return Ok(LZMA2State::Uncompressed { remaining: self.data_remaining });
        }
        self.data_remaining = ((control as usize & 0x1F) << 16 | (header[0] as usize) << 8 | header[1] as usize) + 1;
        self.code_remaining = ((header[2] as usize) << 8 | header[3] as usize) + 1;
        if control >= LZMAFormat::LZMA_PROPERTIES {
            let properties = LZMAProperties::from_byte(header[4])?;
            if properties.literal_context_bits + properties.literal_position_bits > 4 {
                return Err(CompressionError::InvalidData { reason: "invalid properties" });
            }
            self.decoder.model.reset(properties);
        } else if control >= LZMAFormat::LZMA_STATE_RESET {
            let properties = self.decoder.model.properties;
            self.decoder.model.reset(properties);
        }
        self.decoder.range = None;
        Ok(LZMA2State::Start)
    }
}

impl Default for LZMA2Decompressor {
    fn default() -> LZMA2Decompressor {
        LZMA2Decompressor::new(LZMA2DecompressorConfig::default()).expect("the default dictionary is valid")
    }
}

impl Decompressor for LZMA2Decompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let mut rest = input;
        let mut produced = 0;
        loop {
            match self.state {
                LZMA2State::Control => {
                    let Some((control, after)) = rest.split_first() else { break };
                    let control = *control;
                    rest = after;
                    if control == LZMAFormat::END {
                        self.state = LZMA2State::End;
                        continue;
                    }
                    if control > LZMAFormat::UNCOMPRESSED && control < LZMAFormat::LZMA {
                        return Err(CompressionError::InvalidData { reason: "invalid control byte" });
                    }
                    let dictionary_reset =
                        control == LZMAFormat::UNCOMPRESSED_RESET || control >= LZMAFormat::LZMA_DICTIONARY_RESET;
                    if dictionary_reset {
                        self.decoder.window.clear();
                        self.need_dictionary_reset = false;
                        self.need_properties = true;
                    } else if self.need_dictionary_reset {
                        return Err(CompressionError::InvalidData { reason: "no dictionary reset in the first chunk" });
                    }
                    if control >= LZMAFormat::LZMA {
                        if control >= LZMAFormat::LZMA_PROPERTIES {
                            self.need_properties = false;
                        } else if self.need_properties {
                            return Err(CompressionError::InvalidData {
                                reason: "no properties after a dictionary reset",
                            });
                        }
                    }
                    let length = if control < LZMAFormat::LZMA {
                        2
                    } else if control >= LZMAFormat::LZMA_PROPERTIES {
                        5
                    } else {
                        4
                    };
                    self.state = LZMA2State::Header { control, count: 0, length };
                }
                LZMA2State::Header { control, count, length } => {
                    let take = (length - count).min(rest.len());
                    self.header[count..count + take].copy_from_slice(&rest[..take]);
                    rest = &rest[take..];
                    if count + take < length {
                        self.state = LZMA2State::Header { control, count: count + take, length };
                        break;
                    }
                    self.state = self.start_chunk(control)?;
                }
                LZMA2State::Uncompressed { remaining } => {
                    let count = remaining.min(rest.len()).min(output.len() - produced);
                    output[produced..produced + count].copy_from_slice(&rest[..count]);
                    self.decoder.window.extend(&rest[..count]);
                    rest = &rest[count..];
                    produced += count;
                    if count < remaining {
                        self.state = LZMA2State::Uncompressed { remaining: remaining - count };
                        break;
                    }
                    self.state = LZMA2State::Control;
                }
                LZMA2State::Start => {
                    let mut chunk = &rest[..rest.len().min(self.code_remaining)];
                    let before = chunk.len();
                    let started = self.decoder.start(&mut chunk)?;
                    self.code_remaining -= before - chunk.len();
                    rest = &rest[before - chunk.len()..];
                    if !started {
                        break;
                    }
                    self.state = LZMA2State::Symbols;
                }
                LZMA2State::Symbols => {
                    if self.data_remaining == 0 {
                        let finished = self.decoder.range.is_some_and(|range| range.is_finished());
                        if self.code_remaining != 0 || self.decoder.holds_input() || !finished {
                            return Err(CompressionError::InvalidData { reason: "chunk sizes do not match its data" });
                        }
                        self.state = LZMA2State::Control;
                        continue;
                    }
                    let mut chunk = &rest[..rest.len().min(self.code_remaining)];
                    let before = chunk.len();
                    let symbol = self.decoder.decode(&mut chunk)?;
                    self.code_remaining -= before - chunk.len();
                    rest = &rest[before - chunk.len()..];
                    let Some(symbol) = symbol else {
                        if self.code_remaining == 0 {
                            return Err(CompressionError::InvalidData { reason: "chunk sizes do not match its data" });
                        }
                        break;
                    };
                    self.state = match symbol {
                        LZMASymbol::End => {
                            return Err(CompressionError::InvalidData { reason: "end marker in a chunk" });
                        }
                        LZMASymbol::Literal(byte) => LZMA2State::Literal { byte },
                        LZMASymbol::Match { length, .. } if length > self.data_remaining => {
                            return Err(CompressionError::InvalidData { reason: "chunk sizes do not match its data" });
                        }
                        LZMASymbol::Match { distance, length } => LZMA2State::Copy { distance, remaining: length },
                    };
                }
                LZMA2State::Literal { byte } => {
                    if produced == output.len() {
                        break;
                    }
                    produced += self.decoder.write(LZMASymbol::Literal(byte), &mut output[produced..])?;
                    self.data_remaining -= 1;
                    self.state = LZMA2State::Symbols;
                }
                LZMA2State::Copy { distance, remaining } => {
                    let copied = self.decoder.window.copy(distance, remaining, &mut output[produced..])?;
                    produced += copied;
                    self.data_remaining -= copied;
                    if copied < remaining {
                        self.state = LZMA2State::Copy { distance, remaining: remaining - copied };
                        break;
                    }
                    self.state = LZMA2State::Symbols;
                }
                LZMA2State::End => break,
            }
        }
        Ok(Progress { consumed: input.len() - rest.len(), produced, finished: self.state == LZMA2State::End })
    }

    fn finish(&mut self) -> Result<(), CompressionError> {
        if self.state == LZMA2State::End { Ok(()) } else { Err(CompressionError::UnexpectedEnd) }
    }

    fn reset(&mut self) {
        self.decoder = LZMADecoder::new(LZMAProperties::default(), self.config.dictionary_size);
        self.need_dictionary_reset = true;
        self.need_properties = true;
        self.data_remaining = 0;
        self.code_remaining = 0;
        self.state = LZMA2State::Control;
    }
}
