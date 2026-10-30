use super::{DeflateDecompressorConfig, DeflateFormat};
use crate::bytes::{BitOrder, BitQueue};
use crate::codec::huffman::canonical::{HuffmanCode, HuffmanTable};
use crate::codec::lz77::LZ77Window;
use crate::codec::{CompressionError, Decompressor, Progress};

/// Where a [`DeflateDecompressor`] is in its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeflateState {
    /// Before the 3 bits of a block header.
    Header,
    /// Before LEN and NLEN of a stored block.
    StoredLength,
    /// Copying the `remaining` bytes of a stored block.
    Stored { remaining: usize },
    /// Before HLIT, HDIST and HCLEN of a dynamic block.
    Counts,
    /// Reading the code length code lengths: `index` of them so far.
    CodeLengthCodes { index: usize },
    /// Reading the literal/length and distance code lengths: `index` of them so far.
    CodeLengths { index: usize },
    /// Decoding the symbols of a block.
    Symbols,
    /// After a length, before its distance.
    Distance { length: usize },
    /// Copying the `remaining` bytes of a match `distance` bytes back.
    Copy { distance: usize, remaining: usize },
    /// After the last block.
    End,
}

/// Decompresses raw Deflate streams (RFC 1951), with the checks of zlib:
/// code lengths must define complete codes (a single code of 1 bit aside, for
/// literal/length and distance codes), a dynamic block declares at most 286
/// literal/length and 30 distance codes, and a match may not reach before the
/// start of the data (or of the dictionary).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeflateDecompressor {
    config: DeflateDecompressorConfig,
    window: LZ77Window,
    queue: BitQueue,
    state: DeflateState,
    last: bool,
    /// The counts of a dynamic block: literal/length codes, distance codes, code length codes.
    counts: (usize, usize, usize),
    /// The code lengths being read: the code length code, then the literal/length and distance codes.
    lengths: [u8; DeflateFormat::LITERAL_LENGTH_SYMBOLS + DeflateFormat::DISTANCE_SYMBOLS],
    code_length_table: Option<HuffmanTable>,
    /// The tables of the fixed codes, made at the first fixed block.
    fixed_tables: Option<(HuffmanTable, HuffmanTable)>,
    /// The tables of the last dynamic block.
    dynamic_tables: Option<(HuffmanTable, HuffmanTable)>,
    /// Whether the current block uses the fixed codes.
    fixed: bool,
}

impl DeflateDecompressor {
    /// A decompressor of the limits `config`; fails with `InvalidParameter`
    /// for a window outside 8 to 15 bits.
    pub fn new(config: DeflateDecompressorConfig) -> Result<DeflateDecompressor, CompressionError> {
        if !(8..=15).contains(&config.window_bits) {
            return Err(CompressionError::InvalidParameter);
        }
        Ok(DeflateDecompressor {
            config,
            window: LZ77Window::new(1 << config.window_bits),
            queue: BitQueue::with_order(BitOrder::LeastSignificantFirst),
            state: DeflateState::Header,
            last: false,
            counts: (0, 0, 0),
            lengths: [0; DeflateFormat::LITERAL_LENGTH_SYMBOLS + DeflateFormat::DISTANCE_SYMBOLS],
            code_length_table: None,
            fixed_tables: None,
            dynamic_tables: None,
            fixed: false,
        })
    }

    pub fn config(&self) -> DeflateDecompressorConfig {
        self.config
    }

    pub fn state(&self) -> DeflateState {
        self.state
    }

    /// Makes `dictionary` the history before the data (the preset dictionary
    /// of zlib), before the first call of `decompress`.
    pub fn set_dictionary(&mut self, dictionary: &[u8]) {
        self.window.extend(dictionary);
    }

    /// Goes on after the last block (BFINAL, RFC 1951 §3.2.3) with the
    /// blocks that follow at the next byte boundary, whose matches reach
    /// into the history so far: what messages of permessage-deflate that
    /// end with BFINAL need (RFC 7692 §7.2.1, §7.2.3.4). Does nothing before the last block.
    pub fn resume(&mut self) {
        if self.state == DeflateState::End {
            self.queue.align();
            self.state = DeflateState::Header;
            self.last = false;
        }
    }

    /// The bytes of the history so far: the dictionary and the data written.
    pub fn total(&self) -> u64 {
        self.window.total()
    }

    /// The table of `lengths`; fails with `InvalidData` unless they define a
    /// complete code, or (if `single` is allowed) a code of one symbol of 1 bit or no symbol.
    pub fn table(lengths: &[u8], single: bool) -> Result<HuffmanTable, CompressionError> {
        let code = HuffmanCode::from_lengths(lengths)
            .map_err(|_| CompressionError::InvalidData { reason: "over-subscribed code lengths" })?;
        if !code.is_complete() && !(single && code.maximum_length() <= 1) {
            return Err(CompressionError::InvalidData { reason: "incomplete code lengths" });
        }
        Ok(HuffmanTable::new(&code, BitOrder::LeastSignificantFirst))
    }

    /// The fixed tables (section 3.2.6).
    pub fn fixed_tables() -> (HuffmanTable, HuffmanTable) {
        let literal =
            HuffmanTable::from_lengths(&DeflateFormat::fixed_literal_length_lengths(), BitOrder::LeastSignificantFirst);
        let distance =
            HuffmanTable::from_lengths(&DeflateFormat::fixed_distance_lengths(), BitOrder::LeastSignificantFirst);
        (literal.expect("the fixed code is complete"), distance.expect("the fixed code is complete"))
    }

    /// The symbol at the front of the queue in `table` and the length of its
    /// code, if the queue (filled from `input`) holds the code and `extra`
    /// bits after it of the symbol's extra bits; nothing is consumed.
    pub fn peek_symbol(
        queue: &mut BitQueue,
        input: &mut &[u8],
        table: &HuffmanTable,
        extra: impl Fn(u16) -> Result<u32, CompressionError>,
    ) -> Result<Option<(u16, u32, u32)>, CompressionError> {
        let Some((symbol, length)) =
            table.peek(queue, input).map_err(|_| CompressionError::InvalidData { reason: "invalid code" })?
        else {
            return Ok(None);
        };
        let extra = extra(symbol)?;
        if !queue.fill(length + extra, input) {
            return Ok(None);
        }
        Ok(Some((symbol, length, extra)))
    }
}

impl Default for DeflateDecompressor {
    fn default() -> DeflateDecompressor {
        DeflateDecompressor::new(DeflateDecompressorConfig::default()).expect("the default window is valid")
    }
}

impl Decompressor for DeflateDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let mut rest = input;
        let mut produced = 0;
        loop {
            match self.state {
                DeflateState::Header => {
                    let Some(header) = self.queue.read_from(3, &mut rest) else { break };
                    self.last = header & 1 == 1;
                    self.state = match header >> 1 {
                        0 => {
                            // The rest of the byte is ignored (section 3.2.4).
                            self.queue.align();
                            DeflateState::StoredLength
                        }
                        1 => {
                            if self.fixed_tables.is_none() {
                                self.fixed_tables = Some(DeflateDecompressor::fixed_tables());
                            }
                            self.fixed = true;
                            DeflateState::Symbols
                        }
                        2 => {
                            self.fixed = false;
                            DeflateState::Counts
                        }
                        _ => return Err(CompressionError::InvalidData { reason: "invalid block type" }),
                    };
                }
                DeflateState::StoredLength => {
                    let Some(lengths) = self.queue.read_from(32, &mut rest) else { break };
                    let (length, complement) = (lengths & 0xFFFF, lengths >> 16);
                    if length ^ complement != 0xFFFF {
                        return Err(CompressionError::InvalidData { reason: "invalid stored block lengths" });
                    }
                    self.state = DeflateState::Stored { remaining: length as usize };
                }
                DeflateState::Stored { remaining } => {
                    // The queue is empty at a byte boundary: the bytes come straight from the input.
                    let count = remaining.min(rest.len()).min(output.len() - produced);
                    output[produced..produced + count].copy_from_slice(&rest[..count]);
                    self.window.extend(&rest[..count]);
                    rest = &rest[count..];
                    produced += count;
                    if count < remaining {
                        self.state = DeflateState::Stored { remaining: remaining - count };
                        break;
                    }
                    self.state = if self.last { DeflateState::End } else { DeflateState::Header };
                }
                DeflateState::Counts => {
                    let Some(counts) = self.queue.read_from(14, &mut rest) else { break };
                    let literal = (counts & 0x1F) as usize + 257;
                    let distance = ((counts >> 5) & 0x1F) as usize + 1;
                    let code_length = ((counts >> 10) & 0xF) as usize + 4;
                    if literal > DeflateFormat::MAXIMUM_LITERAL_LENGTH_CODES
                        || distance > DeflateFormat::MAXIMUM_DISTANCE_CODES
                    {
                        return Err(CompressionError::InvalidData { reason: "too many length or distance codes" });
                    }
                    self.counts = (literal, distance, code_length);
                    self.lengths[..19].fill(0);
                    self.state = DeflateState::CodeLengthCodes { index: 0 };
                }
                DeflateState::CodeLengthCodes { mut index } => {
                    while index < self.counts.2 {
                        let Some(length) = self.queue.read_from(3, &mut rest) else { break };
                        self.lengths[DeflateFormat::CODE_LENGTH_ORDER[index]] = length as u8;
                        index += 1;
                    }
                    if index < self.counts.2 {
                        self.state = DeflateState::CodeLengthCodes { index };
                        break;
                    }
                    self.code_length_table = Some(DeflateDecompressor::table(&self.lengths[..19], false)?);
                    self.lengths.fill(0);
                    self.state = DeflateState::CodeLengths { index: 0 };
                }
                DeflateState::CodeLengths { mut index } => {
                    let total = self.counts.0 + self.counts.1;
                    let table = self.code_length_table.as_ref().expect("read before the code lengths");
                    while index < total {
                        let extra = |symbol: u16| {
                            Ok(match symbol {
                                16 => 2,
                                17 => 3,
                                18 => 7,
                                _ => 0,
                            })
                        };
                        let Some((symbol, length, extra)) =
                            DeflateDecompressor::peek_symbol(&mut self.queue, &mut rest, table, extra)?
                        else {
                            break;
                        };
                        self.queue.consume(length);
                        let bits = self.queue.read(extra).unwrap_or(0) as usize;
                        let (value, count) = match symbol {
                            0..=15 => (symbol as u8, 1),
                            16 if index == 0 => {
                                return Err(CompressionError::InvalidData { reason: "repeat with no previous length" });
                            }
                            16 => (self.lengths[index - 1], 3 + bits),
                            17 => (0, 3 + bits),
                            _ => (0, 11 + bits),
                        };
                        if index + count > total {
                            return Err(CompressionError::InvalidData { reason: "too many code lengths" });
                        }
                        self.lengths[index..index + count].fill(value);
                        index += count;
                    }
                    if index < total {
                        self.state = DeflateState::CodeLengths { index };
                        break;
                    }
                    let (literal, distance) = (self.counts.0, self.counts.1);
                    if self.lengths[DeflateFormat::END_OF_BLOCK as usize] == 0 {
                        return Err(CompressionError::InvalidData { reason: "no code for the end of the block" });
                    }
                    let literal_table = DeflateDecompressor::table(&self.lengths[..literal], true)?;
                    let distance_table = DeflateDecompressor::table(&self.lengths[literal..literal + distance], true)?;
                    self.dynamic_tables = Some((literal_table, distance_table));
                    self.state = DeflateState::Symbols;
                }
                DeflateState::Symbols => {
                    let tables = if self.fixed { &self.fixed_tables } else { &self.dynamic_tables };
                    let table = &tables.as_ref().expect("read before the symbols").0;
                    let extra = |symbol: u16| match symbol {
                        0..=256 => Ok(0),
                        257..=285 => Ok(DeflateFormat::LENGTH_EXTRA_BITS[symbol as usize - 257] as u32),
                        _ => Err(CompressionError::InvalidData { reason: "invalid literal/length symbol" }),
                    };
                    let Some((symbol, length, extra)) =
                        DeflateDecompressor::peek_symbol(&mut self.queue, &mut rest, table, extra)?
                    else {
                        break;
                    };
                    match symbol {
                        0..=255 => {
                            if produced == output.len() {
                                break;
                            }
                            self.queue.consume(length);
                            output[produced] = symbol as u8;
                            self.window.push(symbol as u8);
                            produced += 1;
                        }
                        DeflateFormat::END_OF_BLOCK => {
                            self.queue.consume(length);
                            self.state = if self.last { DeflateState::End } else { DeflateState::Header };
                        }
                        _ => {
                            self.queue.consume(length);
                            let bits = self.queue.read(extra).unwrap_or(0) as usize;
                            let length = DeflateFormat::LENGTH_BASES[symbol as usize - 257] as usize + bits;
                            self.state = DeflateState::Distance { length };
                        }
                    }
                }
                DeflateState::Distance { length } => {
                    let tables = if self.fixed { &self.fixed_tables } else { &self.dynamic_tables };
                    let table = &tables.as_ref().expect("read before the symbols").1;
                    let extra = |symbol: u16| match symbol {
                        0..=29 => Ok(DeflateFormat::DISTANCE_EXTRA_BITS[symbol as usize] as u32),
                        _ => Err(CompressionError::InvalidData { reason: "invalid distance symbol" }),
                    };
                    let Some((symbol, code_length, extra)) =
                        DeflateDecompressor::peek_symbol(&mut self.queue, &mut rest, table, extra)?
                    else {
                        break;
                    };
                    self.queue.consume(code_length);
                    let bits = self.queue.read(extra).unwrap_or(0) as usize;
                    let distance = DeflateFormat::DISTANCE_BASES[symbol as usize] as usize + bits;
                    if distance as u64 > self.window.total() {
                        return Err(CompressionError::InvalidData { reason: "distance too far back" });
                    }
                    if distance > self.window.len() {
                        return Err(CompressionError::LimitExceeded { limit: self.window.capacity() as u64 });
                    }
                    self.state = DeflateState::Copy { distance, remaining: length };
                }
                DeflateState::Copy { distance, remaining } => {
                    let copied = self.window.copy(distance, remaining, &mut output[produced..])?;
                    produced += copied;
                    if copied < remaining {
                        self.state = DeflateState::Copy { distance, remaining: remaining - copied };
                        break;
                    }
                    self.state = DeflateState::Symbols;
                }
                DeflateState::End => break,
            }
        }
        Ok(Progress { consumed: input.len() - rest.len(), produced, finished: self.state == DeflateState::End })
    }

    fn finish(&mut self) -> Result<(), CompressionError> {
        if self.state == DeflateState::End { Ok(()) } else { Err(CompressionError::UnexpectedEnd) }
    }

    fn reset(&mut self) {
        self.window.clear();
        self.queue.clear();
        self.state = DeflateState::Header;
        self.last = false;
        self.code_length_table = None;
        self.dynamic_tables = None;
        self.fixed = false;
    }
}
