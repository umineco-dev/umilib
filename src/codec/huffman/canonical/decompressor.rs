use super::{CanonicalHuffmanFormat, HuffmanCode, HuffmanTable};
use crate::bytes::{BitOrder, BitQueue};
use crate::codec::{CompressionError, Decompressor, Progress};

/// Where a [`CanonicalHuffmanDecompressor`] is in its stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalHuffmanState {
    /// Before the bit that marks the last block.
    Header,
    /// Reading the code length of the symbol `symbol`.
    Lengths { symbol: usize },
    /// Decoding the codes of a block with `table`.
    Symbols { table: HuffmanTable },
    /// After the stream.
    End,
}

/// Decompresses the format of [`CanonicalHuffmanFormat`]. It needs no
/// buffer: each code is decoded straight into the output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalHuffmanDecompressor {
    queue: BitQueue,
    state: CanonicalHuffmanState,
    last: bool,
    lengths: [u8; CanonicalHuffmanFormat::SYMBOLS],
}

impl CanonicalHuffmanDecompressor {
    pub fn new() -> CanonicalHuffmanDecompressor {
        CanonicalHuffmanDecompressor {
            queue: BitQueue::new(),
            state: CanonicalHuffmanState::Header,
            last: false,
            lengths: [0; CanonicalHuffmanFormat::SYMBOLS],
        }
    }

    pub fn state(&self) -> &CanonicalHuffmanState {
        &self.state
    }

    /// The decoding table of the code `lengths` of a block header; fails
    /// with `InvalidData` unless they define a code the format allows.
    pub fn table(lengths: &[u8]) -> Result<HuffmanTable, CompressionError> {
        let code = HuffmanCode::from_lengths(lengths)
            .map_err(|_| CompressionError::InvalidData { reason: "over-subscribed code lengths" })?;
        let single = lengths.iter().filter(|length| **length > 0).count() == 1 && code.maximum_length() == 1;
        if !code.is_complete() && !single {
            return Err(CompressionError::InvalidData { reason: "incomplete code lengths" });
        }
        if lengths[CanonicalHuffmanFormat::END as usize] == 0 {
            return Err(CompressionError::InvalidData { reason: "no code for the end of the block" });
        }
        Ok(HuffmanTable::new(&code, BitOrder::LeastSignificantFirst))
    }
}

impl Default for CanonicalHuffmanDecompressor {
    fn default() -> CanonicalHuffmanDecompressor {
        CanonicalHuffmanDecompressor::new()
    }
}

impl Decompressor for CanonicalHuffmanDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let mut rest = input;
        let mut produced = 0;
        loop {
            match &mut self.state {
                CanonicalHuffmanState::Header => {
                    let Some(last) = self.queue.read_from(1, &mut rest) else { break };
                    self.last = last == 1;
                    self.state = CanonicalHuffmanState::Lengths { symbol: 0 };
                }
                CanonicalHuffmanState::Lengths { symbol } => {
                    while *symbol < CanonicalHuffmanFormat::SYMBOLS {
                        let Some(length) = self.queue.read_from(CanonicalHuffmanFormat::LENGTH_BITS, &mut rest) else {
                            break;
                        };
                        self.lengths[*symbol] = length as u8;
                        *symbol += 1;
                    }
                    if *symbol < CanonicalHuffmanFormat::SYMBOLS {
                        break;
                    }
                    let table = CanonicalHuffmanDecompressor::table(&self.lengths)?;
                    self.state = CanonicalHuffmanState::Symbols { table };
                }
                CanonicalHuffmanState::Symbols { table } => {
                    let invalid = |_| CompressionError::InvalidData { reason: "invalid code" };
                    let Some((symbol, length)) = table.peek(&mut self.queue, &mut rest).map_err(invalid)? else {
                        break;
                    };
                    if symbol == CanonicalHuffmanFormat::END {
                        self.queue.consume(length);
                        // The rest of the byte of the last code is padding.
                        if self.queue.align() != 0 {
                            return Err(CompressionError::InvalidData { reason: "nonzero padding" });
                        }
                        self.state = if self.last { CanonicalHuffmanState::End } else { CanonicalHuffmanState::Header };
                    } else if produced < output.len() {
                        self.queue.consume(length);
                        output[produced] = symbol as u8;
                        produced += 1;
                    } else {
                        break;
                    }
                }
                CanonicalHuffmanState::End => break,
            }
        }
        let finished = self.state == CanonicalHuffmanState::End;
        Ok(Progress { consumed: input.len() - rest.len(), produced, finished })
    }

    fn finish(&mut self) -> Result<(), CompressionError> {
        if self.state == CanonicalHuffmanState::End { Ok(()) } else { Err(CompressionError::UnexpectedEnd) }
    }

    fn reset(&mut self) {
        *self = CanonicalHuffmanDecompressor::new();
    }
}
