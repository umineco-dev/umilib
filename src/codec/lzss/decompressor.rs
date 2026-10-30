use super::{LZSSConfig, LZSSFormat};
use crate::bytes::{BitOrder, BitQueue};
use crate::codec::lz77::LZ77Window;
use crate::codec::{CompressionError, Decompressor, Progress};

/// Where an [`LZSSDecompressor`] is in its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LZSSState {
    /// At the start of a token.
    Token,
    /// Copying the `remaining` bytes of a match `distance` bytes back.
    Copy { distance: usize, remaining: usize },
    /// After [`Decompressor::finish`] accepted the end of the input.
    End,
}

/// Decompresses the format of [`LZSSFormat`] through its ring buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZSSDecompressor {
    config: LZSSConfig,
    window: LZ77Window,
    queue: BitQueue,
    state: LZSSState,
}

impl LZSSDecompressor {
    /// A decompressor of the parameters `config`; fails with `InvalidParameter` outside their ranges.
    pub fn new(config: LZSSConfig) -> Result<LZSSDecompressor, CompressionError> {
        config.check()?;
        Ok(LZSSDecompressor {
            config,
            window: LZ77Window::with_dictionary(config.ring_size(), &config.dictionary()),
            queue: BitQueue::with_order(BitOrder::MostSignificantFirst),
            state: LZSSState::Token,
        })
    }

    pub fn config(&self) -> LZSSConfig {
        self.config
    }

    pub fn state(&self) -> LZSSState {
        self.state
    }

    /// The distance back of the ring position `position` from the next byte's.
    pub fn distance(&self, position: usize) -> usize {
        let n = self.config.ring_size();
        let next = (self.window.total() as usize).wrapping_add(n - self.config.maximum_length()) % n;
        // The next byte's own position holds the byte N back, which it is about to replace.
        match (next + n - position) % n {
            0 => n,
            distance => distance,
        }
    }
}

impl Decompressor for LZSSDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let mut rest = input;
        let mut produced = 0;
        loop {
            match &mut self.state {
                LZSSState::Token => {
                    // A whole token is taken at once, so the input may end between tokens only.
                    if !self.queue.fill(1, &mut rest) {
                        break;
                    }
                    let literal = self.queue.peek(1) == Some(1);
                    let bits = if literal { 9 } else { 1 + self.config.position_bits + self.config.length_bits };
                    if !self.queue.fill(bits, &mut rest) {
                        break;
                    }
                    if literal {
                        if produced == output.len() {
                            break;
                        }
                        let byte = self.queue.read(9).unwrap_or(0) as u8;
                        output[produced] = byte;
                        self.window.push(byte);
                        produced += 1;
                    } else {
                        self.queue.consume(1);
                        let position = self.queue.read(self.config.position_bits).unwrap_or(0) as usize;
                        let length =
                            self.queue.read(self.config.length_bits).unwrap_or(0) as usize + LZSSFormat::MINIMUM_LENGTH;
                        self.state = LZSSState::Copy { distance: self.distance(position), remaining: length };
                    }
                }
                LZSSState::Copy { distance, remaining } => {
                    let copied = self.window.copy(*distance, *remaining, &mut output[produced..])?;
                    produced += copied;
                    *remaining -= copied;
                    if *remaining > 0 {
                        break;
                    }
                    self.state = LZSSState::Token;
                }
                LZSSState::End => break,
            }
        }
        Ok(Progress { consumed: input.len() - rest.len(), produced, finished: self.state == LZSSState::End })
    }

    /// The input may end between tokens, followed by fewer than 8 zero bits.
    fn finish(&mut self) -> Result<(), CompressionError> {
        match self.state {
            LZSSState::End => Ok(()),
            LZSSState::Token if self.queue.count() < 8 && self.queue.peek_padded(self.queue.count()) == 0 => {
                self.state = LZSSState::End;
                Ok(())
            }
            _ => Err(CompressionError::UnexpectedEnd),
        }
    }

    fn reset(&mut self) {
        self.window = LZ77Window::with_dictionary(self.config.ring_size(), &self.config.dictionary());
        self.queue.clear();
        self.state = LZSSState::Token;
    }
}
