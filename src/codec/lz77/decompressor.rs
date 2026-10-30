use super::{LZ77Format, LZ77Window};
use crate::codec::{CompressionError, Decompressor, Progress};

/// Where an [`LZ77Decompressor`] is in its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LZ77State {
    /// Reading the 2 bytes of a token header: `count` of them so far.
    Header { bytes: [u8; 2], count: usize },
    /// Copying the `remaining` bytes of a match `distance` bytes back.
    Copy { distance: usize, remaining: usize },
    /// The byte that ends a token.
    Literal,
    /// After the stream.
    End,
}

/// Decompresses the format of [`LZ77Format`] through a window of 4096 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZ77Decompressor {
    window: LZ77Window,
    state: LZ77State,
}

impl LZ77Decompressor {
    pub fn new() -> LZ77Decompressor {
        LZ77Decompressor {
            window: LZ77Window::new(LZ77Format::WINDOW),
            state: LZ77State::Header { bytes: [0; 2], count: 0 },
        }
    }

    pub fn state(&self) -> LZ77State {
        self.state
    }
}

impl Default for LZ77Decompressor {
    fn default() -> LZ77Decompressor {
        LZ77Decompressor::new()
    }
}

impl Decompressor for LZ77Decompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let (mut consumed, mut produced) = (0, 0);
        loop {
            match &mut self.state {
                LZ77State::Header { bytes, count } => {
                    while *count < 2 && consumed < input.len() {
                        bytes[*count] = input[consumed];
                        *count += 1;
                        consumed += 1;
                    }
                    if *count < 2 {
                        break;
                    }
                    let header = u16::from_be_bytes(*bytes);
                    let (field, length) = (header >> 4, (header & 0xF) as usize);
                    self.state = match (field, length) {
                        (0, 0) => LZ77State::Literal,
                        (LZ77Format::END, 0) => LZ77State::End,
                        (_, 0) => return Err(CompressionError::InvalidData { reason: "invalid token" }),
                        _ => LZ77State::Copy { distance: field as usize + 1, remaining: length },
                    };
                }
                LZ77State::Copy { distance, remaining } => {
                    let copied = self.window.copy(*distance, *remaining, &mut output[produced..])?;
                    produced += copied;
                    *remaining -= copied;
                    if *remaining > 0 {
                        break;
                    }
                    self.state = LZ77State::Literal;
                }
                LZ77State::Literal => {
                    if consumed == input.len() || produced == output.len() {
                        break;
                    }
                    output[produced] = input[consumed];
                    self.window.push(input[consumed]);
                    consumed += 1;
                    produced += 1;
                    self.state = LZ77State::Header { bytes: [0; 2], count: 0 };
                }
                LZ77State::End => break,
            }
        }
        Ok(Progress { consumed, produced, finished: self.state == LZ77State::End })
    }

    fn finish(&mut self) -> Result<(), CompressionError> {
        if self.state == LZ77State::End { Ok(()) } else { Err(CompressionError::UnexpectedEnd) }
    }

    fn reset(&mut self) {
        self.window.clear();
        self.state = LZ77State::Header { bytes: [0; 2], count: 0 };
    }
}
