use super::PackBitsFormat;
use crate::codec::{CompressionError, Decompressor, Progress};

/// Where a [`PackBitsDecompressor`] is in its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackBitsState {
    /// Before a header byte.
    Header,
    /// Copying `remaining` bytes of the input.
    Copy { remaining: usize },
    /// Before the byte of a repeat of `count` bytes.
    RepeatByte { count: usize },
    /// Repeating `byte` `remaining` more times.
    Repeat { byte: u8, remaining: usize },
    /// After [`Decompressor::finish`] accepted the end of the input.
    End,
}

/// Decompresses the format of [`PackBitsFormat`]; it needs no buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackBitsDecompressor {
    state: PackBitsState,
}

impl PackBitsDecompressor {
    pub fn new() -> PackBitsDecompressor {
        PackBitsDecompressor { state: PackBitsState::Header }
    }

    pub fn state(&self) -> PackBitsState {
        self.state
    }
}

impl Default for PackBitsDecompressor {
    fn default() -> PackBitsDecompressor {
        PackBitsDecompressor::new()
    }
}

impl Decompressor for PackBitsDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let (mut consumed, mut produced) = (0, 0);
        loop {
            match &mut self.state {
                PackBitsState::Header => {
                    let Some(header) = input.get(consumed) else { break };
                    consumed += 1;
                    self.state = match *header {
                        PackBitsFormat::NO_OPERATION => PackBitsState::Header,
                        header if header < 0x80 => PackBitsState::Copy { remaining: header as usize + 1 },
                        header => PackBitsState::RepeatByte { count: 257 - header as usize },
                    };
                }
                PackBitsState::Copy { remaining } => {
                    let count = (*remaining).min(input.len() - consumed).min(output.len() - produced);
                    output[produced..produced + count].copy_from_slice(&input[consumed..consumed + count]);
                    consumed += count;
                    produced += count;
                    *remaining -= count;
                    if *remaining > 0 {
                        break;
                    }
                    self.state = PackBitsState::Header;
                }
                PackBitsState::RepeatByte { count } => {
                    let Some(byte) = input.get(consumed) else { break };
                    consumed += 1;
                    self.state = PackBitsState::Repeat { byte: *byte, remaining: *count };
                }
                PackBitsState::Repeat { byte, remaining } => {
                    let count = (*remaining).min(output.len() - produced);
                    output[produced..produced + count].fill(*byte);
                    produced += count;
                    *remaining -= count;
                    if *remaining > 0 {
                        break;
                    }
                    self.state = PackBitsState::Header;
                }
                PackBitsState::End => break,
            }
        }
        Ok(Progress { consumed, produced, finished: self.state == PackBitsState::End })
    }

    /// The input may end between runs.
    fn finish(&mut self) -> Result<(), CompressionError> {
        match self.state {
            PackBitsState::Header | PackBitsState::End => {
                self.state = PackBitsState::End;
                Ok(())
            }
            _ => Err(CompressionError::UnexpectedEnd),
        }
    }

    fn reset(&mut self) {
        self.state = PackBitsState::Header;
    }
}
