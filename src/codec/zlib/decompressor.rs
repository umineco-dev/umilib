use alloc::vec::Vec;

use super::ZlibFormat;
use crate::codec::deflate::{DeflateDecompressor, DeflateDecompressorConfig};
use crate::codec::{CompressionError, Decompressor, Progress};
use crate::hash::adler32::Adler32;

/// Where a [`ZlibDecompressor`] is in its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZlibState {
    /// Reading the 2 bytes of the header.
    Header,
    /// Reading the 4 bytes of the identifier of the preset dictionary.
    DictionaryIdentifier,
    /// Decompressing the Deflate stream.
    Data,
    /// Reading the 4 bytes of the Adler-32 of the data.
    Trailer,
    /// After the stream.
    End,
}

/// Decompresses the zlib format (RFC 1950): checks the header (the method,
/// the window within the configured one, FCHECK), the dictionary it names,
/// and the Adler-32 of the data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZlibDecompressor {
    config: DeflateDecompressorConfig,
    deflate: DeflateDecompressor,
    dictionary: Option<Vec<u8>>,
    checksum: Adler32,
    field: [u8; 4],
    filled: usize,
    state: ZlibState,
}

impl ZlibDecompressor {
    /// A decompressor whose window holds 2^`config.window_bits` bytes:
    /// streams announcing a larger window fail with `LimitExceeded`.
    pub fn new(config: DeflateDecompressorConfig) -> Result<ZlibDecompressor, CompressionError> {
        Ok(ZlibDecompressor {
            config,
            deflate: DeflateDecompressor::new(config)?,
            dictionary: None,
            checksum: Adler32::new(),
            field: [0; 4],
            filled: 0,
            state: ZlibState::Header,
        })
    }

    /// A decompressor that gives `dictionary` to the streams that name it.
    pub fn with_dictionary(
        config: DeflateDecompressorConfig,
        dictionary: &[u8],
    ) -> Result<ZlibDecompressor, CompressionError> {
        let mut decompressor = ZlibDecompressor::new(config)?;
        decompressor.dictionary = Some(dictionary.to_vec());
        Ok(decompressor)
    }

    pub fn state(&self) -> ZlibState {
        self.state
    }

    /// Fills the field to `length` bytes from `input`; whether it is complete.
    pub fn fill(&mut self, length: usize, input: &mut &[u8]) -> bool {
        let count = (length - self.filled).min(input.len());
        self.field[self.filled..self.filled + count].copy_from_slice(&input[..count]);
        self.filled += count;
        *input = &input[count..];
        if self.filled < length {
            return false;
        }
        self.filled = 0;
        true
    }
}

impl Default for ZlibDecompressor {
    fn default() -> ZlibDecompressor {
        ZlibDecompressor::new(DeflateDecompressorConfig::default()).expect("the default window is valid")
    }
}

impl Decompressor for ZlibDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let mut rest = input;
        let mut produced = 0;
        loop {
            match self.state {
                ZlibState::Header => {
                    if !self.fill(2, &mut rest) {
                        break;
                    }
                    let (method, flags) = (self.field[0], self.field[1]);
                    if method & 0x0F != ZlibFormat::DEFLATE || method >> 4 > ZlibFormat::MAXIMUM_WINDOW_INFORMATION {
                        return Err(CompressionError::InvalidData { reason: "invalid compression method" });
                    }
                    if !(method as u16 * 256 + flags as u16).is_multiple_of(31) {
                        return Err(CompressionError::InvalidData { reason: "invalid header check" });
                    }
                    let window_bits = (method >> 4) as u32 + 8;
                    if window_bits > self.config.window_bits {
                        return Err(CompressionError::LimitExceeded { limit: 1 << self.config.window_bits });
                    }
                    self.state = if flags & ZlibFormat::PRESET_DICTIONARY != 0 {
                        ZlibState::DictionaryIdentifier
                    } else {
                        ZlibState::Data
                    };
                }
                ZlibState::DictionaryIdentifier => {
                    if !self.fill(4, &mut rest) {
                        break;
                    }
                    let identifier = u32::from_be_bytes(self.field);
                    match &self.dictionary {
                        Some(dictionary) if Adler32::checksum(dictionary) == identifier => {
                            self.deflate.set_dictionary(dictionary)
                        }
                        _ => return Err(CompressionError::MissingDictionary { identifier }),
                    }
                    self.state = ZlibState::Data;
                }
                ZlibState::Data => {
                    let progress = self.deflate.decompress(rest, &mut output[produced..])?;
                    self.checksum.update(&output[produced..produced + progress.produced]);
                    rest = &rest[progress.consumed..];
                    produced += progress.produced;
                    if !progress.finished {
                        break;
                    }
                    self.state = ZlibState::Trailer;
                }
                ZlibState::Trailer => {
                    if !self.fill(4, &mut rest) {
                        break;
                    }
                    if u32::from_be_bytes(self.field) != self.checksum.value() {
                        return Err(CompressionError::ChecksumMismatch);
                    }
                    self.state = ZlibState::End;
                }
                ZlibState::End => break,
            }
        }
        Ok(Progress { consumed: input.len() - rest.len(), produced, finished: self.state == ZlibState::End })
    }

    fn finish(&mut self) -> Result<(), CompressionError> {
        if self.state == ZlibState::End { Ok(()) } else { Err(CompressionError::UnexpectedEnd) }
    }

    fn reset(&mut self) {
        self.deflate.reset();
        self.checksum.reset();
        self.filled = 0;
        self.state = ZlibState::Header;
    }
}
