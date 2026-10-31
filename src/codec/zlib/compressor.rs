use alloc::vec::Vec;

use super::ZlibFormat;
use crate::codec::deflate::{DeflateCompressor, DeflateConfig};
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};
use crate::hash::adler32::Adler32;

/// Compresses into the zlib format (RFC 1950) with a [`DeflateCompressor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZlibCompressor {
    config: DeflateConfig,
    deflate: DeflateCompressor,
    dictionary: Option<Vec<u8>>,
    checksum: Adler32,
    /// The header (then the trailer) not yet delivered.
    pending: PendingOutput,
    started: bool,
    finished: bool,
}

impl ZlibCompressor {
    /// A compressor of the parameters `config`; fails with `InvalidParameter` outside their ranges.
    pub fn new(config: DeflateConfig) -> Result<ZlibCompressor, CompressionError> {
        Ok(ZlibCompressor {
            config,
            deflate: DeflateCompressor::new(config)?,
            dictionary: None,
            checksum: Adler32::new(),
            pending: PendingOutput::new(),
            started: false,
            finished: false,
        })
    }

    /// A compressor whose streams use `dictionary` as their preset dictionary
    /// (FDICT), which their decompressor must be given.
    pub fn with_dictionary(config: DeflateConfig, dictionary: &[u8]) -> Result<ZlibCompressor, CompressionError> {
        let mut compressor = ZlibCompressor::new(config)?;
        compressor.dictionary = Some(dictionary.to_vec());
        compressor.deflate.set_dictionary(dictionary);
        Ok(compressor)
    }

    pub fn config(&self) -> DeflateConfig {
        self.config
    }
}

impl Default for ZlibCompressor {
    fn default() -> ZlibCompressor {
        ZlibCompressor::new(DeflateConfig::default()).expect("the default parameters are valid")
    }
}

impl Compressor for ZlibCompressor {
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        if !self.started {
            self.pending.extend(&ZlibFormat::header(
                self.config.window_bits,
                self.config.level,
                self.dictionary.is_some(),
            ));
            if let Some(dictionary) = &self.dictionary {
                self.pending.extend(&Adler32::checksum(dictionary).to_be_bytes());
            }
            self.started = true;
        }
        let mut produced = self.pending.deliver(output);
        if !self.pending.is_empty() {
            return Ok(Progress { consumed: 0, produced, finished: false });
        }
        let mut consumed = 0;
        if !self.finished {
            let progress = self.deflate.compress(input, &mut output[produced..], flush)?;
            self.checksum.update(&input[..progress.consumed]);
            consumed = progress.consumed;
            produced += progress.produced;
            if progress.finished {
                self.pending.extend(&self.checksum.value().to_be_bytes());
                self.finished = true;
            }
        }
        produced += self.pending.deliver(&mut output[produced..]);
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.deflate.reset();
        if let Some(dictionary) = &self.dictionary {
            self.deflate.set_dictionary(dictionary);
        }
        self.checksum.reset();
        self.pending.clear();
        self.started = false;
        self.finished = false;
    }
}
