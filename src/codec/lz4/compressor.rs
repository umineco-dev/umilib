use alloc::vec::Vec;

use super::{LZ4Block, LZ4Config, LZ4FrameFormat};
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};
use crate::hash::xxhash::xxh32::XXH32;

/// Compresses into an LZ4 frame (lz4_Frame_format.md): blocks of
/// [`LZ4Config::block_size`], each compressed (or stored uncompressed when
/// that is not smaller), with the checksums and fields the config asks for.
#[derive(Clone, Debug)]
pub struct LZ4Compressor {
    config: LZ4Config,
    block: LZ4Block,
    /// The input of the block being filled.
    buffer: Vec<u8>,
    pending: PendingOutput,
    content: XXH32,
    size: u64,
    started: bool,
    finished: bool,
}

impl LZ4Compressor {
    /// A compressor of the parameters `config`; fails with `InvalidParameter` for a level beyond 12.
    pub fn new(config: LZ4Config) -> Result<LZ4Compressor, CompressionError> {
        let mut block = LZ4Block::new(config.level)?;
        block.reset(config.dictionary.as_deref().unwrap_or(&[]));
        Ok(LZ4Compressor {
            config,
            block,
            buffer: Vec::new(),
            pending: PendingOutput::new(),
            content: XXH32::new(),
            size: 0,
            started: false,
            finished: false,
        })
    }

    pub fn config(&self) -> &LZ4Config {
        &self.config
    }

    /// The magic number and the frame descriptor.
    pub fn header_bytes(&self) -> Vec<u8> {
        let config = &self.config;
        let mut flags = LZ4FrameFormat::VERSION;
        for (present, flag) in [
            (config.independent_blocks, LZ4FrameFormat::BLOCK_INDEPENDENCE),
            (config.block_checksum, LZ4FrameFormat::BLOCK_CHECKSUM),
            (config.content_size.is_some(), LZ4FrameFormat::CONTENT_SIZE),
            (config.content_checksum, LZ4FrameFormat::CONTENT_CHECKSUM),
            (config.dictionary_identifier.is_some(), LZ4FrameFormat::DICTIONARY_IDENTIFIER),
        ] {
            if present {
                flags |= flag;
            }
        }
        let mut descriptor = alloc::vec![flags, config.block_size.code() << 4];
        if let Some(size) = config.content_size {
            descriptor.extend_from_slice(&size.to_le_bytes());
        }
        if let Some(identifier) = config.dictionary_identifier {
            descriptor.extend_from_slice(&identifier.to_le_bytes());
        }
        descriptor.push((XXH32::hash(0, &descriptor) >> 8) as u8);
        let mut bytes = LZ4FrameFormat::MAGIC.to_le_bytes().to_vec();
        bytes.extend_from_slice(&descriptor);
        bytes
    }

    /// Writes the buffered input as a block.
    pub fn write_block(&mut self) {
        if self.config.independent_blocks {
            self.block.reset(self.config.dictionary.as_deref().unwrap_or(&[]));
        }
        let mut encoded = Vec::new();
        self.block.encode(&self.buffer, &mut encoded);
        let (size, data) = if encoded.len() < self.buffer.len() {
            (encoded.len() as u32, &encoded[..])
        } else {
            (self.buffer.len() as u32 | LZ4FrameFormat::UNCOMPRESSED, &self.buffer[..])
        };
        self.pending.extend(&size.to_le_bytes());
        self.pending.extend(data);
        if self.config.block_checksum {
            self.pending.extend(&XXH32::hash(0, data).to_le_bytes());
        }
        self.content.update(&self.buffer);
        self.size += self.buffer.len() as u64;
        self.buffer.clear();
    }
}

impl Default for LZ4Compressor {
    fn default() -> LZ4Compressor {
        LZ4Compressor::new(LZ4Config::default()).expect("the default parameters are valid")
    }
}

impl Compressor for LZ4Compressor {
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        if !self.started {
            let header = self.header_bytes();
            self.pending.extend(&header);
            self.started = true;
        }
        let (mut consumed, mut produced) = (0, 0);
        let block_size = self.config.block_size.bytes();
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() || self.finished {
                break;
            }
            let take = (input.len() - consumed).min(block_size - self.buffer.len());
            self.buffer.extend_from_slice(&input[consumed..consumed + take]);
            consumed += take;
            if consumed < input.len() {
                // The block is full.
                self.write_block();
                continue;
            }
            match flush {
                Flush::None if self.buffer.len() == block_size => self.write_block(),
                Flush::None => break,
                Flush::Sync if !self.buffer.is_empty() => self.write_block(),
                Flush::Sync => break,
                Flush::Finish => {
                    if !self.buffer.is_empty() {
                        self.write_block();
                    }
                    if self.config.content_size.is_some_and(|size| size != self.size) {
                        return Err(CompressionError::InvalidParameter);
                    }
                    self.pending.extend(&[0; 4]);
                    if self.config.content_checksum {
                        self.pending.extend(&self.content.value().to_le_bytes());
                    }
                    self.finished = true;
                }
            }
        }
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.block.reset(self.config.dictionary.as_deref().unwrap_or(&[]));
        self.buffer.clear();
        self.pending.clear();
        self.content.reset();
        self.size = 0;
        self.started = false;
        self.finished = false;
    }
}
