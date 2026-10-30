use alloc::vec::Vec;

use super::{LZ4Block, LZ4DecompressorConfig, LZ4FrameFormat};
use crate::codec::{CompressionError, Decompressor, PendingOutput, Progress};
use crate::hash::xxhash::xxh32::XXH32;

/// Where an [`LZ4Decompressor`] is in its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LZ4State {
    /// Reading the magic number of a frame.
    Magic,
    /// Reading the frame descriptor.
    Descriptor,
    /// Reading the size of a block (or the end mark).
    BlockSize,
    /// Reading a block of `size` bytes (and its checksum).
    Block {
        size: usize,
        uncompressed: bool,
    },
    /// Reading the content checksum.
    ContentChecksum,
    /// Reading the size of a skippable frame, then skipping its data.
    SkippableSize,
    Skip {
        remaining: u64,
    },
    /// Reading the compressed size of a block of a legacy frame, then the block.
    LegacySize,
    LegacyBlock {
        size: usize,
    },
    /// After a frame, when frames may follow.
    Between,
    /// After the only frame.
    End,
}

/// Decompresses LZ4 frames (lz4_Frame_format.md), skippable frames and
/// legacy frames, checking the reserved bits, the version, the header,
/// block and content checksums, the block sizes and the content size. By
/// default the input is a series of frames that ends with it
/// ([`LZ4DecompressorConfig::multiple_frames`]).
#[derive(Clone, Debug)]
pub struct LZ4Decompressor {
    config: LZ4DecompressorConfig,
    state: LZ4State,
    /// The bytes of the field being read.
    field: Vec<u8>,
    /// The flags and the block maximum size of the frame, its content size.
    flags: u8,
    block_size: usize,
    content_size: Option<u64>,
    /// The bytes of the block being read.
    block: Vec<u8>,
    /// The history blocks refer to: the dictionary, then (for linked blocks) the last 64 KiB.
    history: Vec<u8>,
    pending: PendingOutput,
    content: XXH32,
    size: u64,
    frames: usize,
}

impl LZ4Decompressor {
    pub fn new(config: LZ4DecompressorConfig) -> LZ4Decompressor {
        LZ4Decompressor {
            config,
            state: LZ4State::Magic,
            field: Vec::new(),
            flags: 0,
            block_size: 0,
            content_size: None,
            block: Vec::new(),
            history: Vec::new(),
            pending: PendingOutput::new(),
            content: XXH32::new(),
            size: 0,
            frames: 0,
        }
    }

    pub fn state(&self) -> LZ4State {
        self.state
    }

    /// The number of frames read completely (skippable frames included).
    pub fn frames(&self) -> usize {
        self.frames
    }

    /// Fills the field to `length` bytes from `input`; whether it is complete.
    pub fn fill(&mut self, length: usize, input: &mut &[u8]) -> bool {
        let count = (length.saturating_sub(self.field.len())).min(input.len());
        self.field.extend_from_slice(&input[..count]);
        *input = &input[count..];
        self.field.len() >= length
    }

    /// The little-endian value of the 4 bytes of the field, which is emptied.
    pub fn take_u32(&mut self) -> u32 {
        let value = u32::from_le_bytes([self.field[0], self.field[1], self.field[2], self.field[3]]);
        self.field.clear();
        value
    }

    /// The state after the magic number `magic`.
    pub fn after_magic(&mut self, magic: u32) -> Result<LZ4State, CompressionError> {
        match magic {
            LZ4FrameFormat::MAGIC => Ok(LZ4State::Descriptor),
            magic if magic & 0xFFFF_FFF0 == LZ4FrameFormat::SKIPPABLE_MAGIC => Ok(LZ4State::SkippableSize),
            LZ4FrameFormat::LEGACY_MAGIC => {
                if self.config.maximum_block_size < LZ4FrameFormat::LEGACY_BLOCK_SIZE {
                    return Err(CompressionError::LimitExceeded { limit: self.config.maximum_block_size as u64 });
                }
                Ok(LZ4State::LegacySize)
            }
            _ => Err(CompressionError::InvalidData { reason: "unknown magic number" }),
        }
    }

    /// The state after a frame.
    pub fn end_frame(&mut self) -> LZ4State {
        self.frames += 1;
        if self.config.multiple_frames { LZ4State::Between } else { LZ4State::End }
    }

    /// Reads the frame descriptor in the field: checks it and starts the frame.
    pub fn read_descriptor(&mut self) -> Result<(), CompressionError> {
        let (flags, descriptor) = (self.field[0], self.field[1]);
        let length = self.field.len();
        if XXH32::hash(0, &self.field[..length - 1]) >> 8 & 0xFF != self.field[length - 1] as u32 {
            return Err(CompressionError::ChecksumMismatch);
        }
        if flags & 0xC0 != LZ4FrameFormat::VERSION {
            return Err(CompressionError::InvalidData { reason: "unsupported version" });
        }
        if flags & LZ4FrameFormat::RESERVED_FLAGS != 0 || descriptor & LZ4FrameFormat::RESERVED_BLOCK_DESCRIPTOR != 0 {
            return Err(CompressionError::InvalidData { reason: "reserved bits set" });
        }
        let block_size = LZ4FrameFormat::block_size(descriptor >> 4)
            .ok_or(CompressionError::InvalidData { reason: "invalid block maximum size" })?;
        if block_size > self.config.maximum_block_size {
            return Err(CompressionError::LimitExceeded { limit: self.config.maximum_block_size as u64 });
        }
        let mut position = 2;
        self.content_size = None;
        if flags & LZ4FrameFormat::CONTENT_SIZE != 0 {
            self.content_size = Some(u64::from_le_bytes(self.field[2..10].try_into().expect("8 bytes")));
            position += 8;
        }
        if flags & LZ4FrameFormat::DICTIONARY_IDENTIFIER != 0 {
            let identifier = u32::from_le_bytes(self.field[position..position + 4].try_into().expect("4 bytes"));
            let matches = self.config.dictionary.is_some()
                && self.config.dictionary_identifier.is_none_or(|expected| expected == identifier);
            if !matches {
                return Err(CompressionError::MissingDictionary { identifier });
            }
        }
        self.flags = flags;
        self.block_size = block_size;
        self.content.reset();
        self.size = 0;
        self.restart_history();
        self.field.clear();
        Ok(())
    }

    /// Makes the history the dictionary (its last 64 KiB), or nothing.
    pub fn restart_history(&mut self) {
        self.history.clear();
        if let Some(dictionary) = &self.config.dictionary {
            self.history.extend_from_slice(&dictionary[dictionary.len().saturating_sub(LZ4Block::MAXIMUM_OFFSET)..]);
        }
    }

    /// Decodes a block of the frame (or of a legacy frame if `legacy`) from
    /// `self.block` into the pending output and the history.
    pub fn decode_block(&mut self, uncompressed: bool, legacy: bool) -> Result<(), CompressionError> {
        let independent = legacy || self.flags & LZ4FrameFormat::BLOCK_INDEPENDENCE != 0;
        if independent {
            self.restart_history();
        }
        let start = self.history.len();
        let limit = if legacy { LZ4FrameFormat::LEGACY_BLOCK_SIZE } else { self.block_size };
        if uncompressed {
            self.history.extend_from_slice(&self.block);
        } else {
            LZ4Block::decode(&self.block, &mut self.history, limit).map_err(|error| match error {
                CompressionError::LimitExceeded { .. } => {
                    CompressionError::InvalidData { reason: "block larger than the maximum" }
                }
                error => error,
            })?;
        }
        let data = &self.history[start..];
        self.pending.extend(data);
        if !legacy {
            self.content.update(data);
            self.size += data.len() as u64;
        }
        // Linked blocks keep the last 64 KiB.
        let keep = self.history.len().saturating_sub(LZ4Block::MAXIMUM_OFFSET);
        self.history.drain(..keep);
        self.block.clear();
        Ok(())
    }
}

impl Default for LZ4Decompressor {
    fn default() -> LZ4Decompressor {
        LZ4Decompressor::new(LZ4DecompressorConfig::default())
    }
}

impl Decompressor for LZ4Decompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let mut rest = input;
        let mut produced = 0;
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() {
                break;
            }
            match self.state {
                LZ4State::Magic | LZ4State::Between => {
                    if self.state == LZ4State::Between && rest.is_empty() {
                        break;
                    }
                    if !self.fill(4, &mut rest) {
                        self.state = LZ4State::Magic;
                        break;
                    }
                    let magic = self.take_u32();
                    self.state = self.after_magic(magic)?;
                }
                LZ4State::Descriptor => {
                    if !self.fill(2, &mut rest) {
                        break;
                    }
                    let flags = self.field[0];
                    let length = 3
                        + if flags & LZ4FrameFormat::CONTENT_SIZE != 0 { 8 } else { 0 }
                        + if flags & LZ4FrameFormat::DICTIONARY_IDENTIFIER != 0 { 4 } else { 0 };
                    if !self.fill(length, &mut rest) {
                        break;
                    }
                    self.read_descriptor()?;
                    self.state = LZ4State::BlockSize;
                }
                LZ4State::BlockSize => {
                    if !self.fill(4, &mut rest) {
                        break;
                    }
                    let value = self.take_u32();
                    if value == 0 {
                        self.state = if self.flags & LZ4FrameFormat::CONTENT_CHECKSUM != 0 {
                            LZ4State::ContentChecksum
                        } else {
                            self.end_content()?
                        };
                        continue;
                    }
                    let size = (value & !LZ4FrameFormat::UNCOMPRESSED) as usize;
                    if size > self.block_size {
                        return Err(CompressionError::InvalidData { reason: "block larger than the maximum" });
                    }
                    self.state = LZ4State::Block { size, uncompressed: value & LZ4FrameFormat::UNCOMPRESSED != 0 };
                }
                LZ4State::Block { size, uncompressed } => {
                    let checksum = if self.flags & LZ4FrameFormat::BLOCK_CHECKSUM != 0 { 4 } else { 0 };
                    let count = (size + checksum - self.block.len()).min(rest.len());
                    self.block.extend_from_slice(&rest[..count]);
                    rest = &rest[count..];
                    if self.block.len() < size + checksum {
                        break;
                    }
                    if checksum > 0 {
                        let expected = u32::from_le_bytes(self.block[size..].try_into().expect("4 bytes"));
                        self.block.truncate(size);
                        if XXH32::hash(0, &self.block) != expected {
                            return Err(CompressionError::ChecksumMismatch);
                        }
                    }
                    self.decode_block(uncompressed, false)?;
                    self.state = LZ4State::BlockSize;
                }
                LZ4State::ContentChecksum => {
                    if !self.fill(4, &mut rest) {
                        break;
                    }
                    if self.take_u32() != self.content.value() {
                        return Err(CompressionError::ChecksumMismatch);
                    }
                    self.state = self.end_content()?;
                }
                LZ4State::SkippableSize => {
                    if !self.fill(4, &mut rest) {
                        break;
                    }
                    self.state = LZ4State::Skip { remaining: self.take_u32() as u64 };
                }
                LZ4State::Skip { remaining } => {
                    let count = (remaining.min(rest.len() as u64)) as usize;
                    rest = &rest[count..];
                    if (count as u64) < remaining {
                        self.state = LZ4State::Skip { remaining: remaining - count as u64 };
                        break;
                    }
                    self.state = self.end_frame();
                }
                LZ4State::LegacySize => {
                    if !self.fill(4, &mut rest) {
                        break;
                    }
                    let value = self.take_u32();
                    // A legacy frame ends at another magic number, or at a size of 0 (the Linux extension).
                    if value == 0 {
                        self.state = self.end_frame();
                    } else if value == LZ4FrameFormat::MAGIC
                        || value & 0xFFFF_FFF0 == LZ4FrameFormat::SKIPPABLE_MAGIC
                        || value == LZ4FrameFormat::LEGACY_MAGIC
                    {
                        self.frames += 1;
                        self.state = self.after_magic(value)?;
                    } else {
                        let bound = LZ4FrameFormat::LEGACY_BLOCK_SIZE + LZ4FrameFormat::LEGACY_BLOCK_SIZE / 255 + 16;
                        if value as usize > bound {
                            return Err(CompressionError::InvalidData { reason: "block larger than the maximum" });
                        }
                        self.state = LZ4State::LegacyBlock { size: value as usize };
                    }
                }
                LZ4State::LegacyBlock { size } => {
                    let count = (size - self.block.len()).min(rest.len());
                    self.block.extend_from_slice(&rest[..count]);
                    rest = &rest[count..];
                    if self.block.len() < size {
                        break;
                    }
                    self.decode_block(false, true)?;
                    self.state = LZ4State::LegacySize;
                }
                LZ4State::End => break,
            }
        }
        let finished = self.state == LZ4State::End && self.pending.is_empty();
        Ok(Progress { consumed: input.len() - rest.len(), produced, finished })
    }

    /// The input may end after a frame, or between the blocks of a legacy frame.
    fn finish(&mut self) -> Result<(), CompressionError> {
        if !self.pending.is_empty() {
            return Err(CompressionError::UnexpectedEnd);
        }
        match self.state {
            LZ4State::End => Ok(()),
            LZ4State::Between => {
                self.state = LZ4State::End;
                Ok(())
            }
            LZ4State::LegacySize if self.field.is_empty() => {
                self.frames += 1;
                self.state = LZ4State::End;
                Ok(())
            }
            _ => Err(CompressionError::UnexpectedEnd),
        }
    }

    fn reset(&mut self) {
        self.state = LZ4State::Magic;
        self.field.clear();
        self.block.clear();
        self.history.clear();
        self.pending.clear();
        self.content.reset();
        self.size = 0;
        self.frames = 0;
    }
}

impl LZ4Decompressor {
    /// Checks the content size of the frame that ends, and ends it.
    pub fn end_content(&mut self) -> Result<LZ4State, CompressionError> {
        if self.content_size.is_some_and(|size| size != self.size) {
            return Err(CompressionError::InvalidData { reason: "content size mismatch" });
        }
        Ok(self.end_frame())
    }
}
