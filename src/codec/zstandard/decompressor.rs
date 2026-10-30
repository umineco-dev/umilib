use alloc::vec::Vec;

use super::{
    ZstandardBlockDecoder, ZstandardDecompressorConfig, ZstandardFormat, ZstandardOffsets, ZstandardSequenceTables,
};
use crate::codec::lz77::LZ77Window;
use crate::codec::{CompressionError, Decompressor, PendingOutput, Progress};
use crate::hash::xxhash::xxh64::XXH64;

/// Where a [`ZstandardDecompressor`] is in its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZstandardState {
    /// Reading the magic number of a frame.
    Magic,
    /// Reading the frame header: its descriptor, then the rest of its `length` bytes.
    Descriptor,
    Header {
        length: usize,
    },
    /// Reading a block header, then its content of `size` bytes.
    BlockHeader,
    Block {
        kind: u8,
        size: usize,
        last: bool,
    },
    /// Reading the content checksum.
    Checksum,
    /// Reading the size of a skippable frame, then skipping its data.
    SkippableSize,
    Skip {
        remaining: u64,
    },
    /// After a frame, when frames may follow.
    Between,
    /// After the only frame.
    End,
}

/// Decompresses Zstandard frames and skippable frames (RFC 8878), checking
/// the reserved bits, the window (within the configured limit), the block
/// sizes and contents, the content size and the content checksum. By
/// default the input is a series of frames that ends with it
/// ([`ZstandardDecompressorConfig::multiple_frames`]).
#[derive(Clone, Debug)]
pub struct ZstandardDecompressor {
    config: ZstandardDecompressorConfig,
    state: ZstandardState,
    field: Vec<u8>,
    block: Vec<u8>,
    window: LZ77Window,
    blocks: ZstandardBlockDecoder,
    pending: PendingOutput,
    /// The frame: its flags, window size, content size, dictionary bytes in the window, bytes so far.
    descriptor: u8,
    window_size: u64,
    content_size: Option<u64>,
    dictionary: u64,
    size: u64,
    checksum: XXH64,
    frames: usize,
}

impl ZstandardDecompressor {
    pub fn new(config: ZstandardDecompressorConfig) -> ZstandardDecompressor {
        ZstandardDecompressor {
            config,
            state: ZstandardState::Magic,
            field: Vec::new(),
            block: Vec::new(),
            window: LZ77Window::new(1),
            blocks: ZstandardBlockDecoder::new(),
            pending: PendingOutput::new(),
            descriptor: 0,
            window_size: 0,
            content_size: None,
            dictionary: 0,
            size: 0,
            checksum: XXH64::new(),
            frames: 0,
        }
    }

    pub fn state(&self) -> ZstandardState {
        self.state
    }

    /// The number of frames read completely (skippable frames included).
    pub fn frames(&self) -> usize {
        self.frames
    }

    /// Fills the field to `length` bytes from `input`; whether it is complete.
    pub fn fill(&mut self, length: usize, input: &mut &[u8]) -> bool {
        let count = length.saturating_sub(self.field.len()).min(input.len());
        self.field.extend_from_slice(&input[..count]);
        *input = &input[count..];
        self.field.len() >= length
    }

    /// The length of the frame header of the descriptor `descriptor`.
    pub fn header_length(descriptor: u8) -> usize {
        let single = descriptor & 0x20 != 0;
        let window = if single { 0 } else { 1 };
        let identifier = [0, 1, 2, 4][(descriptor & 3) as usize];
        let size = match descriptor >> 6 {
            0 => single as usize,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        1 + window + identifier + size
    }

    /// Reads the frame header in the field and starts the frame.
    pub fn read_header(&mut self) -> Result<(), CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        let header = core::mem::take(&mut self.field);
        let descriptor = header[0];
        if descriptor & 0x08 != 0 {
            return Err(invalid("reserved bit set"));
        }
        let single = descriptor & 0x20 != 0;
        let mut position = 1;
        let mut window_size = 0;
        if !single {
            window_size = ZstandardFormat::window_size(header[1]);
            position = 2;
        }
        let identifier_length = [0, 1, 2, 4][(descriptor & 3) as usize];
        let mut identifier = 0u32;
        for (index, byte) in header[position..position + identifier_length].iter().enumerate() {
            identifier |= (*byte as u32) << (8 * index);
        }
        position += identifier_length;
        let size_bytes = &header[position..];
        let mut value = 0u64;
        for (index, byte) in size_bytes.iter().enumerate() {
            value |= (*byte as u64) << (8 * index);
        }
        self.content_size = match size_bytes.len() {
            0 => None,
            2 => Some(value + 256),
            _ => Some(value),
        };
        if single {
            window_size = self.content_size.expect("a single segment has a content size").max(1);
        }
        if window_size > self.config.maximum_window {
            return Err(CompressionError::LimitExceeded { limit: self.config.maximum_window });
        }
        // The dictionary: the one named, or raw content for frames that name none.
        self.blocks = ZstandardBlockDecoder::new();
        let dictionary = match (&self.config.dictionary, identifier) {
            (Some(dictionary), 0) => Some(dictionary),
            (Some(dictionary), identifier) if dictionary.identifier == identifier => Some(dictionary),
            (_, 0) => None,
            (_, identifier) => return Err(CompressionError::MissingDictionary { identifier }),
        };
        let content: &[u8] = dictionary.map_or(&[], |dictionary| &dictionary.content);
        self.window = LZ77Window::with_dictionary(window_size as usize + content.len(), content);
        self.dictionary = content.len() as u64;
        if let Some(dictionary) = dictionary {
            self.blocks.huffman = dictionary.huffman.clone();
            self.blocks.tables = dictionary.tables.clone();
            self.blocks.offsets = dictionary.offsets;
        } else {
            self.blocks.tables = ZstandardSequenceTables::default();
            self.blocks.offsets = ZstandardOffsets::new();
        }
        self.descriptor = descriptor;
        self.window_size = window_size;
        self.size = 0;
        self.checksum.reset();
        Ok(())
    }

    /// The state after a frame.
    pub fn end_frame(&mut self) -> ZstandardState {
        self.frames += 1;
        if self.config.multiple_frames { ZstandardState::Between } else { ZstandardState::End }
    }

    /// Checks the content size of the frame that ends.
    pub fn check_size(&self) -> Result<(), CompressionError> {
        if self.content_size.is_some_and(|size| size != self.size) {
            return Err(CompressionError::InvalidData { reason: "content size mismatch" });
        }
        Ok(())
    }
}

impl Default for ZstandardDecompressor {
    fn default() -> ZstandardDecompressor {
        ZstandardDecompressor::new(ZstandardDecompressorConfig::default())
    }
}

impl Decompressor for ZstandardDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let mut rest = input;
        let mut produced = 0;
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() {
                break;
            }
            match self.state {
                ZstandardState::Magic | ZstandardState::Between => {
                    if self.state == ZstandardState::Between && rest.is_empty() {
                        break;
                    }
                    if !self.fill(4, &mut rest) {
                        self.state = ZstandardState::Magic;
                        break;
                    }
                    let magic = u32::from_le_bytes(self.field[..4].try_into().expect("4 bytes"));
                    self.field.clear();
                    self.state = match magic {
                        ZstandardFormat::MAGIC => ZstandardState::Descriptor,
                        magic if magic & 0xFFFF_FFF0 == ZstandardFormat::SKIPPABLE_MAGIC => {
                            ZstandardState::SkippableSize
                        }
                        _ => return Err(CompressionError::InvalidData { reason: "unknown magic number" }),
                    };
                }
                ZstandardState::Descriptor => {
                    if !self.fill(1, &mut rest) {
                        break;
                    }
                    self.state = ZstandardState::Header { length: ZstandardDecompressor::header_length(self.field[0]) };
                }
                ZstandardState::Header { length } => {
                    if !self.fill(length, &mut rest) {
                        break;
                    }
                    self.read_header()?;
                    self.state = ZstandardState::BlockHeader;
                }
                ZstandardState::BlockHeader => {
                    if !self.fill(3, &mut rest) {
                        break;
                    }
                    let header = u32::from_le_bytes([self.field[0], self.field[1], self.field[2], 0]);
                    self.field.clear();
                    let (last, kind, size) = (header & 1 == 1, ((header >> 1) & 3) as u8, (header >> 3) as usize);
                    let maximum = (self.window_size as usize).min(ZstandardFormat::MAXIMUM_BLOCK);
                    if kind == 3 {
                        return Err(CompressionError::InvalidData { reason: "reserved block type" });
                    }
                    if size > maximum {
                        return Err(CompressionError::InvalidData { reason: "block larger than the maximum" });
                    }
                    self.state = ZstandardState::Block { kind, size, last };
                }
                ZstandardState::Block { kind, size, last } => {
                    let length = if kind == ZstandardFormat::RLE_BLOCK { 1 } else { size };
                    let count = (length - self.block.len()).min(rest.len());
                    self.block.extend_from_slice(&rest[..count]);
                    rest = &rest[count..];
                    if self.block.len() < length {
                        break;
                    }
                    let before = self.pending.len();
                    match kind {
                        ZstandardFormat::RAW_BLOCK => {
                            self.window.extend(&self.block);
                            self.pending.extend(&self.block);
                        }
                        ZstandardFormat::RLE_BLOCK => {
                            let data = alloc::vec![self.block[0]; size];
                            self.window.extend(&data);
                            self.pending.extend(&data);
                        }
                        _ => {
                            let maximum = (self.window_size as usize).min(ZstandardFormat::MAXIMUM_BLOCK);
                            self.blocks.decode(
                                &self.block,
                                &mut self.window,
                                self.dictionary,
                                self.window_size,
                                &mut self.pending,
                                maximum,
                            )?;
                        }
                    }
                    let data = &self.pending.as_slice()[before..];
                    self.checksum.update(data);
                    self.size += data.len() as u64;
                    self.block.clear();
                    self.state = if !last {
                        ZstandardState::BlockHeader
                    } else if self.descriptor & 0x04 != 0 {
                        ZstandardState::Checksum
                    } else {
                        self.check_size()?;
                        self.end_frame()
                    };
                }
                ZstandardState::Checksum => {
                    if !self.fill(4, &mut rest) {
                        break;
                    }
                    let expected = u32::from_le_bytes(self.field[..4].try_into().expect("4 bytes"));
                    self.field.clear();
                    if expected != self.checksum.value() as u32 {
                        return Err(CompressionError::ChecksumMismatch);
                    }
                    self.check_size()?;
                    self.state = self.end_frame();
                }
                ZstandardState::SkippableSize => {
                    if !self.fill(4, &mut rest) {
                        break;
                    }
                    let size = u32::from_le_bytes(self.field[..4].try_into().expect("4 bytes"));
                    self.field.clear();
                    self.state = ZstandardState::Skip { remaining: size as u64 };
                }
                ZstandardState::Skip { remaining } => {
                    let count = remaining.min(rest.len() as u64) as usize;
                    rest = &rest[count..];
                    if (count as u64) < remaining {
                        self.state = ZstandardState::Skip { remaining: remaining - count as u64 };
                        break;
                    }
                    self.state = self.end_frame();
                }
                ZstandardState::End => break,
            }
        }
        let finished = self.state == ZstandardState::End && self.pending.is_empty();
        Ok(Progress { consumed: input.len() - rest.len(), produced, finished })
    }

    /// The input may end after a frame.
    fn finish(&mut self) -> Result<(), CompressionError> {
        if !self.pending.is_empty() {
            return Err(CompressionError::UnexpectedEnd);
        }
        match self.state {
            ZstandardState::End => Ok(()),
            ZstandardState::Between => {
                self.state = ZstandardState::End;
                Ok(())
            }
            _ => Err(CompressionError::UnexpectedEnd),
        }
    }

    fn reset(&mut self) {
        self.state = ZstandardState::Magic;
        self.field.clear();
        self.block.clear();
        self.window = LZ77Window::new(1);
        self.pending.clear();
        self.frames = 0;
    }
}
