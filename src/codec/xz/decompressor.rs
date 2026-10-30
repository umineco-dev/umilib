use alloc::vec::Vec;

use super::{
    XZBlockHeader, XZCheck, XZChecksum, XZDecompressorConfig, XZFilter, XZFilterCoder, XZFormat, XZIndexHash,
    XZIndexReader,
};
use crate::codec::filter::FilterChain;
use crate::codec::lzma::{LZMA2Decompressor, LZMA2DecompressorConfig, LZMA2State};
use crate::codec::{CompressionError, Decompressor, Progress};

/// Where an [`XZDecompressor`] is in its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XZState {
    /// Reading the Stream Header: `filled` of its bytes so far.
    StreamHeader {
        filled: usize,
    },
    /// Before a Block Header Size byte or the Index Indicator.
    BlockStart,
    /// Reading a Block Header of `size` bytes: `filled` of them so far.
    BlockHeader {
        size: usize,
        filled: usize,
    },
    /// Decompressing the Compressed Data of a Block.
    Data,
    /// Reading the `remaining` bytes of Block Padding, then the Check.
    BlockPadding {
        remaining: usize,
    },
    Check {
        filled: usize,
    },
    /// Reading the Index after its Indicator.
    Index,
    /// Reading the Stream Footer.
    StreamFooter {
        filled: usize,
    },
    /// After a Stream, when Streams may follow.
    Between,
    /// In Stream Padding: `count` null bytes so far.
    Padding {
        count: u64,
    },
    /// After the only Stream.
    End,
}

/// Decompresses .xz files (The .xz File Format 1.2.1): Streams of Blocks
/// whose filter chains end with LZMA2 (after Delta and BCJ filters), with
/// every check of the format: the magic bytes, the CRC32s of the headers,
/// footers and Index, reserved bits, minimal integers, the sizes of the
/// Block Headers and of the Index against the Blocks decoded, padding, and
/// the Check of each Block (CRC32, CRC64 or SHA-256). By default the input
/// is a file of Streams and Stream Padding that ends with it
/// ([`XZDecompressorConfig::multiple_streams`]).
///
/// The reserved Check types and unknown filters fail with `Unsupported`.
#[derive(Clone, Debug)]
pub struct XZDecompressor {
    config: XZDecompressorConfig,
    state: XZState,
    /// The bytes of the field being read (headers, footers, Checks).
    field: Vec<u8>,
    check: XZCheck,
    stream_flags: [u8; 2],
    streams: u64,
    /// The Block: its header size, recorded sizes, decoder, filters, sizes so far and Check.
    header_size: u64,
    compressed_limit: Option<u64>,
    uncompressed_limit: Option<u64>,
    lzma2: Option<LZMA2Decompressor>,
    chain: FilterChain<XZFilterCoder>,
    compressed: u64,
    uncompressed: u64,
    checksum: XZChecksum,
    /// The Blocks of the Stream, and the reader of its Index.
    blocks: XZIndexHash,
    index: XZIndexReader,
}

impl XZDecompressor {
    /// The most bytes the filters of a Block decode at once.
    pub const FILTER_BUFFER: usize = 1 << 16;

    pub fn new(config: XZDecompressorConfig) -> XZDecompressor {
        XZDecompressor {
            config,
            state: XZState::StreamHeader { filled: 0 },
            field: Vec::new(),
            check: XZCheck::None,
            stream_flags: [0; 2],
            streams: 0,
            header_size: 0,
            compressed_limit: None,
            uncompressed_limit: None,
            lzma2: None,
            chain: FilterChain::new(Vec::new()),
            compressed: 0,
            uncompressed: 0,
            checksum: XZChecksum::new(XZCheck::None),
            blocks: XZIndexHash::new(),
            index: XZIndexReader::new(),
        }
    }

    pub fn config(&self) -> XZDecompressorConfig {
        self.config
    }

    pub fn state(&self) -> XZState {
        self.state
    }

    /// The Check of the current (or last) Stream.
    pub fn check(&self) -> XZCheck {
        self.check
    }

    /// The Streams read completely.
    pub fn streams(&self) -> u64 {
        self.streams
    }

    /// Moves bytes from `input` into the field until it holds `length`; whether it does.
    pub fn fill_field(&mut self, input: &mut &[u8], length: usize) -> bool {
        let take = (length - self.field.len()).min(input.len());
        self.field.extend_from_slice(&input[..take]);
        *input = &input[take..];
        self.field.len() == length
    }

    /// Checks the Stream Header in the field and starts the Stream.
    pub fn start_stream(&mut self) -> Result<(), CompressionError> {
        let header = &self.field;
        if header[..6] != XZFormat::HEADER_MAGIC {
            return Err(CompressionError::InvalidData { reason: "not a .xz stream" });
        }
        if XZFormat::crc32(&header[6..8]).to_le_bytes() != header[8..12] {
            return Err(CompressionError::InvalidData { reason: "stream header CRC32 mismatch" });
        }
        if header[6] != 0 || header[7] & 0xF0 != 0 {
            return Err(CompressionError::Unsupported { feature: "reserved stream flags" });
        }
        self.check = XZCheck::from_id(header[7])?;
        self.stream_flags = [header[6], header[7]];
        self.blocks = XZIndexHash::new();
        Ok(())
    }

    /// Reads the Block Header in the field and starts the Block.
    pub fn start_block(&mut self) -> Result<(), CompressionError> {
        let header = XZBlockHeader::decode(&self.field)?;
        self.header_size = self.field.len() as u64;
        let check_size = self.check.size() as u64;
        if let Some(size) = header.compressed_size
            && size > XZFormat::MAXIMUM_UNPADDED - self.header_size - check_size
        {
            return Err(CompressionError::InvalidData { reason: "compressed size too large" });
        }
        let Some(XZFilter::LZMA2 { dictionary_size }) = header.filters.last() else {
            return Err(CompressionError::Unsupported { feature: "filter chain" });
        };
        if *dictionary_size > self.config.maximum_dictionary_size {
            return Err(CompressionError::LimitExceeded { limit: self.config.maximum_dictionary_size });
        }
        let dictionary_size = usize::try_from(*dictionary_size)
            .map_err(|_| CompressionError::LimitExceeded { limit: usize::MAX as u64 })?;
        self.lzma2 = Some(LZMA2Decompressor::new(LZMA2DecompressorConfig { dictionary_size })?);
        self.chain = FilterChain::new(header.filters.iter().filter_map(XZFilter::coder).collect());
        (self.compressed_limit, self.uncompressed_limit) = (header.compressed_size, header.uncompressed_size);
        (self.compressed, self.uncompressed) = (0, 0);
        self.checksum = XZChecksum::new(self.check);
        Ok(())
    }

    /// Ends the Block after its LZMA2 stream: checks the recorded sizes and
    /// adds its Record; the state of its padding.
    pub fn end_block(&mut self) -> Result<XZState, CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        if self.compressed_limit.is_some_and(|size| size != self.compressed) {
            return Err(invalid("compressed size mismatch"));
        }
        if self.uncompressed_limit.is_some_and(|size| size != self.uncompressed) {
            return Err(invalid("uncompressed size mismatch"));
        }
        let unpadded = self.header_size + self.compressed + self.check.size() as u64;
        self.blocks.append(unpadded, self.uncompressed)?;
        self.lzma2 = None;
        Ok(XZState::BlockPadding { remaining: (4 - (self.compressed % 4) as usize) % 4 })
    }

    /// The input and output the LZMA2 decoder may use within the recorded
    /// sizes of the Block (of `input` and `output` bytes available).
    pub fn limits(&self, input: usize, output: usize) -> (usize, usize) {
        let room = |limit: Option<u64>, used: u64, available: usize| {
            limit.map_or(available, |limit| (limit - used).min(available as u64) as usize)
        };
        (room(self.compressed_limit, self.compressed, input), room(self.uncompressed_limit, self.uncompressed, output))
    }

    /// The error of an LZMA2 decoder that made no progress: data beyond a
    /// recorded size, or `None` if it waits for input or room.
    pub fn stalled(&self, input: usize) -> Option<CompressionError> {
        if self.compressed_limit == Some(self.compressed) {
            return Some(CompressionError::InvalidData { reason: "compressed data longer than its compressed size" });
        }
        if self.uncompressed_limit == Some(self.uncompressed) && input > 0 {
            return Some(CompressionError::InvalidData { reason: "data longer than its uncompressed size" });
        }
        None
    }
}

impl Default for XZDecompressor {
    fn default() -> XZDecompressor {
        XZDecompressor::new(XZDecompressorConfig::default())
    }
}

impl Decompressor for XZDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        let mut rest = input;
        let mut produced = 0;
        loop {
            match self.state {
                XZState::StreamHeader { .. } => {
                    if !self.fill_field(&mut rest, XZFormat::STREAM_HEADER_SIZE) {
                        self.state = XZState::StreamHeader { filled: self.field.len() };
                        break;
                    }
                    self.start_stream()?;
                    self.field.clear();
                    self.state = XZState::BlockStart;
                }
                XZState::BlockStart => {
                    let Some((&byte, after)) = rest.split_first() else { break };
                    rest = after;
                    if byte == 0 {
                        self.index = XZIndexReader::new();
                        self.state = XZState::Index;
                    } else {
                        self.field.push(byte);
                        self.state = XZState::BlockHeader { size: XZBlockHeader::size(byte), filled: 1 };
                    }
                }
                XZState::BlockHeader { size, .. } => {
                    if !self.fill_field(&mut rest, size) {
                        self.state = XZState::BlockHeader { size, filled: self.field.len() };
                        break;
                    }
                    self.start_block()?;
                    self.field.clear();
                    self.state = XZState::Data;
                }
                XZState::Data => {
                    let filtered = !self.chain.filters().is_empty();
                    if !filtered {
                        let (input_room, output_room) = self.limits(rest.len(), output.len() - produced);
                        let lzma2 = self.lzma2.as_mut().expect("a block being decoded");
                        let out = &mut output[produced..produced + output_room];
                        let progress = lzma2.decompress(&rest[..input_room], out)?;
                        self.checksum.update(&out[..progress.produced]);
                        rest = &rest[progress.consumed..];
                        produced += progress.produced;
                        self.compressed += progress.consumed as u64;
                        self.uncompressed += progress.produced as u64;
                        if progress.finished {
                            self.state = self.end_block()?;
                        } else if progress.consumed == 0 && progress.produced == 0 {
                            if let Some(error) = self.stalled(input_room) {
                                return Err(error);
                            }
                            break;
                        }
                        continue;
                    }
                    // Filtered: the LZMA2 output goes through the chain before the output.
                    let ready = self.chain.ready();
                    let count = ready.len().min(output.len() - produced);
                    output[produced..produced + count].copy_from_slice(&ready[..count]);
                    self.checksum.update(&ready[..count]);
                    self.chain.consume(count);
                    produced += count;
                    if !self.chain.ready().is_empty() {
                        break;
                    }
                    let ended = self.lzma2.as_ref().is_some_and(|lzma2| lzma2.state() == LZMA2State::End);
                    if ended {
                        if self.chain.is_empty() {
                            self.state = self.end_block()?;
                        } else {
                            self.chain.decode(true);
                        }
                        continue;
                    }
                    let (input_room, output_room) = self.limits(rest.len(), XZDecompressor::FILTER_BUFFER);
                    let lzma2 = self.lzma2.as_mut().expect("a block being decoded");
                    let mut progress = Progress::default();
                    self.chain.fill(output_room, |spare| {
                        progress = lzma2.decompress(&rest[..input_room], spare)?;
                        Ok::<usize, CompressionError>(progress.produced)
                    })?;
                    rest = &rest[progress.consumed..];
                    self.compressed += progress.consumed as u64;
                    self.uncompressed += progress.produced as u64;
                    self.chain.decode(progress.finished);
                    if !progress.finished && progress.consumed == 0 && progress.produced == 0 {
                        if let Some(error) = self.stalled(input_room) {
                            return Err(error);
                        }
                        break;
                    }
                }
                XZState::BlockPadding { remaining } => {
                    let zeros = rest.iter().take(remaining).take_while(|byte| **byte == 0).count();
                    if zeros < remaining.min(rest.len()) {
                        return Err(invalid("non-zero block padding"));
                    }
                    rest = &rest[zeros..];
                    if zeros < remaining {
                        self.state = XZState::BlockPadding { remaining: remaining - zeros };
                        break;
                    }
                    self.state = XZState::Check { filled: 0 };
                }
                XZState::Check { .. } => {
                    let size = self.check.size();
                    if !self.fill_field(&mut rest, size) {
                        self.state = XZState::Check { filled: self.field.len() };
                        break;
                    }
                    let (value, length) = self.checksum.finish();
                    if self.field[..] != value[..length] {
                        return Err(CompressionError::ChecksumMismatch);
                    }
                    self.field.clear();
                    self.state = XZState::BlockStart;
                }
                XZState::Index => {
                    if !self.index.read(&mut rest)? {
                        break;
                    }
                    if !self.index.hash.matches(&self.blocks) {
                        return Err(invalid("index does not match the blocks"));
                    }
                    self.state = XZState::StreamFooter { filled: 0 };
                }
                XZState::StreamFooter { .. } => {
                    if !self.fill_field(&mut rest, XZFormat::STREAM_FOOTER_SIZE) {
                        self.state = XZState::StreamFooter { filled: self.field.len() };
                        break;
                    }
                    let footer = &self.field;
                    if footer[10..12] != XZFormat::FOOTER_MAGIC {
                        return Err(invalid("stream footer magic mismatch"));
                    }
                    if XZFormat::crc32(&footer[4..10]).to_le_bytes() != footer[..4] {
                        return Err(invalid("stream footer CRC32 mismatch"));
                    }
                    if footer[8..10] != self.stream_flags {
                        return Err(invalid("stream flags of the header and footer differ"));
                    }
                    let backward = u32::from_le_bytes([footer[4], footer[5], footer[6], footer[7]]) as u64;
                    if (backward + 1) * 4 != self.index.size() {
                        return Err(invalid("backward size does not match the index"));
                    }
                    self.field.clear();
                    self.streams += 1;
                    self.state = if self.config.multiple_streams { XZState::Between } else { XZState::End };
                }
                XZState::Between => match rest.first() {
                    None => break,
                    Some(0) => self.state = XZState::Padding { count: 0 },
                    Some(_) => self.state = XZState::StreamHeader { filled: 0 },
                },
                XZState::Padding { count } => {
                    let zeros = rest.iter().take_while(|byte| **byte == 0).count();
                    rest = &rest[zeros..];
                    let count = count + zeros as u64;
                    if rest.is_empty() {
                        self.state = XZState::Padding { count };
                        break;
                    }
                    if !count.is_multiple_of(4) {
                        return Err(invalid("stream padding not a multiple of four bytes"));
                    }
                    self.state = XZState::StreamHeader { filled: 0 };
                }
                XZState::End => break,
            }
        }
        Ok(Progress { consumed: input.len() - rest.len(), produced, finished: self.state == XZState::End })
    }

    /// The input may end after a Stream and its Stream Padding (whose
    /// four-byte units an end inside one leaves incomplete: `UnexpectedEnd`).
    fn finish(&mut self) -> Result<(), CompressionError> {
        match self.state {
            XZState::End | XZState::Between => {
                self.state = XZState::End;
                Ok(())
            }
            XZState::Padding { count } if count.is_multiple_of(4) => {
                self.state = XZState::End;
                Ok(())
            }
            _ => Err(CompressionError::UnexpectedEnd),
        }
    }

    fn reset(&mut self) {
        *self = XZDecompressor::new(self.config);
    }
}
