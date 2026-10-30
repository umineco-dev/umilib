use alloc::vec::Vec;

use super::{
    BrotliBlockSwitch, BrotliCategory, BrotliContextMapReader, BrotliDecompressorConfig, BrotliDistances, BrotliFormat,
    BrotliPrefixCode, BrotliPrefixReader,
};
use crate::bytes::BitQueue;
use crate::codec::lz77::LZ77Window;
use crate::codec::{CompressionError, Decompressor, Progress};

/// Where a [`BrotliDecompressor`] is in its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrotliState {
    /// Before WBITS.
    StreamHeader,
    /// Before the header of a meta-block, up to its ISUNCOMPRESSED bit.
    MetaBlockHeader,
    /// Skipping the `remaining` bytes of metadata.
    Metadata {
        remaining: usize,
    },
    /// Copying the `remaining` bytes of an uncompressed meta-block.
    Uncompressed {
        remaining: usize,
    },
    /// Reading NBLTYPES of `category`, the prefix codes of its block types
    /// and block counts, and its first block count.
    BlockTypes {
        category: BrotliCategory,
    },
    BlockTypeCode {
        category: BrotliCategory,
    },
    BlockCountCode {
        category: BrotliCategory,
    },
    FirstBlockCount {
        category: BrotliCategory,
    },
    /// Reading NPOSTFIX and NDIRECT.
    DistanceParameters,
    /// Reading the context modes of the literal block types: `index` of them so far.
    ContextModes {
        index: usize,
    },
    /// Reading NTREES of `category` (literals or distances), then its context map.
    TreeCount {
        category: BrotliCategory,
    },
    ContextMap {
        category: BrotliCategory,
    },
    /// Reading the prefix codes of `category`: `index` of them so far.
    Codes {
        category: BrotliCategory,
        index: usize,
    },
    /// Before an insert-and-copy length.
    Command,
    /// After the insert length, before the extra bits of the copy length.
    CopyLength {
        insert: usize,
        copy_code: usize,
        implicit_distance: bool,
    },
    /// Inserting the `remaining` literals of a command whose copy is `copy` bytes.
    Literals {
        remaining: usize,
        copy: usize,
        implicit_distance: bool,
    },
    /// Before the distance of a copy of `copy` bytes.
    Distance {
        copy: usize,
        implicit_distance: bool,
    },
    /// Copying the `remaining` bytes of a match `distance` bytes back.
    Copy {
        distance: usize,
        remaining: usize,
    },
    /// Writing a transformed dictionary word: `position` of its `length` bytes so far.
    Word {
        length: usize,
        position: usize,
    },
    /// After the data of a meta-block.
    MetaBlockEnd,
    /// After the last meta-block.
    End,
}

/// Decompresses a Brotli stream (RFC 7932), with the checks of the format
/// and those of the reference decoder: WBITS within the configured limit,
/// reserved and fill bits zero, lengths without superfluous zero bytes or
/// nibbles, complete prefix codes, runs and repeats within their
/// alphabets, distances and dictionary references valid, and commands
/// within their meta-block. The stream ends with its last meta-block: the
/// input after it is not consumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrotliDecompressor {
    config: BrotliDecompressorConfig,
    queue: BitQueue,
    state: BrotliState,
    window: LZ77Window,
    window_size: usize,
    /// The meta-block: whether it is the last, and its bytes not yet produced.
    last: bool,
    remaining: usize,
    switches: [BrotliBlockSwitch; 3],
    distances: BrotliDistances,
    /// The context mode of each literal block type.
    modes: Vec<u8>,
    /// The number of prefix codes of each category (NTREESL, NBLTYPESI, NTREESD).
    trees: [usize; 3],
    literal_map: Vec<u8>,
    distance_map: Vec<u8>,
    codes: [Vec<BrotliPrefixCode>; 3],
    prefix: BrotliPrefixReader,
    context_map: BrotliContextMapReader,
    /// The transformed dictionary word being written.
    word: [u8; 38],
}

impl BrotliDecompressor {
    /// A decompressor of the limits `config`; fails with `InvalidParameter`
    /// for a window limit outside 10 to 24 bits.
    pub fn new(config: BrotliDecompressorConfig) -> Result<BrotliDecompressor, CompressionError> {
        if !(BrotliFormat::MINIMUM_WINDOW_BITS..=BrotliFormat::MAXIMUM_WINDOW_BITS)
            .contains(&config.maximum_window_bits)
        {
            return Err(CompressionError::InvalidParameter);
        }
        Ok(BrotliDecompressor {
            config,
            queue: BitQueue::new(),
            state: BrotliState::StreamHeader,
            window: LZ77Window::new(1),
            window_size: 0,
            last: false,
            remaining: 0,
            switches: Default::default(),
            distances: BrotliDistances::new(),
            modes: Vec::new(),
            trees: [1; 3],
            literal_map: Vec::new(),
            distance_map: Vec::new(),
            codes: Default::default(),
            prefix: BrotliPrefixReader::new(BrotliFormat::LITERALS),
            context_map: BrotliContextMapReader::new(0, 2),
            word: [0; 38],
        })
    }

    pub fn config(&self) -> BrotliDecompressorConfig {
        self.config
    }

    pub fn state(&self) -> BrotliState {
        self.state
    }

    /// The window of the stream (2^WBITS - 16 bytes), once its header is read.
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// The bytes produced so far.
    pub fn total(&self) -> u64 {
        self.window.total()
    }

    /// Reads WBITS (section 9.1); `None` if `input` ran out first.
    pub fn read_window_bits(queue: &mut BitQueue, input: &mut &[u8]) -> Result<Option<u32>, CompressionError> {
        if !queue.fill(1, input) {
            return Ok(None);
        }
        if queue.peek_padded(1) == 0 {
            queue.consume(1);
            return Ok(Some(16));
        }
        if !queue.fill(4, input) {
            return Ok(None);
        }
        let bits = (queue.peek_padded(4) >> 1) as u32;
        if bits != 0 {
            queue.consume(4);
            return Ok(Some(17 + bits));
        }
        if !queue.fill(7, input) {
            return Ok(None);
        }
        let bits = (queue.peek_padded(7) >> 4) as u32;
        if bits == 1 {
            return Err(CompressionError::InvalidData { reason: "invalid window size" });
        }
        queue.consume(7);
        Ok(Some(if bits == 0 { 17 } else { 8 + bits }))
    }

    /// Reads the header of a meta-block up to its ISUNCOMPRESSED bit
    /// (section 9.2), consumed once all of it is queued; the state that
    /// follows it, or `None` if `input` ran out first.
    pub fn read_meta_block_header(&mut self, input: &mut &[u8]) -> Result<Option<BrotliState>, CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        let queue = &mut self.queue;
        if !queue.fill(1, input) {
            return Ok(None);
        }
        let last = queue.peek_padded(1) == 1;
        let mut position = 1;
        if last {
            if !queue.fill(2, input) {
                return Ok(None);
            }
            position = 2;
            if queue.peek_padded(2) >> 1 == 1 {
                queue.consume(2);
                (self.last, self.remaining) = (true, 0);
                return Ok(Some(BrotliState::MetaBlockEnd));
            }
        }
        if !queue.fill(position + 2, input) {
            return Ok(None);
        }
        let nibbles = (queue.peek_padded(position + 2) >> position) as u32;
        position += 2;
        if nibbles == 3 {
            // Metadata: a reserved bit, MSKIPBYTES and MSKIPLEN - 1.
            if !queue.fill(position + 3, input) {
                return Ok(None);
            }
            let bits = queue.peek_padded(position + 3) >> position;
            if bits & 1 != 0 {
                return Err(invalid("reserved bit set"));
            }
            let bytes = (bits >> 1) as u32;
            position += 3;
            if !queue.fill(position + 8 * bytes, input) {
                return Ok(None);
            }
            let value = queue.peek_padded(position + 8 * bytes) >> position;
            if bytes > 1 && value >> (8 * (bytes - 1)) == 0 {
                return Err(invalid("metadata length with a superfluous zero byte"));
            }
            queue.consume(position + 8 * bytes);
            if queue.align() != 0 {
                return Err(invalid("fill bits not zero"));
            }
            let length = if bytes == 0 { 0 } else { value as usize + 1 };
            (self.last, self.remaining) = (last, 0);
            return Ok(Some(BrotliState::Metadata { remaining: length }));
        }
        let nibbles = 4 + nibbles;
        if !queue.fill(position + 4 * nibbles, input) {
            return Ok(None);
        }
        let value = queue.peek_padded(position + 4 * nibbles) >> position;
        if nibbles > 4 && value >> (4 * (nibbles - 1)) == 0 {
            return Err(invalid("meta-block length with a superfluous zero nibble"));
        }
        position += 4 * nibbles;
        let mut uncompressed = false;
        if !last {
            if !queue.fill(position + 1, input) {
                return Ok(None);
            }
            uncompressed = queue.peek_padded(position + 1) >> position == 1;
            position += 1;
        }
        queue.consume(position);
        (self.last, self.remaining) = (last, value as usize + 1);
        if uncompressed {
            if self.queue.align() != 0 {
                return Err(invalid("ignored bits not zero"));
            }
            return Ok(Some(BrotliState::Uncompressed { remaining: self.remaining }));
        }
        for codes in &mut self.codes {
            codes.clear();
        }
        Ok(Some(BrotliState::BlockTypes { category: BrotliCategory::Literal }))
    }

    /// The size of the alphabet of the prefix codes of `category`.
    pub fn alphabet_size(&self, category: BrotliCategory) -> usize {
        match category {
            BrotliCategory::Literal => BrotliFormat::LITERALS,
            BrotliCategory::Command => BrotliFormat::COMMANDS,
            BrotliCategory::Distance => self.distances.alphabet_size(),
        }
    }

    /// The state after the block switch codes of `category`.
    pub fn after_block_types(category: BrotliCategory) -> BrotliState {
        match category {
            BrotliCategory::Literal => BrotliState::BlockTypes { category: BrotliCategory::Command },
            BrotliCategory::Command => BrotliState::BlockTypes { category: BrotliCategory::Distance },
            BrotliCategory::Distance => BrotliState::DistanceParameters,
        }
    }

    /// The state after the context map of `category`, starting the prefix codes after the last one.
    pub fn after_context_map(&mut self, category: BrotliCategory) -> BrotliState {
        if category == BrotliCategory::Literal {
            return BrotliState::TreeCount { category: BrotliCategory::Distance };
        }
        self.prefix = BrotliPrefixReader::new(self.alphabet_size(BrotliCategory::Literal));
        BrotliState::Codes { category: BrotliCategory::Literal, index: 0 }
    }

    /// The state after the prefix codes of `category`.
    pub fn after_codes(&mut self, category: BrotliCategory) -> BrotliState {
        let next = match category {
            BrotliCategory::Literal => BrotliCategory::Command,
            BrotliCategory::Command => BrotliCategory::Distance,
            BrotliCategory::Distance => return BrotliState::Command,
        };
        self.prefix = BrotliPrefixReader::new(self.alphabet_size(next));
        BrotliState::Codes { category: next, index: 0 }
    }

    /// The start of the copy of `copy` bytes at `distance` (of the distance
    /// code `code`): a match in the window, or a transformed dictionary
    /// word beyond it (section 8).
    pub fn start_copy(&mut self, copy: usize, distance: u32, code: u16) -> Result<BrotliState, CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        let maximum = (self.window_size as u64).min(self.window.total());
        if distance as u64 <= maximum {
            if code != 0 {
                self.distances.push(distance);
            }
            if copy > self.remaining {
                return Err(invalid("copy beyond the meta-block"));
            }
            return Ok(BrotliState::Copy { distance: distance as usize, remaining: copy });
        }
        if !(BrotliFormat::MINIMUM_WORD..=BrotliFormat::MAXIMUM_WORD).contains(&copy) {
            return Err(invalid("dictionary reference of an invalid length"));
        }
        let bits = BrotliFormat::DICTIONARY_BITS[copy];
        let identifier = distance as u64 - maximum - 1;
        let (index, transform) = ((identifier & ((1 << bits) - 1)) as usize, (identifier >> bits) as usize);
        let Some(transform) = BrotliFormat::TRANSFORMS.get(transform) else {
            return Err(invalid("dictionary reference of an invalid transform"));
        };
        let length = BrotliFormat::transform(transform, BrotliFormat::word(copy, index), &mut self.word);
        if length > self.remaining {
            return Err(invalid("dictionary word beyond the meta-block"));
        }
        Ok(BrotliState::Word { length, position: 0 })
    }

    /// The state after a copy or a dictionary word: the next command, or the end of the meta-block.
    pub fn after_output(&self) -> BrotliState {
        if self.remaining == 0 { BrotliState::MetaBlockEnd } else { BrotliState::Command }
    }
}

impl Default for BrotliDecompressor {
    fn default() -> BrotliDecompressor {
        BrotliDecompressor::new(BrotliDecompressorConfig::default()).expect("the default limit is valid")
    }
}

impl Decompressor for BrotliDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        let mut rest = input;
        let mut produced = 0;
        loop {
            match self.state {
                BrotliState::StreamHeader => {
                    let Some(bits) = BrotliDecompressor::read_window_bits(&mut self.queue, &mut rest)? else { break };
                    self.window_size = BrotliFormat::window_size(bits);
                    if bits > self.config.maximum_window_bits {
                        return Err(CompressionError::LimitExceeded {
                            limit: BrotliFormat::window_size(self.config.maximum_window_bits) as u64,
                        });
                    }
                    self.window = LZ77Window::new(self.window_size);
                    self.state = BrotliState::MetaBlockHeader;
                }
                BrotliState::MetaBlockHeader => {
                    let Some(state) = self.read_meta_block_header(&mut rest)? else { break };
                    self.state = state;
                }
                BrotliState::Metadata { remaining } => {
                    // The queue is empty at a byte boundary: the bytes come straight from the input.
                    let count = remaining.min(rest.len());
                    rest = &rest[count..];
                    if count < remaining {
                        self.state = BrotliState::Metadata { remaining: remaining - count };
                        break;
                    }
                    self.state = BrotliState::MetaBlockEnd;
                }
                BrotliState::Uncompressed { remaining } => {
                    let count = remaining.min(rest.len()).min(output.len() - produced);
                    output[produced..produced + count].copy_from_slice(&rest[..count]);
                    self.window.extend(&rest[..count]);
                    rest = &rest[count..];
                    produced += count;
                    if count < remaining {
                        self.state = BrotliState::Uncompressed { remaining: remaining - count };
                        break;
                    }
                    self.remaining = 0;
                    self.state = BrotliState::MetaBlockEnd;
                }
                BrotliState::BlockTypes { category } => {
                    let Some(types) = BrotliBlockSwitch::read_types(&mut self.queue, &mut rest) else { break };
                    self.switches[category as usize] = BrotliBlockSwitch::with_types(types);
                    if types < 2 {
                        self.state = BrotliDecompressor::after_block_types(category);
                        continue;
                    }
                    self.prefix = BrotliPrefixReader::new(types + 2);
                    self.state = BrotliState::BlockTypeCode { category };
                }
                BrotliState::BlockTypeCode { category } => {
                    let Some(code) = self.prefix.read(&mut self.queue, &mut rest)? else { break };
                    self.switches[category as usize].type_code = Some(code);
                    self.prefix = BrotliPrefixReader::new(BrotliFormat::BLOCK_COUNTS);
                    self.state = BrotliState::BlockCountCode { category };
                }
                BrotliState::BlockCountCode { category } => {
                    let Some(code) = self.prefix.read(&mut self.queue, &mut rest)? else { break };
                    self.switches[category as usize].count_code = Some(code);
                    self.state = BrotliState::FirstBlockCount { category };
                }
                BrotliState::FirstBlockCount { category } => {
                    let switch = &mut self.switches[category as usize];
                    let Some(count) = switch.read_count(&mut self.queue, &mut rest)? else { break };
                    switch.remaining = count;
                    self.state = BrotliDecompressor::after_block_types(category);
                }
                BrotliState::DistanceParameters => {
                    let Some(bits) = self.queue.read_from(6, &mut rest) else { break };
                    self.distances.postfix = (bits & 3) as u32;
                    self.distances.direct = ((bits >> 2) as u32) << self.distances.postfix;
                    self.trees[BrotliCategory::Command as usize] =
                        self.switches[BrotliCategory::Command as usize].types;
                    self.modes.clear();
                    self.state = BrotliState::ContextModes { index: 0 };
                }
                BrotliState::ContextModes { mut index } => {
                    let types = self.switches[BrotliCategory::Literal as usize].types;
                    while index < types {
                        let Some(mode) = self.queue.read_from(2, &mut rest) else { break };
                        self.modes.push(mode as u8);
                        index += 1;
                    }
                    if index < types {
                        self.state = BrotliState::ContextModes { index };
                        break;
                    }
                    self.state = BrotliState::TreeCount { category: BrotliCategory::Literal };
                }
                BrotliState::TreeCount { category } => {
                    let Some(trees) = BrotliBlockSwitch::read_types(&mut self.queue, &mut rest) else { break };
                    self.trees[category as usize] = trees;
                    let size = match category {
                        BrotliCategory::Literal => 64 * self.switches[category as usize].types,
                        _ => 4 * self.switches[category as usize].types,
                    };
                    if trees >= 2 {
                        self.context_map = BrotliContextMapReader::new(size, trees);
                        self.state = BrotliState::ContextMap { category };
                        continue;
                    }
                    let map = if category == BrotliCategory::Literal {
                        &mut self.literal_map
                    } else {
                        &mut self.distance_map
                    };
                    map.clear();
                    map.resize(size, 0);
                    self.state = self.after_context_map(category);
                }
                BrotliState::ContextMap { category } => {
                    let Some(map) = self.context_map.read(&mut self.queue, &mut rest)? else { break };
                    if category == BrotliCategory::Literal {
                        self.literal_map = map;
                    } else {
                        self.distance_map = map;
                    }
                    self.state = self.after_context_map(category);
                }
                BrotliState::Codes { category, index } => {
                    let Some(code) = self.prefix.read(&mut self.queue, &mut rest)? else { break };
                    self.codes[category as usize].push(code);
                    if index + 1 < self.trees[category as usize] {
                        self.prefix = BrotliPrefixReader::new(self.alphabet_size(category));
                        self.state = BrotliState::Codes { category, index: index + 1 };
                    } else {
                        self.state = self.after_codes(category);
                    }
                }
                BrotliState::Command => {
                    let switch = &mut self.switches[BrotliCategory::Command as usize];
                    if switch.remaining == 0 && !switch.switch(&mut self.queue, &mut rest)? {
                        break;
                    }
                    let code = &self.codes[BrotliCategory::Command as usize][switch.current];
                    let extra = |symbol: u16| BrotliFormat::INSERT_BITS[BrotliFormat::command(symbol).0] as u32;
                    let Some((symbol, bits)) = code.read_with_extra(&mut self.queue, &mut rest, extra)? else { break };
                    switch.remaining -= 1;
                    let (insert_code, copy_code, implicit_distance) = BrotliFormat::command(symbol);
                    let insert = (BrotliFormat::INSERT_BASES[insert_code] + bits) as usize;
                    if insert > self.remaining {
                        return Err(invalid("insert beyond the meta-block"));
                    }
                    self.state = BrotliState::CopyLength { insert, copy_code, implicit_distance };
                }
                BrotliState::CopyLength { insert, copy_code, implicit_distance } => {
                    let Some(bits) = self.queue.read_from(BrotliFormat::COPY_BITS[copy_code] as u32, &mut rest) else {
                        break;
                    };
                    let copy = (BrotliFormat::COPY_BASES[copy_code] + bits as u32) as usize;
                    self.state = BrotliState::Literals { remaining: insert, copy, implicit_distance };
                }
                BrotliState::Literals { mut remaining, copy, implicit_distance } => {
                    let (mut p1, mut p2) = (self.window.byte(1).unwrap_or(0), self.window.byte(2).unwrap_or(0));
                    let switch = &mut self.switches[BrotliCategory::Literal as usize];
                    let codes = &self.codes[BrotliCategory::Literal as usize];
                    while remaining > 0 && produced < output.len() {
                        if switch.remaining == 0 && !switch.switch(&mut self.queue, &mut rest)? {
                            break;
                        }
                        let context = BrotliFormat::literal_context(self.modes[switch.current], p1, p2);
                        let tree = self.literal_map[64 * switch.current + context] as usize;
                        let Some(byte) = codes[tree].read(&mut self.queue, &mut rest)? else { break };
                        switch.remaining -= 1;
                        let byte = byte as u8;
                        output[produced] = byte;
                        self.window.push(byte);
                        produced += 1;
                        (p2, p1) = (p1, byte);
                        remaining -= 1;
                        self.remaining -= 1;
                    }
                    if remaining > 0 {
                        self.state = BrotliState::Literals { remaining, copy, implicit_distance };
                        break;
                    }
                    // A meta-block that ends with the literals ignores the copy.
                    self.state = if self.remaining == 0 {
                        BrotliState::MetaBlockEnd
                    } else {
                        BrotliState::Distance { copy, implicit_distance }
                    };
                }
                BrotliState::Distance { copy, implicit_distance } => {
                    let (code, distance) = if implicit_distance {
                        (0, self.distances.last[0])
                    } else {
                        let switch = &mut self.switches[BrotliCategory::Distance as usize];
                        if switch.remaining == 0 && !switch.switch(&mut self.queue, &mut rest)? {
                            break;
                        }
                        let context = copy.min(5) - 2;
                        let tree = self.distance_map[4 * switch.current + context] as usize;
                        let distances = self.distances;
                        let extra = |symbol: u16| distances.extra_bits(symbol);
                        let code = &self.codes[BrotliCategory::Distance as usize][tree];
                        let Some((symbol, bits)) = code.read_with_extra(&mut self.queue, &mut rest, extra)? else {
                            break;
                        };
                        switch.remaining -= 1;
                        (symbol, self.distances.decode(symbol, bits)?)
                    };
                    self.state = self.start_copy(copy, distance, code)?;
                }
                BrotliState::Copy { distance, remaining } => {
                    let copied = self.window.copy(distance, remaining, &mut output[produced..])?;
                    produced += copied;
                    self.remaining -= copied;
                    if copied < remaining {
                        self.state = BrotliState::Copy { distance, remaining: remaining - copied };
                        break;
                    }
                    self.state = self.after_output();
                }
                BrotliState::Word { length, position } => {
                    let count = (length - position).min(output.len() - produced);
                    let bytes = &self.word[position..position + count];
                    output[produced..produced + count].copy_from_slice(bytes);
                    self.window.extend(bytes);
                    produced += count;
                    self.remaining -= count;
                    if position + count < length {
                        self.state = BrotliState::Word { length, position: position + count };
                        break;
                    }
                    self.state = self.after_output();
                }
                BrotliState::MetaBlockEnd => {
                    if !self.last {
                        self.state = BrotliState::MetaBlockHeader;
                        continue;
                    }
                    // The stream ends in this byte, whose fill bits are zero.
                    if self.queue.align() != 0 {
                        return Err(invalid("fill bits not zero"));
                    }
                    self.state = BrotliState::End;
                }
                BrotliState::End => break,
            }
        }
        Ok(Progress { consumed: input.len() - rest.len(), produced, finished: self.state == BrotliState::End })
    }

    fn finish(&mut self) -> Result<(), CompressionError> {
        if self.state == BrotliState::End { Ok(()) } else { Err(CompressionError::UnexpectedEnd) }
    }

    fn reset(&mut self) {
        let config = self.config;
        *self = BrotliDecompressor::new(config).expect("a valid configuration");
    }
}
