use alloc::vec;
use alloc::vec::Vec;

use super::{BrotliBlockSwitch, BrotliConfig, BrotliDistances, BrotliFormat, BrotliPrefixCode};
use crate::bytes::BitWriter;
use crate::codec::lz77::{LZ77MatchFinder, LZ77MatchFinderConfig};
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};

/// The search of a compression level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrotliLevel {
    pub chain_limit: usize,
    pub nice_length: usize,
    pub lazy: bool,
}

impl BrotliLevel {
    /// The levels 0 to 11.
    pub const LEVELS: [BrotliLevel; 12] = [
        BrotliLevel { chain_limit: 1, nice_length: 8, lazy: false },
        BrotliLevel { chain_limit: 2, nice_length: 16, lazy: false },
        BrotliLevel { chain_limit: 4, nice_length: 24, lazy: false },
        BrotliLevel { chain_limit: 8, nice_length: 32, lazy: false },
        BrotliLevel { chain_limit: 8, nice_length: 32, lazy: true },
        BrotliLevel { chain_limit: 16, nice_length: 48, lazy: true },
        BrotliLevel { chain_limit: 32, nice_length: 64, lazy: true },
        BrotliLevel { chain_limit: 48, nice_length: 96, lazy: true },
        BrotliLevel { chain_limit: 64, nice_length: 128, lazy: true },
        BrotliLevel { chain_limit: 128, nice_length: 192, lazy: true },
        BrotliLevel { chain_limit: 256, nice_length: 258, lazy: true },
        BrotliLevel { chain_limit: 1024, nice_length: 512, lazy: true },
    ];
}

/// A command of a meta-block: `insert` literals, then `copy` bytes at the
/// distance of the distance code `distance_code` and its `distance_bits`
/// extra bits `distance_extra` (a `copy` of 0 ends the meta-block after the literals).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrotliCommand {
    pub insert: u32,
    pub copy: u32,
    pub distance_code: u16,
    pub distance_extra: u32,
    pub distance_bits: u32,
}

impl BrotliCommand {
    /// The insert-and-copy length symbol, its insert and copy extra bits
    /// (values and numbers), and whether the distance is implicit.
    pub fn symbol(&self) -> (u16, (u32, u32), (u32, u32), bool) {
        let (insert_code, insert_extra) = BrotliFormat::insert_code(self.insert);
        let (copy_code, copy_extra) = if self.copy == 0 { (0, 0) } else { BrotliFormat::copy_code(self.copy) };
        let implicit = (self.copy == 0 || self.distance_code == 0) && insert_code < 8 && copy_code < 16;
        (
            BrotliFormat::command_symbol(insert_code, copy_code, implicit),
            (insert_extra, BrotliFormat::INSERT_BITS[insert_code] as u32),
            (copy_extra, BrotliFormat::COPY_BITS[copy_code] as u32),
            implicit,
        )
    }

    /// Whether a distance code follows the literals.
    pub fn has_distance(&self) -> bool {
        self.copy > 0 && !self.symbol().3
    }
}

/// Compresses into a Brotli stream (RFC 7932): meta-blocks of up to 256
/// KiB, each compressed (one block type per category, one prefix code
/// each, the last distances preferred) or uncompressed, whichever is
/// smaller. [`Flush::Sync`] ends the data so far at a byte boundary (with an
/// empty metadata meta-block if needed); [`Flush::Finish`] ends the stream.
#[derive(Clone, Debug)]
pub struct BrotliCompressor {
    config: BrotliConfig,
    level: BrotliLevel,
    finder: LZ77MatchFinder,
    /// The position in the finder's data of the first byte not yet in a meta-block.
    position: usize,
    /// The bytes before `position` the decoder holds.
    history: usize,
    distances: BrotliDistances,
    writer: BitWriter,
    pending: PendingOutput,
    started: bool,
    finished: bool,
}

impl BrotliCompressor {
    /// The shortest match searched.
    pub const MINIMUM_MATCH: usize = 4;
    /// The longest copy length: 2118 + 2^24 - 1.
    pub const MAXIMUM_COPY: usize = 2118 + (1 << 24) - 1;

    /// A compressor of the parameters `config`; fails with `InvalidParameter` outside their ranges.
    pub fn new(config: BrotliConfig) -> Result<BrotliCompressor, CompressionError> {
        let level = *BrotliLevel::LEVELS.get(config.level as usize).ok_or(CompressionError::InvalidParameter)?;
        if !(BrotliFormat::MINIMUM_WINDOW_BITS..=BrotliFormat::MAXIMUM_WINDOW_BITS).contains(&config.window_bits) {
            return Err(CompressionError::InvalidParameter);
        }
        let finder = LZ77MatchFinder::new(LZ77MatchFinderConfig {
            window_bits: config.window_bits,
            chain_bits: config.window_bits.min(22),
            hash_bits: 17,
            maximum_distance: BrotliFormat::window_size(config.window_bits),
            minimum_length: BrotliCompressor::MINIMUM_MATCH,
            maximum_length: BrotliCompressor::MAXIMUM_COPY,
            chain_limit: level.chain_limit,
            nice_length: level.nice_length,
        })?;
        Ok(BrotliCompressor {
            config,
            level,
            finder,
            position: 0,
            history: 0,
            distances: BrotliDistances::new(),
            writer: BitWriter::new(),
            pending: PendingOutput::new(),
            started: false,
            finished: false,
        })
    }

    pub fn config(&self) -> BrotliConfig {
        self.config
    }

    /// The largest meta-block: the window, within 64 KiB to 256 KiB.
    pub fn block_size(&self) -> usize {
        (1usize << self.config.window_bits).clamp(1 << 16, 1 << 18)
    }

    /// The window: 2^WBITS - 16 bytes.
    pub fn window_size(&self) -> usize {
        BrotliFormat::window_size(self.config.window_bits)
    }

    /// Writes WBITS (section 9.1).
    pub fn write_window_bits(bits: u32, writer: &mut BitWriter) {
        match bits {
            16 => writer.write(0, 1),
            17 => writer.write(1, 7),
            18..=24 => writer.write(1 | ((bits - 17) as u64) << 1, 4),
            _ => writer.write(1 | ((bits - 8) as u64) << 4, 7),
        }
    }

    /// Writes the header of a meta-block of `length` bytes (1 to 2^24) that is not the last.
    pub fn write_meta_block_header(length: usize, uncompressed: bool, writer: &mut BitWriter) {
        let value = length as u64 - 1;
        let nibbles = (u64::BITS - value.leading_zeros()).div_ceil(4).max(4);
        writer.write(0, 1);
        writer.write((nibbles - 4) as u64, 2);
        writer.write(value, 4 * nibbles);
        writer.write(uncompressed as u64, 1);
    }

    /// The longest match at `position` among the last distances (of at
    /// least the shortest match): (distance, length).
    pub fn last_distance_match(&self, position: usize, limit: usize, reach: usize) -> Option<(usize, usize)> {
        let data = self.finder.data();
        self.distances
            .last
            .iter()
            .map(|distance| *distance as usize)
            .filter(|distance| *distance <= reach)
            .map(|distance| {
                let length = (0..limit).take_while(|index| data[position + index] == data[position - distance + index]);
                (distance, length.count())
            })
            .filter(|(_, length)| *length >= BrotliCompressor::MINIMUM_MATCH)
            .max_by_key(|(_, length)| *length)
    }

    /// The commands of the data of the finder from `start` to `end`, the
    /// ring of last distances updated as a decoder does.
    pub fn parse(&mut self, start: usize, end: usize) -> Vec<BrotliCommand> {
        let mut commands = Vec::new();
        let mut literal_start = start;
        let mut position = start;
        let window = self.window_size();
        while position < end {
            let limit = (end - position).min(BrotliCompressor::MAXIMUM_COPY);
            let reach = (position - start + self.history).min(window);
            let mut best = self.last_distance_match(position, limit, reach);
            // A match of the finder wins over one at a last distance only if it is longer by 2 or more.
            let searched = if best.is_none_or(|(_, length)| length < self.level.nice_length) {
                self.finder.find(position, limit).filter(|found| found.distance <= reach)
            } else {
                None
            };
            if let Some(found) = searched
                && best.is_none_or(|(_, length)| found.length > length + 1)
            {
                best = Some((found.distance, found.length));
            }
            // At the lazy levels, a longer match one byte later defers this one.
            if self.level.lazy
                && limit > 1
                && let Some((_, length)) = best
            {
                let next = self
                    .finder
                    .find(position + 1, limit - 1)
                    .filter(|found| found.distance <= (reach + 1).min(window))
                    .map_or(0, |found| found.length);
                if next > length + 1 {
                    best = None;
                }
            }
            match best {
                Some((distance, length)) => {
                    let (distance_code, distance_extra, distance_bits) = self.distances.encode(distance as u32);
                    if distance_code != 0 {
                        self.distances.push(distance as u32);
                    }
                    commands.push(BrotliCommand {
                        insert: (position - literal_start) as u32,
                        copy: length as u32,
                        distance_code,
                        distance_extra,
                        distance_bits,
                    });
                    position += length;
                    literal_start = position;
                }
                None => position += 1,
            }
        }
        if literal_start < end {
            let insert = (end - literal_start) as u32;
            commands.push(BrotliCommand { insert, copy: 0, distance_code: 0, distance_extra: 0, distance_bits: 0 });
        }
        commands
    }

    /// Writes the meta-block of the finder's data from `start` to `end`,
    /// compressed or uncompressed, whichever is smaller.
    pub fn write_meta_block(&mut self, start: usize, end: usize) {
        let saved = self.distances;
        let commands = self.parse(start, end);
        let data = &self.finder.data()[start..end];
        let mut literals = [0u32; BrotliFormat::LITERALS];
        let mut symbols = vec![0u32; BrotliFormat::COMMANDS];
        let mut distances = vec![0u32; self.distances.alphabet_size()];
        let mut extra_bits = 0usize;
        let mut position = 0;
        for command in &commands {
            for byte in &data[position..position + command.insert as usize] {
                literals[*byte as usize] += 1;
            }
            position += (command.insert + command.copy) as usize;
            let (symbol, insert, copy, _) = command.symbol();
            symbols[symbol as usize] += 1;
            extra_bits += (insert.1 + copy.1) as usize;
            if command.has_distance() {
                distances[command.distance_code as usize] += 1;
                extra_bits += command.distance_bits as usize;
            }
        }
        let literal_lengths = BrotliPrefixCode::lengths(&literals);
        let command_lengths = BrotliPrefixCode::lengths(&symbols);
        let distance_lengths = BrotliPrefixCode::lengths(&distances);
        let literal_codes = BrotliPrefixCode::codes(&literal_lengths);
        let command_codes = BrotliPrefixCode::codes(&command_lengths);
        let distance_codes = BrotliPrefixCode::codes(&distance_lengths);
        // The size of the compressed meta-block after its header: the trees, then the codes and extra bits.
        let mut trees = BitWriter::new();
        BrotliCompressor::write_tree_header(&mut trees);
        BrotliPrefixCode::write(&literal_lengths, BrotliFormat::LITERALS, &mut trees);
        BrotliPrefixCode::write(&command_lengths, BrotliFormat::COMMANDS, &mut trees);
        BrotliPrefixCode::write(&distance_lengths, distances.len(), &mut trees);
        let cost = |frequencies: &[u32], codes: &[(u16, u8)]| -> usize {
            frequencies.iter().zip(codes).map(|(frequency, (_, bits))| *frequency as usize * *bits as usize).sum()
        };
        let compressed = trees.bit_length()
            + cost(&literals, &literal_codes)
            + cost(&symbols, &command_codes)
            + cost(&distances, &distance_codes)
            + extra_bits;
        let writer = &mut self.writer;
        if compressed >= 8 * data.len() {
            self.distances = saved;
            BrotliCompressor::write_meta_block_header(data.len(), true, writer);
            writer.write_bytes(data);
            return;
        }
        BrotliCompressor::write_meta_block_header(data.len(), false, writer);
        BrotliCompressor::write_tree_header(writer);
        BrotliPrefixCode::write(&literal_lengths, BrotliFormat::LITERALS, writer);
        BrotliPrefixCode::write(&command_lengths, BrotliFormat::COMMANDS, writer);
        BrotliPrefixCode::write(&distance_lengths, distances.len(), writer);
        let mut position = 0;
        for command in &commands {
            let (symbol, insert, copy, implicit) = command.symbol();
            let (code, bits) = command_codes[symbol as usize];
            writer.write(code as u64, bits as u32);
            writer.write(insert.0 as u64, insert.1);
            writer.write(copy.0 as u64, copy.1);
            for byte in &data[position..position + command.insert as usize] {
                let (code, bits) = literal_codes[*byte as usize];
                writer.write(code as u64, bits as u32);
            }
            position += (command.insert + command.copy) as usize;
            if command.copy > 0 && !implicit {
                let (code, bits) = distance_codes[command.distance_code as usize];
                writer.write(code as u64, bits as u32);
                writer.write(command.distance_extra as u64, command.distance_bits);
            }
        }
    }

    /// Writes the part of a compressed meta-block header before its prefix
    /// codes: one block type per category, no postfix bits or direct
    /// distance codes, the context mode LSB6, one literal and one distance prefix code.
    pub fn write_tree_header(writer: &mut BitWriter) {
        for _ in 0..3 {
            BrotliBlockSwitch::write_types(1, writer);
        }
        writer.write(0, 2 + 4 + 2);
        BrotliBlockSwitch::write_types(1, writer);
        BrotliBlockSwitch::write_types(1, writer);
    }

    /// Writes the buffered data into meta-blocks: whole blocks only, unless `all`.
    pub fn encode(&mut self, all: bool) {
        let block = self.block_size();
        loop {
            let available = self.finder.data().len() - self.position;
            if available == 0 || (!all && available < block) {
                break;
            }
            let length = available.min(block);
            self.write_meta_block(self.position, self.position + length);
            self.position += length;
            self.history = (self.history + length).min(self.window_size());
        }
        self.pending.extend(self.writer.completed());
        self.writer.clear_completed();
        let dropped = self.finder.discard(self.position);
        self.position -= dropped;
    }
}

impl Default for BrotliCompressor {
    fn default() -> BrotliCompressor {
        BrotliCompressor::new(BrotliConfig::default()).expect("the default parameters are valid")
    }
}

impl Compressor for BrotliCompressor {
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        if !self.started {
            BrotliCompressor::write_window_bits(self.config.window_bits, &mut self.writer);
            self.started = true;
        }
        let (mut consumed, mut produced) = (0, 0);
        loop {
            produced += self.pending.deliver(&mut output[produced..]);
            if !self.pending.is_empty() || self.finished {
                break;
            }
            let buffered = self.finder.data().len() - self.position;
            let take = (input.len() - consumed).min((2 * self.block_size()).saturating_sub(buffered));
            self.finder.append(&input[consumed..consumed + take]);
            consumed += take;
            if consumed < input.len() || flush == Flush::None {
                self.encode(false);
                if consumed == input.len() && self.pending.is_empty() {
                    break;
                }
                continue;
            }
            self.encode(true);
            if flush == Flush::Sync {
                // An empty metadata meta-block (ISLAST 0, MNIBBLES 0, reserved 0, MSKIPBYTES 0) pads to a byte.
                if !self.writer.bit_length().is_multiple_of(8) {
                    self.writer.write(0b000110, 6);
                    self.writer.align();
                    self.pending.extend(self.writer.completed());
                    self.writer.clear_completed();
                }
                if self.pending.is_empty() {
                    break;
                }
                continue;
            }
            // ISLAST and ISLASTEMPTY end the stream.
            self.writer.write(0b11, 2);
            self.writer.align();
            self.pending.extend(self.writer.completed());
            self.writer.clear_completed();
            self.finished = true;
        }
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.finder.clear();
        self.position = 0;
        self.history = 0;
        self.distances = BrotliDistances::new();
        self.writer = BitWriter::new();
        self.pending.clear();
        self.started = false;
        self.finished = false;
    }
}
