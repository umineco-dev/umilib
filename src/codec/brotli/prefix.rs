use alloc::vec;
use alloc::vec::Vec;

use super::BrotliFormat;
use crate::bytes::{BitOrder, BitQueue, BitWriter};
use crate::codec::CompressionError;
use crate::codec::huffman::canonical::{HuffmanCode, HuffmanTable};

/// A prefix code of Brotli (RFC 7932 section 3): a canonical code of
/// lengths 1 to 15, or a single symbol whose code has no bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrotliPrefixCode {
    Single(u16),
    Table(HuffmanTable),
}

impl BrotliPrefixCode {
    /// ALPHABET_BITS: the bits of a symbol of an alphabet of `size` symbols in a simple prefix code.
    pub fn alphabet_bits(size: usize) -> u32 {
        usize::BITS - (size.max(1) - 1).leading_zeros()
    }

    /// The code of `lengths`; fails with `InvalidData` unless they define a complete code.
    pub fn from_lengths(lengths: &[u8]) -> Result<BrotliPrefixCode, CompressionError> {
        let code = HuffmanCode::from_lengths(lengths)
            .map_err(|_| CompressionError::InvalidData { reason: "over-subscribed code lengths" })?;
        if !code.is_complete() {
            return Err(CompressionError::InvalidData { reason: "incomplete code lengths" });
        }
        Ok(BrotliPrefixCode::Table(HuffmanTable::new(&code, BitOrder::LeastSignificantFirst)))
    }

    /// The next symbol of `queue` (filled from `input` only as far as its
    /// code needs) and the length of its code, without consuming it; `None`
    /// if `input` ran out first.
    pub fn peek(&self, queue: &mut BitQueue, input: &mut &[u8]) -> Result<Option<(u16, u32)>, CompressionError> {
        match self {
            BrotliPrefixCode::Single(symbol) => Ok(Some((*symbol, 0))),
            BrotliPrefixCode::Table(table) => {
                table.peek(queue, input).map_err(|_| CompressionError::InvalidData { reason: "invalid code" })
            }
        }
    }

    /// Decodes and consumes the next symbol of `queue`, as [`BrotliPrefixCode::peek`] finds it.
    pub fn read(&self, queue: &mut BitQueue, input: &mut &[u8]) -> Result<Option<u16>, CompressionError> {
        let Some((symbol, length)) = self.peek(queue, input)? else {
            return Ok(None);
        };
        queue.consume(length);
        Ok(Some(symbol))
    }

    /// The next symbol and `extra(symbol)` bits after its code, consumed
    /// together once `input` holds them all; `None` (consuming nothing) if it ran out first.
    pub fn read_with_extra(
        &self,
        queue: &mut BitQueue,
        input: &mut &[u8],
        extra: impl Fn(u16) -> u32,
    ) -> Result<Option<(u16, u32)>, CompressionError> {
        let Some((symbol, length)) = self.peek(queue, input)? else {
            return Ok(None);
        };
        let bits = extra(symbol);
        if !queue.fill(length + bits, input) {
            return Ok(None);
        }
        queue.consume(length);
        let value = queue.read(bits).expect("filled");
        Ok(Some((symbol, value as u32)))
    }

    /// The code lengths of at most 15 bits that code `frequencies` best (a
    /// single used symbol gets the length 1, and [`BrotliPrefixCode::write`]
    /// describes it as a code without bits).
    pub fn lengths(frequencies: &[u32]) -> Vec<u8> {
        HuffmanCode::lengths_from_frequencies(frequencies, BrotliFormat::MAXIMUM_CODE_LENGTH)
            .expect("the alphabets of Brotli fit 15 bits")
    }

    /// For each symbol of the code of `lengths` (from
    /// [`BrotliPrefixCode::lengths`]): its code, reversed for
    /// [`BitWriter::write`], and its bits; 0 bits for every symbol of a code
    /// of at most one used symbol.
    pub fn codes(lengths: &[u8]) -> Vec<(u16, u8)> {
        if lengths.iter().filter(|length| **length > 0).count() <= 1 {
            return vec![(0, 0); lengths.len()];
        }
        let code = HuffmanCode::from_lengths(lengths).expect("lengths of a code");
        (0..lengths.len()).map(|symbol| (code.reversed_code(symbol) as u16, lengths[symbol])).collect()
    }

    /// Writes the description of the code of `lengths` (from
    /// [`BrotliPrefixCode::lengths`]) of an alphabet of `size` symbols: a
    /// simple prefix code for at most 4 used symbols, otherwise a complex one.
    pub fn write(lengths: &[u8], size: usize, writer: &mut BitWriter) {
        let used: Vec<usize> = (0..lengths.len()).filter(|symbol| lengths[*symbol] > 0).collect();
        if used.len() <= 4 {
            BrotliPrefixCode::write_simple(lengths, &used, size, writer);
        } else {
            BrotliPrefixCode::write_complex(&lengths[..=*used.last().expect("used symbols")], writer);
        }
    }

    /// A simple prefix code (section 3.4) of the `used` symbols (none: the symbol 0).
    pub fn write_simple(lengths: &[u8], used: &[usize], size: usize, writer: &mut BitWriter) {
        let bits = BrotliPrefixCode::alphabet_bits(size);
        // The symbols in the order of their lengths: the shapes 1,1 / 1,2,2 / 2,2,2,2 / 1,2,3,3.
        let mut symbols = used.to_vec();
        symbols.sort_by_key(|symbol| lengths[*symbol]);
        if symbols.is_empty() {
            symbols.push(0);
        }
        writer.write(1, 2);
        writer.write(symbols.len() as u64 - 1, 2);
        for symbol in &symbols {
            writer.write(*symbol as u64, bits);
        }
        if symbols.len() == 4 {
            writer.write((lengths[symbols[0]] == 1) as u64, 1);
        }
    }

    /// A complex prefix code (section 3.5) of `lengths`, which end with a used symbol.
    pub fn write_complex(lengths: &[u8], writer: &mut BitWriter) {
        let symbols = BrotliPrefixCode::code_length_symbols(lengths);
        let mut frequencies = [0u32; 18];
        for (symbol, _) in &symbols {
            frequencies[*symbol as usize] += 1;
        }
        let code_lengths = HuffmanCode::lengths_from_frequencies(&frequencies, 5).expect("18 symbols fit 5 bits");
        // HSKIP: the leading code length code lengths of the order that are zero (2 or 3 of them).
        let skip = match (code_lengths[1], code_lengths[2], code_lengths[3]) {
            (0, 0, 0) => 3,
            (0, 0, _) => 2,
            _ => 0,
        };
        writer.write(skip as u64, 2);
        let mut space = 32i32;
        for symbol in &BrotliFormat::CODE_LENGTH_ORDER[skip..] {
            let (value, count) = BrotliFormat::CODE_LENGTH_CODES[code_lengths[*symbol] as usize];
            writer.write(value as u64, count as u32);
            if code_lengths[*symbol] != 0 {
                space -= 32 >> code_lengths[*symbol];
                // With one code length symbol, all 18 are written (the reader then knows it is alone).
                if space == 0 {
                    break;
                }
            }
        }
        let codes = BrotliPrefixCode::codes(&code_lengths);
        for (symbol, extra) in symbols {
            let (code, bits) = codes[symbol as usize];
            writer.write(code as u64, bits as u32);
            match symbol {
                16 => writer.write(extra as u64, 2),
                17 => writer.write(extra as u64, 3),
                _ => {}
            }
        }
    }

    /// The code length symbols of `lengths` with their extra bits: runs of
    /// zeros as 17 and of a repeated length as 16, never two repeats in a
    /// row (so each repeat stands alone, without the extension of section 3.5).
    pub fn code_length_symbols(lengths: &[u8]) -> Vec<(u8, u8)> {
        let mut symbols: Vec<(u8, u8)> = Vec::new();
        let mut index = 0;
        let mut previous = BrotliFormat::INITIAL_CODE_LENGTH;
        while index < lengths.len() {
            let value = lengths[index];
            let run = lengths[index..].iter().take_while(|length| **length == value).count();
            let repeated = matches!(symbols.last(), Some((16 | 17, _)));
            if value == 0 && run >= 3 && !repeated {
                let count = run.min(10);
                symbols.push((17, (count - 3) as u8));
                index += count;
            } else if value != 0 && value == previous && run >= 3 && !repeated {
                let count = run.min(6);
                symbols.push((16, (count - 3) as u8));
                index += count;
            } else {
                symbols.push((value, 0));
                if value != 0 {
                    previous = value;
                }
                index += 1;
            }
        }
        symbols
    }
}

/// The part of a prefix code a [`BrotliPrefixReader`] reads next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrotliPrefixPhase {
    /// The 2 bits that tell a simple code from a complex one (and its HSKIP).
    Kind,
    /// The code length code lengths of a complex code.
    CodeLengthCode,
    /// The code lengths of a complex code.
    CodeLengths,
}

/// Reads the description of a prefix code (RFC 7932 sections 3.4 and 3.5)
/// from a [`BitQueue`] filled from successive inputs, resuming where the
/// last input ended, with the checks of the reference decoder: the
/// symbols of a simple code are distinct and within the alphabet, and a
/// complex code (and its code length code) is complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrotliPrefixReader {
    size: usize,
    phase: BrotliPrefixPhase,
    /// The code length code: its lengths, the index in [`BrotliFormat::CODE_LENGTH_ORDER`], space left, codes used.
    code_lengths: [u8; 18],
    order: usize,
    code_space: i32,
    code_used: usize,
    code_length_code: Option<BrotliPrefixCode>,
    /// The code lengths: so far `symbol` of them, the last non-zero one,
    /// the repeat count and length of the last repeat code, and space left.
    lengths: Vec<u8>,
    symbol: usize,
    previous: u8,
    repeat: usize,
    repeat_length: u8,
    space: i32,
}

impl BrotliPrefixReader {
    /// A reader of a code of an alphabet of `size` symbols.
    pub fn new(size: usize) -> BrotliPrefixReader {
        BrotliPrefixReader {
            size,
            phase: BrotliPrefixPhase::Kind,
            code_lengths: [0; 18],
            order: 0,
            code_space: 32,
            code_used: 0,
            code_length_code: None,
            lengths: Vec::new(),
            symbol: 0,
            previous: BrotliFormat::INITIAL_CODE_LENGTH,
            repeat: 0,
            repeat_length: 0,
            space: 32768,
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn phase(&self) -> BrotliPrefixPhase {
        self.phase
    }

    /// Reads on from `queue` and `input`: the code once its description is
    /// complete, `None` if `input` ran out first (the reader keeps its place).
    pub fn read(
        &mut self,
        queue: &mut BitQueue,
        input: &mut &[u8],
    ) -> Result<Option<BrotliPrefixCode>, CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        if self.phase == BrotliPrefixPhase::Kind {
            if !queue.fill(2, input) {
                return Ok(None);
            }
            let kind = queue.peek_padded(2);
            if kind == 1 {
                return self.read_simple(queue, input);
            }
            queue.consume(2);
            self.order = kind as usize;
            self.phase = BrotliPrefixPhase::CodeLengthCode;
        }
        if self.phase == BrotliPrefixPhase::CodeLengthCode {
            while self.order < BrotliFormat::CODE_LENGTH_ORDER.len() {
                // The variable-length code of section 3.5 takes 2 to 4 bits: fill only as far as it needs.
                if !queue.fill(2, input) {
                    return Ok(None);
                }
                let mut bits = queue.peek_padded(2);
                if bits == 3 {
                    if !queue.fill(3, input) {
                        return Ok(None);
                    }
                    bits = queue.peek_padded(3);
                    if bits == 7 {
                        if !queue.fill(4, input) {
                            return Ok(None);
                        }
                        bits = queue.peek_padded(4);
                    }
                }
                let (length, count) = BrotliFormat::CODE_LENGTH_DECODING[bits as usize];
                queue.consume(count as u32);
                self.code_lengths[BrotliFormat::CODE_LENGTH_ORDER[self.order]] = length;
                self.order += 1;
                if length != 0 {
                    self.code_space -= 32 >> length;
                    self.code_used += 1;
                    if self.code_space <= 0 {
                        break;
                    }
                }
            }
            if !(self.code_used == 1 || self.code_space == 0) {
                return Err(invalid("invalid code length code"));
            }
            self.code_length_code = Some(if self.code_used == 1 {
                let symbol = self.code_lengths.iter().position(|length| *length != 0).expect("one code length");
                BrotliPrefixCode::Single(symbol as u16)
            } else {
                BrotliPrefixCode::from_lengths(&self.code_lengths)?
            });
            self.lengths = vec![0; self.size];
            self.phase = BrotliPrefixPhase::CodeLengths;
        }
        let code = self.code_length_code.as_ref().expect("read before the code lengths");
        while self.symbol < self.size && self.space > 0 {
            let extra = |symbol: u16| match symbol {
                16 => 2,
                17 => 3,
                _ => 0,
            };
            let Some((symbol, bits)) = code.read_with_extra(queue, input, extra)? else {
                return Ok(None);
            };
            if symbol < 16 {
                self.repeat = 0;
                self.lengths[self.symbol] = symbol as u8;
                if symbol != 0 {
                    self.previous = symbol as u8;
                    self.space -= 32768 >> symbol;
                }
                self.symbol += 1;
                continue;
            }
            // A repeat code extends the count of a repeat code of the same kind just before it.
            let (shift, length) = if symbol == 16 { (2, self.previous) } else { (3, 0) };
            if self.repeat_length != length {
                self.repeat = 0;
                self.repeat_length = length;
            }
            let old = self.repeat;
            if self.repeat > 0 {
                self.repeat = (self.repeat - 2) << shift;
            }
            self.repeat += bits as usize + 3;
            let delta = self.repeat - old;
            if self.symbol + delta > self.size {
                return Err(invalid("code lengths beyond the alphabet"));
            }
            self.lengths[self.symbol..self.symbol + delta].fill(length);
            self.symbol += delta;
            if length != 0 {
                self.space -= (delta << (15 - length)) as i32;
            }
        }
        if self.space != 0 {
            return Err(invalid("incomplete code lengths"));
        }
        BrotliPrefixCode::from_lengths(&self.lengths).map(Some)
    }

    /// Reads a simple prefix code, whose bits are consumed together once all are queued.
    pub fn read_simple(
        &mut self,
        queue: &mut BitQueue,
        input: &mut &[u8],
    ) -> Result<Option<BrotliPrefixCode>, CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        if !queue.fill(4, input) {
            return Ok(None);
        }
        let count = (queue.peek_padded(4) >> 2) as usize + 1;
        let bits = BrotliPrefixCode::alphabet_bits(self.size);
        let total = 4 + count as u32 * bits + (count == 4) as u32;
        if !queue.fill(total, input) {
            return Ok(None);
        }
        let value = queue.peek_padded(total);
        queue.consume(total);
        let mut symbols = [0u16; 4];
        for index in 0..count {
            let symbol = ((value >> (4 + index as u32 * bits)) & BitQueue::mask(bits)) as u16;
            if symbol as usize >= self.size || symbols[..index].contains(&symbol) {
                return Err(invalid("invalid symbol of a simple prefix code"));
            }
            symbols[index] = symbol;
        }
        let shape: &[u8] = match count {
            1 => return Ok(Some(BrotliPrefixCode::Single(symbols[0]))),
            2 => &[1, 1],
            3 => &[1, 2, 2],
            _ if value >> (total - 1) & 1 == 0 => &[2, 2, 2, 2],
            _ => &[1, 2, 3, 3],
        };
        let mut lengths = vec![0u8; self.size];
        for (symbol, length) in symbols.iter().zip(shape) {
            lengths[*symbol as usize] = *length;
        }
        BrotliPrefixCode::from_lengths(&lengths).map(Some)
    }
}
