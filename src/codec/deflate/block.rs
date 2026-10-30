use alloc::vec;
use alloc::vec::Vec;

use super::DeflateFormat;
use crate::bytes::BitWriter;
use crate::codec::huffman::canonical::HuffmanCode;

/// A symbol of a compressed block: a literal byte or a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeflateSymbol {
    Literal(u8),
    Match { length: u16, distance: u16 },
}

/// The kind of a block (the BTYPE of section 3.2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeflateBlockKind {
    Stored,
    Fixed,
    Dynamic,
}

/// Writes the blocks of a Deflate stream: given the symbols of a block and
/// the bytes they stand for, [`DeflateBlock::write`] chooses the kind of
/// block that takes the fewest bits (or stored blocks, if asked) and writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeflateBlock {
    literal_frequencies: Vec<u32>,
    distance_frequencies: Vec<u32>,
}

impl DeflateBlock {
    pub fn new() -> DeflateBlock {
        DeflateBlock {
            literal_frequencies: vec![0; DeflateFormat::LITERAL_LENGTH_SYMBOLS],
            distance_frequencies: vec![0; DeflateFormat::DISTANCE_SYMBOLS],
        }
    }

    /// Writes `symbols`, which stand for `bytes`, as one block (or as
    /// stored blocks of at most 65535 bytes), the last of the stream if
    /// `last`; only stored blocks if `stored_only`. Returns the kind written.
    pub fn write(
        &mut self,
        writer: &mut BitWriter,
        symbols: &[DeflateSymbol],
        bytes: &[u8],
        last: bool,
        stored_only: bool,
    ) -> DeflateBlockKind {
        self.literal_frequencies.fill(0);
        self.distance_frequencies.fill(0);
        for symbol in symbols {
            match *symbol {
                DeflateSymbol::Literal(byte) => self.literal_frequencies[byte as usize] += 1,
                DeflateSymbol::Match { length, distance } => {
                    self.literal_frequencies[257 + DeflateFormat::length_index(length as usize)] += 1;
                    self.distance_frequencies[DeflateFormat::distance_symbol(distance as usize)] += 1;
                }
            }
        }
        self.literal_frequencies[DeflateFormat::END_OF_BLOCK as usize] = 1;
        // The bits of the block after its 3 header bits, for each kind.
        let stored_bits = DeflateBlock::stored_bits(writer.bit_length() + 3, bytes.len());
        if stored_only {
            DeflateBlock::write_stored(writer, bytes, last);
            return DeflateBlockKind::Stored;
        }
        let fixed_literal = DeflateFormat::fixed_literal_length_lengths();
        let fixed_distance = DeflateFormat::fixed_distance_lengths();
        let fixed_bits = self.data_bits(&fixed_literal, &fixed_distance);
        let literal_lengths = DeflateBlock::lengths(
            &self.literal_frequencies[..DeflateFormat::MAXIMUM_LITERAL_LENGTH_CODES],
            DeflateFormat::MAXIMUM_CODE_LENGTH,
        );
        let distance_lengths = DeflateBlock::lengths(
            &self.distance_frequencies[..DeflateFormat::MAXIMUM_DISTANCE_CODES],
            DeflateFormat::MAXIMUM_CODE_LENGTH,
        );
        let header = DeflateBlock::dynamic_header(&literal_lengths, &distance_lengths);
        let dynamic_bits = header.bit_length() + self.data_bits(&literal_lengths, &distance_lengths);
        if stored_bits < fixed_bits.min(dynamic_bits) {
            DeflateBlock::write_stored(writer, bytes, last);
            DeflateBlockKind::Stored
        } else if fixed_bits <= dynamic_bits {
            writer.write(last as u64 | 1 << 1, 3);
            DeflateBlock::write_symbols(
                writer,
                symbols,
                &HuffmanCode::from_lengths(&fixed_literal).expect("the fixed code"),
                &HuffmanCode::from_lengths(&fixed_distance).expect("the fixed code"),
            );
            DeflateBlockKind::Fixed
        } else {
            writer.write(last as u64 | 2 << 1, 3);
            DeflateBlock::write_dynamic_header(writer, &literal_lengths, &distance_lengths);
            let literal = HuffmanCode::from_lengths(&literal_lengths).expect("lengths from frequencies");
            let distance = HuffmanCode::from_lengths(&distance_lengths).expect("lengths from frequencies");
            DeflateBlock::write_symbols(writer, symbols, &literal, &distance);
            DeflateBlockKind::Dynamic
        }
    }

    /// The bits of stored blocks of `length` bytes starting at the bit `position` of the stream.
    pub fn stored_bits(position: usize, length: usize) -> usize {
        let blocks = length.div_ceil(DeflateFormat::MAXIMUM_STORED).max(1);
        // Padding to a byte after the header, then LEN, NLEN and the bytes; later blocks are aligned.
        (8 - position % 8) % 8 + blocks * 32 + (blocks - 1) * 8 + length * 8
    }

    /// Writes `bytes` as stored blocks of at most 65535 bytes, the last of them the last of the stream if `last`.
    pub fn write_stored(writer: &mut BitWriter, bytes: &[u8], last: bool) {
        let mut chunks = bytes.chunks(DeflateFormat::MAXIMUM_STORED).peekable();
        if chunks.peek().is_none() {
            DeflateBlock::write_stored_chunk(writer, &[], last);
        }
        while let Some(chunk) = chunks.next() {
            DeflateBlock::write_stored_chunk(writer, chunk, last && chunks.peek().is_none());
        }
    }

    /// Writes one stored block.
    pub fn write_stored_chunk(writer: &mut BitWriter, chunk: &[u8], last: bool) {
        writer.write(last as u64, 3);
        writer.align();
        let length = chunk.len() as u16;
        writer.write_bytes(&[length as u8, (length >> 8) as u8, !length as u8, (!length >> 8) as u8]);
        writer.write_bytes(chunk);
    }

    /// The bits of the symbols of the block and its end with the codes of `literal_lengths` and `distance_lengths`.
    pub fn data_bits(&self, literal_lengths: &[u8], distance_lengths: &[u8]) -> usize {
        let mut bits = 0;
        for (symbol, frequency) in self.literal_frequencies.iter().enumerate() {
            if *frequency > 0 {
                let extra = if symbol >= 257 { DeflateFormat::LENGTH_EXTRA_BITS[symbol - 257] as usize } else { 0 };
                bits += *frequency as usize * (literal_lengths.get(symbol).copied().unwrap_or(0) as usize + extra);
            }
        }
        for (symbol, frequency) in self.distance_frequencies.iter().enumerate() {
            if *frequency > 0 {
                let extra = DeflateFormat::DISTANCE_EXTRA_BITS[symbol] as usize;
                bits += *frequency as usize * (distance_lengths.get(symbol).copied().unwrap_or(0) as usize + extra);
            }
        }
        bits
    }

    /// Code lengths of at most `maximum_length` bits for `frequencies`, with
    /// at least two codes (as zlib makes them, so that every decoder accepts
    /// the code: a complete one).
    pub fn lengths(frequencies: &[u32], maximum_length: u32) -> Vec<u8> {
        let mut frequencies = frequencies.to_vec();
        let mut used = frequencies.iter().filter(|frequency| **frequency > 0).count();
        let mut symbol = 0;
        while used < 2 {
            if frequencies[symbol] == 0 {
                frequencies[symbol] = 1;
                used += 1;
            }
            symbol += 1;
        }
        HuffmanCode::lengths_from_frequencies(&frequencies, maximum_length)
            .expect("the alphabets of Deflate fit their lengths")
    }

    /// The code lengths of `literal_lengths` and `distance_lengths` (each
    /// without its trailing zeros, keeping 257 and 1), as symbols of the code
    /// length code with their extra bits (section 3.2.7): runs of a length
    /// repeated with 16, runs of zeros with 17 and 18.
    pub fn code_length_symbols(literal_lengths: &[u8], distance_lengths: &[u8]) -> (usize, usize, Vec<(u8, u8)>) {
        let literal = literal_lengths.iter().rposition(|length| *length > 0).map_or(0, |last| last + 1).max(257);
        let distance = distance_lengths.iter().rposition(|length| *length > 0).map_or(0, |last| last + 1).max(1);
        let lengths: Vec<u8> =
            literal_lengths[..literal].iter().chain(&distance_lengths[..distance]).copied().collect();
        let mut symbols = Vec::new();
        let mut index = 0;
        while index < lengths.len() {
            let value = lengths[index];
            let run = lengths[index..].iter().take_while(|length| **length == value).count();
            if value == 0 && run >= 3 {
                let count = run.min(138);
                if count >= 11 {
                    symbols.push((18, (count - 11) as u8));
                } else {
                    symbols.push((17, (count - 3) as u8));
                }
                index += count;
            } else if value != 0 && run >= 4 {
                symbols.push((value, 0));
                let count = (run - 1).min(6);
                symbols.push((16, (count - 3) as u8));
                index += 1 + count;
            } else {
                symbols.push((value, 0));
                index += 1;
            }
        }
        (literal, distance, symbols)
    }

    /// The header of a dynamic block after its 3 header bits, in a writer of its own (to count its bits).
    pub fn dynamic_header(literal_lengths: &[u8], distance_lengths: &[u8]) -> BitWriter {
        let mut writer = BitWriter::new();
        DeflateBlock::write_dynamic_header(&mut writer, literal_lengths, distance_lengths);
        writer
    }

    /// Writes HLIT, HDIST, HCLEN, the code length code and the code lengths.
    pub fn write_dynamic_header(writer: &mut BitWriter, literal_lengths: &[u8], distance_lengths: &[u8]) {
        let (literal, distance, symbols) = DeflateBlock::code_length_symbols(literal_lengths, distance_lengths);
        let mut frequencies = [0u32; 19];
        for (symbol, _) in &symbols {
            frequencies[*symbol as usize] += 1;
        }
        let lengths = DeflateBlock::lengths(&frequencies, DeflateFormat::MAXIMUM_CODE_LENGTH_CODE_LENGTH);
        let code = HuffmanCode::from_lengths(&lengths).expect("lengths from frequencies");
        let count = DeflateFormat::CODE_LENGTH_ORDER
            .iter()
            .rposition(|symbol| lengths[*symbol] > 0)
            .map_or(0, |last| last + 1)
            .max(4);
        writer.write((literal - 257) as u64, 5);
        writer.write((distance - 1) as u64, 5);
        writer.write((count - 4) as u64, 4);
        for symbol in &DeflateFormat::CODE_LENGTH_ORDER[..count] {
            writer.write(lengths[*symbol] as u64, 3);
        }
        for (symbol, extra) in symbols {
            writer.write(code.reversed_code(symbol as usize) as u64, code.length(symbol as usize));
            match symbol {
                16 => writer.write(extra as u64, 2),
                17 => writer.write(extra as u64, 3),
                18 => writer.write(extra as u64, 7),
                _ => {}
            }
        }
    }

    /// Writes the symbols and the end of the block with the codes `literal` and `distance`.
    pub fn write_symbols(
        writer: &mut BitWriter,
        symbols: &[DeflateSymbol],
        literal: &HuffmanCode,
        distance: &HuffmanCode,
    ) {
        for symbol in symbols {
            match *symbol {
                DeflateSymbol::Literal(byte) => {
                    writer.write(literal.reversed_code(byte as usize) as u64, literal.length(byte as usize))
                }
                DeflateSymbol::Match { length, distance: back } => {
                    let index = DeflateFormat::length_index(length as usize);
                    writer.write(literal.reversed_code(257 + index) as u64, literal.length(257 + index));
                    writer.write(
                        (length - DeflateFormat::LENGTH_BASES[index]) as u64,
                        DeflateFormat::LENGTH_EXTRA_BITS[index] as u32,
                    );
                    let symbol = DeflateFormat::distance_symbol(back as usize);
                    writer.write(distance.reversed_code(symbol) as u64, distance.length(symbol));
                    writer.write(
                        (back - DeflateFormat::DISTANCE_BASES[symbol]) as u64,
                        DeflateFormat::DISTANCE_EXTRA_BITS[symbol] as u32,
                    );
                }
            }
        }
        let end = DeflateFormat::END_OF_BLOCK as usize;
        writer.write(literal.reversed_code(end) as u64, literal.length(end));
    }
}

impl Default for DeflateBlock {
    fn default() -> DeflateBlock {
        DeflateBlock::new()
    }
}
