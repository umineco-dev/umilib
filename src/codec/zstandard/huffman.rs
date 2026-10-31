use alloc::vec;
use alloc::vec::Vec;

use super::ZstandardFormat;
use crate::bytes::{BackwardBitReader, BackwardBitWriter};
use crate::codec::CompressionError;
use crate::codec::fse::{FSEDecodingTable, FSEDistribution, FSEEncodingTable};
use crate::codec::huffman::canonical::HuffmanCode;

/// The prefix code of Zstandard literals (RFC 8878 section 4.2): weights
/// per symbol, codes of `maximum_bits + 1 - weight` bits distributed from
/// the lowest weight in the order of the symbols, the longest codes
/// numerically smallest. The table maps the next `maximum_bits` bits of a
/// backward stream (first bit most significant) to a symbol and its length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZstandardHuffman {
    pub maximum_bits: u32,
    /// The weight of each symbol (0 for none).
    pub weights: Vec<u8>,
    /// Per value of `maximum_bits` bits: the symbol and the length of its code.
    pub table: Vec<(u8, u8)>,
}

impl ZstandardHuffman {
    /// The code of the weights of the symbols 0 to n - 2 (the weight of the
    /// last symbol completes the sum to a power of 2); fails with
    /// `InvalidData` if they do not define a code of at most 11 bits.
    pub fn from_weights(listed: &[u8]) -> Result<ZstandardHuffman, CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        if listed.len() > 255 {
            return Err(invalid("too many Huffman weights"));
        }
        let mut sum = 0u32;
        for weight in listed {
            if *weight as u32 > ZstandardFormat::MAXIMUM_HUFFMAN_BITS {
                return Err(invalid("Huffman weight too large"));
            }
            if *weight > 0 {
                sum += 1 << (weight - 1);
            }
        }
        if sum == 0 {
            return Err(invalid("no Huffman weight"));
        }
        let maximum_bits = 32 - sum.leading_zeros();
        if maximum_bits > ZstandardFormat::MAXIMUM_HUFFMAN_BITS {
            return Err(invalid("Huffman code too long"));
        }
        let rest = (1u32 << maximum_bits) - sum;
        if !rest.is_power_of_two() {
            return Err(invalid("Huffman weights do not complete a code"));
        }
        let mut weights = listed.to_vec();
        weights.push(rest.trailing_zeros() as u8 + 1);
        // The codes of weight 1 come in pairs (the reference decoder's check).
        let ones = weights.iter().filter(|weight| **weight == 1).count();
        if ones < 2 || ones % 2 != 0 {
            return Err(invalid("Huffman weights do not complete a code"));
        }
        Ok(ZstandardHuffman::from_all_weights(maximum_bits, weights))
    }

    /// The code of the weights of every symbol, of `maximum_bits` bits at most.
    pub fn from_all_weights(maximum_bits: u32, weights: Vec<u8>) -> ZstandardHuffman {
        let mut table = vec![(0u8, 0u8); 1 << maximum_bits];
        let mut start = 0usize;
        for weight in 1..=maximum_bits as u8 {
            let span = 1usize << (weight - 1);
            for (symbol, _) in weights.iter().enumerate().filter(|(_, symbol_weight)| **symbol_weight == weight) {
                table[start..start + span].fill((symbol as u8, (maximum_bits + 1 - weight as u32) as u8));
                start += span;
            }
        }
        ZstandardHuffman { maximum_bits, weights, table }
    }

    /// The code of the frequencies of the bytes (2 or more present), of at most 11 bits.
    pub fn from_frequencies(frequencies: &[u32; 256]) -> ZstandardHuffman {
        let lengths = HuffmanCode::lengths_from_frequencies(frequencies, ZstandardFormat::MAXIMUM_HUFFMAN_BITS)
            .expect("256 symbols fit 11 bits");
        let maximum_bits = lengths.iter().copied().max().unwrap_or(0) as u32;
        let weights = lengths
            .iter()
            .map(|length| if *length == 0 { 0 } else { (maximum_bits + 1 - *length as u32) as u8 })
            .collect();
        ZstandardHuffman::from_all_weights(maximum_bits, weights)
    }

    /// The code of each symbol: its value (first bit most significant) and its length.
    pub fn codes(&self) -> Vec<(u32, u32)> {
        let mut codes = vec![(0u32, 0u32); self.weights.len()];
        let mut start = 0u32;
        for weight in 1..=self.maximum_bits as u8 {
            for (symbol, _) in self.weights.iter().enumerate().filter(|(_, symbol_weight)| **symbol_weight == weight) {
                codes[symbol] = (start >> (weight - 1), self.maximum_bits + 1 - weight as u32);
                start += 1 << (weight - 1);
            }
        }
        codes
    }

    /// Reads a Huffman tree description (section 4.2.1) from the start of
    /// `bytes`: the code and the bytes it took.
    pub fn read(bytes: &[u8]) -> Result<(ZstandardHuffman, usize), CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        let header = *bytes.first().ok_or(invalid("truncated Huffman description"))? as usize;
        if header >= 128 {
            let count = header - 127;
            let data = bytes.get(1..1 + count.div_ceil(2)).ok_or(invalid("truncated Huffman description"))?;
            let weights: Vec<u8> = (0..count)
                .map(|index| if index % 2 == 0 { data[index / 2] >> 4 } else { data[index / 2] & 0xF })
                .collect();
            return Ok((ZstandardHuffman::from_weights(&weights)?, 1 + count.div_ceil(2)));
        }
        let data = bytes.get(1..1 + header).ok_or(invalid("truncated Huffman description"))?;
        let (distribution, used) = FSEDistribution::read(data, ZstandardFormat::WEIGHTS_MAXIMUM_LOG, 16)?;
        let table = FSEDecodingTable::new(&distribution);
        let mut reader = BackwardBitReader::new(&data[used..])
            .ok_or(CompressionError::InvalidData { reason: "bitstream without its final bit" })?;
        let mut states = [table.initial_state(&mut reader), table.initial_state(&mut reader)];
        let mut weights = Vec::new();
        // The two states take turns; when an update reads past the start, the other state's symbol ends the series.
        let mut turn = 0;
        loop {
            if weights.len() >= 255 {
                return Err(invalid("too many Huffman weights"));
            }
            weights.push(table.entries[states[turn]].symbol);
            states[turn] = table.next_state(states[turn], &mut reader);
            if reader.overflowed() {
                weights.push(table.entries[states[1 - turn]].symbol);
                break;
            }
            turn = 1 - turn;
        }
        Ok((ZstandardHuffman::from_weights(&weights)?, 1 + header))
    }

    /// Writes the tree description: the weights of the symbols before the
    /// last present one, directly if they are at most 128, otherwise
    /// FSE-compressed; `None` if they cannot be described.
    pub fn write(&self) -> Option<Vec<u8>> {
        let last = self.weights.iter().rposition(|weight| *weight > 0)?;
        let listed = &self.weights[..last];
        if listed.len() <= 128 {
            let mut out = vec![(127 + listed.len()) as u8];
            for pair in listed.chunks(2) {
                out.push(pair[0] << 4 | pair.get(1).copied().unwrap_or(0));
            }
            return Some(out);
        }
        let mut counts = [0u32; 16];
        for weight in listed {
            counts[*weight as usize] += 1;
        }
        if counts.iter().filter(|count| **count > 0).count() < 2 {
            return None;
        }
        let distribution = FSEDistribution::normalize(&counts, ZstandardFormat::WEIGHTS_MAXIMUM_LOG).ok()?;
        let table = FSEEncodingTable::new(&distribution);
        let mut writer = BackwardBitWriter::new();
        // As the reference encoder: the last symbols initialize the states, the others are encoded in pairs from the end.
        let mut symbols = listed.iter().rev().map(|weight| *weight as usize);
        let mut states = [0u32; 2];
        if listed.len() % 2 == 1 {
            states[0] = table.initial_state(symbols.next()?);
            states[1] = table.initial_state(symbols.next()?);
            states[0] = table.encode(states[0], symbols.next()?, &mut writer);
        } else {
            states[1] = table.initial_state(symbols.next()?);
            states[0] = table.initial_state(symbols.next()?);
        }
        while let Some(second) = symbols.next() {
            states[1] = table.encode(states[1], second, &mut writer);
            states[0] = table.encode(states[0], symbols.next()?, &mut writer);
        }
        table.flush(states[1], &mut writer);
        table.flush(states[0], &mut writer);
        let mut description = Vec::new();
        distribution.write(&mut description).ok()?;
        description.extend(writer.finish());
        if description.len() > 127 {
            return None;
        }
        let mut out = vec![description.len() as u8];
        out.extend(description);
        Some(out)
    }

    /// Decodes `count` symbols of the backward stream `stream` into `out`;
    /// fails with `InvalidData` unless the stream is consumed exactly.
    pub fn decode_stream(&self, stream: &[u8], count: usize, out: &mut Vec<u8>) -> Result<(), CompressionError> {
        let mut reader = BackwardBitReader::new(stream)
            .ok_or(CompressionError::InvalidData { reason: "bitstream without its final bit" })?;
        for _ in 0..count {
            let (symbol, length) = self.table[reader.peek(self.maximum_bits) as usize];
            out.push(symbol);
            reader.read(length as u32);
            if reader.overflowed() {
                return Err(CompressionError::InvalidData { reason: "Huffman stream shorter than its symbols" });
            }
        }
        if !reader.is_finished() {
            return Err(CompressionError::InvalidData { reason: "Huffman stream not consumed exactly" });
        }
        Ok(())
    }

    /// Encodes `data` as a backward stream.
    pub fn encode_stream(codes: &[(u32, u32)], data: &[u8]) -> Vec<u8> {
        let mut writer = BackwardBitWriter::new();
        for byte in data.iter().rev() {
            let (code, length) = codes[*byte as usize];
            writer.write(code, length);
        }
        writer.finish()
    }
}
