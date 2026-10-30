use alloc::vec::Vec;

use super::{ZstandardFormat, ZstandardHuffman};
use crate::codec::CompressionError;

/// The literals section of a compressed block (RFC 8878 section 3.1.1.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZstandardLiterals;

impl ZstandardLiterals {
    /// Decodes the literals section at the start of `block` into `out`,
    /// with the Huffman code of the previous compressed literals in
    /// `previous` (which it replaces with a new one); returns the bytes taken.
    pub fn decode(
        block: &[u8],
        previous: &mut Option<ZstandardHuffman>,
        out: &mut Vec<u8>,
    ) -> Result<usize, CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        let first = *block.first().ok_or(invalid("truncated literals section"))?;
        let kind = first & 3;
        let format = (first >> 2) & 3;
        let header = |length: usize| block.get(..length).ok_or(invalid("truncated literals section"));
        out.clear();
        if kind == ZstandardFormat::RAW_LITERALS || kind == ZstandardFormat::RLE_LITERALS {
            let (size, length) = match format {
                0 | 2 => ((first >> 3) as usize, 1),
                1 => {
                    let bytes = header(2)?;
                    ((bytes[0] >> 4) as usize | (bytes[1] as usize) << 4, 2)
                }
                _ => {
                    let bytes = header(3)?;
                    ((bytes[0] >> 4) as usize | (bytes[1] as usize) << 4 | (bytes[2] as usize) << 12, 3)
                }
            };
            if size > ZstandardFormat::MAXIMUM_BLOCK {
                return Err(invalid("literals larger than a block"));
            }
            if kind == ZstandardFormat::RAW_LITERALS {
                out.extend_from_slice(block.get(length..length + size).ok_or(invalid("truncated literals section"))?);
                return Ok(length + size);
            }
            let byte = *block.get(length).ok_or(invalid("truncated literals section"))?;
            out.resize(size, byte);
            return Ok(length + 1);
        }
        let (bits, length, streams) = match format {
            0 => (10, 3, 1),
            1 => (10, 3, 4),
            2 => (14, 4, 4),
            _ => (18, 5, 4),
        };
        let bytes = header(length)?;
        let mut value = 0u64;
        for (index, byte) in bytes.iter().enumerate() {
            value |= (*byte as u64) << (8 * index);
        }
        let mask = (1u64 << bits) - 1;
        let regenerated = ((value >> 4) & mask) as usize;
        let compressed = ((value >> (4 + bits)) & mask) as usize;
        if regenerated > ZstandardFormat::MAXIMUM_BLOCK {
            return Err(invalid("literals larger than a block"));
        }
        let content = block.get(length..length + compressed).ok_or(invalid("truncated literals section"))?;
        let mut position = 0;
        if kind == ZstandardFormat::COMPRESSED_LITERALS {
            let (code, used) = ZstandardHuffman::read(content)?;
            *previous = Some(code);
            position = used;
        }
        let code = previous.as_ref().ok_or(invalid("treeless literals without a previous code"))?;
        let data = &content[position..];
        if streams == 1 {
            code.decode_stream(data, regenerated, out)?;
        } else {
            let table = data.get(..6).ok_or(invalid("truncated jump table"))?;
            let sizes = [
                u16::from_le_bytes([table[0], table[1]]) as usize,
                u16::from_le_bytes([table[2], table[3]]) as usize,
                u16::from_le_bytes([table[4], table[5]]) as usize,
            ];
            let total = data.len() - 6;
            let first_three: usize = sizes.iter().sum();
            if first_three > total {
                return Err(invalid("jump table beyond the streams"));
            }
            let each = regenerated.div_ceil(4);
            if each * 3 > regenerated {
                return Err(invalid("too few literals for four streams"));
            }
            let mut start = 6;
            for (index, size) in sizes.iter().copied().chain([total - first_three]).enumerate() {
                let count = if index < 3 { each } else { regenerated - 3 * each };
                code.decode_stream(&data[start..start + size], count, out)?;
                start += size;
            }
        }
        Ok(length + compressed)
    }

    /// Writes the header of raw or RLE literals of `size` bytes.
    pub fn write_raw_header(kind: u8, size: usize, out: &mut Vec<u8>) {
        if size < 32 {
            out.push(kind | (size as u8) << 3);
        } else if size < 4096 {
            out.extend_from_slice(&[kind | 1 << 2 | ((size & 0xF) as u8) << 4, (size >> 4) as u8]);
        } else {
            out.extend_from_slice(&[kind | 3 << 2 | ((size & 0xF) as u8) << 4, (size >> 4) as u8, (size >> 12) as u8]);
        }
    }

    /// Encodes `literals` as the smallest of raw, RLE and Huffman-compressed literals.
    pub fn encode(literals: &[u8], out: &mut Vec<u8>) {
        let raw = |out: &mut Vec<u8>| {
            ZstandardLiterals::write_raw_header(ZstandardFormat::RAW_LITERALS, literals.len(), out);
            out.extend_from_slice(literals);
        };
        if !literals.is_empty() && literals.iter().all(|byte| *byte == literals[0]) && literals.len() > 1 {
            ZstandardLiterals::write_raw_header(ZstandardFormat::RLE_LITERALS, literals.len(), out);
            out.push(literals[0]);
            return;
        }
        let mut frequencies = [0u32; 256];
        for byte in literals {
            frequencies[*byte as usize] += 1;
        }
        if literals.len() < 64 || frequencies.iter().filter(|count| **count > 0).count() < 2 {
            raw(out);
            return;
        }
        let code = ZstandardHuffman::from_frequencies(&frequencies);
        let Some(description) = code.write() else {
            raw(out);
            return;
        };
        let codes = code.codes();
        let mut content = description;
        let streams = if literals.len() < 256 { 1 } else { 4 };
        if streams == 1 {
            content.extend(ZstandardHuffman::encode_stream(&codes, literals));
        } else {
            let each = literals.len().div_ceil(4);
            let encoded: Vec<Vec<u8>> =
                literals.chunks(each).map(|chunk| ZstandardHuffman::encode_stream(&codes, chunk)).collect();
            for stream in &encoded[..3] {
                content.extend_from_slice(&(stream.len() as u16).to_le_bytes());
            }
            for stream in &encoded {
                content.extend_from_slice(stream);
            }
        }
        let largest = literals.len().max(content.len());
        let (format, bits, length) = match (streams, largest) {
            (1, _) => (0u64, 10, 3),
            (_, 0..=1023) => (1, 10, 3),
            (_, 1024..=16383) => (2, 14, 4),
            _ => (3, 18, 5),
        };
        if content.len() + length >= literals.len() + if literals.len() < 4096 { 2 } else { 3 }
            || content.len() >= 1 << bits
        {
            raw(out);
            return;
        }
        let value = ZstandardFormat::COMPRESSED_LITERALS as u64
            | format << 2
            | (literals.len() as u64) << 4
            | (content.len() as u64) << (4 + bits);
        out.extend_from_slice(&value.to_le_bytes()[..length]);
        out.extend_from_slice(&content);
    }
}
