use alloc::vec::Vec;

use super::{
    ZstandardFormat, ZstandardHuffman, ZstandardLiterals, ZstandardOffsets, ZstandardSequence, ZstandardSequenceTables,
    ZstandardSequences,
};
use crate::codec::lz77::{LZ77MatchFinder, LZ77Window};
use crate::codec::{CompressionError, PendingOutput};

/// The state a frame's compressed blocks carry from one to the next: the
/// Huffman code of the last compressed literals, the sequence tables and
/// the repeat offsets (RFC 8878 section 3.1.1.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZstandardBlockDecoder {
    pub huffman: Option<ZstandardHuffman>,
    pub tables: ZstandardSequenceTables,
    pub offsets: ZstandardOffsets,
    literals: Vec<u8>,
    sequences: Vec<ZstandardSequence>,
    scratch: Vec<u8>,
}

impl ZstandardBlockDecoder {
    pub fn new() -> ZstandardBlockDecoder {
        ZstandardBlockDecoder::default()
    }

    /// Decodes the compressed block `block` into `out` and the history
    /// `window` (which starts with `dictionary` bytes of a dictionary); fails
    /// with `InvalidData` if it breaks the format, regenerates more than
    /// `maximum` bytes, or refers to data beyond `window_size` bytes back (or
    /// into the dictionary once the frame has more than `window_size` bytes).
    pub fn decode(
        &mut self,
        block: &[u8],
        window: &mut LZ77Window,
        dictionary: u64,
        window_size: u64,
        out: &mut PendingOutput,
        maximum: usize,
    ) -> Result<(), CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        let used = ZstandardLiterals::decode(block, &mut self.huffman, &mut self.literals)?;
        ZstandardSequences::decode(&block[used..], &mut self.tables, &mut self.sequences)?;
        let mut produced = 0usize;
        let mut literal = 0usize;
        for sequence in &self.sequences {
            let length = sequence.literals_length as usize;
            let literals = self
                .literals
                .get(literal..literal + length)
                .ok_or(invalid("sequences use more literals than decoded"))?;
            literal += length;
            let offset = self.offsets.resolve(sequence.offset_value, sequence.literals_length)? as usize;
            produced += length + sequence.match_length as usize;
            if produced > maximum {
                return Err(invalid("block larger than the maximum"));
            }
            window.extend(literals);
            out.extend(literals);
            let frame = window.total() - dictionary;
            let reachable = if offset as u64 <= frame {
                offset as u64 <= window_size
            } else {
                frame <= window_size && offset as u64 <= frame + dictionary
            };
            if !reachable || offset > window.len() {
                return Err(invalid("offset beyond the window"));
            }
            self.scratch.resize(sequence.match_length as usize, 0);
            window.copy(offset, sequence.match_length as usize, &mut self.scratch)?;
            out.extend(&self.scratch);
        }
        let rest = &self.literals[literal..];
        if produced + rest.len() > maximum {
            return Err(invalid("block larger than the maximum"));
        }
        window.extend(rest);
        out.extend(rest);
        Ok(())
    }
}

/// The search of a compression level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZstandardLevel {
    pub window_log: u32,
    pub chain_limit: usize,
    pub nice_length: usize,
    pub lazy: bool,
}

impl ZstandardLevel {
    /// The levels 1 to 19 (index 0 is level 1).
    pub const LEVELS: [ZstandardLevel; 19] = [
        ZstandardLevel { window_log: 19, chain_limit: 1, nice_length: 16, lazy: false },
        ZstandardLevel { window_log: 20, chain_limit: 2, nice_length: 24, lazy: false },
        ZstandardLevel { window_log: 21, chain_limit: 4, nice_length: 32, lazy: false },
        ZstandardLevel { window_log: 21, chain_limit: 8, nice_length: 32, lazy: true },
        ZstandardLevel { window_log: 21, chain_limit: 12, nice_length: 48, lazy: true },
        ZstandardLevel { window_log: 21, chain_limit: 16, nice_length: 64, lazy: true },
        ZstandardLevel { window_log: 22, chain_limit: 24, nice_length: 64, lazy: true },
        ZstandardLevel { window_log: 22, chain_limit: 32, nice_length: 96, lazy: true },
        ZstandardLevel { window_log: 22, chain_limit: 48, nice_length: 128, lazy: true },
        ZstandardLevel { window_log: 22, chain_limit: 64, nice_length: 128, lazy: true },
        ZstandardLevel { window_log: 22, chain_limit: 96, nice_length: 160, lazy: true },
        ZstandardLevel { window_log: 23, chain_limit: 128, nice_length: 192, lazy: true },
        ZstandardLevel { window_log: 23, chain_limit: 192, nice_length: 256, lazy: true },
        ZstandardLevel { window_log: 23, chain_limit: 256, nice_length: 256, lazy: true },
        ZstandardLevel { window_log: 23, chain_limit: 384, nice_length: 384, lazy: true },
        ZstandardLevel { window_log: 23, chain_limit: 512, nice_length: 512, lazy: true },
        ZstandardLevel { window_log: 23, chain_limit: 768, nice_length: 768, lazy: true },
        ZstandardLevel { window_log: 23, chain_limit: 1024, nice_length: 1024, lazy: true },
        ZstandardLevel { window_log: 23, chain_limit: 2048, nice_length: 2048, lazy: true },
    ];
}

/// Turns the data of a match finder into compressed blocks: sequences found
/// greedily (lazily at the higher levels), preferring the repeat offsets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZstandardBlockEncoder {
    pub finder: LZ77MatchFinder,
    pub level: ZstandardLevel,
    pub offsets: ZstandardOffsets,
}

impl ZstandardBlockEncoder {
    /// The shortest match.
    pub const MINIMUM_MATCH: usize = 3;
    /// The longest match.
    pub const MAXIMUM_MATCH: usize = 131074;

    /// The longest match at `position` among the repeat offsets: (offset, length).
    pub fn repeat_match(
        &self,
        position: usize,
        literals_length: u32,
        limit: usize,
        history: usize,
    ) -> Option<(u32, usize)> {
        let offsets = self.offsets.offsets;
        let candidates = if literals_length > 0 {
            [offsets[0], offsets[1], offsets[2]]
        } else {
            [offsets[1], offsets[2], offsets[0].saturating_sub(1)]
        };
        let data = self.finder.data();
        candidates
            .iter()
            .filter(|offset| **offset > 0 && **offset as usize <= history)
            .map(|offset| {
                (
                    *offset,
                    (0..limit)
                        .take_while(|index| data[position + index] == data[position - *offset as usize + index])
                        .count(),
                )
            })
            .filter(|(_, length)| *length >= ZstandardBlockEncoder::MINIMUM_MATCH)
            .max_by_key(|(_, length)| *length)
    }

    /// The sequences and literals of the data of the finder from `start` to
    /// `end` (whose bytes before `start`, up to `history` of them, may be referred to).
    pub fn parse(&mut self, start: usize, end: usize, history: usize) -> (Vec<ZstandardSequence>, Vec<u8>) {
        let mut sequences = Vec::new();
        let mut literals = Vec::new();
        let mut literal_start = start;
        let mut position = start;
        let window = 1usize << self.level.window_log;
        while position < end {
            let limit = (end - position).min(ZstandardBlockEncoder::MAXIMUM_MATCH);
            let reach = (position - start + history).min(window);
            let literals_length = (position - literal_start) as u32;
            let mut best = self.repeat_match(position, literals_length, limit, reach);
            // A match of the finder wins over a repeat match only if it is longer by 2 or more.
            let searched = if best.is_none_or(|(_, length)| length < self.level.nice_length) {
                self.finder.find(position, limit).filter(|found| found.distance <= reach)
            } else {
                None
            };
            if let Some(found) = searched
                && best.is_none_or(|(_, length)| found.length > length + 1)
            {
                best = Some((found.distance as u32, found.length));
            }
            // At the lazy levels, a longer match one byte later defers this one.
            if self.level.lazy
                && limit > 1
                && let Some((_, length)) = best
            {
                let next = self
                    .finder
                    .find(position + 1, limit - 1)
                    .filter(|found| found.distance <= reach + 1)
                    .map_or(0, |found| found.length);
                if next > length + 1 {
                    best = None;
                }
            }
            match best {
                Some((offset, length)) => {
                    literals.extend_from_slice(&self.finder.data()[literal_start..position]);
                    let offset_value = self.offsets.encode(offset, literals_length);
                    self.offsets.resolve(offset_value, literals_length).expect("encoded offsets resolve");
                    sequences.push(ZstandardSequence { literals_length, offset_value, match_length: length as u32 });
                    position += length;
                    literal_start = position;
                }
                None => position += 1,
            }
        }
        literals.extend_from_slice(&self.finder.data()[literal_start..end]);
        (sequences, literals)
    }

    /// Encodes the block of the finder's data from `start` to `end` into
    /// `out` (header included) as the smallest of a compressed, raw or RLE block.
    pub fn encode(&mut self, start: usize, end: usize, history: usize, last: bool, out: &mut Vec<u8>) {
        let saved = self.offsets;
        let (sequences, literals) = self.parse(start, end, history);
        let data = &self.finder.data()[start..end];
        let mut content = Vec::new();
        ZstandardLiterals::encode(&literals, &mut content);
        if sequences.is_empty() {
            content.push(0);
        } else {
            ZstandardSequences::encode(&sequences, &mut content);
        }
        let size = data.len();
        let header = |kind: u8, size: usize| (last as u32 | (kind as u32) << 1 | (size as u32) << 3).to_le_bytes();
        if size > 1 && data.iter().all(|byte| *byte == data[0]) {
            // An RLE block leaves the repeat offsets as they were.
            self.offsets = saved;
            out.extend_from_slice(&header(ZstandardFormat::RLE_BLOCK, size)[..3]);
            out.push(data[0]);
        } else if content.len() >= size || content.len() > ZstandardFormat::MAXIMUM_BLOCK {
            self.offsets = saved;
            out.extend_from_slice(&header(ZstandardFormat::RAW_BLOCK, size)[..3]);
            out.extend_from_slice(data);
        } else {
            out.extend_from_slice(&header(ZstandardFormat::COMPRESSED_BLOCK, content.len())[..3]);
            out.extend(content);
        }
    }

    /// An empty last block (a raw block of 0 bytes).
    pub fn empty_last_block(out: &mut Vec<u8>) {
        out.extend_from_slice(&[1, 0, 0]);
    }
}
