use alloc::vec::Vec;

use crate::codec::CompressionError;
use crate::codec::lz77::{LZ77MatchFinder, LZ77MatchFinderConfig};

/// The LZ4 block format (lz4_Block_format.md): sequences of a token (the
/// literal length in its high 4 bits, the match length less 4 in its low 4
/// bits, 15 continuing in bytes of 255 and a last smaller one), the
/// literals, then (except in the last sequence) a little-endian offset of
/// 1 to 65535 and the rest of the match length.
///
/// A block carries no sizes: [`LZ4Block::decode`] reads the whole block it
/// is given, within a limit on the bytes it writes. [`LZ4Block::encode`]
/// follows the end-of-block rules of the format (the last 5 bytes are
/// literals, the last match starts at least 12 bytes before the end), which
/// the decoder does not require of other encoders.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZ4Block {
    finder: LZ77MatchFinder,
}

impl LZ4Block {
    /// The shortest match.
    pub const MINIMUM_MATCH: usize = 4;
    /// The farthest offset.
    pub const MAXIMUM_OFFSET: usize = 65535;
    /// The bytes at the end of a block that are always literals.
    pub const LAST_LITERALS: usize = 5;
    /// The last match starts at least this many bytes before the end of a block.
    pub const MATCH_FIND_LIMIT: usize = 12;
    /// The candidates the encoder examines at the levels 0 to 12 (1 for the
    /// fast levels, more for the high-compression ones).
    pub const CHAIN_LIMITS: [usize; 13] = [1, 1, 1, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096];

    /// An encoder searching as `level` (0 to 12) does; fails with `InvalidParameter` beyond 12.
    pub fn new(level: u32) -> Result<LZ4Block, CompressionError> {
        let chain_limit = *LZ4Block::CHAIN_LIMITS.get(level as usize).ok_or(CompressionError::InvalidParameter)?;
        let finder = LZ77MatchFinder::new(LZ77MatchFinderConfig {
            window_bits: 16,
            chain_bits: 16,
            hash_bits: 16,
            maximum_distance: LZ4Block::MAXIMUM_OFFSET,
            minimum_length: LZ4Block::MINIMUM_MATCH,
            maximum_length: 1 << 16,
            chain_limit,
            nice_length: 1 << 16,
        })?;
        Ok(LZ4Block { finder })
    }

    /// Forgets the history; the next block may refer to `prefix` (its last
    /// 64 KiB), such as a dictionary.
    pub fn reset(&mut self, prefix: &[u8]) {
        self.finder.clear();
        self.finder.append(&prefix[prefix.len().saturating_sub(LZ4Block::MAXIMUM_OFFSET)..]);
    }

    /// Encodes `data` as a block appended to `out`; its matches may refer to
    /// the history: the prefix of [`LZ4Block::reset`] and the blocks encoded
    /// since, as far as 65535 bytes back.
    pub fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) {
        // Positions are recomputed for each block, so what discarding drops needs no bookkeeping.
        self.finder.discard(self.finder.data().len());
        let start = self.finder.data().len();
        self.finder.append(data);
        let end = start + data.len();
        let (mut position, mut literals) = (start, start);
        // A match must start at least 12 bytes before the end and leave the last 5 bytes.
        while position + LZ4Block::MATCH_FIND_LIMIT <= end {
            let limit = end - LZ4Block::LAST_LITERALS - position;
            match self.finder.find(position, limit) {
                Some(found) => {
                    LZ4Block::write_sequence(
                        &self.finder.data()[literals..position],
                        Some((found.distance, found.length)),
                        out,
                    );
                    position += found.length;
                    literals = position;
                }
                None => position += 1,
            }
        }
        LZ4Block::write_sequence(&self.finder.data()[literals..end], None, out);
    }

    /// Writes a sequence of `literals` and a match (offset, length), or the last sequence.
    pub fn write_sequence(literals: &[u8], found: Option<(usize, usize)>, out: &mut Vec<u8>) {
        let match_length = found.map_or(0, |(_, length)| length - LZ4Block::MINIMUM_MATCH);
        out.push((literals.len().min(15) as u8) << 4 | match_length.min(15) as u8);
        if literals.len() >= 15 {
            LZ4Block::write_length(literals.len() - 15, out);
        }
        out.extend_from_slice(literals);
        if let Some((offset, _)) = found {
            out.extend_from_slice(&(offset as u16).to_le_bytes());
            if match_length >= 15 {
                LZ4Block::write_length(match_length - 15, out);
            }
        }
    }

    /// Writes the rest of a length: bytes of 255, then the remainder.
    pub fn write_length(mut length: usize, out: &mut Vec<u8>) {
        while length >= 255 {
            out.push(255);
            length -= 255;
        }
        out.push(length as u8);
    }

    /// Reads the rest of a length from `block` at `position`; fails with
    /// `InvalidData` at the end of the block.
    pub fn read_length(block: &[u8], position: &mut usize) -> Result<usize, CompressionError> {
        let mut length = 0usize;
        loop {
            let byte = *block.get(*position).ok_or(CompressionError::InvalidData { reason: "truncated block" })?;
            *position += 1;
            length = length.saturating_add(byte as usize);
            if byte != 255 {
                return Ok(length);
            }
        }
    }

    /// Decodes the whole `block`, appending its data to `out`, whose bytes are
    /// the history matches may refer to (a dictionary or previous blocks);
    /// fails with `LimitExceeded` beyond `limit` bytes of data and with
    /// `InvalidData` for a truncated block, an offset of 0 or one beyond the history.
    pub fn decode(block: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), CompressionError> {
        let maximum = out.len().saturating_add(limit);
        let exceeded = CompressionError::LimitExceeded { limit: limit as u64 };
        let mut position = 0;
        loop {
            let token = *block.get(position).ok_or(CompressionError::InvalidData { reason: "truncated block" })?;
            position += 1;
            let mut literals = (token >> 4) as usize;
            if literals == 15 {
                literals = literals.saturating_add(LZ4Block::read_length(block, &mut position)?);
            }
            if literals > block.len() - position {
                return Err(CompressionError::InvalidData { reason: "truncated block" });
            }
            if literals > maximum - out.len() {
                return Err(exceeded);
            }
            out.extend_from_slice(&block[position..position + literals]);
            position += literals;
            if position == block.len() {
                return Ok(());
            }
            let offset =
                block.get(position..position + 2).ok_or(CompressionError::InvalidData { reason: "truncated block" })?;
            let offset = u16::from_le_bytes([offset[0], offset[1]]) as usize;
            position += 2;
            if offset == 0 || offset > out.len() {
                return Err(CompressionError::InvalidData { reason: "invalid offset" });
            }
            let mut length = (token & 0xF) as usize;
            if length == 15 {
                length = length.saturating_add(LZ4Block::read_length(block, &mut position)?);
            }
            let length = length.saturating_add(LZ4Block::MINIMUM_MATCH);
            if length > maximum - out.len() {
                return Err(exceeded);
            }
            let start = out.len() - offset;
            if offset >= length {
                out.extend_from_within(start..start + length);
            } else {
                // Overlapping: the bytes copied are copied again, a period of `offset` bytes at a time.
                let mut remaining = length;
                while remaining > 0 {
                    let count = remaining.min(out.len() - start);
                    out.extend_from_within(start..start + count);
                    remaining -= count;
                }
            }
        }
    }

    /// The block of `data` with no history, encoded at `level` (0 to 12).
    pub fn compress(data: &[u8], level: u32) -> Result<Vec<u8>, CompressionError> {
        let mut block = LZ4Block::new(level)?;
        let mut out = Vec::new();
        block.encode(data, &mut out);
        Ok(out)
    }

    /// The data of the whole `block`, with no history, of at most `limit` bytes.
    pub fn decompress(block: &[u8], limit: usize) -> Result<Vec<u8>, CompressionError> {
        let mut out = Vec::new();
        LZ4Block::decode(block, &mut out, limit)?;
        Ok(out)
    }
}
