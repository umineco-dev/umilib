use super::{BrotliFormat, BrotliPrefixCode};
use crate::bytes::{BitQueue, BitWriter};
use crate::codec::CompressionError;

/// The three block categories of a meta-block (RFC 7932 section 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrotliCategory {
    Literal = 0,
    Command = 1,
    Distance = 2,
}

impl BrotliCategory {
    /// The categories in the order of the meta-block header.
    pub const ALL: [BrotliCategory; 3] = [BrotliCategory::Literal, BrotliCategory::Command, BrotliCategory::Distance];
}

/// The block switches of one category (section 6): its number of block
/// types, the prefix codes of the block type and count codes, the current
/// and previous block types, and the elements left in the current block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrotliBlockSwitch {
    pub types: usize,
    pub type_code: Option<BrotliPrefixCode>,
    pub count_code: Option<BrotliPrefixCode>,
    pub current: usize,
    pub previous: usize,
    pub remaining: u32,
    /// A block type read whose block count is not read yet.
    pending: Option<usize>,
}

impl BrotliBlockSwitch {
    /// One block type, whose block never ends.
    pub fn new() -> BrotliBlockSwitch {
        BrotliBlockSwitch::with_types(1)
    }

    /// `types` block types, before the codes and the first block count are read.
    pub fn with_types(types: usize) -> BrotliBlockSwitch {
        BrotliBlockSwitch {
            types,
            type_code: None,
            count_code: None,
            current: 0,
            previous: 1,
            remaining: BrotliFormat::UNLIMITED_BLOCK,
            pending: None,
        }
    }

    /// Reads a number of block types or of prefix trees (NBLTYPESx,
    /// NTREESx: 1 to 256) in the variable-length code of section 9.2,
    /// consuming it once all of it is queued; `None` if `input` ran out first.
    pub fn read_types(queue: &mut BitQueue, input: &mut &[u8]) -> Option<usize> {
        if !queue.fill(1, input) {
            return None;
        }
        if queue.peek_padded(1) == 0 {
            queue.consume(1);
            return Some(1);
        }
        if !queue.fill(4, input) {
            return None;
        }
        let bits = (queue.peek_padded(4) >> 1) as u32;
        if bits == 0 {
            queue.consume(4);
            return Some(2);
        }
        if !queue.fill(4 + bits, input) {
            return None;
        }
        let extra = (queue.peek_padded(4 + bits) >> 4) as usize;
        queue.consume(4 + bits);
        Some((1 << bits) + 1 + extra)
    }

    /// Writes `types` (1 to 256) in the code [`BrotliBlockSwitch::read_types`] reads.
    pub fn write_types(types: usize, writer: &mut BitWriter) {
        debug_assert!((1..=256).contains(&types));
        match types {
            1 => writer.write(0, 1),
            2 => writer.write(1, 4),
            _ => {
                let bits = usize::BITS - 1 - (types - 1).leading_zeros();
                writer.write(1 | (bits as u64) << 1, 4);
                writer.write((types - 1 - (1 << bits)) as u64, bits);
            }
        }
    }

    /// Reads a block count: its code and extra bits, consumed together once all are queued.
    pub fn read_count(&self, queue: &mut BitQueue, input: &mut &[u8]) -> Result<Option<u32>, CompressionError> {
        let code = self.count_code.as_ref().expect("read before the block counts");
        let extra = |symbol: u16| BrotliFormat::BLOCK_COUNT_BITS[symbol as usize] as u32;
        let Some((symbol, bits)) = code.read_with_extra(queue, input, extra)? else {
            return Ok(None);
        };
        Ok(Some(BrotliFormat::BLOCK_COUNT_BASES[symbol as usize] + bits))
    }

    /// Reads a block switch command (a block type and a block count) and
    /// starts the block; false if `input` ran out first (the type read so far is kept).
    /// With one block type, the block starts again without reading anything.
    pub fn switch(&mut self, queue: &mut BitQueue, input: &mut &[u8]) -> Result<bool, CompressionError> {
        if self.types < 2 {
            // One block type has no switches: its block goes on (as in the reference decoder).
            self.remaining = BrotliFormat::UNLIMITED_BLOCK;
            return Ok(true);
        }
        if self.pending.is_none() {
            let code = self.type_code.as_ref().expect("read before the block switches");
            let Some(symbol) = code.read(queue, input)? else {
                return Ok(false);
            };
            self.pending = Some(match symbol {
                0 => self.previous,
                1 => (self.current + 1) % self.types,
                _ => symbol as usize - 2,
            });
        }
        let Some(count) = self.read_count(queue, input)? else {
            return Ok(false);
        };
        self.previous = self.current;
        self.current = self.pending.take().expect("a pending block type");
        self.remaining = count;
        Ok(true)
    }

    /// The block count code and extra bits of `count` (1 to 16793840).
    pub fn count_code(count: u32) -> (usize, u32) {
        let code =
            BrotliFormat::BLOCK_COUNT_BASES.iter().rposition(|base| *base <= count).expect("a count of 1 or more");
        (code, count - BrotliFormat::BLOCK_COUNT_BASES[code])
    }
}

impl Default for BrotliBlockSwitch {
    fn default() -> BrotliBlockSwitch {
        BrotliBlockSwitch::new()
    }
}
