use alloc::vec;
use alloc::vec::Vec;

use super::HuffmanCode;
use crate::bytes::{BitOrder, BitQueue};
use crate::codec::huffman::HuffmanError;

/// A table that decodes the codes of a [`HuffmanCode`]: from the next
/// [`HuffmanTable::peek_bits`] bits of a stream as a value of the table's
/// [`BitOrder`] (the first bit of a code the least significant bit of the
/// value, as in Deflate and Brotli, or the most significant, as in
/// Zstandard's backward streams; missing bits as zeros),
/// [`HuffmanTable::decode`] gives the symbol and the length of its code.
///
/// For codes of up to [`HuffmanTable::DIRECT_BITS`] bits: of
/// [`BitOrder::LeastSignificantFirst`], codes of up to
/// [`HuffmanTable::PRIMARY_BITS`] bits are found in one lookup and longer
/// ones in a second table of their prefix; of
/// [`BitOrder::MostSignificantFirst`], one table spans the longest code.
/// Longer codes (up to [`HuffmanCode::MAXIMUM_LENGTH`], such as those of
/// HPACK) would need tables of millions of entries: those of up to
/// [`HuffmanTable::PRIMARY_BITS`] bits are found in one lookup, in either
/// order, and the rest by the canonical order of their codes, a length at a
/// time ([`HuffmanTable::search`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HuffmanTable {
    /// Per entry: the symbol (bits 0 to 15) and the length (bits 16 to 21),
    /// 0 for no code; or, with [`HuffmanTable::LINK`], the offset of a
    /// second table (bits 0 to 23) and the bits that index it (bits 24 to 28).
    entries: Vec<u32>,
    primary_bits: u32,
    maximum_length: u32,
    order: BitOrder,
    /// Whether the table is [`HuffmanTable::searched`]: its entries are
    /// indexed by the first primary bits, first bit most significant, and,
    /// per length above them, `lengths` has the first code of that length,
    /// how many there are, and where their symbols start in `symbols`,
    /// which lists them by length, then by symbol.
    searched: bool,
    lengths: Vec<(u32, u32, u32)>,
    symbols: Vec<u16>,
}

impl HuffmanTable {
    /// The bits of the first lookup: of [`BitOrder::LeastSignificantFirst`],
    /// and of codes longer than [`HuffmanTable::DIRECT_BITS`].
    pub const PRIMARY_BITS: u32 = 10;
    /// The longest code a table holds in its entries.
    pub const DIRECT_BITS: u32 = 15;
    /// The flag of an entry that links to a second table.
    pub const LINK: u32 = 1 << 31;

    /// The table of `code` for streams of bit order `order`.
    pub fn new(code: &HuffmanCode, order: BitOrder) -> HuffmanTable {
        if code.maximum_length() > HuffmanTable::DIRECT_BITS {
            return HuffmanTable::searched(code, order);
        }
        match order {
            BitOrder::MostSignificantFirst => HuffmanTable::single(code),
            BitOrder::LeastSignificantFirst => HuffmanTable::linked(code),
        }
    }

    /// The table of the code of `lengths` ([`HuffmanCode::from_lengths`]).
    pub fn from_lengths(lengths: &[u8], order: BitOrder) -> Result<HuffmanTable, HuffmanError> {
        Ok(HuffmanTable::new(&HuffmanCode::from_lengths(lengths)?, order))
    }

    /// The table for [`BitOrder::MostSignificantFirst`]: one level of
    /// 2^(longest code) entries indexed by the bits, first bit most significant.
    pub fn single(code: &HuffmanCode) -> HuffmanTable {
        let maximum_length = code.maximum_length();
        let bits = maximum_length.max(1);
        let mut entries = vec![0u32; 1 << bits];
        for symbol in 0..code.symbols() {
            let length = code.length(symbol);
            if length == 0 {
                continue;
            }
            let start = (code.code(symbol) << (bits - length)) as usize;
            let entry = symbol as u32 | length << 16;
            entries[start..start + (1 << (bits - length))].fill(entry);
        }
        HuffmanTable {
            entries,
            primary_bits: bits,
            maximum_length,
            order: BitOrder::MostSignificantFirst,
            searched: false,
            lengths: Vec::new(),
            symbols: Vec::new(),
        }
    }

    /// The table for [`BitOrder::LeastSignificantFirst`]: a first level
    /// indexed by the first [`HuffmanTable::PRIMARY_BITS`] bits (first bit
    /// least significant), linking the prefixes of longer codes to second levels.
    pub fn linked(code: &HuffmanCode) -> HuffmanTable {
        let maximum_length = code.maximum_length();
        let primary = HuffmanTable::PRIMARY_BITS.min(maximum_length.max(1));
        let mut entries = vec![0u32; 1 << primary];
        // The bits each second table needs: the longest code of its prefix, less the primary bits.
        let mut second_bits = vec![0u32; 1 << primary];
        for symbol in 0..code.symbols() {
            let length = code.length(symbol);
            if length > primary {
                let prefix = (code.reversed_code(symbol) & ((1 << primary) - 1)) as usize;
                second_bits[prefix] = second_bits[prefix].max(length - primary);
            }
        }
        for (prefix, bits) in second_bits.iter().enumerate() {
            if *bits > 0 {
                let offset = entries.len() as u32;
                entries[prefix] = HuffmanTable::LINK | offset | bits << 24;
                entries.resize(entries.len() + (1 << bits), 0);
            }
        }
        for symbol in 0..code.symbols() {
            let length = code.length(symbol);
            if length == 0 {
                continue;
            }
            let reversed = code.reversed_code(symbol);
            let entry = symbol as u32 | length << 16;
            if length <= primary {
                // Every index whose low `length` bits are the reversed code.
                for index in (reversed as usize..1 << primary).step_by(1 << length) {
                    entries[index] = entry;
                }
            } else {
                let link = entries[(reversed & ((1 << primary) - 1)) as usize];
                let (offset, bits) = ((link & 0x00FF_FFFF) as usize, (link >> 24) & 0x1F);
                let rest = reversed >> primary;
                for index in (rest as usize..1 << bits).step_by(1 << (length - primary)) {
                    entries[offset + index] = entry;
                }
            }
        }
        HuffmanTable {
            entries,
            primary_bits: primary,
            maximum_length,
            order: BitOrder::LeastSignificantFirst,
            searched: false,
            lengths: Vec::new(),
            symbols: Vec::new(),
        }
    }

    /// The table of codes too long for entries: the codes of up to
    /// [`HuffmanTable::PRIMARY_BITS`] bits in a first table, the longer
    /// ones searched by length; streams of either order.
    pub fn searched(code: &HuffmanCode, order: BitOrder) -> HuffmanTable {
        let maximum_length = code.maximum_length();
        let primary = HuffmanTable::PRIMARY_BITS.min(maximum_length.max(1));
        let mut entries = vec![0u32; 1 << primary];
        let mut lengths = vec![(0u32, 0u32, 0u32); maximum_length.saturating_sub(primary) as usize];
        let mut symbols = Vec::new();
        for length in primary + 1..=maximum_length {
            let start = symbols.len() as u32;
            // Canonical codes of one length are consecutive, in the order of the symbols.
            for symbol in (0..code.symbols()).filter(|symbol| code.length(*symbol) == length) {
                if symbols.len() as u32 == start {
                    lengths[(length - primary - 1) as usize].0 = code.code(symbol);
                }
                symbols.push(symbol as u16);
            }
            lengths[(length - primary - 1) as usize].1 = symbols.len() as u32 - start;
            lengths[(length - primary - 1) as usize].2 = start;
        }
        for symbol in 0..code.symbols() {
            let length = code.length(symbol);
            if length == 0 || length > primary {
                continue;
            }
            let start = (code.code(symbol) << (primary - length)) as usize;
            entries[start..start + (1 << (primary - length))].fill(symbol as u32 | length << 16);
        }
        HuffmanTable { entries, primary_bits: primary, maximum_length, order, searched: true, lengths, symbols }
    }

    /// The symbol and length of the code longer than the primary bits that
    /// starts `code`, the next [`HuffmanTable::peek_bits`] bits with the
    /// first bit most significant; fails with `InvalidCode` if none does.
    pub fn search(&self, code: u64) -> Result<(u16, u32), HuffmanError> {
        for (index, (first, count, start)) in self.lengths.iter().enumerate() {
            let length = self.primary_bits + 1 + index as u32;
            let prefix = code >> (self.maximum_length - length);
            if let Some(offset) = prefix.checked_sub(u64::from(*first)).filter(|offset| *offset < u64::from(*count)) {
                return Ok((self.symbols[(*start as u64 + offset) as usize], length));
            }
        }
        Err(HuffmanError::InvalidCode)
    }

    /// The bits to peek before [`HuffmanTable::decode`]: the longest code.
    pub fn peek_bits(&self) -> u32 {
        self.maximum_length.max(1)
    }

    /// The bit order of the streams the table reads.
    pub fn order(&self) -> BitOrder {
        self.order
    }

    /// The symbol and the length of the code at the start of `bits`, the
    /// next [`HuffmanTable::peek_bits`] bits of the stream in the table's
    /// order; fails with `InvalidCode` if they start with no code.
    pub fn decode(&self, bits: u64) -> Result<(u16, u32), HuffmanError> {
        if self.searched {
            return self.decode_searched(bits);
        }
        let entry = match self.order {
            BitOrder::MostSignificantFirst => self.entries[(bits & ((1 << self.primary_bits) - 1)) as usize],
            BitOrder::LeastSignificantFirst => {
                let entry = self.entries[(bits & ((1 << self.primary_bits) - 1)) as usize];
                if entry & HuffmanTable::LINK != 0 {
                    let (offset, second) = ((entry & 0x00FF_FFFF) as usize, (entry >> 24) & 0x1F);
                    self.entries[offset + ((bits >> self.primary_bits) & ((1 << second) - 1)) as usize]
                } else {
                    entry
                }
            }
        };
        let length = (entry >> 16) & 0x3F;
        if length == 0 {
            return Err(HuffmanError::InvalidCode);
        }
        Ok((entry as u16, length))
    }

    /// [`HuffmanTable::decode`] of a [`HuffmanTable::searched`] table.
    pub fn decode_searched(&self, bits: u64) -> Result<(u16, u32), HuffmanError> {
        let maximum_length = self.maximum_length.max(1);
        let bits = bits & BitQueue::mask(maximum_length);
        // The value with the first bit most significant, as canonical codes compare.
        let code = match self.order {
            BitOrder::MostSignificantFirst => bits,
            BitOrder::LeastSignificantFirst => bits.reverse_bits() >> (64 - maximum_length),
        };
        let index = code >> (maximum_length - self.primary_bits);
        let entry = self.entries[index as usize];
        let length = (entry >> 16) & 0x3F;
        if length > 0 {
            return Ok((entry as u16, length));
        }
        self.search(code)
    }

    /// The next symbol of `queue` and the length of its code, without
    /// consuming the code, filling the queue from `input` a byte at a time
    /// only while the queued bits do not hold a whole code (so no byte past
    /// the code is taken); `None` if `input` ran out first.
    pub fn peek(&self, queue: &mut BitQueue, input: &mut &[u8]) -> Result<Option<(u16, u32)>, HuffmanError> {
        loop {
            let bits = queue.peek_padded(self.peek_bits());
            // A queue of the other order gives the bits of the value in reverse.
            let bits = if queue.order() == self.order { bits } else { bits.reverse_bits() >> (64 - self.peek_bits()) };
            // Codes are prefix-free: a code within the queued bits is the code of the stream.
            match self.decode(bits) {
                Ok((symbol, length)) if length <= queue.count() => return Ok(Some((symbol, length))),
                Err(error) if queue.count() >= self.peek_bits() => return Err(error),
                _ => {
                    if !queue.fill(queue.count() + 8, input) {
                        return Ok(None);
                    }
                }
            }
        }
    }

    /// Decodes and consumes the next symbol of `queue`, as [`HuffmanTable::peek`] finds it.
    pub fn read(&self, queue: &mut BitQueue, input: &mut &[u8]) -> Result<Option<u16>, HuffmanError> {
        let Some((symbol, length)) = self.peek(queue, input)? else {
            return Ok(None);
        };
        queue.consume(length);
        Ok(Some(symbol))
    }
}
