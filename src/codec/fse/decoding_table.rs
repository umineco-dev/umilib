use alloc::vec;
use alloc::vec::Vec;

use super::FSEDistribution;
use crate::bytes::BackwardBitReader;

/// An entry of an [`FSEDecodingTable`]: the symbol of a state, and the
/// bits to read and the baseline to add for the next state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FSEDecodingEntry {
    pub symbol: u8,
    pub bits: u8,
    pub baseline: u16,
}

impl FSEDecodingEntry {
    /// The next state, from the value of the [`FSEDecodingEntry::bits`] bits read.
    pub const fn next_state(&self, value: u32) -> usize {
        self.baseline as usize + value as usize
    }
}

/// The decoding table of a distribution (RFC 8878 section 4.1.1): the
/// entry of each of its 2^accuracy_log states.
///
/// A decoder reads the initial state (accuracy_log bits), then, per symbol,
/// takes the symbol of its state's entry and reads the entry's bits for the
/// next state. [`FSEDecodingTable::initial_state`] and
/// [`FSEDecodingTable::next_state`] do it on a [`BackwardBitReader`]; the
/// entries serve any other source of bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FSEDecodingTable {
    pub accuracy_log: u32,
    pub entries: Vec<FSEDecodingEntry>,
}

impl FSEDecodingTable {
    /// The table of `distribution`, which must be valid (see [`FSEDistribution`]).
    pub fn new(distribution: &FSEDistribution) -> FSEDecodingTable {
        let size = 1usize << distribution.accuracy_log;
        let symbols = distribution.spread();
        let mut next: Vec<u32> = distribution
            .probabilities
            .iter()
            .map(|probability| if *probability == -1 { 1 } else { *probability as u32 })
            .collect();
        let mut entries = vec![FSEDecodingEntry::default(); size];
        for (state, symbol) in symbols.iter().enumerate() {
            let symbol = *symbol as usize;
            let probability = distribution.probabilities[symbol];
            if probability == -1 {
                entries[state] =
                    FSEDecodingEntry { symbol: symbol as u8, bits: distribution.accuracy_log as u8, baseline: 0 };
                continue;
            }
            // The states of a symbol in order take the values probability .. 2 × probability - 1.
            let value = next[symbol];
            next[symbol] += 1;
            let bits = distribution.accuracy_log - (31 - value.leading_zeros());
            let baseline = (value << bits) as usize - size;
            entries[state] = FSEDecodingEntry { symbol: symbol as u8, bits: bits as u8, baseline: baseline as u16 };
        }
        FSEDecodingTable { accuracy_log: distribution.accuracy_log, entries }
    }

    /// The table of a single symbol (Zstandard's RLE mode): its one state decodes it, with no bits.
    pub fn single(symbol: u8) -> FSEDecodingTable {
        FSEDecodingTable { accuracy_log: 0, entries: vec![FSEDecodingEntry { symbol, bits: 0, baseline: 0 }] }
    }

    /// The initial state, read from `reader`.
    pub fn initial_state(&self, reader: &mut BackwardBitReader<'_>) -> usize {
        reader.read(self.accuracy_log) as usize
    }

    /// The next state after `state`, read from `reader`.
    pub fn next_state(&self, state: usize, reader: &mut BackwardBitReader<'_>) -> usize {
        let entry = self.entries[state];
        entry.next_state(reader.read(entry.bits as u32))
    }
}
