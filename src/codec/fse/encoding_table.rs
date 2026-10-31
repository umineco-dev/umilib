use alloc::vec;
use alloc::vec::Vec;

use super::FSEDistribution;
use crate::bytes::BackwardBitWriter;

/// The encoding table of a distribution, the reverse of its
/// [`FSEDecodingTable`](super::FSEDecodingTable): for each symbol, the
/// transform of a state into the bits written and the state before it.
///
/// Symbols are encoded in the reverse of the order they are decoded in:
/// [`FSEEncodingTable::initial_state`] of the symbol decoded last, then
/// [`FSEEncodingTable::encode`] of each other symbol, and
/// [`FSEEncodingTable::flush`] of the final state, which the decoder reads
/// first. Encoder states are the decoder's states plus 2^accuracy_log.
/// [`FSEEncodingTable::transition`] gives the bits and the state without
/// writing, for any other bit writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FSEEncodingTable {
    pub accuracy_log: u32,
    /// The states (plus the table size) in the order of their symbols.
    states: Vec<u16>,
    /// Per symbol: (delta of the bits, delta to find the state); `None` for absent symbols.
    transforms: Vec<Option<(i32, i32)>>,
}

impl FSEEncodingTable {
    /// The table of `distribution`, which must be valid (see [`FSEDistribution`]).
    pub fn new(distribution: &FSEDistribution) -> FSEEncodingTable {
        let size = 1usize << distribution.accuracy_log;
        let symbols = distribution.spread();
        let counts: Vec<u32> = distribution
            .probabilities
            .iter()
            .map(|probability| if *probability == -1 { 1 } else { *probability as u32 })
            .collect();
        let mut cumulative = vec![0u32; counts.len() + 1];
        for (symbol, count) in counts.iter().enumerate() {
            cumulative[symbol + 1] = cumulative[symbol] + count;
        }
        let mut states = vec![0u16; size];
        let mut next = cumulative.clone();
        for (position, symbol) in symbols.iter().enumerate() {
            states[next[*symbol as usize] as usize] = (size + position) as u16;
            next[*symbol as usize] += 1;
        }
        let log = distribution.accuracy_log as i32;
        let transforms = counts
            .iter()
            .enumerate()
            .map(|(symbol, count)| match count {
                0 => None,
                1 => Some(((log << 16) - (1 << log), cumulative[symbol] as i32 - 1)),
                count => {
                    let bits_out = log - (31 - (count - 1).leading_zeros() as i32);
                    let minimum_state = (*count as i32) << bits_out;
                    Some(((bits_out << 16) - minimum_state, cumulative[symbol] as i32 - *count as i32))
                }
            })
            .collect();
        FSEEncodingTable { accuracy_log: distribution.accuracy_log, states, transforms }
    }

    /// Whether `symbol` has a probability in the distribution (only such symbols can be encoded).
    pub fn contains(&self, symbol: usize) -> bool {
        matches!(self.transforms.get(symbol), Some(Some(_)))
    }

    /// Whether `state` is a state of the encoder (2^accuracy_log to 2^(accuracy_log + 1) - 1).
    pub fn is_state(&self, state: u32) -> bool {
        (self.states.len()..self.states.len() * 2).contains(&(state as usize))
    }

    fn transform(&self, symbol: usize) -> (i32, i32) {
        self.transforms[symbol].expect("a symbol of the distribution")
    }

    /// The first state, for the symbol decoded last (a symbol the table [`FSEEncodingTable::contains`]).
    pub fn initial_state(&self, symbol: usize) -> u32 {
        let (delta_bits, delta_state) = self.transform(symbol);
        let bits_out = ((delta_bits + (1 << 15)) >> 16) as u32;
        let value = ((bits_out as i32) << 16) - delta_bits;
        self.states[((value >> bits_out) + delta_state) as usize] as u32
    }

    /// The step from `state` (an encoder state) for `symbol` (a symbol the
    /// table [`FSEEncodingTable::contains`]): the number of low bits of
    /// `state` to write, and the state before it.
    pub fn transition(&self, state: u32, symbol: usize) -> (u32, u32) {
        let (delta_bits, delta_state) = self.transform(symbol);
        let bits_out = ((state as i32 + delta_bits) >> 16) as u32;
        (bits_out, self.states[((state >> bits_out) as i32 + delta_state) as usize] as u32)
    }

    /// Writes the bits that lead from `symbol` to `state` and returns the state before it.
    pub fn encode(&self, state: u32, symbol: usize, writer: &mut BackwardBitWriter) -> u32 {
        let (bits_out, previous) = self.transition(state, symbol);
        writer.write(state, bits_out);
        previous
    }

    /// Writes the final state (the initial state of the decoder: `state`
    /// without its top bit, in accuracy_log bits).
    pub fn flush(&self, state: u32, writer: &mut BackwardBitWriter) {
        writer.write(state, self.accuracy_log);
    }
}
