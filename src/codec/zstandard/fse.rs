use alloc::vec;
use alloc::vec::Vec;

use super::{ZstandardBitReader, ZstandardBitWriter};
use crate::bytes::BitReader;
use crate::codec::CompressionError;

/// A normalized distribution of Finite State Entropy (RFC 8878 section
/// 4.1.1): the probabilities of the symbols 0 to the last present one, on a
/// scale of 2^accuracy_log, where -1 means "less than 1" (counted as 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FSEDistribution {
    pub accuracy_log: u32,
    pub probabilities: Vec<i16>,
}

impl FSEDistribution {
    /// The smallest accuracy log of a table description.
    pub const MINIMUM_LOG: u32 = 5;

    /// Reads a table description from the start of `bytes`: returns the
    /// distribution and the bytes it took. Fails with `InvalidData` for an
    /// accuracy log above `maximum_log`, more than `maximum_symbols`
    /// symbols, a total above the scale, fewer than two present symbols or a
    /// truncated description.
    pub fn read(
        bytes: &[u8],
        maximum_log: u32,
        maximum_symbols: usize,
    ) -> Result<(FSEDistribution, usize), CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        let mut reader = BitReader::new(bytes);
        let accuracy_log =
            reader.read(4).ok_or(invalid("truncated table description"))? as u32 + FSEDistribution::MINIMUM_LOG;
        if accuracy_log > maximum_log {
            return Err(invalid("accuracy log too large"));
        }
        let scale = 1i32 << accuracy_log;
        let mut remaining = scale;
        let mut probabilities: Vec<i16> = Vec::new();
        while remaining > 0 {
            if probabilities.len() >= maximum_symbols {
                return Err(invalid("too many symbols in a table description"));
            }
            // Values 0 to remaining + 1 in `bits` bits, the small ones in a bit less (table 20).
            let maximum = remaining + 1;
            let bits = 32 - (maximum as u32).leading_zeros();
            let low_count = (1i32 << bits) - 1 - maximum;
            let small = reader.peek_padded(bits - 1) as i32;
            let value = if small < low_count {
                reader.skip(bits as usize - 1).then_some(()).ok_or(invalid("truncated table description"))?;
                small
            } else {
                let value = reader.read(bits).ok_or(invalid("truncated table description"))? as i32;
                if value >= 1 << (bits - 1) { value - low_count } else { value }
            };
            let probability = value - 1;
            remaining -= if probability == -1 { 1 } else { probability };
            probabilities.push(probability as i16);
            if probability == 0 {
                // Repeat flags: 2 bits each, 3 meaning more follow.
                loop {
                    let repeat = reader.read(2).ok_or(invalid("truncated table description"))?;
                    for _ in 0..repeat {
                        if probabilities.len() >= maximum_symbols {
                            return Err(invalid("too many symbols in a table description"));
                        }
                        probabilities.push(0);
                    }
                    if repeat != 3 {
                        break;
                    }
                }
            }
        }
        if remaining < 0 {
            return Err(invalid("table description above its scale"));
        }
        if probabilities.iter().filter(|probability| **probability != 0).count() < 2 {
            return Err(invalid("table description of one symbol"));
        }
        let used = reader.position().div_ceil(8);
        Ok((FSEDistribution { accuracy_log, probabilities }, used))
    }

    /// Writes the table description (the reverse of [`FSEDistribution::read`]).
    pub fn write(&self, out: &mut Vec<u8>) {
        let mut writer = crate::bytes::BitWriter::new();
        writer.write((self.accuracy_log - FSEDistribution::MINIMUM_LOG) as u64, 4);
        let mut remaining = 1i32 << self.accuracy_log;
        let mut index = 0;
        while remaining > 0 && index < self.probabilities.len() {
            let probability = self.probabilities[index] as i32;
            let maximum = remaining + 1;
            let bits = 32 - (maximum as u32).leading_zeros();
            let low_count = (1i32 << bits) - 1 - maximum;
            let value = probability + 1;
            if value < low_count {
                writer.write(value as u64, bits - 1);
            } else if value < 1 << (bits - 1) {
                writer.write(value as u64, bits);
            } else {
                writer.write((value + low_count) as u64, bits);
            }
            remaining -= if probability == -1 { 1 } else { probability };
            index += 1;
            if probability == 0 {
                let zeros = self.probabilities[index..].iter().take_while(|probability| **probability == 0).count();
                let mut left = zeros;
                loop {
                    let repeat = left.min(3);
                    writer.write(repeat as u64, 2);
                    left -= repeat;
                    if repeat != 3 {
                        break;
                    }
                }
                index += zeros;
            }
        }
        out.extend_from_slice(&writer.finish());
    }

    /// The distribution of `counts` (2 or more present symbols) on a scale of 2^accuracy_log:
    /// every present symbol gets at least 1, the rest in proportion.
    pub fn normalize(counts: &[u32], accuracy_log: u32) -> FSEDistribution {
        let last = counts.iter().rposition(|count| *count > 0).map_or(0, |last| last + 1);
        let counts = &counts[..last];
        let total: u64 = counts.iter().map(|count| *count as u64).sum();
        let scale = 1i64 << accuracy_log;
        let mut probabilities: Vec<i16> = counts
            .iter()
            .map(|count| {
                if *count == 0 { 0 } else { ((*count as i64 * scale + total as i64 / 2) / total as i64).max(1) as i16 }
            })
            .collect();
        // Moves the difference to the largest symbols, keeping each at least 1.
        let mut difference = scale - probabilities.iter().map(|probability| *probability as i64).sum::<i64>();
        while difference != 0 {
            let largest = (0..probabilities.len()).max_by_key(|index| probabilities[*index]).expect("a present symbol");
            let step = if difference > 0 { difference } else { difference.max(1 - probabilities[largest] as i64) };
            if step == 0 {
                // The largest is 1: take from any symbol above 1 (there is one, as the total exceeds the scale).
                let other = (0..probabilities.len()).find(|index| probabilities[*index] > 1).expect("a symbol above 1");
                probabilities[other] -= 1;
                difference += 1;
                continue;
            }
            probabilities[largest] += step as i16;
            difference -= step;
        }
        FSEDistribution { accuracy_log, probabilities }
    }

    /// The table positions of the symbols, as both tables spread them:
    /// "less than 1" symbols from the end, the others with the step
    /// (size / 2 + size / 8 + 3), skipping those positions.
    pub fn spread(&self) -> Vec<u8> {
        let size = 1usize << self.accuracy_log;
        let mut symbols = vec![0u8; size];
        let mut high = size;
        for (symbol, probability) in self.probabilities.iter().enumerate() {
            if *probability == -1 {
                high -= 1;
                symbols[high] = symbol as u8;
            }
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mut position = 0;
        for (symbol, probability) in self.probabilities.iter().enumerate() {
            for _ in 0..(*probability).max(0) {
                symbols[position] = symbol as u8;
                position = (position + step) & (size - 1);
                while position >= high {
                    position = (position + step) & (size - 1);
                }
            }
        }
        symbols
    }
}

/// An entry of an [`FSEDecodingTable`]: the symbol of a state, and the
/// bits to read and the baseline to add for the next state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FSEDecodingEntry {
    pub symbol: u8,
    pub bits: u8,
    pub baseline: u16,
}

/// The decoding table of a distribution (section 4.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FSEDecodingTable {
    pub accuracy_log: u32,
    pub entries: Vec<FSEDecodingEntry>,
}

impl FSEDecodingTable {
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

    /// The table of a single symbol (RLE mode): every state decodes it, with no bits.
    pub fn single(symbol: u8) -> FSEDecodingTable {
        FSEDecodingTable { accuracy_log: 0, entries: vec![FSEDecodingEntry { symbol, bits: 0, baseline: 0 }] }
    }

    /// The initial state, read from `reader`.
    pub fn initial_state(&self, reader: &mut ZstandardBitReader<'_>) -> usize {
        reader.read(self.accuracy_log) as usize
    }

    /// The next state after `state`.
    pub fn next_state(&self, state: usize, reader: &mut ZstandardBitReader<'_>) -> usize {
        let entry = self.entries[state];
        entry.baseline as usize + reader.read(entry.bits as u32) as usize
    }
}

/// The encoding table of a distribution, the reverse of its
/// [`FSEDecodingTable`]: for each symbol, the transform of a state into the
/// bits written and the next state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FSEEncodingTable {
    pub accuracy_log: u32,
    /// The states (plus the table size) in the order of their symbols.
    states: Vec<u16>,
    /// Per symbol: (delta of the bits, delta to find the state).
    transforms: Vec<(i32, i32)>,
}

impl FSEEncodingTable {
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
                0 => (0, 0),
                1 => ((log << 16) - (1 << log), cumulative[symbol] as i32 - 1),
                count => {
                    let bits_out = log - (31 - (count - 1).leading_zeros() as i32);
                    let minimum_state = (*count as i32) << bits_out;
                    ((bits_out << 16) - minimum_state, cumulative[symbol] as i32 - *count as i32)
                }
            })
            .collect();
        FSEEncodingTable { accuracy_log: distribution.accuracy_log, states, transforms }
    }

    /// The first state, for the symbol decoded last.
    pub fn initial_state(&self, symbol: usize) -> u32 {
        let (delta_bits, delta_state) = self.transforms[symbol];
        let bits_out = ((delta_bits + (1 << 15)) >> 16) as u32;
        let value = ((bits_out as i32) << 16) - delta_bits;
        self.states[((value >> bits_out) + delta_state) as usize] as u32
    }

    /// Writes the bits that lead from `symbol` to `state` and returns the state before it.
    pub fn encode(&self, state: u32, symbol: usize, writer: &mut ZstandardBitWriter) -> u32 {
        let (delta_bits, delta_state) = self.transforms[symbol];
        let bits_out = ((state as i32 + delta_bits) >> 16) as u32;
        writer.write(state, bits_out);
        self.states[((state >> bits_out) as i32 + delta_state) as usize] as u32
    }

    /// Writes the final state (the initial state of the decoder).
    pub fn flush(&self, state: u32, writer: &mut ZstandardBitWriter) {
        writer.write(state, self.accuracy_log);
    }
}
