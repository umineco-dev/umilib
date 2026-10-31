use alloc::vec;
use alloc::vec::Vec;

use crate::bytes::{BitReader, BitWriter};
use crate::codec::CompressionError;

/// A normalized distribution of Finite State Entropy (RFC 8878 section
/// 4.1.1): the probabilities of the symbols 0 to the last present one, on a
/// scale of 2^accuracy_log, where -1 means "less than 1" (counted as 1).
///
/// The tables ([`FSEDecodingTable`](super::FSEDecodingTable),
/// [`FSEEncodingTable`](super::FSEEncodingTable)) need a valid
/// distribution, as [`FSEDistribution::new`], [`FSEDistribution::read`]
/// and [`FSEDistribution::normalize`] make: the fields are public for
/// constants such as the predefined distributions of Zstandard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FSEDistribution {
    pub accuracy_log: u32,
    pub probabilities: Vec<i16>,
}

impl FSEDistribution {
    /// The smallest accuracy log of a table description.
    pub const MINIMUM_LOG: u32 = 5;
    /// The largest accuracy log: states of 16 bits, as in the FSE library
    /// (its `FSE_MAX_TABLELOG`).
    pub const MAXIMUM_LOG: u32 = 15;
    /// The most symbols: symbols are bytes.
    pub const MAXIMUM_SYMBOLS: usize = 256;

    /// The distribution of `probabilities` on a scale of 2^`accuracy_log`;
    /// fails with `InvalidParameter` unless the accuracy log is at most
    /// [`FSEDistribution::MAXIMUM_LOG`], there are at most
    /// [`FSEDistribution::MAXIMUM_SYMBOLS`] probabilities, each is -1 or
    /// more, and they add up to the scale (-1 counting as 1).
    pub fn new(accuracy_log: u32, probabilities: Vec<i16>) -> Result<FSEDistribution, CompressionError> {
        if accuracy_log > FSEDistribution::MAXIMUM_LOG
            || probabilities.len() > FSEDistribution::MAXIMUM_SYMBOLS
            || probabilities.iter().any(|probability| *probability < -1)
        {
            return Err(CompressionError::InvalidParameter);
        }
        let total: i64 =
            probabilities.iter().map(|probability| if *probability == -1 { 1 } else { *probability as i64 }).sum();
        if total != 1 << accuracy_log {
            return Err(CompressionError::InvalidParameter);
        }
        Ok(FSEDistribution { accuracy_log, probabilities })
    }

    /// Reads a table description (RFC 8878 section 4.1.1, the format of
    /// `FSE_readNCount` of the FSE library) from the start of `bytes`:
    /// returns the distribution and the bytes it took. Fails with
    /// `InvalidData` for an accuracy log above `maximum_log` (or
    /// [`FSEDistribution::MAXIMUM_LOG`]), more than `maximum_symbols` (or
    /// [`FSEDistribution::MAXIMUM_SYMBOLS`]) symbols, a total above the
    /// scale, fewer than two present symbols or a truncated description.
    pub fn read(
        bytes: &[u8],
        maximum_log: u32,
        maximum_symbols: usize,
    ) -> Result<(FSEDistribution, usize), CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        let maximum_log = maximum_log.min(FSEDistribution::MAXIMUM_LOG);
        let maximum_symbols = maximum_symbols.min(FSEDistribution::MAXIMUM_SYMBOLS);
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

    /// Writes the table description (the reverse of [`FSEDistribution::read`]);
    /// fails with `InvalidParameter` for an accuracy log the description
    /// cannot hold (below [`FSEDistribution::MINIMUM_LOG`] or above
    /// [`FSEDistribution::MAXIMUM_LOG`]).
    pub fn write(&self, out: &mut Vec<u8>) -> Result<(), CompressionError> {
        if !(FSEDistribution::MINIMUM_LOG..=FSEDistribution::MAXIMUM_LOG).contains(&self.accuracy_log) {
            return Err(CompressionError::InvalidParameter);
        }
        let mut writer = BitWriter::new();
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
        Ok(())
    }

    /// The distribution of `counts` on a scale of 2^accuracy_log: every
    /// present symbol gets at least 1, the rest in proportion. Fails with
    /// `InvalidParameter` for fewer than 2 present symbols, more than the
    /// scale, a last present symbol above [`FSEDistribution::MAXIMUM_SYMBOLS`]
    /// or an accuracy log above [`FSEDistribution::MAXIMUM_LOG`].
    pub fn normalize(counts: &[u32], accuracy_log: u32) -> Result<FSEDistribution, CompressionError> {
        let last = counts.iter().rposition(|count| *count > 0).map_or(0, |last| last + 1);
        let counts = &counts[..last];
        let present = counts.iter().filter(|count| **count > 0).count();
        if accuracy_log > FSEDistribution::MAXIMUM_LOG
            || counts.len() > FSEDistribution::MAXIMUM_SYMBOLS
            || present < 2
            || present > 1 << accuracy_log
        {
            return Err(CompressionError::InvalidParameter);
        }
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
        Ok(FSEDistribution { accuracy_log, probabilities })
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
