use alloc::vec;
use alloc::vec::Vec;

use super::{BrotliPrefixCode, BrotliPrefixReader};
use crate::bytes::{BitQueue, BitWriter};
use crate::codec::CompressionError;

/// The part of a context map a [`BrotliContextMapReader`] reads next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrotliContextMapPhase {
    /// RLEMAX.
    RunMaximum,
    /// The prefix code of the values and runs.
    Code,
    /// The values.
    Values,
    /// The IMTF bit.
    Transform,
}

/// A context map (RFC 7932 section 7.3): the index of the prefix code of
/// each pair of a block type and a context ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrotliContextMap;

impl BrotliContextMap {
    /// The longest run of zeros a symbol of RLEMAX stands for, plus one.
    pub const MAXIMUM_RUN_MAXIMUM: u32 = 16;

    /// The inverse move-to-front transform of section 7.3, in place.
    pub fn inverse_move_to_front(values: &mut [u8]) {
        let mut table: [u8; 256] = core::array::from_fn(|index| index as u8);
        for value in values {
            let index = *value as usize;
            let front = table[index];
            *value = front;
            table.copy_within(..index, 1);
            table[0] = front;
        }
    }

    /// The move-to-front transform that [`BrotliContextMap::inverse_move_to_front`] undoes, in place.
    pub fn move_to_front(values: &mut [u8]) {
        let mut table: [u8; 256] = core::array::from_fn(|index| index as u8);
        for value in values {
            let index = table.iter().position(|entry| entry == value).expect("every byte is in the table");
            let front = table[index];
            *value = index as u8;
            table.copy_within(..index, 1);
            table[0] = front;
        }
    }

    /// Writes the context map `map` of `trees` prefix codes (2 or more):
    /// move-to-front values, with the runs of zeros coded by RLEMAX symbols.
    pub fn write(map: &[u8], trees: usize, writer: &mut BitWriter) {
        let mut values = map.to_vec();
        BrotliContextMap::move_to_front(&mut values);
        // RLEMAX: enough for the longest run of zeros, at most 16.
        let mut longest = 0usize;
        let mut run = 0usize;
        for value in &values {
            run = if *value == 0 { run + 1 } else { 0 };
            longest = longest.max(run);
        }
        let run_maximum = if longest < 2 { 0 } else { (usize::BITS - 1 - longest.leading_zeros()).min(16) };
        // The symbols: 0, runs of zeros (1 to RLEMAX with extra bits), values plus RLEMAX.
        let mut symbols: Vec<(u16, u32)> = Vec::new();
        let mut index = 0;
        while index < values.len() {
            if values[index] != 0 {
                symbols.push((values[index] as u16 + run_maximum as u16, 0));
                index += 1;
                continue;
            }
            let run = values[index..].iter().take_while(|value| **value == 0).count();
            let mut left = run;
            while left > 0 {
                if left == 1 || run_maximum == 0 {
                    symbols.push((0, 0));
                    left -= 1;
                    continue;
                }
                let longest = (1usize << (run_maximum + 1)) - 1;
                let take = left.min(longest);
                let code = usize::BITS - 1 - take.leading_zeros();
                symbols.push((code as u16, (take - (1 << code)) as u32));
                left -= take;
            }
            index += run;
        }
        let size = trees + run_maximum as usize;
        let mut frequencies = vec![0u32; size];
        for (symbol, _) in &symbols {
            frequencies[*symbol as usize] += 1;
        }
        if run_maximum == 0 {
            writer.write(0, 1);
        } else {
            writer.write(1 | ((run_maximum - 1) as u64) << 1, 5);
        }
        let lengths = BrotliPrefixCode::lengths(&frequencies);
        BrotliPrefixCode::write(&lengths, size, writer);
        let codes = BrotliPrefixCode::codes(&lengths);
        for (symbol, extra) in symbols {
            let (code, bits) = codes[symbol as usize];
            writer.write(code as u64, bits as u32);
            if (1..=run_maximum as u16).contains(&symbol) {
                writer.write(extra as u64, symbol as u32);
            }
        }
        writer.write(1, 1);
    }
}

/// Reads a context map of `size` values for `trees` prefix codes (2 or
/// more) from a [`BitQueue`] filled from successive inputs, resuming where
/// the last input ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrotliContextMapReader {
    trees: usize,
    phase: BrotliContextMapPhase,
    run_maximum: u32,
    reader: BrotliPrefixReader,
    code: Option<BrotliPrefixCode>,
    map: Vec<u8>,
    index: usize,
}

impl BrotliContextMapReader {
    pub fn new(size: usize, trees: usize) -> BrotliContextMapReader {
        BrotliContextMapReader {
            trees,
            phase: BrotliContextMapPhase::RunMaximum,
            run_maximum: 0,
            reader: BrotliPrefixReader::new(trees),
            code: None,
            map: vec![0; size],
            index: 0,
        }
    }

    pub fn phase(&self) -> BrotliContextMapPhase {
        self.phase
    }

    /// Reads on from `queue` and `input`: the map once it is complete,
    /// `None` if `input` ran out first (the reader keeps its place).
    pub fn read(&mut self, queue: &mut BitQueue, input: &mut &[u8]) -> Result<Option<Vec<u8>>, CompressionError> {
        if self.phase == BrotliContextMapPhase::RunMaximum {
            if !queue.fill(1, input) {
                return Ok(None);
            }
            if queue.peek_padded(1) == 1 {
                if !queue.fill(5, input) {
                    return Ok(None);
                }
                self.run_maximum = (queue.peek_padded(5) >> 1) as u32 + 1;
                queue.consume(5);
            } else {
                queue.consume(1);
            }
            self.reader = BrotliPrefixReader::new(self.trees + self.run_maximum as usize);
            self.phase = BrotliContextMapPhase::Code;
        }
        if self.phase == BrotliContextMapPhase::Code {
            let Some(code) = self.reader.read(queue, input)? else {
                return Ok(None);
            };
            self.code = Some(code);
            self.phase = BrotliContextMapPhase::Values;
        }
        if self.phase == BrotliContextMapPhase::Values {
            let code = self.code.as_ref().expect("read before the values");
            let run_maximum = self.run_maximum;
            while self.index < self.map.len() {
                let extra = |symbol: u16| if (1..=run_maximum).contains(&(symbol as u32)) { symbol as u32 } else { 0 };
                let Some((symbol, bits)) = code.read_with_extra(queue, input, extra)? else {
                    return Ok(None);
                };
                let symbol = symbol as u32;
                if symbol == 0 || symbol > run_maximum {
                    self.map[self.index] = symbol.saturating_sub(run_maximum) as u8;
                    self.index += 1;
                    continue;
                }
                let run = (1usize << symbol) + bits as usize;
                if self.index + run > self.map.len() {
                    return Err(CompressionError::InvalidData { reason: "context map run beyond its size" });
                }
                // The map starts zeroed.
                self.index += run;
            }
            self.phase = BrotliContextMapPhase::Transform;
        }
        let Some(transform) = queue.read_from(1, input) else {
            return Ok(None);
        };
        let mut map = core::mem::take(&mut self.map);
        if transform == 1 {
            BrotliContextMap::inverse_move_to_front(&mut map);
        }
        Ok(Some(map))
    }
}
