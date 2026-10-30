use alloc::vec::Vec;
use core::fmt;
use core::ops::RangeInclusive;

use super::{IMAPError, IMAPReader, IMAPWriter};

/// A number of a sequence set (RFC 9051 §9 `seq-number`): a number of 1 or
/// more, or `*`, the largest in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IMAPSequenceNumber {
    Number(u32),
    Last,
}

/// A set of message sequence numbers or UIDs (`sequence-set`): ranges, in
/// any order; or `$`, the result saved by the last SEARCH (RFC 9051 §6.4.4.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IMAPSequenceSet {
    pub ranges: Vec<(IMAPSequenceNumber, IMAPSequenceNumber)>,
    pub saved: bool,
}

impl IMAPSequenceNumber {
    /// The number, `*` being `last`.
    pub fn resolve(self, last: u32) -> u32 {
        match self {
            IMAPSequenceNumber::Number(number) => number,
            IMAPSequenceNumber::Last => last,
        }
    }

    pub fn read(reader: &mut IMAPReader<'_>) -> Result<IMAPSequenceNumber, IMAPError> {
        match reader.eat(b'*') {
            true => Ok(IMAPSequenceNumber::Last),
            false => reader.nz_number().map(IMAPSequenceNumber::Number),
        }
    }
}

impl fmt::Display for IMAPSequenceNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IMAPSequenceNumber::Number(number) => write!(formatter, "{number}"),
            IMAPSequenceNumber::Last => formatter.write_str("*"),
        }
    }
}

impl IMAPSequenceSet {
    /// The set of `ranges`.
    pub fn new(ranges: &[(IMAPSequenceNumber, IMAPSequenceNumber)]) -> IMAPSequenceSet {
        IMAPSequenceSet { ranges: ranges.to_vec(), saved: false }
    }

    /// `$`.
    pub fn saved() -> IMAPSequenceSet {
        IMAPSequenceSet { ranges: Vec::new(), saved: true }
    }

    /// The set of `numbers`, as few ranges as they make.
    pub fn from_numbers(numbers: &[u32]) -> IMAPSequenceSet {
        let mut sorted = numbers.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mut ranges: Vec<(IMAPSequenceNumber, IMAPSequenceNumber)> = Vec::new();
        for number in sorted {
            match ranges.last_mut() {
                Some((_, IMAPSequenceNumber::Number(end))) if end.checked_add(1) == Some(number) => *end = number,
                _ => ranges.push((IMAPSequenceNumber::Number(number), IMAPSequenceNumber::Number(number))),
            }
        }
        IMAPSequenceSet { ranges, saved: false }
    }

    pub fn read(reader: &mut IMAPReader<'_>) -> Result<IMAPSequenceSet, IMAPError> {
        if reader.eat(b'$') {
            return Ok(IMAPSequenceSet::saved());
        }
        let mut ranges = Vec::new();
        loop {
            let first = IMAPSequenceNumber::read(reader)?;
            let last = if reader.eat(b':') { IMAPSequenceNumber::read(reader)? } else { first };
            ranges.push((first, last));
            if !reader.eat(b',') {
                break;
            }
        }
        Ok(IMAPSequenceSet { ranges, saved: false })
    }

    /// The set of the text `text`.
    pub fn parse(text: &[u8]) -> Result<IMAPSequenceSet, IMAPError> {
        let mut reader = IMAPReader::new(text, 1);
        let set = IMAPSequenceSet::read(&mut reader)?;
        reader.end()?;
        Ok(set)
    }

    /// The ranges with `*` as `last`, each in order, sorted and merged.
    pub fn resolve(&self, last: u32) -> Vec<RangeInclusive<u32>> {
        let mut ranges: Vec<RangeInclusive<u32>> = self
            .ranges
            .iter()
            .map(|(first, second)| {
                let (first, second) = (first.resolve(last), second.resolve(last));
                first.min(second)..=first.max(second)
            })
            .collect();
        ranges.sort_unstable_by_key(|range| *range.start());
        let mut merged: Vec<RangeInclusive<u32>> = Vec::with_capacity(ranges.len());
        for range in ranges {
            match merged.last_mut() {
                Some(previous) if range.start().saturating_sub(1) <= *previous.end() => {
                    *previous = *previous.start()..=(*previous.end()).max(*range.end());
                }
                _ => merged.push(range),
            }
        }
        merged
    }

    /// Whether `number` is in the set, `*` being `last` (§9: a range is of the numbers
    /// between its ends, in either order).
    pub fn contains(&self, number: u32, last: u32) -> bool {
        self.ranges.iter().any(|(first, second)| {
            let (first, second) = (first.resolve(last), second.resolve(last));
            (first.min(second)..=first.max(second)).contains(&number)
        })
    }

    pub fn write(&self, writer: &mut IMAPWriter) {
        writer.raw(alloc::format!("{self}").as_bytes());
    }
}

impl fmt::Display for IMAPSequenceSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.saved {
            return formatter.write_str("$");
        }
        for (index, (first, last)) in self.ranges.iter().enumerate() {
            if index > 0 {
                formatter.write_str(",")?;
            }
            match first == last {
                true => write!(formatter, "{first}")?,
                false => write!(formatter, "{first}:{last}")?,
            }
        }
        Ok(())
    }
}
