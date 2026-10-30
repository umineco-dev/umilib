use alloc::collections::BTreeMap;
use core::ops::RangeInclusive;

/// A set of integers kept as disjoint, non-adjacent inclusive ranges: the
/// packet numbers received or acknowledged, the stream offsets received
/// (RFC 9000 §13.2, §2.2). Each operation costs the logarithm of the
/// number of ranges, plus the ranges it merges.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct QUICRangeSet {
    /// Each range's end (inclusive), by its start.
    ranges: BTreeMap<u64, u64>,
}

impl QUICRangeSet {
    pub fn new() -> QUICRangeSet {
        QUICRangeSet::default()
    }

    /// The number of ranges.
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn contains(&self, value: u64) -> bool {
        self.ranges.range(..=value).next_back().is_some_and(|(_, end)| *end >= value)
    }

    /// Whether every value of `range` is in the set.
    pub fn contains_range(&self, range: RangeInclusive<u64>) -> bool {
        self.ranges.range(..=*range.start()).next_back().is_some_and(|(_, end)| end >= range.end())
    }

    pub fn smallest(&self) -> Option<u64> {
        self.ranges.keys().next().copied()
    }

    pub fn largest(&self) -> Option<u64> {
        self.ranges.values().next_back().copied()
    }

    /// Adds `range` and returns how many of its values were not in the set.
    pub fn insert(&mut self, range: RangeInclusive<u64>) -> u64 {
        let (first, last) = (*range.start(), *range.end());
        if first > last {
            return 0;
        }
        let overlap = |start: u64, end: u64| (end.min(last) + 1).saturating_sub(start.max(first));
        let (mut start, mut end) = (first, last);
        let mut covered = 0;
        // A range that starts before this one and reaches or touches it.
        if let Some((&before, &before_end)) = self.ranges.range(..first).next_back()
            && before_end.saturating_add(1) >= first
        {
            covered += overlap(before, before_end);
            start = before;
            end = end.max(before_end);
            self.ranges.remove(&before);
        }
        // The ranges that start within this one or right after it.
        while let Some((&next, &next_end)) = self.ranges.range(first..).next() {
            if next > last.saturating_add(1) {
                break;
            }
            covered += overlap(next, next_end);
            end = end.max(next_end);
            self.ranges.remove(&next);
        }
        self.ranges.insert(start, end);
        (last - first + 1) - covered
    }

    /// Removes the values of `range`.
    pub fn remove(&mut self, range: RangeInclusive<u64>) {
        let (start, end) = (*range.start(), *range.end());
        if start > end {
            return;
        }
        let first = self.ranges.range(..start).next_back().map(|(start, _)| *start).unwrap_or(start);
        let overlapping: alloc::vec::Vec<(u64, u64)> = self
            .ranges
            .range(first..=end)
            .map(|(start, end)| (*start, *end))
            .filter(|(_, range_end)| *range_end >= start)
            .collect();
        for (range_start, range_end) in overlapping {
            self.ranges.remove(&range_start);
            if range_start < start {
                self.ranges.insert(range_start, start - 1);
            }
            if range_end > end {
                self.ranges.insert(end + 1, range_end);
            }
        }
    }

    /// Removes every value below `value`.
    pub fn remove_below(&mut self, value: u64) {
        if let Some(below) = value.checked_sub(1) {
            self.remove(0..=below);
        }
    }

    /// Removes the ranges of the smallest values until at most `limit` are
    /// left, so that a peer cannot make the set grow without bound.
    pub fn truncate(&mut self, limit: usize) {
        while self.ranges.len() > limit {
            self.ranges.pop_first();
        }
    }

    /// The ranges, from the smallest.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = RangeInclusive<u64>> + '_ {
        self.ranges.iter().map(|(start, end)| *start..=*end)
    }

    /// The first range that starts at or after `value`, or contains it.
    pub fn next_from(&self, value: u64) -> Option<RangeInclusive<u64>> {
        if let Some((start, end)) = self.ranges.range(..=value).next_back()
            && *end >= value
        {
            return Some(*start..=*end);
        }
        self.ranges.range(value..).next().map(|(start, end)| *start..=*end)
    }
}
