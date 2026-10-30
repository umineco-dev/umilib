use alloc::collections::BTreeMap;

use super::IPFragmentBuffer;
use crate::runtime::Instant;

/// What a reassembly keeps of the first fragment of its datagram, which the
/// reassembled datagram takes its headers from: the IPv4 header, or the
/// IPv6 header with the per-fragment headers.
pub trait IPFirstFragment {
    /// The bytes it holds beyond its own size (its per-fragment headers).
    fn memory(&self) -> usize;
}

/// One datagram being reassembled, of either IP version: the first fragment
/// `F` received at offset zero, the data, and the deadline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IPReassembly<F> {
    /// The first fragment received at offset zero: the headers of the
    /// datagram, and, with the start of `buffer`, what an ICMP Time Exceeded
    /// message quotes.
    pub first: Option<F>,
    pub buffer: IPFragmentBuffer,
    /// When the reassembly is given up, counted from its first-arriving fragment.
    pub deadline: Instant,
    /// Whether fragments overlapped: the datagram's fragments are dropped,
    /// those not yet received too, until the deadline (RFC 5722 §4).
    pub abandoned: bool,
}

impl<F: IPFirstFragment> IPReassembly<F> {
    pub fn new(deadline: Instant) -> IPReassembly<F> {
        IPReassembly { first: None, buffer: IPFragmentBuffer::new(), deadline, abandoned: false }
    }

    /// The bytes the reassembly holds (see [`IPFragmentBuffer::memory`]).
    pub fn memory(&self) -> usize {
        self.buffer.memory() + self.first.as_ref().map_or(0, IPFirstFragment::memory)
    }

    /// Releases what the reassembly holds and marks it abandoned.
    pub fn abandon(&mut self) {
        self.first = None;
        self.buffer = IPFragmentBuffer::new();
        self.abandoned = true;
    }
}

/// The datagrams being reassembled, of either IP version, by their key `K`,
/// and the bytes they hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IPReassemblyTable<K, F> {
    pub entries: BTreeMap<K, IPReassembly<F>>,
    /// The sum of the [`IPReassembly::memory`] of `entries`.
    pub buffered: usize,
}

impl<K, F> Default for IPReassemblyTable<K, F> {
    fn default() -> IPReassemblyTable<K, F> {
        IPReassemblyTable { entries: BTreeMap::new(), buffered: 0 }
    }
}

impl<K: Ord + Copy, F: IPFirstFragment> IPReassemblyTable<K, F> {
    pub fn new() -> IPReassemblyTable<K, F> {
        IPReassemblyTable::default()
    }

    /// Makes room for the datagram of `key` (a new one if it is not there)
    /// to grow by `growth` bytes within `maximum_entries` datagrams and
    /// `maximum_bytes` bytes, dropping other datagrams with the earliest
    /// deadlines: any of them for the count, only those that hold bytes for
    /// the bytes. Returns `false`, dropping nothing, if the datagram could
    /// not fit even alone.
    pub fn make_room(&mut self, key: &K, growth: usize, maximum_entries: usize, maximum_bytes: usize) -> bool {
        let new = !self.entries.contains_key(key);
        let held = self.entries.get(key).map_or(0, IPReassembly::memory);
        if held.saturating_add(growth) > maximum_bytes || (new && maximum_entries == 0) {
            return false;
        }
        loop {
            let too_many = new && self.entries.len() >= maximum_entries;
            let too_large = self.buffered + growth > maximum_bytes;
            if !too_many && !too_large {
                return true;
            }
            let victim = self
                .entries
                .iter()
                .filter(|(other, reassembly)| *other != key && (too_many || reassembly.memory() > 0))
                .min_by_key(|(_, reassembly)| reassembly.deadline)
                .map(|(other, _)| *other);
            // The datagram fits alone, so the others are dropped before none is left.
            let Some(victim) = victim else { return false };
            self.discard(&victim);
        }
    }

    /// Adds a datagram of `key` with the deadline `deadline` if there is none.
    pub fn open(&mut self, key: K, deadline: Instant) {
        self.entries.entry(key).or_insert_with(|| IPReassembly::new(deadline));
    }

    /// Calls `change` on the datagram of `key`, keeping `buffered` up to date.
    pub fn modify<T>(&mut self, key: &K, change: impl FnOnce(&mut IPReassembly<F>) -> T) -> Option<T> {
        let reassembly = self.entries.get_mut(key)?;
        let before = reassembly.memory();
        let result = change(reassembly);
        self.buffered = self.buffered - before + reassembly.memory();
        Some(result)
    }

    /// Abandons the datagram of `key` (see [`IPReassembly::abandon`]).
    pub fn abandon(&mut self, key: &K) {
        self.modify(key, IPReassembly::abandon);
    }

    /// Removes the datagram of `key` and returns it.
    pub fn discard(&mut self, key: &K) -> Option<IPReassembly<F>> {
        let reassembly = self.entries.remove(key)?;
        self.buffered -= reassembly.memory();
        Some(reassembly)
    }

    /// The earliest deadline of the datagrams.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.entries.values().map(|reassembly| reassembly.deadline).min()
    }

    /// Removes a datagram whose deadline is at or before `now` and returns it.
    pub fn expire(&mut self, now: Instant) -> Option<(K, IPReassembly<F>)> {
        let key = *self.entries.iter().find(|(_, reassembly)| reassembly.deadline <= now)?.0;
        self.discard(&key).map(|reassembly| (key, reassembly))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
