use alloc::vec;
use alloc::vec::Vec;

use super::Filter;

/// Filters applied one after another to a stream, in one buffer: encoding
/// applies them in their order, decoding in the reverse order (the order of
/// a .xz filter chain, whose first filter sees the original data).
///
/// Bytes are appended with [`FilterChain::extend`] or [`FilterChain::fill`]; after
/// [`FilterChain::encode`] or [`FilterChain::decode`], the bytes every filter
/// converted are [`FilterChain::ready`] and are taken with
/// [`FilterChain::consume`]. The bytes a filter is still waiting on stay in
/// the buffer, at most the sum of the lookaheads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterChain<F> {
    filters: Vec<F>,
    buffer: Vec<u8>,
    /// Per stage (in the order the stages run), the bytes at the front of the buffer it has converted.
    converted: Vec<usize>,
}

impl<F: Filter> FilterChain<F> {
    /// A chain of `filters` (in encoding order).
    pub fn new(filters: Vec<F>) -> FilterChain<F> {
        let stages = filters.len();
        FilterChain { filters, buffer: Vec::new(), converted: vec![0; stages] }
    }

    pub fn filters(&self) -> &[F] {
        &self.filters
    }

    /// The bytes in the buffer: ready, and waiting on more data.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// The most bytes the filters may hold back.
    pub fn lookahead(&self) -> usize {
        self.filters.iter().map(Filter::lookahead).sum()
    }

    /// Appends `data` to the stream.
    pub fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Appends the bytes `write` writes into `room` bytes of space after
    /// the buffer (it returns how many it wrote, or an error, which leaves
    /// the buffer as it was).
    pub fn fill<E>(&mut self, room: usize, write: impl FnOnce(&mut [u8]) -> Result<usize, E>) -> Result<usize, E> {
        let start = self.buffer.len();
        self.buffer.resize(start + room, 0);
        let written = write(&mut self.buffer[start..]);
        let length = *written.as_ref().unwrap_or(&0);
        self.buffer.truncate(start + length.min(room));
        written
    }

    /// Encodes the new bytes with the filters in order; `end` says the
    /// stream ends with them (the bytes no filter can convert stay as they are).
    pub fn encode(&mut self, end: bool) {
        self.run(end, true);
    }

    /// Decodes the new bytes with the filters in reverse order; `end` says
    /// the stream ends with them.
    pub fn decode(&mut self, end: bool) {
        self.run(end, false);
    }

    /// Runs the filters as successive stages: in order if `encoding`, in reverse order otherwise.
    pub fn run(&mut self, end: bool, encoding: bool) {
        let mut available = self.buffer.len();
        let stages = self.filters.len();
        for stage in 0..stages {
            let index = if encoding { stage } else { stages - 1 - stage };
            let start = self.converted[stage];
            let filter = &mut self.filters[index];
            let piece = &mut self.buffer[start..available];
            let done = if encoding { filter.encode(piece) } else { filter.decode(piece) };
            self.converted[stage] = if end { available } else { start + done };
            available = self.converted[stage];
        }
    }

    /// The bytes every filter has converted, at the front of the buffer.
    pub fn ready(&self) -> &[u8] {
        let ready = self.converted.last().copied().unwrap_or(self.buffer.len());
        &self.buffer[..ready]
    }

    /// Drops the first `count` ready bytes.
    pub fn consume(&mut self, count: usize) {
        let count = count.min(self.ready().len());
        self.buffer.drain(..count);
        for converted in &mut self.converted {
            *converted -= count;
        }
    }

    /// Starts a new stream: empties the buffer and resets the filters.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.converted.fill(0);
        self.filters.iter_mut().for_each(Filter::reset);
    }
}
