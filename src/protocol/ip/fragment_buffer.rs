use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::IPError;

/// The data of one datagram being reassembled from fragments, of either IP
/// version: the bytes received at their offsets, where each fragment
/// received starts and ends, and the length once the last fragment is
/// received.
///
/// A fragment that overlaps another fails with [`IPError::Overlap`], after
/// which the datagram is to be abandoned (RFC 5722, RFC 8200 §4.5, and
/// RFC 1858 for IPv4). Only an exact duplicate of a fragment received (the
/// same offset and length, the same bytes, the same last flag) is ignored,
/// as RFC 8200 §4.5 allows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IPFragmentBuffer {
    /// The bytes up to the end of the furthest fragment received.
    pub data: Vec<u8>,
    /// The end of each fragment received, by its start; they do not overlap.
    pub fragments: BTreeMap<usize, usize>,
    /// The length of the datagram's data, known from its last fragment.
    pub length: Option<usize>,
    /// The start of the last fragment received.
    pub last: Option<usize>,
    /// The count of bytes received: the sum of the lengths of `fragments`.
    pub received: usize,
}

impl IPFragmentBuffer {
    /// The bytes [`IPFragmentBuffer::memory`] counts for the record of one fragment.
    pub const FRAGMENT_RECORD: usize = 2 * core::mem::size_of::<usize>();

    pub const fn new() -> IPFragmentBuffer {
        IPFragmentBuffer { data: Vec::new(), fragments: BTreeMap::new(), length: None, last: None, received: 0 }
    }

    /// Checks the bytes `bytes` at `offset`, the last ones if `last`, against
    /// the fragments received, the data having at most `maximum` bytes, and
    /// returns how much [`IPFragmentBuffer::memory`] would grow if they were
    /// inserted: zero for a fragment without bytes or an exact duplicate.
    pub fn check(&self, offset: usize, bytes: &[u8], last: bool, maximum: usize) -> Result<usize, IPError> {
        let end = offset.checked_add(bytes.len()).filter(|&end| end <= maximum).ok_or(IPError::Length)?;
        match self.length {
            Some(length) if end > length || (last && end != length) => return Err(IPError::Length),
            None if last && self.data.len() > end => return Err(IPError::Length),
            _ => {}
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        // The fragment received that starts last before this one's end is the
        // only one that can overlap it, the fragments being apart.
        if let Some((&start, &stop)) = self.fragments.range(..end).next_back()
            && stop > offset
        {
            let duplicate = (start, stop) == (offset, end)
                && self.data[offset..end] == *bytes
                && last == (self.last == Some(offset));
            return if duplicate { Ok(0) } else { Err(IPError::Overlap) };
        }
        Ok(end.saturating_sub(self.data.len()) + IPFragmentBuffer::FRAGMENT_RECORD)
    }

    /// Adds the bytes `bytes` of the datagram's data at `offset`, which are
    /// the last ones if `last`, after the same checks as
    /// [`IPFragmentBuffer::check`]. Returns whether every byte is received.
    /// A fragment without bytes adds nothing but, if it is the last, the end.
    pub fn insert(&mut self, offset: usize, bytes: &[u8], last: bool, maximum: usize) -> Result<bool, IPError> {
        self.check(offset, bytes, last, maximum)?;
        let end = offset + bytes.len();
        if last {
            self.length = Some(end);
            self.last = Some(offset);
        }
        if !bytes.is_empty() && self.fragments.get(&offset) != Some(&end) {
            if self.data.len() < end {
                self.data.resize(end, 0);
            }
            self.data[offset..end].copy_from_slice(bytes);
            self.fragments.insert(offset, end);
            self.received += bytes.len();
        }
        Ok(self.is_complete())
    }

    /// Whether the last fragment and every byte before it are received.
    pub fn is_complete(&self) -> bool {
        self.length == Some(self.received)
    }

    /// The count of bytes received.
    pub fn received_length(&self) -> usize {
        self.received
    }

    /// The bytes the buffer holds, approximately: its data and
    /// [`IPFragmentBuffer::FRAGMENT_RECORD`] for each fragment (neither the
    /// spare capacity nor the inner nodes of its collections).
    pub fn memory(&self) -> usize {
        self.data.len() + self.fragments.len() * IPFragmentBuffer::FRAGMENT_RECORD
    }
}
