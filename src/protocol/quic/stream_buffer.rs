use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use super::{QUICError, QUICErrorCode, QUICRangeSet, QUICVarint};

/// The bytes of a stream received out of order (RFC 9000 §2.2), joined
/// back in order for the reader: STREAM data, or a level's CRYPTO data.
#[derive(Clone, Debug, Default)]
pub struct QUICReceiveBuffer {
    /// The bytes received past `read`, by offset, without overlaps.
    chunks: BTreeMap<u64, Vec<u8>>,
    /// The offsets received, from 0.
    received: QUICRangeSet,
    /// The offset up to which the reader took the bytes.
    pub read: u64,
    /// The largest offset received: data up to it counts against flow
    /// control though some may be missing (RFC 9000 §4.1).
    pub highest: u64,
    /// The final size, once known (RFC 9000 §4.5).
    pub final_size: Option<u64>,
}

impl QUICReceiveBuffer {
    pub fn new() -> QUICReceiveBuffer {
        QUICReceiveBuffer::default()
    }

    /// Takes `data` at `offset`, the end of the stream if `fin`. Bytes
    /// received before are kept, not replaced. Fails with FINAL_SIZE_ERROR
    /// for data past a known final size, or a final size that differs from
    /// one known or is below data received (RFC 9000 §4.5).
    pub fn insert(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<(), QUICError> {
        let end = offset
            .checked_add(data.len() as u64)
            .filter(|end| *end <= QUICVarint::MAXIMUM)
            .ok_or(QUICError::transport(QUICErrorCode::FLOW_CONTROL_ERROR, "stream data past 2^62 - 1"))?;
        let final_size = QUICError::transport(QUICErrorCode::FINAL_SIZE_ERROR, "final size changed");
        match self.final_size {
            Some(size) if end > size || (fin && end != size) => return Err(final_size),
            None if fin && end < self.highest => return Err(final_size),
            _ => {}
        }
        if fin {
            self.final_size = Some(end);
        }
        self.highest = self.highest.max(end);
        // Only the bytes that are new: each gap of what was received.
        let mut position = offset.max(self.read);
        while position < end {
            match self.received.next_from(position) {
                Some(range) if *range.start() <= position => position = range.end() + 1,
                next => {
                    let gap_end = next.map_or(end, |range| (*range.start()).min(end));
                    let piece = &data[(position - offset) as usize..(gap_end - offset) as usize];
                    self.chunks.insert(position, piece.to_vec());
                    self.received.insert(position..=gap_end - 1);
                    position = gap_end;
                }
            }
        }
        Ok(())
    }

    /// The bytes that can be read now: those received in order past `read`.
    pub fn readable(&self) -> usize {
        match self.received.next_from(self.read) {
            Some(range) if *range.start() <= self.read => (range.end() + 1 - self.read) as usize,
            _ => 0,
        }
    }

    /// Reads bytes in order into `out` and returns how many.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let mut count = 0;
        while count < out.len() {
            let Some(mut entry) = self.chunks.first_entry() else { break };
            if *entry.key() != self.read {
                break;
            }
            let chunk = entry.get_mut();
            let taken = chunk.len().min(out.len() - count);
            out[count..count + taken].copy_from_slice(&chunk[..taken]);
            count += taken;
            self.read += taken as u64;
            if taken == chunk.len() {
                entry.remove();
            } else {
                let rest = chunk.split_off(taken);
                entry.remove();
                self.chunks.insert(self.read, rest);
            }
        }
        self.received.remove_below(self.read);
        count
    }

    /// Takes every byte that can be read.
    pub fn read_all(&mut self) -> Vec<u8> {
        let mut out = alloc::vec![0; self.readable()];
        let count = self.read(&mut out);
        out.truncate(count);
        out
    }

    /// Whether the reader took every byte up to the final size.
    pub fn is_finished(&self) -> bool {
        self.final_size == Some(self.read)
    }

    /// The bytes held for the reader, received in order or not.
    pub fn buffered(&self) -> usize {
        self.chunks.values().map(Vec::len).sum()
    }

    /// Drops what is held, as a reset stream does (RFC 9000 §3.2).
    pub fn discard(&mut self) {
        self.chunks.clear();
        self.received = QUICRangeSet::new();
    }
}

/// The bytes of a stream to send (RFC 9000 §2.2, §13.3): kept until
/// acknowledged, sent once, and sent again when the packets carrying them
/// are lost. The same serves a level's CRYPTO data.
#[derive(Clone, Debug, Default)]
pub struct QUICSendBuffer {
    /// The bytes from `base` on: all before it were acknowledged.
    data: VecDeque<u8>,
    base: u64,
    /// The offset up to which bytes were ever sent: new data starts there.
    pub sent: u64,
    /// The ranges acknowledged at or past `base`.
    acknowledged: QUICRangeSet,
    /// The ranges to send again, lost with their packets.
    lost: QUICRangeSet,
    /// Whether the writer ended the stream: its final size is [`QUICSendBuffer::written`].
    pub fin: bool,
    pub fin_sent: bool,
    pub fin_acknowledged: bool,
    /// Whether the FIN must be sent again.
    pub fin_lost: bool,
}

impl QUICSendBuffer {
    pub fn new() -> QUICSendBuffer {
        QUICSendBuffer::default()
    }

    /// The offset past the last byte written: the final size once `fin`.
    pub fn written(&self) -> u64 {
        self.base + self.data.len() as u64
    }

    /// The bytes held: written and not yet acknowledged.
    pub fn buffered(&self) -> usize {
        self.data.len()
    }

    /// Appends `data`; fails with [`QUICError::State`] after the end, and
    /// with FLOW_CONTROL_ERROR past 2^62 - 1 (RFC 9000 §4.5).
    pub fn write(&mut self, data: &[u8]) -> Result<(), QUICError> {
        if self.fin {
            return Err(QUICError::State);
        }
        if self.written() + data.len() as u64 > QUICVarint::MAXIMUM {
            return Err(QUICError::transport(QUICErrorCode::FLOW_CONTROL_ERROR, "stream past 2^62 - 1"));
        }
        self.data.extend(data);
        Ok(())
    }

    /// Ends the stream after what was written.
    pub fn finish(&mut self) {
        self.fin = true;
    }

    /// Whether something is waiting to be sent: data lost, data new below
    /// `limit` (the flow control limit of the stream's offsets), or the FIN.
    pub fn has_data(&self, limit: u64) -> bool {
        !self.lost.is_empty()
            || (self.sent < self.written() && self.sent < limit)
            || (self.fin && (!self.fin_sent || self.fin_lost) && self.sent == self.written())
    }

    /// The next bytes to send, at most `maximum` of them: lost ones first,
    /// then new ones up to the offset `limit` (RFC 9000 §4.1). Returns their
    /// offset, the bytes, and whether the FIN goes with them; `None` if
    /// there is nothing to send.
    pub fn next(&mut self, maximum: usize, limit: u64) -> Option<(u64, Vec<u8>, bool)> {
        if let Some(range) = self.lost.next_from(0) {
            let start = *range.start();
            let end = (*range.end() + 1).min(start + maximum as u64);
            self.lost.remove(start..=end - 1);
            let bytes = self.bytes(start, end);
            let fin = self.fin && end == self.written() && (self.fin_lost || !self.fin_sent);
            if fin {
                self.fin_sent = true;
                self.fin_lost = false;
            }
            return Some((start, bytes, fin));
        }
        let end = self.written().min(limit).min(self.sent + maximum as u64);
        if end > self.sent || (self.fin && self.sent == self.written() && (!self.fin_sent || self.fin_lost)) {
            let start = self.sent;
            let bytes = self.bytes(start, end);
            self.sent = end;
            let fin = self.fin && end == self.written();
            if fin {
                self.fin_sent = true;
                self.fin_lost = false;
            }
            if bytes.is_empty() && !fin {
                return None;
            }
            return Some((start, bytes, fin));
        }
        None
    }

    /// The bytes from `start` to `end`, which must be held: at or past the
    /// first byte not acknowledged, and written.
    pub fn bytes(&self, start: u64, end: u64) -> Vec<u8> {
        let from = (start - self.base) as usize;
        let to = (end - self.base) as usize;
        self.data.range(from..to).copied().collect()
    }

    /// The peer received the bytes at `offset` and the FIN if `fin`.
    pub fn acknowledge(&mut self, offset: u64, length: usize, fin: bool) {
        if length > 0 {
            let end = offset + length as u64 - 1;
            if end >= self.base {
                self.acknowledged.insert(offset.max(self.base)..=end);
                self.lost.remove(offset..=end);
            }
        }
        if fin {
            self.fin_acknowledged = true;
            self.fin_lost = false;
        }
        // The acknowledged bytes at the front are released.
        while let Some(range) = self.acknowledged.next_from(0) {
            if *range.start() != self.base {
                break;
            }
            let released = (range.end() + 1 - self.base) as usize;
            self.data.drain(..released.min(self.data.len()));
            self.base = range.end() + 1;
            self.acknowledged.remove_below(self.base);
        }
    }

    /// The packet with the bytes at `offset`, and the FIN if `fin`, was
    /// lost: what of it is not acknowledged goes again.
    pub fn lose(&mut self, offset: u64, length: usize, fin: bool) {
        if length > 0 {
            let start = offset.max(self.base);
            let end = offset + length as u64;
            let mut position = start;
            while position < end {
                match self.acknowledged.next_from(position) {
                    Some(range) if *range.start() <= position => position = range.end() + 1,
                    next => {
                        let gap_end = next.map_or(end, |range| (*range.start()).min(end));
                        self.lost.insert(position..=gap_end - 1);
                        position = gap_end;
                    }
                }
            }
        }
        if fin && !self.fin_acknowledged {
            self.fin_lost = true;
        }
    }

    /// Whether every byte and the FIN were acknowledged.
    pub fn is_acknowledged(&self) -> bool {
        self.fin && self.fin_acknowledged && self.data.is_empty()
    }

    /// Drops every byte, as a reset stream does (RFC 9000 §3.1).
    pub fn discard(&mut self) {
        self.base = self.written();
        self.data.clear();
        self.acknowledged = QUICRangeSet::new();
        self.lost = QUICRangeSet::new();
    }
}
