use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use super::{TCPSACKBlock, TCPSequence};

/// The data a connection has to send, from SND.UNA on: sent and not yet
/// acknowledged, then not yet sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TCPSendBuffer {
    pub data: VecDeque<u8>,
    /// The sequence number of the first byte of `data`.
    pub start: TCPSequence,
    pub capacity: usize,
}

impl TCPSendBuffer {
    pub fn new(start: TCPSequence, capacity: usize) -> TCPSendBuffer {
        TCPSendBuffer { data: VecDeque::new(), start, capacity }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The room left.
    pub fn space(&self) -> usize {
        self.capacity.saturating_sub(self.data.len())
    }

    /// The sequence number after the last byte.
    pub fn end(&self) -> TCPSequence {
        self.start.add(self.data.len() as u32)
    }

    /// Takes as much of `data` as fits and returns how much.
    pub fn append(&mut self, data: &[u8]) -> usize {
        let taken = data.len().min(self.space());
        self.data.extend(&data[..taken]);
        taken
    }

    /// Forgets the bytes before `upto` and returns how many.
    pub fn acknowledge(&mut self, upto: TCPSequence) -> usize {
        if upto.is_at_or_before(self.start) {
            return 0;
        }
        let count = (upto.distance(self.start) as usize).min(self.data.len());
        self.data.drain(..count);
        self.start = self.start.add(count as u32);
        count
    }

    /// The bytes from `from`, at most `length` of them.
    pub fn slice(&mut self, from: TCPSequence, length: usize) -> &[u8] {
        let offset = (from.distance(self.start) as usize).min(self.data.len());
        let end = offset.saturating_add(length).min(self.data.len());
        &self.data.make_contiguous()[offset..end]
    }
}

/// The data a connection received: in order and not yet read, then the
/// segments that came out of order (RFC 9293 SHLD-31), which the SACK blocks
/// report (RFC 2018 §4).
///
/// Out-of-order blocks are keyed by their position: the bytes from the
/// start of the connection, in 64 bits, so that keys never wrap. Their number
/// is bounded by the capacity ([`TCPReceiveBuffer::BLOCK_COST`]), so that
/// small segments cannot make a peer hold more memory or work than the
/// buffer allows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TCPReceiveBuffer {
    pub data: VecDeque<u8>,
    /// The sequence number of the next byte expected in order.
    pub next: TCPSequence,
    /// The position of `next`.
    pub position: u64,
    /// The out-of-order blocks by position, apart and not touching.
    pub pending: BTreeMap<u64, Vec<u8>>,
    /// The bytes of `pending`.
    pub pending_bytes: usize,
    /// The positions of the latest out-of-order segments, the latest first,
    /// for the order of the SACK blocks.
    pub recent: VecDeque<u64>,
    pub capacity: usize,
}

impl TCPReceiveBuffer {
    /// The bytes of capacity each out-of-order block costs at most in
    /// number: there are at most `capacity / BLOCK_COST` blocks.
    pub const BLOCK_COST: usize = 64;
    /// How many recent segments are remembered for the SACK blocks.
    pub const RECENT: usize = 8;

    pub fn new(next: TCPSequence, capacity: usize) -> TCPReceiveBuffer {
        TCPReceiveBuffer {
            data: VecDeque::new(),
            next,
            position: 0,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            recent: VecDeque::new(),
            capacity,
        }
    }

    /// The bytes held out of order.
    pub fn pending_len(&self) -> usize {
        self.pending_bytes
    }

    /// The most out-of-order blocks held.
    pub fn block_limit(&self) -> usize {
        (self.capacity / TCPReceiveBuffer::BLOCK_COST).max(1)
    }

    /// The room left, from which the window offered is taken.
    pub fn space(&self) -> usize {
        self.capacity.saturating_sub(self.data.len() + self.pending_bytes)
    }

    /// The sequence number of the next byte to read.
    pub fn read_position(&self) -> TCPSequence {
        self.next.sub(self.data.len() as u32)
    }

    /// Takes `payload`, which starts at `sequence`, up to `limit` (the right
    /// edge of the window), and returns how many bytes it added in order.
    /// Out-of-order data that would make more blocks than
    /// [`TCPReceiveBuffer::block_limit`] is dropped; the peer sends it again.
    pub fn insert(&mut self, sequence: TCPSequence, payload: &[u8], limit: TCPSequence) -> usize {
        // Keep only what is at or after `next` and before `limit`.
        let skip = if sequence.is_before(self.next) { self.next.distance(sequence) as usize } else { 0 };
        if skip >= payload.len() || limit.is_at_or_before(sequence.add(skip as u32)) {
            return 0;
        }
        let start = sequence.add(skip as u32);
        let room = limit.distance(start) as usize;
        let payload = &payload[skip..skip + room.min(payload.len() - skip)];
        if start == self.next {
            let before = self.data.len();
            self.data.extend(payload);
            self.advance(payload.len());
            self.pull();
            return self.data.len() - before;
        }
        let position = self.position + start.distance(self.next) as u64;
        self.store(position, payload);
        0
    }

    /// Moves `next` on by `count` bytes taken in order.
    pub fn advance(&mut self, count: usize) {
        self.next = self.next.add(count as u32);
        self.position += count as u64;
    }

    /// Adds out-of-order bytes at `position`, joining the blocks they touch;
    /// where they overlap, the bytes already held are kept.
    pub fn store(&mut self, position: u64, payload: &[u8]) {
        let end = position + payload.len() as u64;
        let before = self.pending.range(..=position).next_back().map(|(start, bytes)| (*start, bytes.len() as u64));
        let joins_before = before.is_some_and(|(start, length)| start + length >= position);
        let joins_after = self.pending.range(position..=end).next().is_some();
        if !joins_before && !joins_after && self.pending.len() >= self.block_limit() {
            return;
        }
        let (start, mut block) = match before.filter(|_| joins_before) {
            Some((start, _)) => {
                let mut block = self.pending.remove(&start).unwrap_or_default();
                self.pending_bytes -= block.len();
                let held = start + block.len() as u64;
                if end > held {
                    block.extend_from_slice(&payload[(held - position) as usize..]);
                }
                (start, block)
            }
            None => (position, payload.to_vec()),
        };
        // The blocks that start within the joined block, or right after it.
        while let Some((&next, _)) = self.pending.range(start..).next() {
            let block_end = start + block.len() as u64;
            if next > block_end {
                break;
            }
            let bytes = self.pending.remove(&next).unwrap_or_default();
            self.pending_bytes -= bytes.len();
            let overlap = ((block_end - next) as usize).min(bytes.len());
            let at = (next - start) as usize;
            block[at..at + overlap].copy_from_slice(&bytes[..overlap]);
            block.extend_from_slice(&bytes[overlap..]);
        }
        self.pending_bytes += block.len();
        self.pending.insert(start, block);
        self.recent.retain(|recent| *recent != position);
        self.recent.push_front(position);
        self.recent.truncate(TCPReceiveBuffer::RECENT);
    }

    /// Moves the out-of-order data that now follows `next` into order.
    pub fn pull(&mut self) {
        while let Some((&start, _)) = self.pending.first_key_value()
            && start <= self.position
        {
            let bytes = self.pending.remove(&start).unwrap_or_default();
            self.pending_bytes -= bytes.len();
            let skip = (self.position - start) as usize;
            if skip < bytes.len() {
                self.data.extend(&bytes[skip..]);
                self.advance(bytes.len() - skip);
            }
        }
        let position = self.position;
        self.recent.retain(|recent| *recent >= position);
    }

    /// Reads into `out` and returns how many bytes.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.data.len());
        for (slot, byte) in out.iter_mut().zip(self.data.drain(..count)) {
            *slot = byte;
        }
        count
    }

    /// The SACK blocks of the out-of-order data, at most `limit`: the block
    /// of the latest segment first, then those of the segments before it
    /// (RFC 2018 §4).
    pub fn sack_blocks(&self, limit: usize) -> ([TCPSACKBlock; 4], usize) {
        let mut blocks = [TCPSACKBlock::default(); 4];
        let mut count = 0;
        let limit = limit.min(blocks.len());
        for &position in &self.recent {
            if count == limit {
                break;
            }
            let Some((&start, bytes)) = self.pending.range(..=position).next_back() else { continue };
            let left = self.next.add((start - self.position) as u32);
            let block = TCPSACKBlock { left, right: left.add(bytes.len() as u32) };
            if position < start + bytes.len() as u64 && !blocks[..count].contains(&block) {
                blocks[count] = block;
                count += 1;
            }
        }
        (blocks, count)
    }
}

/// What the sender knows from SACK blocks (RFC 6675 §3): the ranges above
/// SND.UNA that the receiver holds, sorted and apart. Their number is
/// bounded ([`TCPScoreboard::limit`]), so that a receiver SACKing tiny
/// ranges cannot make the sender's work grow without bound.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TCPScoreboard {
    pub blocks: Vec<TCPSACKBlock>,
}

impl TCPScoreboard {
    /// DupThresh (RFC 6675 §2).
    pub const DUPLICATE_THRESHOLD: u32 = 3;

    /// The most blocks kept for `flight` bytes in flight, sent in segments
    /// of at least `segment` bytes: one per segment, which an honest
    /// receiver never exceeds, since it SACKs what arrived and each block is
    /// apart from the next by a hole.
    pub fn limit(flight: u32, segment: u32) -> usize {
        (flight / segment.max(1)) as usize + 1
    }

    /// Records `sack`, ignoring blocks that are empty or outside
    /// [`una`, `max`), such as the D-SACK blocks of RFC 2883, and new blocks
    /// beyond `limit`.
    pub fn update(&mut self, sack: &[TCPSACKBlock], una: TCPSequence, max: TCPSequence, limit: usize) {
        for block in sack {
            let valid =
                block.left.is_before(block.right) && block.left.is_at_or_after(una) && block.right.is_at_or_before(max);
            if !valid {
                continue;
            }
            let key = |block: &TCPSACKBlock| block.left.distance(una);
            // The blocks from the first that ends at or after this one starts.
            let first = self.blocks.partition_point(|other| other.right.is_before(block.left));
            let mut last = first;
            let mut merged = *block;
            while last < self.blocks.len() && self.blocks[last].left.is_at_or_before(merged.right) {
                let other = self.blocks[last];
                merged = TCPSACKBlock { left: merged.left.min(other.left), right: merged.right.max(other.right) };
                last += 1;
            }
            if first == last && self.blocks.len() >= limit {
                continue;
            }
            self.blocks.splice(first..last, core::iter::once(merged));
            debug_assert!(self.blocks.windows(2).all(|pair| key(&pair[0]) < key(&pair[1])));
        }
    }

    /// Forgets what `una` acknowledges.
    pub fn acknowledge(&mut self, una: TCPSequence) {
        self.blocks.retain_mut(|block| {
            if block.left.is_before(una) {
                block.left = una;
            }
            block.left.is_before(block.right)
        });
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
    }

    /// The bytes SACKed.
    pub fn sacked(&self) -> u32 {
        self.blocks.iter().map(|block| block.right.distance(block.left)).sum()
    }

    pub fn is_sacked(&self, sequence: TCPSequence) -> bool {
        self.blocks.iter().any(|block| sequence.is_in(block.left, block.right))
    }

    /// The holes in [`una`, `max`): the unSACKed ranges, each with whether
    /// it is lost: whether DupThresh blocks or more than (DupThresh - 1)
    /// segments of SACKed bytes lie above it (RFC 6675 IsLost). The last
    /// hole, above every block, is never lost.
    pub fn holes(&self, una: TCPSequence, max: TCPSequence, mss: u32) -> Vec<(TCPSequence, TCPSequence, bool)> {
        let mut holes = Vec::new();
        // The blocks and SACKed bytes from each block up, from the top down.
        let mut above = Vec::with_capacity(self.blocks.len());
        let mut bytes = 0u32;
        for (count, block) in self.blocks.iter().rev().enumerate() {
            bytes = bytes.saturating_add(block.right.distance(block.left));
            above.push((count as u32 + 1, bytes));
        }
        above.reverse();
        let mut cursor = una;
        for (block, (count, bytes)) in self.blocks.iter().zip(above) {
            if cursor.is_before(block.left) {
                let lost = count >= TCPScoreboard::DUPLICATE_THRESHOLD
                    || bytes > (TCPScoreboard::DUPLICATE_THRESHOLD - 1) * mss;
                holes.push((cursor, block.left, lost));
            }
            cursor = cursor.max(block.right);
        }
        if cursor.is_before(max) {
            holes.push((cursor, max, false));
        }
        holes
    }

    /// Whether the byte at `sequence` is lost (RFC 6675 IsLost).
    pub fn is_lost(&self, sequence: TCPSequence, una: TCPSequence, max: TCPSequence, mss: u32) -> bool {
        self.holes(una, max, mss).iter().any(|&(start, end, lost)| lost && sequence.is_in(start, end))
    }

    /// The first lost byte at or after `from` and how many lost bytes follow it (RFC 6675 NextSeg (1)).
    pub fn next_lost(
        &self,
        from: TCPSequence,
        una: TCPSequence,
        max: TCPSequence,
        mss: u32,
    ) -> Option<(TCPSequence, u32)> {
        self.holes(una, max, mss)
            .into_iter()
            .filter(|&(_, end, lost)| lost && end.is_after(from))
            .map(|(start, end, _)| {
                let start = start.max(from);
                (start, end.distance(start))
            })
            .next()
    }

    /// The first unSACKed byte at or after `from` below the highest SACKed
    /// byte, and how many unSACKed bytes follow it (RFC 6675 NextSeg (3)).
    pub fn next_unsacked(&self, from: TCPSequence, una: TCPSequence, max: TCPSequence) -> Option<(TCPSequence, u32)> {
        let top = self.blocks.last()?.right;
        self.holes(una, max, 1)
            .into_iter()
            .filter(|&(_, end, _)| end.is_after(from) && end.is_at_or_before(top))
            .map(|(start, end, _)| {
                let start = start.max(from);
                (start, end.distance(start))
            })
            .next()
    }

    /// The last unSACKed range in [`una`, `max`), which holds the highest
    /// unSACKed byte (RFC 6675 NextSeg (4)).
    pub fn highest_unsacked(&self, una: TCPSequence, max: TCPSequence) -> Option<(TCPSequence, TCPSequence)> {
        self.holes(una, max, 1).last().map(|&(start, end, _)| (start, end))
    }

    /// The pipe of RFC 6675 §4 (SetPipe): the bytes thought to be in the
    /// network. Of the bytes in [`una`, `max`) that are not SACKed, each
    /// counts once if it is not lost, and once more if it was retransmitted
    /// (below `retransmitted`, HighRxt + 1).
    pub fn pipe(&self, una: TCPSequence, max: TCPSequence, retransmitted: TCPSequence, mss: u32) -> u32 {
        let mut pipe = 0u32;
        for (start, end, lost) in self.holes(una, max, mss) {
            if !lost {
                pipe = pipe.saturating_add(end.distance(start));
            }
            if retransmitted.is_after(start) {
                pipe = pipe.saturating_add(retransmitted.min(end).distance(start));
            }
        }
        pipe
    }
}
