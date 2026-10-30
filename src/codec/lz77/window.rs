use alloc::vec::Vec;

use crate::codec::CompressionError;

/// The history a decompressor of an LZ77 format copies matches from: the
/// last [`LZ77Window::capacity`] bytes of its output (after an optional
/// dictionary). It grows as data comes, up to its capacity, then keeps the
/// latest bytes in a ring, so a short stream does not allocate a whole window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LZ77Window {
    buffer: Vec<u8>,
    capacity: usize,
    /// Where the next byte goes: the end of `buffer` while it grows, then a
    /// position of the ring.
    position: usize,
    total: u64,
}

impl LZ77Window {
    /// An empty window keeping the last `capacity` bytes (at least 1).
    pub fn new(capacity: usize) -> LZ77Window {
        LZ77Window { buffer: Vec::new(), capacity: capacity.max(1), position: 0, total: 0 }
    }

    /// A window keeping the last `capacity` bytes whose history starts with
    /// `dictionary` (only its last `capacity` bytes are kept).
    pub fn with_dictionary(capacity: usize, dictionary: &[u8]) -> LZ77Window {
        let mut window = LZ77Window::new(capacity);
        window.extend(dictionary);
        window
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The number of bytes a match can reach back: the history kept.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// The number of bytes ever added (the dictionary included).
    pub fn total(&self) -> u64 {
        self.total
    }

    /// The bytes that can be written at the write position before the ring
    /// wraps, and whether they are appended (while the window grows).
    pub fn room(&self) -> (usize, bool) {
        if self.buffer.len() < self.capacity {
            (self.capacity - self.buffer.len(), true)
        } else {
            (self.capacity - self.position, false)
        }
    }

    /// Moves the write position after `count` bytes written at it.
    pub fn advance(&mut self, count: usize) {
        self.position += count;
        if self.position == self.capacity {
            self.position = 0;
        }
        self.total += count as u64;
    }

    /// Adds `byte` to the history.
    pub fn push(&mut self, byte: u8) {
        if self.buffer.len() < self.capacity {
            self.buffer.push(byte);
        } else {
            self.buffer[self.position] = byte;
        }
        self.advance(1);
    }

    /// Adds `bytes` to the history.
    pub fn extend(&mut self, mut bytes: &[u8]) {
        if bytes.len() > self.capacity {
            self.total += (bytes.len() - self.capacity) as u64;
            bytes = &bytes[bytes.len() - self.capacity..];
        }
        while !bytes.is_empty() {
            let (room, appending) = self.room();
            let count = room.min(bytes.len());
            if appending {
                self.buffer.extend_from_slice(&bytes[..count]);
            } else {
                self.buffer[self.position..self.position + count].copy_from_slice(&bytes[..count]);
            }
            self.advance(count);
            bytes = &bytes[count..];
        }
    }

    /// The byte `distance` bytes back (1 for the last byte); `None` beyond the history.
    pub fn byte(&self, distance: usize) -> Option<u8> {
        if distance == 0 || distance > self.len() {
            return None;
        }
        let index = (self.position + self.buffer.len() - distance) % self.buffer.len();
        Some(self.buffer[index])
    }

    /// Copies the match of `length` bytes starting `distance` bytes back
    /// (which may overlap the bytes it produces) into `output` and the
    /// history, as far as `output` has room; returns the bytes copied. Fails
    /// with `InvalidData` if `distance` is 0 or beyond the history.
    pub fn copy(&mut self, distance: usize, length: usize, output: &mut [u8]) -> Result<usize, CompressionError> {
        if distance == 0 || distance > self.len() {
            return Err(CompressionError::InvalidData { reason: "match distance beyond the history" });
        }
        let total = length.min(output.len());
        let mut done = 0;
        while done < total {
            let (room, appending) = self.room();
            let write = if appending { self.buffer.len() } else { self.position };
            let source = (write + self.buffer.len() - distance) % self.buffer.len();
            // No more than the distance, so that source and destination do not overlap.
            let count = (total - done).min(distance).min(room).min(self.buffer.len() - source);
            if appending {
                self.buffer.extend_from_within(source..source + count);
            } else {
                self.buffer.copy_within(source..source + count, write);
            }
            output[done..done + count].copy_from_slice(&self.buffer[write..write + count]);
            self.advance(count);
            done += count;
        }
        Ok(total)
    }

    /// Empties the history, keeping the capacity and the allocation.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.position = 0;
        self.total = 0;
    }
}
