use super::BitOrder;

/// A queue of up to 64 bits that a streaming decoder fills from successive
/// input slices, a byte at a time, and reads bits from in its [`BitOrder`].
///
/// [`BitQueue::fill`] takes a byte only while the queue holds fewer bits
/// than requested, so a decoder that asks for the bits it needs never takes
/// a byte past the end of its stream: after the last bit, fewer than 8 bits
/// stay queued and the following bytes stay in the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitQueue {
    /// The queued bits in their low `count` bits: for
    /// [`BitOrder::LeastSignificantFirst`] the next bit is bit 0, for
    /// [`BitOrder::MostSignificantFirst`] bit `count - 1`.
    bits: u64,
    count: u32,
    order: BitOrder,
}

impl BitQueue {
    /// The most bits [`BitQueue::fill`], [`BitQueue::peek`] and [`BitQueue::read`] take at once.
    pub const MAXIMUM_BITS: u32 = 56;

    /// An empty queue of [`BitOrder::LeastSignificantFirst`].
    pub const fn new() -> BitQueue {
        BitQueue::with_order(BitOrder::LeastSignificantFirst)
    }

    /// An empty queue of `order`.
    pub const fn with_order(order: BitOrder) -> BitQueue {
        BitQueue { bits: 0, count: 0, order }
    }

    pub const fn order(&self) -> BitOrder {
        self.order
    }

    /// The number of bits queued.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// The mask of the low `count` bits.
    pub const fn mask(count: u32) -> u64 {
        if count >= 64 { u64::MAX } else { (1u64 << count) - 1 }
    }

    /// Appends the bits of `byte` (when fewer than 57 bits are queued).
    pub fn push(&mut self, byte: u8) {
        debug_assert!(self.count <= BitQueue::MAXIMUM_BITS);
        match self.order {
            BitOrder::LeastSignificantFirst => self.bits |= (byte as u64) << self.count,
            BitOrder::MostSignificantFirst => self.bits = self.bits << 8 | byte as u64,
        }
        self.count += 8;
    }

    /// Moves bytes from the front of `input` into the queue until it holds
    /// `count` bits (at most [`BitQueue::MAXIMUM_BITS`]) or `input` is
    /// empty; returns whether it holds `count` bits.
    pub fn fill(&mut self, count: u32, input: &mut &[u8]) -> bool {
        let count = count.min(BitQueue::MAXIMUM_BITS);
        while self.count < count {
            let Some((byte, rest)) = input.split_first() else {
                return false;
            };
            self.push(*byte);
            *input = rest;
        }
        true
    }

    /// The next `count` bits (at most [`BitQueue::MAXIMUM_BITS`]) as a value
    /// in the order of the queue, the missing ones as zeros, without consuming them.
    pub fn peek_padded(&self, count: u32) -> u64 {
        match self.order {
            BitOrder::LeastSignificantFirst => self.bits & BitQueue::mask(count),
            BitOrder::MostSignificantFirst if count <= self.count => {
                (self.bits >> (self.count - count)) & BitQueue::mask(count)
            }
            BitOrder::MostSignificantFirst => (self.bits << (count - self.count)) & BitQueue::mask(count),
        }
    }

    /// The next `count` bits without consuming them; `None` if fewer are queued.
    pub fn peek(&self, count: u32) -> Option<u64> {
        if count > self.count {
            return None;
        }
        Some(self.peek_padded(count))
    }

    /// Drops the next `count` bits (at most the bits queued).
    pub fn consume(&mut self, count: u32) {
        debug_assert!(count <= self.count);
        let count = count.min(self.count);
        self.count -= count;
        self.bits = match self.order {
            BitOrder::LeastSignificantFirst if count >= 64 => 0,
            BitOrder::LeastSignificantFirst => self.bits >> count,
            BitOrder::MostSignificantFirst => self.bits & BitQueue::mask(self.count),
        };
    }

    /// Consumes and returns the next `count` bits; `None` (consuming nothing) if fewer are queued.
    pub fn read(&mut self, count: u32) -> Option<u64> {
        let value = self.peek(count)?;
        self.consume(count);
        Some(value)
    }

    /// Fills to `count` bits from `input`, then reads them; `None` if
    /// `input` ran out first (its bytes stay queued for the next call).
    pub fn read_from(&mut self, count: u32, input: &mut &[u8]) -> Option<u64> {
        if !self.fill(count, input) {
            return None;
        }
        self.read(count)
    }

    /// Drops the bits up to the next byte boundary of the stream (those of
    /// a partly read byte), returning them.
    pub fn align(&mut self) -> u64 {
        let count = self.count % 8;
        let value = self.peek_padded(count);
        self.consume(count);
        value
    }

    /// Drops every queued bit, keeping the order.
    pub fn clear(&mut self) {
        *self = BitQueue::with_order(self.order);
    }
}

impl Default for BitQueue {
    fn default() -> BitQueue {
        BitQueue::new()
    }
}
