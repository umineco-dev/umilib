/// A sequence number (RFC 9293 §3.4): 32 bits, compared modulo 2^32, so that
/// `a.is_before(b)` holds when `b` is less than 2^31 ahead of `a`. It has no
/// order of its own, because that comparison is not transitive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TCPSequence(pub u32);

impl TCPSequence {
    /// The number `count` after this one.
    pub const fn add(self, count: u32) -> TCPSequence {
        TCPSequence(self.0.wrapping_add(count))
    }

    /// The number `count` before this one.
    pub const fn sub(self, count: u32) -> TCPSequence {
        TCPSequence(self.0.wrapping_sub(count))
    }

    /// How far this number is after `earlier`, modulo 2^32.
    pub const fn distance(self, earlier: TCPSequence) -> u32 {
        self.0.wrapping_sub(earlier.0)
    }

    pub const fn is_before(self, other: TCPSequence) -> bool {
        (self.0.wrapping_sub(other.0) as i32) < 0
    }

    pub const fn is_after(self, other: TCPSequence) -> bool {
        other.is_before(self)
    }

    pub const fn is_at_or_before(self, other: TCPSequence) -> bool {
        !self.is_after(other)
    }

    pub const fn is_at_or_after(self, other: TCPSequence) -> bool {
        !self.is_before(other)
    }

    /// Whether this number is in `[start, end)`.
    pub const fn is_in(self, start: TCPSequence, end: TCPSequence) -> bool {
        self.is_at_or_after(start) && self.is_before(end)
    }

    /// The later of the two.
    pub const fn max(self, other: TCPSequence) -> TCPSequence {
        if self.is_before(other) { other } else { self }
    }

    /// The earlier of the two.
    pub const fn min(self, other: TCPSequence) -> TCPSequence {
        if self.is_before(other) { self } else { other }
    }
}
