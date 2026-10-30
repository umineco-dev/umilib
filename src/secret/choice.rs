use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

/// A secret boolean, stored as `0` or `1`, combined without branching.
///
/// It prints as `Choice(..)` so that its value never reaches a log.
#[derive(Clone, Copy)]
pub struct Choice(u8);

impl core::fmt::Debug for Choice {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Choice(..)")
    }
}

impl Choice {
    /// The secret value `true`.
    pub const TRUE: Choice = Choice(1);
    /// The secret value `false`.
    pub const FALSE: Choice = Choice(0);

    /// Creates a choice from the lowest bit of `bit`; the other bits are ignored.
    pub fn from_bit(bit: u8) -> Choice {
        Choice(core::hint::black_box(bit & 1))
    }

    /// The choice as `0` or `1`.
    pub fn bit(self) -> u8 {
        core::hint::black_box(self.0)
    }

    /// Reveals the choice. Only call this when the result is allowed to become public.
    pub fn into_bool(self) -> bool {
        self.bit() == 1
    }
}

impl From<bool> for Choice {
    /// Creates a choice from a public boolean.
    fn from(value: bool) -> Choice {
        Choice::from_bit(value as u8)
    }
}

impl BitAnd for Choice {
    type Output = Choice;
    fn bitand(self, other: Choice) -> Choice {
        Choice::from_bit(self.0 & other.0)
    }
}

impl BitOr for Choice {
    type Output = Choice;
    fn bitor(self, other: Choice) -> Choice {
        Choice::from_bit(self.0 | other.0)
    }
}

impl BitXor for Choice {
    type Output = Choice;
    fn bitxor(self, other: Choice) -> Choice {
        Choice::from_bit(self.0 ^ other.0)
    }
}

impl Not for Choice {
    type Output = Choice;
    fn not(self) -> Choice {
        Choice::from_bit(self.0 ^ 1)
    }
}

impl BitAndAssign for Choice {
    fn bitand_assign(&mut self, other: Choice) {
        *self = *self & other;
    }
}

impl BitOrAssign for Choice {
    fn bitor_assign(&mut self, other: Choice) {
        *self = *self | other;
    }
}

impl BitXorAssign for Choice {
    fn bitxor_assign(&mut self, other: Choice) {
        *self = *self ^ other;
    }
}
