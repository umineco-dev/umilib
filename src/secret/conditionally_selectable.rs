use super::Choice;

/// Selection between two values without branching on the secret [`Choice`].
pub trait ConditionallySelectable: Copy {
    /// Returns `a` if `choice` is false and `b` if it is true.
    fn select(a: &Self, b: &Self, choice: Choice) -> Self;

    /// Replaces `self` with `other` if `choice` is true.
    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        *self = Self::select(self, other, choice);
    }

    /// Swaps `a` and `b` if `choice` is true.
    fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        let original = *a;
        a.conditional_assign(b, choice);
        b.conditional_assign(&original, choice);
    }
}

macro_rules! conditionally_selectable {
    ($($type:ty),* $(,)?) => {
        $(
            impl ConditionallySelectable for $type {
                fn select(a: &$type, b: &$type, choice: Choice) -> $type {
                    let mask = (0 as $type).wrapping_sub(choice.bit() as $type);
                    a ^ (mask & (a ^ b))
                }
            }
        )*
    };
}

conditionally_selectable!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

impl<T: ConditionallySelectable, const N: usize> ConditionallySelectable for [T; N] {
    fn select(a: &[T; N], b: &[T; N], choice: Choice) -> [T; N] {
        let mut result = *a;
        for (output, other) in result.iter_mut().zip(b) {
            output.conditional_assign(other, choice);
        }
        result
    }
}

impl ConditionallySelectable for Choice {
    fn select(a: &Choice, b: &Choice, choice: Choice) -> Choice {
        Choice::from_bit(u8::select(&a.bit(), &b.bit(), choice))
    }
}
