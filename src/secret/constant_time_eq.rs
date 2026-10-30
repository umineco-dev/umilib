use super::Choice;

/// Equality that takes the same time for every value of the same length.
pub trait ConstantTimeEq {
    /// Returns [`Choice::TRUE`] if `self` equals `other`.
    fn ct_eq(&self, other: &Self) -> Choice;

    /// Returns [`Choice::TRUE`] if `self` differs from `other`.
    fn ct_ne(&self, other: &Self) -> Choice {
        !self.ct_eq(other)
    }
}

macro_rules! constant_time_eq {
    ($($unsigned:ty => $signed:ty),* $(,)?) => {
        $(
            impl ConstantTimeEq for $unsigned {
                fn ct_eq(&self, other: &$unsigned) -> Choice {
                    let difference = core::hint::black_box(self ^ other);
                    // The highest bit of `x | -x` is set exactly when `x != 0`.
                    let nonzero = (difference | difference.wrapping_neg()) >> (<$unsigned>::BITS - 1);
                    Choice::from_bit(nonzero as u8 ^ 1)
                }
            }

            impl ConstantTimeEq for $signed {
                fn ct_eq(&self, other: &$signed) -> Choice {
                    (*self as $unsigned).ct_eq(&(*other as $unsigned))
                }
            }
        )*
    };
}

constant_time_eq!(u8 => i8, u16 => i16, u32 => i32, u64 => i64, u128 => i128, usize => isize);

impl<T: ConstantTimeEq> ConstantTimeEq for [T] {
    /// Lengths are compared in variable time: they are treated as public.
    fn ct_eq(&self, other: &[T]) -> Choice {
        if self.len() != other.len() {
            return Choice::FALSE;
        }
        self.iter().zip(other).fold(Choice::TRUE, |equal, (left, right)| equal & left.ct_eq(right))
    }
}

impl<T: ConstantTimeEq, const N: usize> ConstantTimeEq for [T; N] {
    fn ct_eq(&self, other: &[T; N]) -> Choice {
        self.as_slice().ct_eq(other.as_slice())
    }
}

impl ConstantTimeEq for Choice {
    fn ct_eq(&self, other: &Choice) -> Choice {
        !(*self ^ *other)
    }
}
