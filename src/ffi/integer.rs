/// A `u128` split into two `u64` halves, because C has no portable 128-bit integer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct U128 {
    pub high: u64,
    pub low: u64,
}

impl From<u128> for U128 {
    fn from(value: u128) -> U128 {
        U128 { high: (value >> 64) as u64, low: value as u64 }
    }
}

impl From<U128> for u128 {
    fn from(value: U128) -> u128 {
        ((value.high as u128) << 64) | value.low as u128
    }
}

/// An `i128` in two's complement, split into a signed high half and an unsigned low half.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct I128 {
    pub high: i64,
    pub low: u64,
}

impl From<i128> for I128 {
    fn from(value: i128) -> I128 {
        I128 { high: (value >> 64) as i64, low: value as u64 }
    }
}

impl From<I128> for i128 {
    fn from(value: I128) -> i128 {
        ((value.high as i128) << 64) | value.low as i128
    }
}

/// A C `char`, used for NUL-terminated strings.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Char(pub core::ffi::c_char);
