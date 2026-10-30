use alloc::vec::Vec;

use super::HPACKError;

/// The integers of HPACK and QPACK (RFC 7541 §5.1): a value in the low N
/// bits of a byte whose other bits belong to the representation, continued
/// in bytes of 7 bits, least significant first, when it fills them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HPACKInteger;

impl HPACKInteger {
    /// The largest integer read: 2^62 - 1, as large as the other integers of
    /// HTTP/2 and HTTP/3 (RFC 7541 §5.1 leaves the limit to the decoder).
    pub const MAXIMUM: u64 = (1 << 62) - 1;

    /// Writes `value` with an N-bit prefix, `prefix` of 1 to 8, in the low
    /// bits of a first byte whose high bits are `flags`.
    pub fn write(out: &mut Vec<u8>, prefix: u32, flags: u8, value: u64) {
        let limit = (1u64 << prefix) - 1;
        let flags = if prefix >= 8 { 0 } else { flags & !(limit as u8) };
        if value < limit {
            out.push(flags | value as u8);
            return;
        }
        out.push(flags | limit as u8);
        let mut rest = value - limit;
        while rest >= 0x80 {
            out.push(0x80 | (rest & 0x7F) as u8);
            rest >>= 7;
        }
        out.push(rest as u8);
    }

    /// The bytes [`HPACKInteger::write`] writes.
    pub fn length(prefix: u32, value: u64) -> usize {
        let limit = (1u64 << prefix) - 1;
        if value < limit {
            return 1;
        }
        let mut rest = value - limit;
        let mut length = 2;
        while rest >= 0x80 {
            rest >>= 7;
            length += 1;
        }
        length
    }

    /// Reads an integer of an N-bit prefix from the front of `input`,
    /// advancing it; returns the high bits of the first byte, not of the
    /// prefix, and the value. Fails with [`HPACKError::Truncated`] or
    /// [`HPACKError::IntegerOverflow`].
    pub fn read(input: &mut &[u8], prefix: u32) -> Result<(u8, u64), HPACKError> {
        let (&first, mut rest) = input.split_first().ok_or(HPACKError::Truncated)?;
        let limit = (1u64 << prefix) - 1;
        let flags = if prefix >= 8 { 0 } else { first & !(limit as u8) };
        let mut value = u64::from(first) & limit;
        if value == limit {
            let mut shift = 0u32;
            loop {
                let (&byte, after) = rest.split_first().ok_or(HPACKError::Truncated)?;
                rest = after;
                let part = u64::from(byte & 0x7F);
                if shift > 56 || (part << shift) >> shift != part {
                    return Err(HPACKError::IntegerOverflow);
                }
                value = value.checked_add(part << shift).ok_or(HPACKError::IntegerOverflow)?;
                if value > HPACKInteger::MAXIMUM {
                    return Err(HPACKError::IntegerOverflow);
                }
                if byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
        }
        *input = rest;
        Ok((flags, value))
    }
}
