use crate::bytes::{BytesError, Reader, Writer};

/// The variable-length integers of QUIC (RFC 9000 §16): the two most
/// significant bits of the first byte give the length, 1, 2, 4 or 8 bytes,
/// and the other bits the value, in network byte order, up to 2^62 - 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QUICVarint;

impl QUICVarint {
    /// The largest value: 2^62 - 1.
    pub const MAXIMUM: u64 = (1 << 62) - 1;

    /// The fewest bytes that encode `value`: 1, 2, 4 or 8, or `None` above
    /// [`QUICVarint::MAXIMUM`].
    pub const fn length(value: u64) -> Option<usize> {
        match value {
            0..=63 => Some(1),
            64..=16_383 => Some(2),
            16_384..=1_073_741_823 => Some(4),
            1_073_741_824..=QUICVarint::MAXIMUM => Some(8),
            _ => None,
        }
    }

    /// The length that the first byte `first` of an encoding announces.
    pub const fn encoded_length(first: u8) -> usize {
        1 << (first >> 6)
    }

    /// Reads a value and the number of bytes that encoded it.
    pub fn read_with_length(reader: &mut Reader<'_>) -> Result<(u64, usize), BytesError> {
        let first = reader.peek(1)?[0];
        let length = QUICVarint::encoded_length(first);
        let bytes = reader.read_slice(length)?;
        let value = bytes[1..].iter().fold(u64::from(first & 0x3F), |value, byte| (value << 8) | u64::from(*byte));
        Ok((value, length))
    }

    /// Reads a value. Values need not be in their shortest encoding (RFC
    /// 9000 §16), except frame types: see [`QUICVarint::read_with_length`].
    pub fn read(reader: &mut Reader<'_>) -> Result<u64, BytesError> {
        QUICVarint::read_with_length(reader).map(|(value, _)| value)
    }

    /// Writes `value` in its shortest encoding; fails above [`QUICVarint::MAXIMUM`].
    pub fn write(out: &mut impl Writer, value: u64) -> Result<(), BytesError> {
        let length = QUICVarint::length(value).ok_or(BytesError::ValueTooLarge { length: 8 })?;
        QUICVarint::write_with_length(out, value, length)
    }

    /// Writes each of `values` in its shortest encoding.
    pub fn write_all(out: &mut impl Writer, values: &[u64]) -> Result<(), BytesError> {
        values.iter().try_for_each(|value| QUICVarint::write(out, *value))
    }

    /// Writes `value` in `length` bytes (1, 2, 4 or 8), as a field whose
    /// length was set before its value is known; fails if it does not fit.
    pub fn write_with_length(out: &mut impl Writer, value: u64, length: usize) -> Result<(), BytesError> {
        let prefix: u8 = match length {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => return Err(BytesError::InvalidLength { length, maximum: 8 }),
        };
        if QUICVarint::length(value).is_none_or(|shortest| shortest > length) {
            return Err(BytesError::ValueTooLarge { length });
        }
        let bytes = value.to_be_bytes();
        let mut encoded = [0u8; 8];
        encoded[..length].copy_from_slice(&bytes[8 - length..]);
        encoded[0] |= prefix << 6;
        out.write(&encoded[..length])
    }
}
