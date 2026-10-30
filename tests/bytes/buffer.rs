use umilib::bytes::{Buffer, BytesError, Reader, Writer};

#[test]
fn writes_big_and_little_endian_integers() {
    let mut buffer = Buffer::new();
    buffer.write_be(0x0102_0304u32).unwrap();
    buffer.write_le(0x0102_0304u32).unwrap();
    buffer.write_be(-2i16).unwrap();
    buffer.write_u8(0xAA).unwrap();
    assert_eq!(buffer.as_slice(), &[1, 2, 3, 4, 4, 3, 2, 1, 0xFF, 0xFE, 0xAA]);
    assert_eq!(buffer.len(), 11);
}

#[test]
fn sized_writes_round_trip_through_sized_reads() {
    let unsigned: [u64; 6] = [0, 1, 0xFF, 0x1234, 0xFF_FFFF, 0x1_0000_0000];
    for &value in &unsigned {
        for length in 1..=8usize {
            let mut buffer = Buffer::new();
            let fits = length == 8 || value < 1u64 << (8 * length);
            assert_eq!(buffer.write_be_sized(value, length).is_ok(), fits, "{value:#x} in {length} bytes");
            if fits {
                assert_eq!(buffer.len(), length);
                assert_eq!(Reader::new(buffer.as_slice()).read_be_sized::<u64>(length), Ok(value));
                let mut little = Buffer::new();
                little.write_le_sized(value, length).unwrap();
                assert_eq!(Reader::new(little.as_slice()).read_le_sized::<u64>(length), Ok(value));
            } else {
                assert_eq!(buffer.write_be_sized(value, length), Err(BytesError::ValueTooLarge { length }));
                assert_eq!(buffer.write_le_sized(value, length), Err(BytesError::ValueTooLarge { length }));
                assert!(buffer.is_empty());
            }
        }
    }
}

#[test]
fn sized_writes_of_signed_values_require_a_faithful_sign() {
    let cases: [(i32, usize, bool); 8] = [
        (-1, 1, true),
        (-128, 1, true),
        (-129, 1, false),
        (127, 1, true),
        (128, 1, false),
        (-32768, 2, true),
        (0x7F_FFFF, 3, true),
        (0x80_0000, 3, false),
    ];
    for (value, length, fits) in cases {
        let mut buffer = Buffer::new();
        assert_eq!(buffer.write_be_sized(value, length).is_ok(), fits, "{value} in {length} bytes");
        if fits {
            assert_eq!(Reader::new(buffer.as_slice()).read_be_sized::<i32>(length), Ok(value));
        }
    }
}

#[test]
fn rejects_sized_lengths_outside_the_integer() {
    let mut buffer = Buffer::new();
    assert_eq!(buffer.write_be_sized(1u16, 0), Err(BytesError::InvalidLength { length: 0, maximum: 2 }));
    assert_eq!(buffer.write_le_sized(1u16, 3), Err(BytesError::InvalidLength { length: 3, maximum: 2 }));
    assert!(buffer.is_empty());
}

#[test]
fn every_integer_type_round_trips() {
    let mut buffer = Buffer::new();
    buffer.write_be(u128::MAX - 1).unwrap();
    buffer.write_le(i128::MIN + 1).unwrap();
    buffer.write_be(u64::MAX).unwrap();
    buffer.write_le(i64::MIN).unwrap();
    buffer.write_be(i8::MIN).unwrap();
    let mut reader = Reader::new(buffer.as_slice());
    assert_eq!(reader.read_be::<u128>(), Ok(u128::MAX - 1));
    assert_eq!(reader.read_le::<i128>(), Ok(i128::MIN + 1));
    assert_eq!(reader.read_be::<u64>(), Ok(u64::MAX));
    assert_eq!(reader.read_le::<i64>(), Ok(i64::MIN));
    assert_eq!(reader.read_be::<i8>(), Ok(i8::MIN));
    assert!(reader.is_empty());
}

#[test]
fn limit_bounds_the_contents_and_failed_writes_change_nothing() {
    let mut buffer = Buffer::with_limit(4);
    assert_eq!(buffer.limit(), Some(4));
    buffer.write(&[1, 2, 3]).unwrap();
    assert_eq!(buffer.write(&[4, 5]), Err(BytesError::CapacityExceeded { requested: 2, limit: 4 }));
    assert_eq!(buffer.write_be(1u16), Err(BytesError::CapacityExceeded { requested: 2, limit: 4 }));
    assert_eq!(buffer.as_slice(), &[1, 2, 3]);
    buffer.write_u8(4).unwrap();
    assert_eq!(buffer.write_u8(5), Err(BytesError::CapacityExceeded { requested: 1, limit: 4 }));
    assert_eq!(buffer.write(&[]), Ok(()));
    assert_eq!(buffer.as_slice(), &[1, 2, 3, 4]);
}

#[test]
fn set_limit_refuses_limits_below_the_contents() {
    let mut buffer = Buffer::new();
    buffer.write(&[1, 2, 3]).unwrap();
    assert_eq!(buffer.set_limit(Some(2)), Err(BytesError::CapacityExceeded { requested: 3, limit: 2 }));
    assert_eq!(buffer.limit(), None);
    assert_eq!(buffer.set_limit(Some(3)), Ok(()));
    assert_eq!(buffer.write_u8(4), Err(BytesError::CapacityExceeded { requested: 1, limit: 3 }));
    assert_eq!(buffer.set_limit(None), Ok(()));
    assert_eq!(buffer.write_u8(4), Ok(()));
}

#[test]
fn clear_and_truncate_keep_the_limit() {
    let mut buffer = Buffer::with_limit(8);
    buffer.write(&[1, 2, 3, 4]).unwrap();
    buffer.truncate(2);
    assert_eq!(buffer.as_slice(), &[1, 2]);
    buffer.truncate(10);
    assert_eq!(buffer.len(), 2);
    buffer.clear();
    assert!(buffer.is_empty());
    assert_eq!(buffer.limit(), Some(8));
    assert_eq!(Buffer::from(vec![9, 8]).into_vec(), vec![9, 8]);
    assert!(Buffer::with_capacity(16).is_empty());
}

#[test]
fn capacity_can_be_requested_without_panicking() {
    let buffer = Buffer::try_with_capacity(64).unwrap();
    assert!(buffer.capacity() >= 64);
    assert!(buffer.is_empty());
    assert!(matches!(Buffer::try_with_capacity(usize::MAX), Err(BytesError::CapacityExceeded { .. })));
}

/// An integer larger than the largest supported size.
#[derive(Clone, Copy)]
struct Wide;

impl umilib::bytes::Integer for Wide {
    const SIZE: usize = 32;
    const SIGNED: bool = false;
    fn from_be_slice(_: &[u8]) -> Self {
        Wide
    }
    fn from_le_slice(_: &[u8]) -> Self {
        Wide
    }
    fn to_be_slice(self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
    fn to_le_slice(self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}

#[test]
fn integers_larger_than_the_maximum_size_are_rejected() {
    let mut buffer = Buffer::new();
    assert!(matches!(buffer.write_be(Wide), Err(BytesError::InvalidLength { .. })));
    assert!(matches!(buffer.write_le_sized(Wide, 4), Err(BytesError::InvalidLength { .. })));
    assert!(matches!(Reader::new(&[0; 64]).read_be_sized::<Wide>(4), Err(BytesError::InvalidLength { .. })));
    assert!(buffer.is_empty());
}
