use umilib::bytes::{BytesError, Reader};

#[test]
fn reads_big_endian_integers_most_significant_byte_first() {
    let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    assert_eq!(Reader::new(&bytes).read_be::<u8>(), Ok(0x01));
    assert_eq!(Reader::new(&bytes).read_be::<u16>(), Ok(0x0102));
    assert_eq!(Reader::new(&bytes).read_be::<u32>(), Ok(0x0102_0304));
    assert_eq!(Reader::new(&bytes).read_be::<u64>(), Ok(0x0102_0304_0506_0708));
    assert_eq!(Reader::new(&bytes).read_be::<u128>(), Ok(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10));
}

#[test]
fn reads_little_endian_integers_least_significant_byte_first() {
    let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    assert_eq!(Reader::new(&bytes).read_le::<u16>(), Ok(0x0201));
    assert_eq!(Reader::new(&bytes).read_le::<u32>(), Ok(0x0403_0201));
    assert_eq!(Reader::new(&bytes).read_le::<u64>(), Ok(0x0807_0605_0403_0201));
    assert_eq!(Reader::new(&bytes).read_le::<u128>(), Ok(0x100F_0E0D_0C0B_0A09_0807_0605_0403_0201));
}

#[test]
fn reads_signed_integers_in_twos_complement() {
    assert_eq!(Reader::new(&[0xFF]).read_be::<i8>(), Ok(-1));
    assert_eq!(Reader::new(&[0x80, 0x00]).read_be::<i16>(), Ok(i16::MIN));
    assert_eq!(Reader::new(&[0xFE, 0xFF, 0xFF, 0xFF]).read_le::<i32>(), Ok(-2));
    assert_eq!(Reader::new(&[0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).read_be::<i64>(), Ok(i64::MAX));
}

#[test]
fn reads_24_bit_lengths_as_used_by_tls() {
    // RFC 8446 section 3.3: uint24 is three bytes in network byte order.
    let mut reader = Reader::new(&[0x01, 0x00, 0x00, 0xAA]);
    assert_eq!(reader.read_be_sized::<u32>(3), Ok(0x01_0000));
    assert_eq!(reader.position(), 3);
    assert_eq!(Reader::new(&[0x03, 0x02, 0x01]).read_le_sized::<u32>(3), Ok(0x01_0203));
}

#[test]
fn sign_extends_shortened_signed_integers() {
    assert_eq!(Reader::new(&[0xFF, 0xFE]).read_be_sized::<i32>(2), Ok(-2));
    assert_eq!(Reader::new(&[0x7F, 0xFE]).read_be_sized::<i32>(2), Ok(0x7FFE));
    assert_eq!(Reader::new(&[0xFE, 0xFF]).read_le_sized::<i64>(2), Ok(-2));
    assert_eq!(Reader::new(&[0xFF, 0xFF]).read_be_sized::<u32>(2), Ok(0xFFFF));
}

#[test]
fn rejects_sized_lengths_outside_the_integer() {
    let bytes = [0u8; 16];
    assert_eq!(Reader::new(&bytes).read_be_sized::<u32>(0), Err(BytesError::InvalidLength { length: 0, maximum: 4 }));
    assert_eq!(Reader::new(&bytes).read_be_sized::<u32>(5), Err(BytesError::InvalidLength { length: 5, maximum: 4 }));
    assert_eq!(Reader::new(&bytes).read_le_sized::<u8>(2), Err(BytesError::InvalidLength { length: 2, maximum: 1 }));
    assert_eq!(Reader::new(&bytes).read_be_sized::<u128>(16), Ok(0));
}

#[test]
fn failed_reads_do_not_move_the_cursor() {
    let mut reader = Reader::new(&[1, 2, 3]);
    reader.read_u8().unwrap();
    assert_eq!(reader.read_be::<u32>(), Err(BytesError::UnexpectedEnd { needed: 4, remaining: 2 }));
    assert_eq!(reader.read_slice(3), Err(BytesError::UnexpectedEnd { needed: 3, remaining: 2 }));
    assert_eq!(reader.read_array::<3>(), Err(BytesError::UnexpectedEnd { needed: 3, remaining: 2 }));
    assert_eq!(reader.skip(3), Err(BytesError::UnexpectedEnd { needed: 3, remaining: 2 }));
    assert_eq!(reader.read_be_sized::<u32>(3), Err(BytesError::UnexpectedEnd { needed: 3, remaining: 2 }));
    assert!(reader.read_reader(3).is_err());
    assert_eq!(reader.position(), 1);
    assert_eq!(reader.remaining(), 2);
    assert_eq!(reader.read_be::<u16>(), Ok(0x0203));
    assert!(reader.is_empty());
    assert_eq!(reader.read_u8(), Err(BytesError::UnexpectedEnd { needed: 1, remaining: 0 }));
}

#[test]
fn slices_borrow_the_input_without_copying() {
    let bytes = [10, 20, 30, 40, 50];
    let mut reader = Reader::new(&bytes);
    let slice = reader.read_slice(2).unwrap();
    assert_eq!(slice, &[10, 20]);
    assert!(core::ptr::eq(slice.as_ptr(), bytes.as_ptr()));
    assert_eq!(reader.peek(2), Ok(&[30, 40][..]));
    assert_eq!(reader.position(), 2);
    assert_eq!(reader.read_array::<2>(), Ok([30, 40]));
    assert_eq!(reader.read_rest(), &[50]);
    assert_eq!(reader.read_rest(), &[] as &[u8]);
    assert!(reader.is_empty());
}

#[test]
fn nested_readers_cover_exactly_the_requested_bytes() {
    let mut reader = Reader::new(&[0x00, 0x02, 0xAB, 0xCD, 0xEF]);
    let length = reader.read_be::<u16>().unwrap() as usize;
    let mut inner = reader.read_reader(length).unwrap();
    assert_eq!(inner.remaining(), 2);
    assert_eq!(inner.read_be::<u16>(), Ok(0xABCD));
    assert!(inner.is_empty());
    assert_eq!(reader.read_u8(), Ok(0xEF));
}

#[test]
fn zero_length_operations_always_succeed() {
    let mut reader = Reader::new(&[]);
    assert_eq!(reader.read_slice(0), Ok(&[] as &[u8]));
    assert_eq!(reader.peek(0), Ok(&[] as &[u8]));
    assert_eq!(reader.skip(0), Ok(()));
    assert_eq!(reader.read_array::<0>(), Ok([]));
    assert!(reader.is_empty());
}

#[test]
fn errors_describe_themselves() {
    let error = BytesError::UnexpectedEnd { needed: 4, remaining: 2 };
    assert_eq!(error.to_string(), "unexpected end of input: needed 4 bytes, 2 remaining");
}
