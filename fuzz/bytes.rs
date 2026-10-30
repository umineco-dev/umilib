//! Fuzz targets of `umilib::bytes`.

use umilib::bytes::{Buffer, BytesError, Reader, SliceWriter, Writer};
use umilib::platform::fuzz::{FuzzFunction, FuzzTarget};

/// Applies the operations encoded in the input to a reader over the input and
/// checks that the cursor stays consistent and failures change nothing.
pub const READER: FuzzFunction<fn(&[u8])> = FuzzFunction::new("bytes-reader", |data| {
    let mut reader = Reader::new(data);
    let mut operations = data.iter().copied();
    while let Some(operation) = operations.next() {
        let before = reader;
        let length = operations.next().unwrap_or(0) as usize % 20;
        let result: Result<(), BytesError> = match operation % 9 {
            0 => reader.read_slice(length).map(|slice| assert_eq!(slice.len(), length)),
            1 => reader.read_be::<u32>().map(drop),
            2 => reader.read_le::<i64>().map(drop),
            3 => reader.read_be_sized::<u64>(length).map(drop),
            4 => reader.read_le_sized::<i16>(length).map(drop),
            5 => reader.skip(length),
            6 => reader.read_reader(length).map(|inner| assert_eq!(inner.remaining(), length)),
            7 => reader.peek(length).map(drop),
            _ => reader.read_u8().map(drop),
        };
        assert_eq!(reader.position() + reader.remaining(), data.len());
        if result.is_err() {
            assert_eq!(reader, before, "a failed read must not move the cursor");
        }
    }
});

/// Writes the integers encoded in the input with sized writes and checks that
/// sized reads return the same values, through both writers.
pub const WRITER: FuzzFunction<fn(&[u8])> = FuzzFunction::new("bytes-writer", |data| {
    let mut source = Reader::new(data);
    let limit = source.read_u8().unwrap_or(0) as usize;
    let mut buffer = Buffer::with_limit(limit);
    let mut storage = vec![0u8; limit];
    let mut slice = SliceWriter::new(&mut storage);
    let mut written = Vec::new();
    while let (Ok(value), Ok(length)) = (source.read_be::<i64>(), source.read_u8()) {
        let length = 1 + length as usize % 8;
        let result = buffer.write_be_sized(value, length);
        assert_eq!(result, slice.write_be_sized(value, length), "both writers must agree");
        if result.is_ok() {
            written.push((value, length));
        }
    }
    assert_eq!(buffer.as_slice(), slice.written());
    assert!(buffer.len() <= limit);
    let mut reader = Reader::new(buffer.as_slice());
    for (value, length) in written {
        assert_eq!(reader.read_be_sized::<i64>(length), Ok(value));
    }
    assert!(reader.is_empty());
});

pub const TARGETS: &[&dyn FuzzTarget] = &[&READER, &WRITER];
