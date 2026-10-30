use umilib::bytes::{BytesError, SliceWriter, Writer};

#[test]
fn fills_the_slice_from_the_start() {
    let mut storage = [0u8; 6];
    let mut writer = SliceWriter::new(&mut storage);
    writer.write_be(0x0102u16).unwrap();
    writer.write_le(0x0304u16).unwrap();
    assert_eq!(writer.position(), 4);
    assert_eq!(writer.remaining(), 2);
    assert_eq!(writer.written(), &[1, 2, 4, 3]);
    assert_eq!(writer.into_written(), &mut [1, 2, 4, 3]);
    assert_eq!(storage, [1, 2, 4, 3, 0, 0]);
}

#[test]
fn refuses_writes_that_do_not_fit_and_changes_nothing() {
    let mut storage = [0u8; 3];
    let mut writer = SliceWriter::new(&mut storage);
    writer.write_u8(7).unwrap();
    assert_eq!(writer.write_be(1u32), Err(BytesError::CapacityExceeded { requested: 4, limit: 3 }));
    assert_eq!(writer.write(&[1, 2, 3]), Err(BytesError::CapacityExceeded { requested: 3, limit: 3 }));
    assert_eq!(writer.position(), 1);
    writer.write(&[8, 9]).unwrap();
    assert_eq!(writer.remaining(), 0);
    assert_eq!(storage, [7, 8, 9]);
}

#[test]
fn capacity_is_the_whole_slice() {
    let mut storage = [0u8; 5];
    let mut writer = SliceWriter::new(&mut storage);
    writer.write_u8(1).unwrap();
    assert_eq!((writer.capacity(), writer.remaining()), (5, 4));
}
