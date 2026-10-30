use std::ptr;

use umilib::bytes::{Buffer, Reader, SliceWriter};
use umilib::ffi::Buffer as FFIBuffer;
use umilib::ffi::U128;
use umilib::ffi::bytes::{buffer::*, reader::*, slice_writer::*};

use super::Check;

#[test]
fn reader_reads_like_the_rust_api() {
    let data = [0x00, 0x02, 0xAB, 0xCD, 0x01, 0x02, 0x03, 0xFF, 0xFE];
    let mut reader: *mut Reader<'static> = ptr::null_mut();
    unsafe {
        Check::ok(umilib_bytes_reader_new(data.as_ptr(), data.len(), &mut reader));
        let mut length = 0u16;
        Check::ok(umilib_bytes_reader_read_be_u16(reader, &mut length));
        assert_eq!(length, 2);
        let mut inner: *mut Reader<'static> = ptr::null_mut();
        Check::ok(umilib_bytes_reader_read_reader(reader, length as usize, &mut inner));
        let mut value = 0u16;
        Check::ok(umilib_bytes_reader_read_le_u16(inner, &mut value));
        assert_eq!(value, 0xCDAB);
        let mut empty = false;
        Check::ok(umilib_bytes_reader_is_empty(inner, &mut empty));
        assert!(empty);
        umilib_bytes_reader_free(inner);

        let mut sized = 0u32;
        Check::ok(umilib_bytes_reader_read_be_sized_u32(reader, 3, &mut sized));
        assert_eq!(sized, 0x01_0203);
        let mut signed = 0i32;
        Check::ok(umilib_bytes_reader_read_be_sized_i32(reader, 2, &mut signed));
        assert_eq!(signed, -2);

        let mut position = 0usize;
        Check::ok(umilib_bytes_reader_position(reader, &mut position));
        assert_eq!(position, data.len());
        let mut byte = 0u8;
        Check::fails(umilib_bytes_reader_read_u8(reader, &mut byte), "bytes", "UnexpectedEnd");
        Check::fails(umilib_bytes_reader_read_be_sized_u32(reader, 5, &mut sized), "bytes", "InvalidLength");
        Check::fails(umilib_bytes_reader_read_u8(reader, ptr::null_mut()), "ffi", "NullPointer");
        umilib_bytes_reader_free(reader);
    }
}

#[test]
fn reader_slices_point_into_the_caller_memory() {
    let data = [1u8, 2, 3, 4, 5];
    let mut reader: *mut Reader<'static> = ptr::null_mut();
    unsafe {
        Check::ok(umilib_bytes_reader_new(data.as_ptr(), data.len(), &mut reader));
        let mut slice: *const u8 = ptr::null();
        Check::ok(umilib_bytes_reader_peek(reader, 2, &mut slice));
        assert_eq!(slice, data.as_ptr());
        Check::ok(umilib_bytes_reader_read_slice(reader, 2, &mut slice));
        assert_eq!(slice, data.as_ptr());
        // A null output must not consume input.
        Check::fails(umilib_bytes_reader_read_slice(reader, 1, ptr::null_mut()), "ffi", "NullPointer");
        let mut copy = [0u8; 2];
        Check::ok(umilib_bytes_reader_read_array(reader, 2, copy.as_mut_ptr()));
        assert_eq!(copy, [3, 4]);
        Check::fails(umilib_bytes_reader_read_array(reader, 2, copy.as_mut_ptr()), "bytes", "UnexpectedEnd");
        let mut remaining = 0usize;
        Check::ok(umilib_bytes_reader_remaining(reader, &mut remaining));
        assert_eq!(remaining, 1);
        let mut length = 0usize;
        Check::ok(umilib_bytes_reader_read_rest(reader, &mut slice, &mut length));
        assert_eq!((slice, length), (data.as_ptr().add(4), 1));
        Check::ok(umilib_bytes_reader_skip(reader, 0));
        Check::fails(umilib_bytes_reader_skip(reader, 1), "bytes", "UnexpectedEnd");
        umilib_bytes_reader_free(reader);
        umilib_bytes_reader_free(ptr::null_mut());
    }
}

#[test]
fn reader_accepts_empty_input_without_a_pointer() {
    let mut reader: *mut Reader<'static> = ptr::null_mut();
    unsafe {
        Check::ok(umilib_bytes_reader_new(ptr::null(), 0, &mut reader));
        let mut empty = false;
        Check::ok(umilib_bytes_reader_is_empty(reader, &mut empty));
        assert!(empty);
        umilib_bytes_reader_free(reader);
        Check::fails(umilib_bytes_reader_new(ptr::null(), 1, &mut reader), "ffi", "NullPointer");
        Check::fails(umilib_bytes_reader_new(ptr::null(), 0, ptr::null_mut()), "ffi", "NullPointer");
    }
}

#[test]
fn buffer_writes_like_the_rust_api() {
    let mut buffer: *mut Buffer = ptr::null_mut();
    unsafe {
        Check::ok(umilib_bytes_buffer_with_limit(6, &mut buffer));
        Check::ok(umilib_bytes_buffer_write_be_u16(buffer, 0x0102));
        Check::ok(umilib_bytes_buffer_write_le_sized_u32(buffer, 0x0304, 2));
        Check::fails(umilib_bytes_buffer_write_be_sized_u32(buffer, 0x1_0000, 2), "bytes", "ValueTooLarge");
        Check::ok(umilib_bytes_buffer_write(buffer, [5u8].as_ptr(), 1));
        Check::fails(umilib_bytes_buffer_write_be_u16(buffer, 0), "bytes", "CapacityExceeded");
        Check::ok(umilib_bytes_buffer_write_u8(buffer, 6));

        let (mut has_limit, mut limit) = (false, 0usize);
        Check::ok(umilib_bytes_buffer_limit(buffer, &mut has_limit, &mut limit));
        assert_eq!((has_limit, limit), (true, 6));
        Check::fails(umilib_bytes_buffer_set_limit(buffer, true, 5), "bytes", "CapacityExceeded");
        Check::ok(umilib_bytes_buffer_set_limit(buffer, false, 0));
        Check::ok(umilib_bytes_buffer_write_be_u128(buffer, U128 { high: 0, low: 7 }));

        let (mut data, mut length): (*const u8, usize) = (ptr::null(), 0);
        Check::ok(umilib_bytes_buffer_as_slice(buffer, &mut data, &mut length));
        let mut expected = vec![1, 2, 4, 3, 5, 6];
        expected.extend_from_slice(&7u128.to_be_bytes());
        assert_eq!(std::slice::from_raw_parts(data, length), expected.as_slice());

        Check::ok(umilib_bytes_buffer_truncate(buffer, 3));
        let mut size = 0usize;
        Check::ok(umilib_bytes_buffer_len(buffer, &mut size));
        assert_eq!(size, 3);
        let mut vector = FFIBuffer::EMPTY;
        Check::ok(umilib_bytes_buffer_into_vec(buffer, &mut vector));
        assert_eq!(vector.as_slice(), &[1, 2, 4]);
        umilib::ffi::umilib_ffi_buffer_free(&mut vector);

        Check::ok(umilib_bytes_buffer_new(&mut buffer));
        Check::ok(umilib_bytes_buffer_clear(buffer));
        let mut empty = false;
        Check::ok(umilib_bytes_buffer_is_empty(buffer, &mut empty));
        assert!(empty);
        umilib_bytes_buffer_free(buffer);
        Check::ok(umilib_bytes_buffer_with_capacity(8, &mut buffer));
        umilib_bytes_buffer_free(buffer);
    }
}

#[test]
fn slice_writer_fills_the_caller_memory() {
    let mut storage = [0u8; 4];
    // The writer borrows the storage mutably: only this pointer may be used until it is released.
    let base = storage.as_mut_ptr();
    let mut writer: *mut SliceWriter<'static> = ptr::null_mut();
    unsafe {
        Check::ok(umilib_bytes_slice_writer_new(base, 4, &mut writer));
        Check::ok(umilib_bytes_slice_writer_write_le_i16(writer, -2));
        Check::fails(umilib_bytes_slice_writer_write_be_u32(writer, 1), "bytes", "CapacityExceeded");
        let mut remaining = 0usize;
        Check::ok(umilib_bytes_slice_writer_remaining(writer, &mut remaining));
        assert_eq!(remaining, 2);
        let (mut data, mut length): (*const u8, usize) = (ptr::null(), 0);
        Check::ok(umilib_bytes_slice_writer_written(writer, &mut data, &mut length));
        assert_eq!((data, length), (base.cast_const(), 2));
        let mut written = 0usize;
        Check::ok(umilib_bytes_slice_writer_into_written(writer, &mut written));
        assert_eq!(written, 2);
    }
    assert_eq!(storage, [0xFE, 0xFF, 0, 0]);
}

#[test]
fn buffer_accepts_its_own_contents_as_input() {
    let mut buffer: *mut Buffer = ptr::null_mut();
    unsafe {
        Check::ok(umilib_bytes_buffer_with_capacity(4, &mut buffer));
        Check::ok(umilib_bytes_buffer_write(buffer, [1u8, 2, 3, 4].as_ptr(), 4));
        let (mut data, mut length): (*const u8, usize) = (ptr::null(), 0);
        Check::ok(umilib_bytes_buffer_as_slice(buffer, &mut data, &mut length));
        // Appending the buffer to itself reallocates; the input must be read first.
        Check::ok(umilib_bytes_buffer_write(buffer, data, length));
        Check::ok(umilib_bytes_buffer_as_slice(buffer, &mut data, &mut length));
        assert_eq!(std::slice::from_raw_parts(data, length), &[1, 2, 3, 4, 1, 2, 3, 4]);
        umilib_bytes_buffer_free(buffer);
    }
}

#[test]
fn slice_writer_accepts_its_own_storage_as_input() {
    let mut storage = [1u8, 2, 3, 4, 0, 0, 0, 0];
    let base = storage.as_mut_ptr();
    let mut writer: *mut SliceWriter<'static> = ptr::null_mut();
    unsafe {
        Check::ok(umilib_bytes_slice_writer_new(base, 8, &mut writer));
        Check::ok(umilib_bytes_slice_writer_write(writer, base, 4));
        Check::ok(umilib_bytes_slice_writer_write(writer, base.add(2), 4));
        umilib_bytes_slice_writer_free(writer);
    }
    // The second input, bytes 2 to 6, is [3, 4, 0, 0] when it is read.
    assert_eq!(storage, [1, 2, 3, 4, 3, 4, 0, 0]);
}

#[test]
fn impossible_allocations_fail_instead_of_aborting() {
    let mut buffer: *mut Buffer = ptr::null_mut();
    unsafe {
        Check::fails(umilib_bytes_buffer_with_capacity(usize::MAX, &mut buffer), "bytes", "CapacityExceeded");
        assert!(buffer.is_null());
    }
}
