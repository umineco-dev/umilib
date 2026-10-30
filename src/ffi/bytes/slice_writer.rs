use super::{BytesStatus, WriterStorage};
use crate::bytes::{SliceWriter, Writer};
use crate::ffi::{I128, Pointer, Status, ToStatus, U128};

crate::ffi_functions! {
    const METHODS;

    /// Creates a writer that fills `length` bytes at `data` from the start.
    /// The bytes must stay valid until the writer is released.
    pub unsafe extern "C" fn umilib_bytes_slice_writer_new(data: *mut u8, length: usize, out: *mut *mut SliceWriter<'static>) -> *const Status {
        Status::from_result((|| {
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: the caller keeps `data` valid and unaliased for the life of the writer.
            let bytes = unsafe { Pointer::slice_mut(data, length) }?;
            // SAFETY: the caller passes a writable pointer, checked to be non-null above.
            unsafe { Pointer::write_handle(out, SliceWriter::new(bytes)) }
        })())
    }

    /// Releases a writer. Does nothing if `writer` is null.
    pub unsafe extern "C" fn umilib_bytes_slice_writer_free(writer: *mut SliceWriter<'static>) {
        // SAFETY: the caller passes a handle from `umilib_bytes_slice_writer_new`.
        unsafe { Pointer::free(writer) }
    }

    /// Writes the number of bytes written into `out`.
    pub unsafe extern "C" fn umilib_bytes_slice_writer_position(writer: *const SliceWriter<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let writer = unsafe { Pointer::reference(writer) }?;
            unsafe { Pointer::write(out, writer.position()) }
        })())
    }

    /// Writes the length of the whole slice into `out`.
    pub unsafe extern "C" fn umilib_bytes_slice_writer_capacity(writer: *const SliceWriter<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let writer = unsafe { Pointer::reference(writer) }?;
            unsafe { Pointer::write(out, writer.capacity()) }
        })())
    }

    /// Writes the number of bytes that can still be written into `out`.
    pub unsafe extern "C" fn umilib_bytes_slice_writer_remaining(writer: *const SliceWriter<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let writer = unsafe { Pointer::reference(writer) }?;
            unsafe { Pointer::write(out, writer.remaining()) }
        })())
    }

    /// Writes a pointer to the written bytes into `out_data` and their number into `out_length`.
    pub unsafe extern "C" fn umilib_bytes_slice_writer_written(writer: *const SliceWriter<'static>, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let writer = unsafe { Pointer::reference(writer) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out_data, writer.written().as_ptr()) }?;
            unsafe { Pointer::write(out_length, writer.position()) }
        })())
    }

    /// Writes the number of bytes written into `out` and releases the writer handle.
    /// On failure the handle is not released.
    pub unsafe extern "C" fn umilib_bytes_slice_writer_into_written(writer: *mut SliceWriter<'static>, out: *mut usize) -> *const Status {
        if writer.is_null() || out.is_null() {
            return &Status::NULL_POINTER;
        }
        // SAFETY: the caller passes a handle from `umilib_bytes_slice_writer_new`, which is not used afterwards.
        let writer = unsafe { alloc::boxed::Box::from_raw(writer) };
        // SAFETY: the caller passes a writable pointer, checked to be non-null above.
        Status::from_result(unsafe { Pointer::write(out, writer.into_written().len()) })
    }
}

writer_functions! {
    SliceWriter<'static>;
    umilib_bytes_slice_writer_write, umilib_bytes_slice_writer_write_u8;
    u8 => u8: umilib_bytes_slice_writer_write_be_u8, umilib_bytes_slice_writer_write_le_u8, umilib_bytes_slice_writer_write_be_sized_u8, umilib_bytes_slice_writer_write_le_sized_u8;
    u16 => u16: umilib_bytes_slice_writer_write_be_u16, umilib_bytes_slice_writer_write_le_u16, umilib_bytes_slice_writer_write_be_sized_u16, umilib_bytes_slice_writer_write_le_sized_u16;
    u32 => u32: umilib_bytes_slice_writer_write_be_u32, umilib_bytes_slice_writer_write_le_u32, umilib_bytes_slice_writer_write_be_sized_u32, umilib_bytes_slice_writer_write_le_sized_u32;
    u64 => u64: umilib_bytes_slice_writer_write_be_u64, umilib_bytes_slice_writer_write_le_u64, umilib_bytes_slice_writer_write_be_sized_u64, umilib_bytes_slice_writer_write_le_sized_u64;
    u128 => U128: umilib_bytes_slice_writer_write_be_u128, umilib_bytes_slice_writer_write_le_u128, umilib_bytes_slice_writer_write_be_sized_u128, umilib_bytes_slice_writer_write_le_sized_u128;
    i8 => i8: umilib_bytes_slice_writer_write_be_i8, umilib_bytes_slice_writer_write_le_i8, umilib_bytes_slice_writer_write_be_sized_i8, umilib_bytes_slice_writer_write_le_sized_i8;
    i16 => i16: umilib_bytes_slice_writer_write_be_i16, umilib_bytes_slice_writer_write_le_i16, umilib_bytes_slice_writer_write_be_sized_i16, umilib_bytes_slice_writer_write_le_sized_i16;
    i32 => i32: umilib_bytes_slice_writer_write_be_i32, umilib_bytes_slice_writer_write_le_i32, umilib_bytes_slice_writer_write_be_sized_i32, umilib_bytes_slice_writer_write_le_sized_i32;
    i64 => i64: umilib_bytes_slice_writer_write_be_i64, umilib_bytes_slice_writer_write_le_i64, umilib_bytes_slice_writer_write_be_sized_i64, umilib_bytes_slice_writer_write_le_sized_i64;
    i128 => I128: umilib_bytes_slice_writer_write_be_i128, umilib_bytes_slice_writer_write_le_i128, umilib_bytes_slice_writer_write_be_sized_i128, umilib_bytes_slice_writer_write_le_sized_i128;
}

/// Every function exported for [`SliceWriter`].
pub const FUNCTIONS: &[crate::ffi::Function] =
    &crate::ffi::Function::concat::<{ METHODS.len() + WRITER.len() }>(&[METHODS, WRITER]);
