use super::{BytesStatus, WriterStorage};
use crate::bytes::{Buffer, Writer};
use crate::ffi::{Buffer as FFIBuffer, I128, Pointer, Status, ToStatus, U128};

crate::ffi_functions! {
    const METHODS;

    /// Creates an empty buffer without a limit.
    pub unsafe extern "C" fn umilib_bytes_buffer_new(out: *mut *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Buffer::new()) })
    }

    /// Creates an empty buffer that never holds more than `limit` bytes.
    pub unsafe extern "C" fn umilib_bytes_buffer_with_limit(limit: usize, out: *mut *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Buffer::with_limit(limit)) })
    }

    /// Creates an empty buffer that can hold `capacity` bytes without reallocating.
    /// Fails with `CapacityExceeded` if the memory cannot be allocated.
    pub unsafe extern "C" fn umilib_bytes_buffer_with_capacity(capacity: usize, out: *mut *mut Buffer) -> *const Status {
        Status::from_result((|| {
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let buffer = Buffer::try_with_capacity(capacity).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer, checked to be non-null above.
            unsafe { Pointer::write_handle(out, buffer) }
        })())
    }

    /// Like `umilib_bytes_buffer_with_capacity`; both fail instead of aborting
    /// when the memory cannot be allocated.
    pub unsafe extern "C" fn umilib_bytes_buffer_try_with_capacity(capacity: usize, out: *mut *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        unsafe { umilib_bytes_buffer_with_capacity(capacity, out) }
    }

    /// Writes the number of bytes the buffer can hold without reallocating into `out`.
    pub unsafe extern "C" fn umilib_bytes_buffer_capacity(buffer: *const Buffer, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let buffer = unsafe { Pointer::reference(buffer) }?;
            unsafe { Pointer::write(out, buffer.capacity()) }
        })())
    }

    /// Releases a buffer. Does nothing if `buffer` is null.
    pub unsafe extern "C" fn umilib_bytes_buffer_free(buffer: *mut Buffer) {
        // SAFETY: the caller passes a handle created by this module.
        unsafe { Pointer::free(buffer) }
    }

    /// Writes whether the buffer has a limit into `out_has_limit` and the limit, if any, into `out_limit`.
    pub unsafe extern "C" fn umilib_bytes_buffer_limit(buffer: *const Buffer, out_has_limit: *mut bool, out_limit: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let buffer = unsafe { Pointer::reference(buffer) }?;
            if out_has_limit.is_null() || out_limit.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out_has_limit, buffer.limit().is_some()) }?;
            unsafe { Pointer::write(out_limit, buffer.limit().unwrap_or(0)) }
        })())
    }

    /// Sets the limit to `limit` if `has_limit` is true, or removes it.
    /// Fails if the buffer already holds more than the new limit.
    pub unsafe extern "C" fn umilib_bytes_buffer_set_limit(buffer: *mut Buffer, has_limit: bool, limit: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let buffer = unsafe { Pointer::reference_mut(buffer) }?;
            buffer.set_limit(has_limit.then_some(limit)).map_err(|error| error.to_status())
        })())
    }

    /// Writes the number of bytes written into `out`.
    pub unsafe extern "C" fn umilib_bytes_buffer_len(buffer: *const Buffer, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let buffer = unsafe { Pointer::reference(buffer) }?;
            unsafe { Pointer::write(out, buffer.len()) }
        })())
    }

    /// Writes whether nothing has been written into `out`.
    pub unsafe extern "C" fn umilib_bytes_buffer_is_empty(buffer: *const Buffer, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let buffer = unsafe { Pointer::reference(buffer) }?;
            unsafe { Pointer::write(out, buffer.is_empty()) }
        })())
    }

    /// Writes a pointer to the written bytes into `out_data` and their number into `out_length`.
    /// The pointer is valid until the buffer is next modified or released.
    pub unsafe extern "C" fn umilib_bytes_buffer_as_slice(buffer: *const Buffer, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let buffer = unsafe { Pointer::reference(buffer) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            unsafe { Pointer::write(out_data, buffer.as_slice().as_ptr()) }?;
            unsafe { Pointer::write(out_length, buffer.len()) }
        })())
    }

    /// Removes every byte, keeping the allocation and the limit.
    pub unsafe extern "C" fn umilib_bytes_buffer_clear(buffer: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(buffer) }?.clear();
            Ok(())
        })())
    }

    /// Shortens the buffer to `length` bytes. Does nothing if it is already shorter.
    pub unsafe extern "C" fn umilib_bytes_buffer_truncate(buffer: *mut Buffer, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(buffer) }?.truncate(length);
            Ok(())
        })())
    }

    /// Moves the written bytes into `out` and releases the buffer handle.
    /// On failure the handle is not released.
    pub unsafe extern "C" fn umilib_bytes_buffer_into_vec(buffer: *mut Buffer, out: *mut FFIBuffer) -> *const Status {
        if buffer.is_null() || out.is_null() {
            return &Status::NULL_POINTER;
        }
        // SAFETY: the caller passes a handle created by this module, which is not used afterwards.
        let buffer = unsafe { alloc::boxed::Box::from_raw(buffer) };
        // SAFETY: the caller passes a writable pointer, checked to be non-null above.
        Status::from_result(unsafe { Pointer::write(out, FFIBuffer::from_vec(buffer.into_vec())) })
    }
}

writer_functions! {
    Buffer;
    umilib_bytes_buffer_write, umilib_bytes_buffer_write_u8;
    u8 => u8: umilib_bytes_buffer_write_be_u8, umilib_bytes_buffer_write_le_u8, umilib_bytes_buffer_write_be_sized_u8, umilib_bytes_buffer_write_le_sized_u8;
    u16 => u16: umilib_bytes_buffer_write_be_u16, umilib_bytes_buffer_write_le_u16, umilib_bytes_buffer_write_be_sized_u16, umilib_bytes_buffer_write_le_sized_u16;
    u32 => u32: umilib_bytes_buffer_write_be_u32, umilib_bytes_buffer_write_le_u32, umilib_bytes_buffer_write_be_sized_u32, umilib_bytes_buffer_write_le_sized_u32;
    u64 => u64: umilib_bytes_buffer_write_be_u64, umilib_bytes_buffer_write_le_u64, umilib_bytes_buffer_write_be_sized_u64, umilib_bytes_buffer_write_le_sized_u64;
    u128 => U128: umilib_bytes_buffer_write_be_u128, umilib_bytes_buffer_write_le_u128, umilib_bytes_buffer_write_be_sized_u128, umilib_bytes_buffer_write_le_sized_u128;
    i8 => i8: umilib_bytes_buffer_write_be_i8, umilib_bytes_buffer_write_le_i8, umilib_bytes_buffer_write_be_sized_i8, umilib_bytes_buffer_write_le_sized_i8;
    i16 => i16: umilib_bytes_buffer_write_be_i16, umilib_bytes_buffer_write_le_i16, umilib_bytes_buffer_write_be_sized_i16, umilib_bytes_buffer_write_le_sized_i16;
    i32 => i32: umilib_bytes_buffer_write_be_i32, umilib_bytes_buffer_write_le_i32, umilib_bytes_buffer_write_be_sized_i32, umilib_bytes_buffer_write_le_sized_i32;
    i64 => i64: umilib_bytes_buffer_write_be_i64, umilib_bytes_buffer_write_le_i64, umilib_bytes_buffer_write_be_sized_i64, umilib_bytes_buffer_write_le_sized_i64;
    i128 => I128: umilib_bytes_buffer_write_be_i128, umilib_bytes_buffer_write_le_i128, umilib_bytes_buffer_write_be_sized_i128, umilib_bytes_buffer_write_le_sized_i128;
}

/// Every function exported for [`Buffer`].
pub const FUNCTIONS: &[crate::ffi::Function] =
    &crate::ffi::Function::concat::<{ METHODS.len() + WRITER.len() }>(&[METHODS, WRITER]);
