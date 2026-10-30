use crate::bytes::LineBuffer;
use crate::ffi::{Buffer, Pointer, Status, ToStatus};

crate::ffi_functions! {

    /// Creates an empty line buffer.
    pub unsafe extern "C" fn umilib_bytes_line_buffer_new(out: *mut *mut LineBuffer) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, LineBuffer::new()) })
    }

    /// Appends the `length` bytes at `data`.
    pub unsafe extern "C" fn umilib_bytes_line_buffer_push(buffer: *mut LineBuffer, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let buffer = unsafe { Pointer::reference_mut(buffer) }?;
            buffer.push(unsafe { Pointer::slice(data, length) }?);
            Ok(())
        })())
    }

    /// Writes the number of bytes not yet read into `out`.
    pub unsafe extern "C" fn umilib_bytes_line_buffer_len(buffer: *const LineBuffer, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let buffer = unsafe { Pointer::reference(buffer) }?;
            unsafe { Pointer::write(out, buffer.len()) }
        })())
    }

    /// Writes a copy of the bytes not yet read into `out`.
    pub unsafe extern "C" fn umilib_bytes_line_buffer_unread(buffer: *const LineBuffer, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let buffer = unsafe { Pointer::reference(buffer) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(buffer.unread().to_vec())) }
        })())
    }

    /// Skips up to `count` bytes.
    pub unsafe extern "C" fn umilib_bytes_line_buffer_consume(buffer: *mut LineBuffer, count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(buffer) }?.consume(count);
            Ok(())
        })())
    }

    /// Writes up to `count` bytes, read, into `out`.
    pub unsafe extern "C" fn umilib_bytes_line_buffer_take(buffer: *mut LineBuffer, count: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let buffer = unsafe { Pointer::reference_mut(buffer) }?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write(out, Buffer::from_vec(buffer.take(count))) }
        })())
    }

    /// Discards every byte not yet read.
    pub unsafe extern "C" fn umilib_bytes_line_buffer_clear(buffer: *mut LineBuffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(buffer) }?.clear();
            Ok(())
        })())
    }

    /// Writes whether a whole line is here into `out_found` and the line, its CRLF removed, into
    /// `out`. A line of more than `maximum` bytes, its CRLF counted, fails once with LineTooLong.
    pub unsafe extern "C" fn umilib_bytes_line_buffer_line(buffer: *mut LineBuffer, maximum: usize, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let buffer = unsafe { Pointer::reference_mut(buffer) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let line = buffer.line(maximum).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_found, line.is_some()) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(line.unwrap_or_default())) }
        })())
    }

    /// Releases a line buffer. Does nothing if `buffer` is null.
    pub unsafe extern "C" fn umilib_bytes_line_buffer_free(buffer: *mut LineBuffer) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(buffer) }
    }
}
