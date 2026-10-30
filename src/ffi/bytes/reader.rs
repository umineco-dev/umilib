use crate::bytes::Reader;
use crate::ffi::{I128, Pointer, Status, ToStatus, U128};

crate::ffi_functions! {
    const METHODS;

    /// Creates a reader over `length` bytes at `data`, which must stay valid
    /// and unchanged until the reader and every slice read from it are no longer used.
    pub unsafe extern "C" fn umilib_bytes_reader_new(data: *const u8, length: usize, out: *mut *mut Reader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller keeps `data` valid for the life of the reader.
            let bytes = unsafe { Pointer::slice(data, length) }?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, Reader::new(bytes)) }
        })())
    }

    /// Releases a reader. Does nothing if `reader` is null.
    pub unsafe extern "C" fn umilib_bytes_reader_free(reader: *mut Reader<'static>) {
        // SAFETY: the caller passes a handle from `umilib_bytes_reader_new` or `umilib_bytes_reader_read_reader`.
        unsafe { Pointer::free(reader) }
    }

    /// Writes the number of bytes already read into `out`.
    pub unsafe extern "C" fn umilib_bytes_reader_position(reader: *const Reader<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write(out, reader.position()) }
        })())
    }

    /// Writes the number of bytes left to read into `out`.
    pub unsafe extern "C" fn umilib_bytes_reader_remaining(reader: *const Reader<'static>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write(out, reader.remaining()) }
        })())
    }

    /// Writes whether every byte has been read into `out`.
    pub unsafe extern "C" fn umilib_bytes_reader_is_empty(reader: *const Reader<'static>, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            unsafe { Pointer::write(out, reader.is_empty()) }
        })())
    }

    /// Writes a pointer to the next `length` bytes into `out` without consuming them.
    pub unsafe extern "C" fn umilib_bytes_reader_peek(reader: *const Reader<'static>, length: usize, out: *mut *const u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference(reader) }?;
            let slice = reader.peek(length).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, slice.as_ptr()) }
        })())
    }

    /// Consumes the next `length` bytes and writes a pointer to them into `out`.
    pub unsafe extern "C" fn umilib_bytes_reader_read_slice(reader: *mut Reader<'static>, length: usize, out: *mut *const u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let slice = reader.read_slice(length).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, slice.as_ptr()) }
        })())
    }

    /// Consumes the next `length` bytes and copies them to `out`, which has room for `length` bytes.
    pub unsafe extern "C" fn umilib_bytes_reader_read_array(reader: *mut Reader<'static>, length: usize, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and `length` writable bytes.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            let out = unsafe { Pointer::slice_mut(out, length) }?;
            let mut copy = *reader;
            out.copy_from_slice(copy.read_slice(length).map_err(|error| error.to_status())?);
            *reader = copy;
            Ok(())
        })())
    }

    /// Consumes the next `length` bytes and writes a new reader over them into `out`.
    pub unsafe extern "C" fn umilib_bytes_reader_read_reader(reader: *mut Reader<'static>, length: usize, out: *mut *mut Reader<'static>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let child = reader.read_reader(length).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, child) }
        })())
    }

    /// Consumes every remaining byte and writes a pointer to them into `out_data` and their number into `out_length`.
    pub unsafe extern "C" fn umilib_bytes_reader_read_rest(reader: *mut Reader<'static>, out_data: *mut *const u8, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out_data.is_null() || out_length.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let rest = reader.read_rest();
            unsafe { Pointer::write(out_data, rest.as_ptr()) }?;
            unsafe { Pointer::write(out_length, rest.len()) }
        })())
    }

    /// Consumes `length` bytes.
    pub unsafe extern "C" fn umilib_bytes_reader_skip(reader: *mut Reader<'static>, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            reader.skip(length).map_err(|error| error.to_status())
        })())
    }

    /// Consumes one byte and writes it into `out`.
    pub unsafe extern "C" fn umilib_bytes_reader_read_u8(reader: *mut Reader<'static>, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reader = unsafe { Pointer::reference_mut(reader) }?;
            if out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let value = reader.read_u8().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, value) }
        })())
    }
}

/// Defines the integer reading functions of [`Reader`] for each integer type.
macro_rules! reader_integers {
    ($($rust:ty => $c:ty: $be:ident, $le:ident, $be_sized:ident, $le_sized:ident;)*) => {
        crate::ffi_functions! {
            const INTEGERS;
            $(
                /// Consumes a big-endian integer of the full size of the type and writes it into `out`.
                pub unsafe extern "C" fn $be(reader: *mut Reader<'static>, out: *mut $c) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle and a writable pointer.
                        let reader = unsafe { Pointer::reference_mut(reader) }?;
                        if out.is_null() {
                            return Err(&Status::NULL_POINTER);
                        }
                        let value = reader.read_be::<$rust>().map_err(|error| error.to_status())?;
                        unsafe { Pointer::write(out, <$c>::from(value)) }
                    })())
                }

                /// Consumes a little-endian integer of the full size of the type and writes it into `out`.
                pub unsafe extern "C" fn $le(reader: *mut Reader<'static>, out: *mut $c) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle and a writable pointer.
                        let reader = unsafe { Pointer::reference_mut(reader) }?;
                        if out.is_null() {
                            return Err(&Status::NULL_POINTER);
                        }
                        let value = reader.read_le::<$rust>().map_err(|error| error.to_status())?;
                        unsafe { Pointer::write(out, <$c>::from(value)) }
                    })())
                }

                /// Consumes a big-endian integer encoded in `length` bytes and writes it into `out`.
                /// Signed integers are sign-extended.
                pub unsafe extern "C" fn $be_sized(reader: *mut Reader<'static>, length: usize, out: *mut $c) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle and a writable pointer.
                        let reader = unsafe { Pointer::reference_mut(reader) }?;
                        if out.is_null() {
                            return Err(&Status::NULL_POINTER);
                        }
                        let value = reader.read_be_sized::<$rust>(length).map_err(|error| error.to_status())?;
                        unsafe { Pointer::write(out, <$c>::from(value)) }
                    })())
                }

                /// Consumes a little-endian integer encoded in `length` bytes and writes it into `out`.
                /// Signed integers are sign-extended.
                pub unsafe extern "C" fn $le_sized(reader: *mut Reader<'static>, length: usize, out: *mut $c) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle and a writable pointer.
                        let reader = unsafe { Pointer::reference_mut(reader) }?;
                        if out.is_null() {
                            return Err(&Status::NULL_POINTER);
                        }
                        let value = reader.read_le_sized::<$rust>(length).map_err(|error| error.to_status())?;
                        unsafe { Pointer::write(out, <$c>::from(value)) }
                    })())
                }
            )*
        }
    };
}

reader_integers! {
    u8 => u8: umilib_bytes_reader_read_be_u8, umilib_bytes_reader_read_le_u8, umilib_bytes_reader_read_be_sized_u8, umilib_bytes_reader_read_le_sized_u8;
    u16 => u16: umilib_bytes_reader_read_be_u16, umilib_bytes_reader_read_le_u16, umilib_bytes_reader_read_be_sized_u16, umilib_bytes_reader_read_le_sized_u16;
    u32 => u32: umilib_bytes_reader_read_be_u32, umilib_bytes_reader_read_le_u32, umilib_bytes_reader_read_be_sized_u32, umilib_bytes_reader_read_le_sized_u32;
    u64 => u64: umilib_bytes_reader_read_be_u64, umilib_bytes_reader_read_le_u64, umilib_bytes_reader_read_be_sized_u64, umilib_bytes_reader_read_le_sized_u64;
    u128 => U128: umilib_bytes_reader_read_be_u128, umilib_bytes_reader_read_le_u128, umilib_bytes_reader_read_be_sized_u128, umilib_bytes_reader_read_le_sized_u128;
    i8 => i8: umilib_bytes_reader_read_be_i8, umilib_bytes_reader_read_le_i8, umilib_bytes_reader_read_be_sized_i8, umilib_bytes_reader_read_le_sized_i8;
    i16 => i16: umilib_bytes_reader_read_be_i16, umilib_bytes_reader_read_le_i16, umilib_bytes_reader_read_be_sized_i16, umilib_bytes_reader_read_le_sized_i16;
    i32 => i32: umilib_bytes_reader_read_be_i32, umilib_bytes_reader_read_le_i32, umilib_bytes_reader_read_be_sized_i32, umilib_bytes_reader_read_le_sized_i32;
    i64 => i64: umilib_bytes_reader_read_be_i64, umilib_bytes_reader_read_le_i64, umilib_bytes_reader_read_be_sized_i64, umilib_bytes_reader_read_le_sized_i64;
    i128 => I128: umilib_bytes_reader_read_be_i128, umilib_bytes_reader_read_le_i128, umilib_bytes_reader_read_be_sized_i128, umilib_bytes_reader_read_le_sized_i128;
}

/// Every function exported for [`Reader`].
pub const FUNCTIONS: &[crate::ffi::Function] =
    &crate::ffi::Function::concat::<{ METHODS.len() + INTEGERS.len() }>(&[METHODS, INTEGERS]);
