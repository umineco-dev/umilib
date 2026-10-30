//! The C ABI of [`crate::bytes`].
//!
//! Integer methods are exported once per integer type, with the type name as
//! a suffix: `Reader::read_be::<u32>` is `umilib_bytes_reader_read_be_u32`.
//! 128-bit integers use [`U128`](crate::ffi::U128) and [`I128`](crate::ffi::I128).

/// Defines the methods of [`Writer`](crate::bytes::Writer) for one implementor.
macro_rules! writer_functions {
    (
        $handle:ty;
        $write:ident, $write_u8:ident;
        $($rust:ty => $c:ty: $be:ident, $le:ident, $be_sized:ident, $le_sized:ident;)*
    ) => {
        crate::ffi_functions! {
            const WRITER;

            /// Appends `length` bytes at `data`. `data` may point into the writer's own storage.
            pub unsafe extern "C" fn $write(writer: *mut $handle, data: *const u8, length: usize) -> *const Status {
                Status::from_result((|| {
                    Pointer::check_range(data, length)?;
                    // SAFETY: the caller passes a valid handle.
                    let (readable, capacity) = unsafe { Pointer::reference(writer) }?.storage();
                    let (start, address) = (readable.as_ptr() as usize, data as usize);
                    let copy;
                    let bytes = if Pointer::overlaps(data, length, readable.as_ptr(), capacity) {
                        // Input from the writer's own storage is read through the
                        // writer, never through the caller's pointer (which would
                        // invalidate the writer's exclusive borrow), and copied
                        // first, because writing may reallocate or overwrite it.
                        let offset = address.wrapping_sub(start);
                        let source = readable.get(offset..offset.saturating_add(length)).filter(|_| address >= start);
                        let source = source.ok_or(&Status::INVALID_ARGUMENT)?;
                        let mut owned = alloc::vec::Vec::new();
                        owned.try_reserve_exact(length).map_err(|_| &BytesStatus::CAPACITY_EXCEEDED)?;
                        owned.extend_from_slice(source);
                        copy = owned;
                        copy.as_slice()
                    } else {
                        // SAFETY: the caller passes `length` readable bytes outside the writer.
                        unsafe { Pointer::slice(data, length) }?
                    };
                    let writer = unsafe { Pointer::reference_mut(writer) }?;
                    writer.write(bytes).map_err(|error| error.to_status())
                })())
            }

            /// Appends one byte.
            pub unsafe extern "C" fn $write_u8(writer: *mut $handle, value: u8) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle.
                    let writer = unsafe { Pointer::reference_mut(writer) }?;
                    writer.write_u8(value).map_err(|error| error.to_status())
                })())
            }

            $(
                /// Appends `value` as big-endian bytes of the full size of the type.
                pub unsafe extern "C" fn $be(writer: *mut $handle, value: $c) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle.
                        let writer = unsafe { Pointer::reference_mut(writer) }?;
                        writer.write_be(<$rust>::from(value)).map_err(|error| error.to_status())
                    })())
                }

                /// Appends `value` as little-endian bytes of the full size of the type.
                pub unsafe extern "C" fn $le(writer: *mut $handle, value: $c) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle.
                        let writer = unsafe { Pointer::reference_mut(writer) }?;
                        writer.write_le(<$rust>::from(value)).map_err(|error| error.to_status())
                    })())
                }

                /// Appends `value` as `length` big-endian bytes; fails if it does not fit.
                pub unsafe extern "C" fn $be_sized(writer: *mut $handle, value: $c, length: usize) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle.
                        let writer = unsafe { Pointer::reference_mut(writer) }?;
                        writer.write_be_sized(<$rust>::from(value), length).map_err(|error| error.to_status())
                    })())
                }

                /// Appends `value` as `length` little-endian bytes; fails if it does not fit.
                pub unsafe extern "C" fn $le_sized(writer: *mut $handle, value: $c, length: usize) -> *const Status {
                    Status::from_result((|| {
                        // SAFETY: the caller passes a valid handle.
                        let writer = unsafe { Pointer::reference_mut(writer) }?;
                        writer.write_le_sized(<$rust>::from(value), length).map_err(|error| error.to_status())
                    })())
                }
            )*
        }
    };
}

pub mod buffer;
pub mod line_buffer;
pub mod reader;
pub mod slice_writer;

use crate::bytes::{BitOrder, Buffer, BytesError, LineBuffer, Reader, SliceWriter};
use crate::ffi::{Definition, Function, Module, Status, ToStatus, Type, Value};

impl Value for Reader<'static> {
    const TYPE: Type = Type::Named("umilib_bytes_Reader");
}

impl Value for Buffer {
    const TYPE: Type = Type::Named("umilib_bytes_Buffer");
}

impl Value for LineBuffer {
    const TYPE: Type = Type::Named("umilib_bytes_LineBuffer");
}

impl Value for SliceWriter<'static> {
    const TYPE: Type = Type::Named("umilib_bytes_SliceWriter");
}

/// A writer whose storage can be located in memory, to detect input that aliases it.
pub trait WriterStorage {
    /// The initialized bytes the writer owns or borrows, and the length of the
    /// whole memory it may write to (which starts at the same address).
    fn storage(&self) -> (&[u8], usize);
}

impl WriterStorage for Buffer {
    fn storage(&self) -> (&[u8], usize) {
        (self.as_slice(), self.capacity())
    }
}

impl WriterStorage for SliceWriter<'static> {
    fn storage(&self) -> (&[u8], usize) {
        (self.as_slice(), self.capacity())
    }
}

/// The statuses of [`BytesError`], one per variant.
pub struct BytesStatus;

impl BytesStatus {
    pub const UNEXPECTED_END: Status = Status::new(c"bytes", c"UnexpectedEnd", c"unexpected end of input");
    pub const CAPACITY_EXCEEDED: Status = Status::new(c"bytes", c"CapacityExceeded", c"capacity exceeded");
    pub const VALUE_TOO_LARGE: Status =
        Status::new(c"bytes", c"ValueTooLarge", c"value does not fit in the requested number of bytes");
    pub const INVALID_LENGTH: Status =
        Status::new(c"bytes", c"InvalidLength", c"integer length is zero or larger than the integer type");
    pub const LINE_TOO_LONG: Status = Status::new(c"bytes", c"LineTooLong", c"a line longer than the maximum");
}

impl ToStatus for BytesError {
    fn to_status(&self) -> &'static Status {
        match self {
            BytesError::UnexpectedEnd { .. } => &BytesStatus::UNEXPECTED_END,
            BytesError::CapacityExceeded { .. } => &BytesStatus::CAPACITY_EXCEEDED,
            BytesError::ValueTooLarge { .. } => &BytesStatus::VALUE_TOO_LARGE,
            BytesError::InvalidLength { .. } => &BytesStatus::INVALID_LENGTH,
            BytesError::LineTooLong { .. } => &BytesStatus::LINE_TOO_LONG,
        }
    }
}

/// The values of [`BitOrder`] in the C ABI.
pub struct BitOrderKind;

impl BitOrderKind {
    pub const LEAST_SIGNIFICANT_FIRST: u8 = 0;
    pub const MOST_SIGNIFICANT_FIRST: u8 = 1;

    pub fn decode(kind: u8) -> Result<BitOrder, &'static Status> {
        match kind {
            BitOrderKind::LEAST_SIGNIFICANT_FIRST => Ok(BitOrder::LeastSignificantFirst),
            BitOrderKind::MOST_SIGNIFICANT_FIRST => Ok(BitOrder::MostSignificantFirst),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    pub fn encode(order: BitOrder) -> u8 {
        match order {
            BitOrder::LeastSignificantFirst => BitOrderKind::LEAST_SIGNIFICANT_FIRST,
            BitOrder::MostSignificantFirst => BitOrderKind::MOST_SIGNIFICANT_FIRST,
        }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "bytes",
    definitions: &[
        Definition::Opaque {
            name: "umilib_bytes_Reader",
            documentation: " A cursor over caller-owned bytes, which must outlive the reader.",
        },
        Definition::Opaque {
            name: "umilib_bytes_Buffer",
            documentation: " A growable byte buffer with an optional limit.",
        },
        Definition::Opaque {
            name: "umilib_bytes_LineBuffer",
            documentation: " Received bytes read as CRLF-ended lines or counted bytes.",
        },
        Definition::Opaque {
            name: "umilib_bytes_SliceWriter",
            documentation: " A writer into caller-owned bytes, which must outlive the writer.",
        },
    ],
    functions: &Function::concat::<
        {
            reader::FUNCTIONS.len()
                + buffer::FUNCTIONS.len()
                + line_buffer::FUNCTIONS.len()
                + slice_writer::FUNCTIONS.len()
        },
    >(&[reader::FUNCTIONS, buffer::FUNCTIONS, line_buffer::FUNCTIONS, slice_writer::FUNCTIONS]),
    modules: &[],
};
