//! The C ABI of [`crate::codec::gzip`]. The optional fields of a header
//! (extra field, name, comment) are byte strings; a null pointer means the
//! field is absent.

use alloc::vec::Vec;

use crate::codec::deflate::{DeflateConfig, DeflateDecompressorConfig};
use crate::codec::gzip::{GzipCompressor, GzipConfig, GzipDecompressor, GzipDecompressorConfig, GzipHeader};
use crate::ffi::{Buffer, Definition, Function, Module, Pointer, Status, ToStatus};

/// The optional fields of a gzip header in the C ABI.
pub struct GzipField;

impl GzipField {
    pub const EXTRA: u8 = 0;
    pub const NAME: u8 = 1;
    pub const COMMENT: u8 = 2;

    /// The field `field` of `header`.
    pub fn get(header: &GzipHeader, field: u8) -> Result<&Option<Vec<u8>>, &'static Status> {
        match field {
            GzipField::EXTRA => Ok(&header.extra),
            GzipField::NAME => Ok(&header.name),
            GzipField::COMMENT => Ok(&header.comment),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }

    /// The `length` bytes at `data`, or `None` if `data` is null.
    ///
    /// # Safety
    ///
    /// `data` is null or points to `length` readable bytes.
    pub unsafe fn read(data: *const u8, length: usize) -> Result<Option<Vec<u8>>, &'static Status> {
        if data.is_null() {
            return Ok(None);
        }
        // SAFETY: guaranteed by the caller.
        Ok(Some(unsafe { Pointer::slice(data, length) }?.to_vec()))
    }
}

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new compressor of a member of `level` (0 to 9) whose header has the modification
    /// time `modification_time`, the operating system `operating_system`, the flags `text` and
    /// `header_checksum`, and the extra field, name and comment given (or none, for null pointers),
    /// into `out`. Names and comments may not hold zero bytes.
    pub unsafe extern "C" fn umilib_codec_gzip_gzip_compressor_new(
        level: u32,
        modification_time: u32,
        operating_system: u8,
        text: bool,
        header_checksum: bool,
        extra: *const u8,
        extra_length: usize,
        name: *const u8,
        name_length: usize,
        comment: *const u8,
        comment_length: usize,
        out: *mut *mut GzipCompressor,
    ) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes null or readable bytes for each field.
            let header = GzipHeader {
                text,
                modification_time,
                extra_flags: 0,
                operating_system,
                extra: unsafe { GzipField::read(extra, extra_length) }?,
                name: unsafe { GzipField::read(name, name_length) }?,
                comment: unsafe { GzipField::read(comment, comment_length) }?,
                header_checksum,
            };
            let config = GzipConfig { deflate: DeflateConfig { level, window_bits: 15 }, header };
            let compressor = GzipCompressor::new(config).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, compressor) }
        })())
    }

    /// Writes a new decompressor into `out`: of a file of any number of members if
    /// `multiple_members`, otherwise of one member; names, comments and extra fields longer than
    /// `maximum_field` bytes fail with `LimitExceeded`; the Deflate data keeps a window of
    /// 2^`window_bits` bytes (8 to 15), matches reaching farther failing with `LimitExceeded`.
    pub unsafe extern "C" fn umilib_codec_gzip_gzip_decompressor_new(multiple_members: bool, maximum_field: usize, window_bits: u32, out: *mut *mut GzipDecompressor) -> *const Status {
        Status::from_result((|| {
            let deflate = DeflateDecompressorConfig { window_bits };
            let config = GzipDecompressorConfig { multiple_members, maximum_field, deflate };
            let decompressor = GzipDecompressor::new(config).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, decompressor) }
        })())
    }

    /// Writes the default `multiple_members`, `maximum_field` and `window_bits` of a decompressor.
    pub unsafe extern "C" fn umilib_codec_gzip_gzip_decompressor_config_default(multiple_members: *mut bool, maximum_field: *mut usize, window_bits: *mut u32) -> *const Status {
        Status::from_result((|| {
            let config = GzipDecompressorConfig::default();
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(multiple_members, config.multiple_members) }?;
            unsafe { Pointer::write(maximum_field, config.maximum_field) }?;
            unsafe { Pointer::write(window_bits, config.deflate.window_bits) }
        })())
    }

    /// Writes the fixed fields of the header of the member being read (or of the last one) and the
    /// number of members read completely.
    pub unsafe extern "C" fn umilib_codec_gzip_gzip_decompressor_header(
        state: *const GzipDecompressor,
        text: *mut bool,
        modification_time: *mut u32,
        extra_flags: *mut u8,
        operating_system: *mut u8,
        header_checksum: *mut bool,
        members: *mut usize,
    ) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let state = unsafe { Pointer::reference(state) }?;
            let header = state.header();
            unsafe { Pointer::write(text, header.text) }?;
            unsafe { Pointer::write(modification_time, header.modification_time) }?;
            unsafe { Pointer::write(extra_flags, header.extra_flags) }?;
            unsafe { Pointer::write(operating_system, header.operating_system) }?;
            unsafe { Pointer::write(header_checksum, header.header_checksum) }?;
            unsafe { Pointer::write(members, state.members()) }
        })())
    }

    /// Writes whether the header has the field `field` (0 extra, 1 name, 2 comment) into
    /// `has_value`, and its bytes into `out`.
    pub unsafe extern "C" fn umilib_codec_gzip_gzip_decompressor_header_field(state: *const GzipDecompressor, field: u8, has_value: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let state = unsafe { Pointer::reference(state) }?;
            let value = GzipField::get(state.header(), field)?;
            unsafe { Pointer::write(has_value, value.is_some()) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(value.clone().unwrap_or_default())) }
        })())
    }
}

crate::ffi_compressor!(compressor; GzipCompressor, "umilib_codec_gzip_gzip_compressor", "umilib_codec_gzip_GzipCompressor");
crate::ffi_decompressor!(decompressor; GzipDecompressor, "umilib_codec_gzip_gzip_decompressor", "umilib_codec_gzip_GzipDecompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "gzip",
    definitions: &[
        Definition::Opaque {
            name: "umilib_codec_gzip_GzipCompressor",
            documentation: " A compressor of gzip members (RFC 1952).",
        },
        Definition::Opaque {
            name: "umilib_codec_gzip_GzipDecompressor",
            documentation: " A decompressor of gzip files (RFC 1952).",
        },
    ],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + compressor::FUNCTIONS.len() + decompressor::FUNCTIONS.len() }>(
        &[CONSTRUCTORS, compressor::FUNCTIONS, decompressor::FUNCTIONS],
    ),
    modules: &[],
};
