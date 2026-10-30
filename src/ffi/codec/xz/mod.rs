//! The C ABI of [`crate::codec::xz`]. Checks are their Check IDs (0 none,
//! 1 CRC32, 4 CRC64, 10 SHA-256) and filters before LZMA2 are
//! [`XZFilterFlags`]: a Filter ID and one value.

use alloc::vec::Vec;

use crate::codec::filter::bcj::BCJArchitecture;
use crate::codec::lzma::LZMAConfig;
use crate::codec::xz::{XZCheck, XZCompressor, XZConfig, XZDecompressor, XZDecompressorConfig, XZFilter, XZFormat};
use crate::ffi::{Definition, Function, Module, Parameter, Pointer, Status, ToStatus, Type, Value};

/// A filter of a .xz chain in the C ABI: its Filter ID (0x03 Delta, 0x04
/// to 0x0B BCJ, 0x21 LZMA2) and its value (the distance of Delta, the start
/// offset of BCJ, the dictionary size of LZMA2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct XZFilterFlags {
    pub id: u64,
    pub value: u64,
}

impl XZFilterFlags {
    /// The filter; fails with `InvalidArgument` for an unknown ID or a value out of range.
    pub fn to_filter(&self) -> Result<XZFilter, &'static Status> {
        let invalid = &Status::INVALID_ARGUMENT;
        match self.id {
            XZFormat::DELTA => Ok(XZFilter::Delta { distance: u16::try_from(self.value).map_err(|_| invalid)? }),
            XZFormat::X86..=XZFormat::RISCV => Ok(XZFilter::BCJ {
                architecture: BCJArchitecture::ALL[(self.id - XZFormat::X86) as usize],
                start_offset: u32::try_from(self.value).map_err(|_| invalid)?,
            }),
            XZFormat::LZMA2 => Ok(XZFilter::LZMA2 { dictionary_size: self.value }),
            _ => Err(invalid),
        }
    }
}

impl Value for XZFilterFlags {
    const TYPE: Type = Type::Named("umilib_codec_xz_XZFilterFlags");
}

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new compressor into `out`: LZMA2 of `level` (0 to 9) and `dictionary_size` (0 for
    /// the level's), the Check `check` (its ID), Blocks of `block_size` bytes (0 for one Block) and
    /// the `filter_count` filters at `filters` before LZMA2 (null if none).
    pub unsafe extern "C" fn umilib_codec_xz_xz_compressor_new(
        level: u32,
        dictionary_size: u64,
        check: u8,
        block_size: u64,
        filters: *const XZFilterFlags,
        filter_count: usize,
        out: *mut *mut XZCompressor,
    ) -> *const Status {
        Status::from_result((|| {
            let check = XZCheck::from_id(check).map_err(|_| &Status::INVALID_ARGUMENT)?;
            // SAFETY: the caller passes `filter_count` readable filters.
            let flags = if filter_count == 0 { &[][..] } else { unsafe { Pointer::slice_of(filters, filter_count) }? };
            let filters = flags.iter().map(XZFilterFlags::to_filter).collect::<Result<Vec<XZFilter>, _>>()?;
            let dictionary_size = if dictionary_size == 0 {
                None
            } else {
                Some(usize::try_from(dictionary_size).map_err(|_| &Status::INVALID_ARGUMENT)?)
            };
            let config = XZConfig {
                lzma: LZMAConfig { level, dictionary_size, ..LZMAConfig::default() },
                check,
                filters,
                block_size: (block_size != 0).then_some(block_size),
            };
            let compressor = XZCompressor::new(config).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, compressor) }
        })())
    }

    /// Writes a new decompressor into `out`: LZMA2 dictionaries of at most `maximum_dictionary_size`
    /// bytes, and a file of Streams if `multiple_streams` (otherwise one Stream).
    pub unsafe extern "C" fn umilib_codec_xz_xz_decompressor_new(maximum_dictionary_size: u64, multiple_streams: bool, out: *mut *mut XZDecompressor) -> *const Status {
        let config = XZDecompressorConfig { maximum_dictionary_size, multiple_streams };
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, XZDecompressor::new(config)) })
    }


    /// Writes the defaults: the level and the Check ID of a compressor, the maximum dictionary and
    /// multiple Streams of a decompressor.
    pub unsafe extern "C" fn umilib_codec_xz_xz_config_defaults(level: *mut u32, check: *mut u8, maximum_dictionary_size: *mut u64, multiple_streams: *mut bool) -> *const Status {
        Status::from_result((|| {
            let (config, limits) = (XZConfig::default(), XZDecompressorConfig::default());
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(level, config.lzma.level) }?;
            unsafe { Pointer::write(check, config.check.id()) }?;
            unsafe { Pointer::write(maximum_dictionary_size, limits.maximum_dictionary_size) }?;
            unsafe { Pointer::write(multiple_streams, limits.multiple_streams) }
        })())
    }

    /// Writes the Streams `state` has read completely into `streams` and the Check ID of its current
    /// (or last) Stream into `check`.
    pub unsafe extern "C" fn umilib_codec_xz_xz_decompressor_streams(state: *const XZDecompressor, streams: *mut u64, check: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write(streams, state.streams()) }?;
            unsafe { Pointer::write(check, state.check().id()) }
        })())
    }
}

crate::ffi_compressor!(compressor; XZCompressor, "umilib_codec_xz_xz_compressor", "umilib_codec_xz_XZCompressor");
crate::ffi_decompressor!(decompressor; XZDecompressor, "umilib_codec_xz_xz_decompressor", "umilib_codec_xz_XZDecompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "xz",
    definitions: &[
        Definition::Structure {
            name: "umilib_codec_xz_XZFilterFlags",
            documentation: " A filter of a .xz chain: its Filter ID (0x03 Delta, 0x04 to 0x0B BCJ, 0x21 LZMA2) and\n \
                            its value (the distance of Delta, the start offset of BCJ, the dictionary size of LZMA2).",
            fields: &[
                Parameter { name: "id", value: <u64 as Value>::TYPE },
                Parameter { name: "value", value: <u64 as Value>::TYPE },
            ],
        },
        Definition::Opaque { name: "umilib_codec_xz_XZCompressor", documentation: " A compressor of .xz Streams." },
        Definition::Opaque {
            name: "umilib_codec_xz_XZDecompressor",
            documentation: " A decompressor of .xz files and Streams.",
        },
    ],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + compressor::FUNCTIONS.len() + decompressor::FUNCTIONS.len() }>(
        &[CONSTRUCTORS, compressor::FUNCTIONS, decompressor::FUNCTIONS],
    ),
    modules: &[],
};
