//! The C ABI of [`crate::codec::zstandard`]. Dictionaries are handles made
//! from their bytes; a null dictionary means none, and optional values come
//! with a flag that says whether they are present.

use crate::codec::zstandard::{
    ZstandardCompressor, ZstandardConfig, ZstandardDecompressor, ZstandardDecompressorConfig, ZstandardDictionary,
};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for ZstandardDictionary {
    const TYPE: Type = Type::Named("umilib_codec_zstandard_ZstandardDictionary");
}

crate::ffi_functions! {
    const FUNCTIONS;

    /// Writes a new dictionary of the `length` bytes at `data` (formatted, or raw content) into `out`.
    pub unsafe extern "C" fn umilib_codec_zstandard_zstandard_dictionary_new(data: *const u8, length: usize, out: *mut *mut ZstandardDictionary) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let dictionary = ZstandardDictionary::new(unsafe { Pointer::slice(data, length) }?).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, dictionary) }
        })())
    }

    /// Releases a dictionary. Does nothing if `dictionary` is null.
    pub unsafe extern "C" fn umilib_codec_zstandard_zstandard_dictionary_free(dictionary: *mut ZstandardDictionary) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(dictionary) }
    }

    /// Writes the identifier of `dictionary` (0 for raw content) into `out`.
    pub unsafe extern "C" fn umilib_codec_zstandard_zstandard_dictionary_identifier(dictionary: *const ZstandardDictionary, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let dictionary = unsafe { Pointer::reference(dictionary) }?;
            unsafe { Pointer::write(out, dictionary.identifier) }
        })())
    }

    /// Writes a new compressor into `out`: `level` 1 to 19, the window log if `has_window_log`,
    /// the content checksum, the content size if `has_content_size`, and a copy of `dictionary` unless it is null.
    pub unsafe extern "C" fn umilib_codec_zstandard_zstandard_compressor_new(
        level: u32,
        has_window_log: bool,
        window_log: u32,
        content_checksum: bool,
        has_content_size: bool,
        content_size: u64,
        dictionary: *const ZstandardDictionary,
        out: *mut *mut ZstandardCompressor,
    ) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes null or a valid handle.
            let dictionary = if dictionary.is_null() { None } else { Some(unsafe { Pointer::reference(dictionary) }?.clone()) };
            let config = ZstandardConfig {
                level,
                window_log: has_window_log.then_some(window_log),
                content_checksum,
                content_size: has_content_size.then_some(content_size),
                dictionary,
            };
            let compressor = ZstandardCompressor::new(config).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, compressor) }
        })())
    }

    /// Writes a new decompressor into `out`: windows of at most `maximum_window` bytes, a series of
    /// frames if `multiple_frames`, and a copy of `dictionary` unless it is null.
    pub unsafe extern "C" fn umilib_codec_zstandard_zstandard_decompressor_new(
        maximum_window: u64,
        multiple_frames: bool,
        dictionary: *const ZstandardDictionary,
        out: *mut *mut ZstandardDecompressor,
    ) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes null or a valid handle.
            let dictionary = if dictionary.is_null() { None } else { Some(unsafe { Pointer::reference(dictionary) }?.clone()) };
            let config = ZstandardDecompressorConfig { maximum_window, multiple_frames, dictionary };
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, ZstandardDecompressor::new(config)) }
        })())
    }

    /// Writes the defaults: the level and the content checksum of a compressor, the maximum window
    /// and multiple frames of a decompressor.
    pub unsafe extern "C" fn umilib_codec_zstandard_zstandard_config_defaults(level: *mut u32, content_checksum: *mut bool, maximum_window: *mut u64, multiple_frames: *mut bool) -> *const Status {
        Status::from_result((|| {
            let (config, limits) = (ZstandardConfig::default(), ZstandardDecompressorConfig::default());
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(level, config.level) }?;
            unsafe { Pointer::write(content_checksum, config.content_checksum) }?;
            unsafe { Pointer::write(maximum_window, limits.maximum_window) }?;
            unsafe { Pointer::write(multiple_frames, limits.multiple_frames) }
        })())
    }
}

crate::ffi_compressor!(compressor; ZstandardCompressor, "umilib_codec_zstandard_zstandard_compressor", "umilib_codec_zstandard_ZstandardCompressor");
crate::ffi_decompressor!(decompressor; ZstandardDecompressor, "umilib_codec_zstandard_zstandard_decompressor", "umilib_codec_zstandard_ZstandardDecompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "zstandard",
    definitions: &[
        Definition::Opaque {
            name: "umilib_codec_zstandard_ZstandardDictionary",
            documentation: " A Zstandard dictionary.",
        },
        Definition::Opaque {
            name: "umilib_codec_zstandard_ZstandardCompressor",
            documentation: " A compressor of Zstandard frames.",
        },
        Definition::Opaque {
            name: "umilib_codec_zstandard_ZstandardDecompressor",
            documentation: " A decompressor of Zstandard frames.",
        },
    ],
    functions: &Function::concat::<{ FUNCTIONS.len() + compressor::FUNCTIONS.len() + decompressor::FUNCTIONS.len() }>(
        &[FUNCTIONS, compressor::FUNCTIONS, decompressor::FUNCTIONS],
    ),
    modules: &[],
};
