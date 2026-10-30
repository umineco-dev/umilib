//! The C ABI of [`crate::codec::zlib`]. A null dictionary means none.

use crate::codec::deflate::{DeflateConfig, DeflateDecompressorConfig};
use crate::codec::zlib::{ZlibCompressor, ZlibDecompressor};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus};

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new compressor of `level` (0 to 9) and a window of 2^`window_bits` bytes (8 to 15),
    /// with the preset dictionary of `dictionary_length` bytes at `dictionary` unless it is null, into `out`.
    pub unsafe extern "C" fn umilib_codec_zlib_zlib_compressor_new(level: u32, window_bits: u32, dictionary: *const u8, dictionary_length: usize, out: *mut *mut ZlibCompressor) -> *const Status {
        Status::from_result((|| {
            let config = DeflateConfig { level, window_bits };
            let compressor = if dictionary.is_null() {
                ZlibCompressor::new(config)
            } else {
                // SAFETY: the caller passes readable bytes.
                ZlibCompressor::with_dictionary(config, unsafe { Pointer::slice(dictionary, dictionary_length) }?)
            };
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, compressor.map_err(|error| error.to_status())?) }
        })())
    }

    /// Writes a new decompressor keeping a window of 2^`window_bits` bytes (8 to 15), with the
    /// preset dictionary of `dictionary_length` bytes at `dictionary` unless it is null, into `out`.
    pub unsafe extern "C" fn umilib_codec_zlib_zlib_decompressor_new(window_bits: u32, dictionary: *const u8, dictionary_length: usize, out: *mut *mut ZlibDecompressor) -> *const Status {
        Status::from_result((|| {
            let config = DeflateDecompressorConfig { window_bits };
            let decompressor = if dictionary.is_null() {
                ZlibDecompressor::new(config)
            } else {
                // SAFETY: the caller passes readable bytes.
                ZlibDecompressor::with_dictionary(config, unsafe { Pointer::slice(dictionary, dictionary_length) }?)
            };
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, decompressor.map_err(|error| error.to_status())?) }
        })())
    }
}

crate::ffi_compressor!(compressor; ZlibCompressor, "umilib_codec_zlib_zlib_compressor", "umilib_codec_zlib_ZlibCompressor");
crate::ffi_decompressor!(decompressor; ZlibDecompressor, "umilib_codec_zlib_zlib_decompressor", "umilib_codec_zlib_ZlibDecompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "zlib",
    definitions: &[
        Definition::Opaque {
            name: "umilib_codec_zlib_ZlibCompressor",
            documentation: " A compressor of zlib streams (RFC 1950).",
        },
        Definition::Opaque {
            name: "umilib_codec_zlib_ZlibDecompressor",
            documentation: " A decompressor of zlib streams (RFC 1950).",
        },
    ],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + compressor::FUNCTIONS.len() + decompressor::FUNCTIONS.len() }>(
        &[CONSTRUCTORS, compressor::FUNCTIONS, decompressor::FUNCTIONS],
    ),
    modules: &[],
};
