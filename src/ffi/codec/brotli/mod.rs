//! The C ABI of [`crate::codec::brotli`].

use crate::codec::brotli::{BrotliCompressor, BrotliConfig, BrotliDecompressor, BrotliDecompressorConfig};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus};

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new compressor of `level` (0 to 11) and WBITS `window_bits` (10 to 24) into `out`.
    pub unsafe extern "C" fn umilib_codec_brotli_brotli_compressor_new(level: u32, window_bits: u32, out: *mut *mut BrotliCompressor) -> *const Status {
        Status::from_result((|| {
            let compressor = BrotliCompressor::new(BrotliConfig { level, window_bits }).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, compressor) }
        })())
    }

    /// Writes the default level and window bits of a compressor into `level` and `window_bits`, and
    /// the default limit of a decompressor into `maximum_window_bits`.
    pub unsafe extern "C" fn umilib_codec_brotli_brotli_config_defaults(level: *mut u32, window_bits: *mut u32, maximum_window_bits: *mut u32) -> *const Status {
        Status::from_result((|| {
            let (config, limits) = (BrotliConfig::default(), BrotliDecompressorConfig::default());
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(level, config.level) }?;
            unsafe { Pointer::write(window_bits, config.window_bits) }?;
            unsafe { Pointer::write(maximum_window_bits, limits.maximum_window_bits) }
        })())
    }

    /// Writes a new decompressor of streams of WBITS up to `maximum_window_bits` (10 to 24) into `out`.
    pub unsafe extern "C" fn umilib_codec_brotli_brotli_decompressor_new(maximum_window_bits: u32, out: *mut *mut BrotliDecompressor) -> *const Status {
        Status::from_result((|| {
            let decompressor = BrotliDecompressor::new(BrotliDecompressorConfig { maximum_window_bits }).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, decompressor) }
        })())
    }
}

crate::ffi_compressor!(compressor; BrotliCompressor, "umilib_codec_brotli_brotli_compressor", "umilib_codec_brotli_BrotliCompressor");
crate::ffi_decompressor!(decompressor; BrotliDecompressor, "umilib_codec_brotli_brotli_decompressor", "umilib_codec_brotli_BrotliDecompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "brotli",
    definitions: &[
        Definition::Opaque {
            name: "umilib_codec_brotli_BrotliCompressor",
            documentation: " A compressor of Brotli streams (RFC 7932).",
        },
        Definition::Opaque {
            name: "umilib_codec_brotli_BrotliDecompressor",
            documentation: " A decompressor of Brotli streams (RFC 7932).",
        },
    ],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + compressor::FUNCTIONS.len() + decompressor::FUNCTIONS.len() }>(
        &[CONSTRUCTORS, compressor::FUNCTIONS, decompressor::FUNCTIONS],
    ),
    modules: &[],
};
