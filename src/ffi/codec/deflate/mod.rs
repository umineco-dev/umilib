//! The C ABI of [`crate::codec::deflate`].

use crate::codec::deflate::{DeflateCompressor, DeflateConfig, DeflateDecompressor, DeflateDecompressorConfig};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus};

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new compressor of `level` (0 to 9) and a window of 2^`window_bits` bytes (8 to 15) into `out`.
    pub unsafe extern "C" fn umilib_codec_deflate_deflate_compressor_new(level: u32, window_bits: u32, out: *mut *mut DeflateCompressor) -> *const Status {
        Status::from_result((|| {
            let compressor = DeflateCompressor::new(DeflateConfig { level, window_bits }).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, compressor) }
        })())
    }

    /// Makes the `length` bytes at `dictionary` the history before the data, before the first compression.
    pub unsafe extern "C" fn umilib_codec_deflate_deflate_compressor_set_dictionary(state: *mut DeflateCompressor, dictionary: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let state = unsafe { Pointer::reference_mut(state) }?;
            state.set_dictionary(unsafe { Pointer::slice(dictionary, length) }?);
            Ok(())
        })())
    }

    /// Writes the default level and window bits into `level` and `window_bits`.
    pub unsafe extern "C" fn umilib_codec_deflate_deflate_config_default(level: *mut u32, window_bits: *mut u32) -> *const Status {
        Status::from_result((|| {
            let config = DeflateConfig::default();
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(level, config.level) }?;
            unsafe { Pointer::write(window_bits, config.window_bits) }
        })())
    }

    /// Writes a new decompressor keeping a window of 2^`window_bits` bytes (8 to 15) into `out`.
    pub unsafe extern "C" fn umilib_codec_deflate_deflate_decompressor_new(window_bits: u32, out: *mut *mut DeflateDecompressor) -> *const Status {
        Status::from_result((|| {
            let decompressor = DeflateDecompressor::new(DeflateDecompressorConfig { window_bits }).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, decompressor) }
        })())
    }

    /// Makes the `length` bytes at `dictionary` the history before the data, before the first decompression.
    pub unsafe extern "C" fn umilib_codec_deflate_deflate_decompressor_set_dictionary(state: *mut DeflateDecompressor, dictionary: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let state = unsafe { Pointer::reference_mut(state) }?;
            state.set_dictionary(unsafe { Pointer::slice(dictionary, length) }?);
            Ok(())
        })())
    }

    /// After the last block, goes on with the blocks that follow at the next byte, the history kept.
    pub unsafe extern "C" fn umilib_codec_deflate_deflate_decompressor_resume(state: *mut DeflateDecompressor) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(state) }?.resume();
            Ok(())
        })())
    }
}

crate::ffi_compressor!(compressor; DeflateCompressor, "umilib_codec_deflate_deflate_compressor", "umilib_codec_deflate_DeflateCompressor");
crate::ffi_decompressor!(decompressor; DeflateDecompressor, "umilib_codec_deflate_deflate_decompressor", "umilib_codec_deflate_DeflateDecompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "deflate",
    definitions: &[
        Definition::Opaque {
            name: "umilib_codec_deflate_DeflateCompressor",
            documentation: " A compressor of raw Deflate streams (RFC 1951).",
        },
        Definition::Opaque {
            name: "umilib_codec_deflate_DeflateDecompressor",
            documentation: " A decompressor of raw Deflate streams (RFC 1951).",
        },
    ],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + compressor::FUNCTIONS.len() + decompressor::FUNCTIONS.len() }>(
        &[CONSTRUCTORS, compressor::FUNCTIONS, decompressor::FUNCTIONS],
    ),
    modules: &[],
};
