//! The C ABI of [`crate::codec::lzss`]. Both sides take the parameters EI
//! (`position_bits`) and EJ (`length_bits`), which streams do not record.

use crate::codec::lzss::{LZSSCompressor, LZSSConfig, LZSSDecompressor};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus};

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new compressor of the parameters EI = `position_bits` and EJ = `length_bits` into `out`.
    pub unsafe extern "C" fn umilib_codec_lzss_lzss_compressor_new(position_bits: u32, length_bits: u32, out: *mut *mut LZSSCompressor) -> *const Status {
        Status::from_result((|| {
            let compressor = LZSSCompressor::new(LZSSConfig { position_bits, length_bits }).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, compressor) }
        })())
    }

    /// Writes the parameters of the reference (EI = 11, EJ = 4) into `position_bits` and `length_bits`.
    pub unsafe extern "C" fn umilib_codec_lzss_lzss_config_default(position_bits: *mut u32, length_bits: *mut u32) -> *const Status {
        Status::from_result((|| {
            let config = LZSSConfig::default();
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(position_bits, config.position_bits) }?;
            unsafe { Pointer::write(length_bits, config.length_bits) }
        })())
    }

    /// Writes a new decompressor of the parameters EI = `position_bits` and EJ = `length_bits` into `out`.
    pub unsafe extern "C" fn umilib_codec_lzss_lzss_decompressor_new(position_bits: u32, length_bits: u32, out: *mut *mut LZSSDecompressor) -> *const Status {
        Status::from_result((|| {
            let decompressor = LZSSDecompressor::new(LZSSConfig { position_bits, length_bits }).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, decompressor) }
        })())
    }
}

crate::ffi_compressor!(compressor; LZSSCompressor, "umilib_codec_lzss_lzss_compressor", "umilib_codec_lzss_LZSSCompressor");
crate::ffi_decompressor!(decompressor; LZSSDecompressor, "umilib_codec_lzss_lzss_decompressor", "umilib_codec_lzss_LZSSDecompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "lzss",
    definitions: &[
        Definition::Opaque {
            name: "umilib_codec_lzss_LZSSCompressor",
            documentation: " A compressor of the LZSS format of Haruhiko Okumura.",
        },
        Definition::Opaque {
            name: "umilib_codec_lzss_LZSSDecompressor",
            documentation: " A decompressor of the LZSS format of Haruhiko Okumura.",
        },
    ],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + compressor::FUNCTIONS.len() + decompressor::FUNCTIONS.len() }>(
        &[CONSTRUCTORS, compressor::FUNCTIONS, decompressor::FUNCTIONS],
    ),
    modules: &[],
};
