//! The C ABI of [`crate::codec::lz77`].

use crate::codec::lz77::{LZ77Compressor, LZ77Config, LZ77Decompressor};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus};

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new compressor examining at most `chain_limit` candidates per match (1 or more) into `out`.
    pub unsafe extern "C" fn umilib_codec_lz77_lz77_compressor_new(chain_limit: usize, out: *mut *mut LZ77Compressor) -> *const Status {
        Status::from_result((|| {
            let compressor = LZ77Compressor::new(LZ77Config { chain_limit }).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, compressor) }
        })())
    }

    /// Writes the default chain limit into `out`.
    pub unsafe extern "C" fn umilib_codec_lz77_lz77_config_default_chain_limit(out: *mut usize) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, LZ77Config::default().chain_limit) })
    }

    /// Writes a new decompressor into `out`.
    pub unsafe extern "C" fn umilib_codec_lz77_lz77_decompressor_new(out: *mut *mut LZ77Decompressor) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, LZ77Decompressor::new()) })
    }
}

crate::ffi_compressor!(compressor; LZ77Compressor, "umilib_codec_lz77_lz77_compressor", "umilib_codec_lz77_LZ77Compressor");
crate::ffi_decompressor!(decompressor; LZ77Decompressor, "umilib_codec_lz77_lz77_decompressor", "umilib_codec_lz77_LZ77Decompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "lz77",
    definitions: &[
        Definition::Opaque {
            name: "umilib_codec_lz77_LZ77Compressor",
            documentation: " A compressor of the LZ77 format of umilib.",
        },
        Definition::Opaque {
            name: "umilib_codec_lz77_LZ77Decompressor",
            documentation: " A decompressor of the LZ77 format of umilib.",
        },
    ],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + compressor::FUNCTIONS.len() + decompressor::FUNCTIONS.len() }>(
        &[CONSTRUCTORS, compressor::FUNCTIONS, decompressor::FUNCTIONS],
    ),
    modules: &[],
};
