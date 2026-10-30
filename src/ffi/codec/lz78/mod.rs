//! The C ABI of [`crate::codec::lz78`].

use crate::codec::lz78::{LZ78Compressor, LZ78Config, LZ78Decompressor, LZ78DecompressorConfig};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus};

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new compressor of dictionaries of at most 2^`dictionary_bits` phrases (1 to 24) into `out`.
    pub unsafe extern "C" fn umilib_codec_lz78_lz78_compressor_new(dictionary_bits: u32, out: *mut *mut LZ78Compressor) -> *const Status {
        Status::from_result((|| {
            let compressor = LZ78Compressor::new(LZ78Config { dictionary_bits }).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, compressor) }
        })())
    }

    /// Writes the default dictionary bits of the compressor and the default limit of the
    /// decompressor into `dictionary_bits` and `maximum_dictionary_bits`.
    pub unsafe extern "C" fn umilib_codec_lz78_lz78_config_defaults(dictionary_bits: *mut u32, maximum_dictionary_bits: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(dictionary_bits, LZ78Config::default().dictionary_bits) }?;
            unsafe { Pointer::write(maximum_dictionary_bits, LZ78DecompressorConfig::default().maximum_dictionary_bits) }
        })())
    }

    /// Writes a new decompressor accepting dictionaries of at most 2^`maximum_dictionary_bits` phrases into `out`.
    pub unsafe extern "C" fn umilib_codec_lz78_lz78_decompressor_new(maximum_dictionary_bits: u32, out: *mut *mut LZ78Decompressor) -> *const Status {
        let decompressor = LZ78Decompressor::new(LZ78DecompressorConfig { maximum_dictionary_bits });
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, decompressor) })
    }
}

crate::ffi_compressor!(compressor; LZ78Compressor, "umilib_codec_lz78_lz78_compressor", "umilib_codec_lz78_LZ78Compressor");
crate::ffi_decompressor!(decompressor; LZ78Decompressor, "umilib_codec_lz78_lz78_decompressor", "umilib_codec_lz78_LZ78Decompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "lz78",
    definitions: &[
        Definition::Opaque {
            name: "umilib_codec_lz78_LZ78Compressor",
            documentation: " A compressor of the LZ78 format of umilib.",
        },
        Definition::Opaque {
            name: "umilib_codec_lz78_LZ78Decompressor",
            documentation: " A decompressor of the LZ78 format of umilib.",
        },
    ],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + compressor::FUNCTIONS.len() + decompressor::FUNCTIONS.len() }>(
        &[CONSTRUCTORS, compressor::FUNCTIONS, decompressor::FUNCTIONS],
    ),
    modules: &[],
};
