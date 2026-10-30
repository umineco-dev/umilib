//! The C ABI of [`crate::codec::lzma`]. Properties are passed as lc, lp
//! and pb; optional sizes with a flag that says whether they are present.

use crate::codec::lzma::{
    LZMA2Compressor, LZMA2Decompressor, LZMA2DecompressorConfig, LZMACompressor, LZMAConfig, LZMADecompressor,
    LZMADecompressorConfig, LZMAFormat, LZMAProperties,
};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus};

/// The configuration of the C arguments of a compressor.
pub struct LZMAArguments;

impl LZMAArguments {
    pub fn config(
        level: u32,
        lc: u32,
        lp: u32,
        pb: u32,
        has_dictionary_size: bool,
        dictionary_size: usize,
        uncompressed_size: Option<u64>,
    ) -> LZMAConfig {
        LZMAConfig {
            level,
            properties: LZMAProperties { literal_context_bits: lc, literal_position_bits: lp, position_bits: pb },
            dictionary_size: has_dictionary_size.then_some(dictionary_size),
            uncompressed_size,
        }
    }
}

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new compressor of .lzma files into `out`: `level` 0 to 9, the properties lc, lp
    /// and pb, the dictionary size if `has_dictionary_size` (otherwise the level's), and the size of
    /// the data if `has_uncompressed_size` (otherwise an end marker).
    pub unsafe extern "C" fn umilib_codec_lzma_lzma_compressor_new(
        level: u32,
        lc: u32,
        lp: u32,
        pb: u32,
        has_dictionary_size: bool,
        dictionary_size: usize,
        has_uncompressed_size: bool,
        uncompressed_size: u64,
        out: *mut *mut LZMACompressor,
    ) -> *const Status {
        Status::from_result((|| {
            let config = LZMAArguments::config(level, lc, lp, pb, has_dictionary_size, dictionary_size, has_uncompressed_size.then_some(uncompressed_size));
            let compressor = LZMACompressor::new(config).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, compressor) }
        })())
    }

    /// Writes a new decompressor of .lzma files accepting dictionaries of at most `maximum_dictionary_size` bytes into `out`.
    pub unsafe extern "C" fn umilib_codec_lzma_lzma_decompressor_new(maximum_dictionary_size: usize, out: *mut *mut LZMADecompressor) -> *const Status {
        let decompressor = LZMADecompressor::new(LZMADecompressorConfig { maximum_dictionary_size });
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, decompressor) })
    }

    /// Writes a new compressor of raw LZMA2 streams into `out` (as for .lzma files, with lc + lp at most 4).
    pub unsafe extern "C" fn umilib_codec_lzma_lzma2_compressor_new(
        level: u32,
        lc: u32,
        lp: u32,
        pb: u32,
        has_dictionary_size: bool,
        dictionary_size: usize,
        out: *mut *mut LZMA2Compressor,
    ) -> *const Status {
        Status::from_result((|| {
            let config = LZMAArguments::config(level, lc, lp, pb, has_dictionary_size, dictionary_size, None);
            let compressor = LZMA2Compressor::new(config).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, compressor) }
        })())
    }

    /// Writes the dictionary size the decompressor of the streams of `state` needs into `out`.
    pub unsafe extern "C" fn umilib_codec_lzma_lzma2_compressor_dictionary_size(state: *const LZMA2Compressor, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write(out, state.dictionary_size()) }
        })())
    }

    /// Writes a new decompressor of raw LZMA2 streams of a dictionary of `dictionary_size` bytes into `out`.
    pub unsafe extern "C" fn umilib_codec_lzma_lzma2_decompressor_new(dictionary_size: usize, out: *mut *mut LZMA2Decompressor) -> *const Status {
        Status::from_result((|| {
            let decompressor = LZMA2Decompressor::new(LZMA2DecompressorConfig { dictionary_size }).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, decompressor) }
        })())
    }

    /// Writes the dictionary size of the LZMA2 properties byte `byte` (0 to 40) into `out`.
    pub unsafe extern "C" fn umilib_codec_lzma_lzma_format_lzma2_dictionary_size(byte: u8, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            let size = LZMAFormat::lzma2_dictionary_size(byte).ok_or(&Status::INVALID_ARGUMENT)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, size) }
        })())
    }

    /// Writes the defaults: the level and lc, lp, pb of the compressors, and the maximum dictionary
    /// of a .lzma decompressor and the dictionary of an LZMA2 decompressor.
    pub unsafe extern "C" fn umilib_codec_lzma_lzma_config_defaults(
        level: *mut u32,
        lc: *mut u32,
        lp: *mut u32,
        pb: *mut u32,
        maximum_dictionary_size: *mut usize,
        lzma2_dictionary_size: *mut usize,
    ) -> *const Status {
        Status::from_result((|| {
            let config = LZMAConfig::default();
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(level, config.level) }?;
            unsafe { Pointer::write(lc, config.properties.literal_context_bits) }?;
            unsafe { Pointer::write(lp, config.properties.literal_position_bits) }?;
            unsafe { Pointer::write(pb, config.properties.position_bits) }?;
            unsafe { Pointer::write(maximum_dictionary_size, LZMADecompressorConfig::default().maximum_dictionary_size) }?;
            unsafe { Pointer::write(lzma2_dictionary_size, LZMA2DecompressorConfig::default().dictionary_size) }
        })())
    }
}

crate::ffi_compressor!(compressor; LZMACompressor, "umilib_codec_lzma_lzma_compressor", "umilib_codec_lzma_LZMACompressor");
crate::ffi_decompressor!(decompressor; LZMADecompressor, "umilib_codec_lzma_lzma_decompressor", "umilib_codec_lzma_LZMADecompressor");
crate::ffi_compressor!(compressor2; LZMA2Compressor, "umilib_codec_lzma_lzma2_compressor", "umilib_codec_lzma_LZMA2Compressor");
crate::ffi_decompressor!(decompressor2; LZMA2Decompressor, "umilib_codec_lzma_lzma2_decompressor", "umilib_codec_lzma_LZMA2Decompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "lzma",
    definitions: &[
        Definition::Opaque { name: "umilib_codec_lzma_LZMACompressor", documentation: " A compressor of .lzma files." },
        Definition::Opaque {
            name: "umilib_codec_lzma_LZMADecompressor",
            documentation: " A decompressor of .lzma files.",
        },
        Definition::Opaque {
            name: "umilib_codec_lzma_LZMA2Compressor",
            documentation: " A compressor of raw LZMA2 streams.",
        },
        Definition::Opaque {
            name: "umilib_codec_lzma_LZMA2Decompressor",
            documentation: " A decompressor of raw LZMA2 streams.",
        },
    ],
    functions: &Function::concat::<
        {
            CONSTRUCTORS.len()
                + compressor::FUNCTIONS.len()
                + decompressor::FUNCTIONS.len()
                + compressor2::FUNCTIONS.len()
                + decompressor2::FUNCTIONS.len()
        },
    >(&[
        CONSTRUCTORS,
        compressor::FUNCTIONS,
        decompressor::FUNCTIONS,
        compressor2::FUNCTIONS,
        decompressor2::FUNCTIONS,
    ]),
    modules: &[],
};
