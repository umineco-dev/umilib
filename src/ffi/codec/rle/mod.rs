//! The C ABI of [`crate::codec::rle`].

use crate::codec::rle::{PackBitsCompressor, PackBitsDecompressor};
use crate::ffi::{Definition, Function, Module, Pointer, Status};

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new PackBits compressor into `out`.
    pub unsafe extern "C" fn umilib_codec_rle_pack_bits_compressor_new(out: *mut *mut PackBitsCompressor) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, PackBitsCompressor::new()) })
    }

    /// Writes a new PackBits decompressor into `out`.
    pub unsafe extern "C" fn umilib_codec_rle_pack_bits_decompressor_new(out: *mut *mut PackBitsDecompressor) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, PackBitsDecompressor::new()) })
    }
}

crate::ffi_compressor!(compressor; PackBitsCompressor, "umilib_codec_rle_pack_bits_compressor", "umilib_codec_rle_PackBitsCompressor");
crate::ffi_decompressor!(decompressor; PackBitsDecompressor, "umilib_codec_rle_pack_bits_decompressor", "umilib_codec_rle_PackBitsDecompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "rle",
    definitions: &[
        Definition::Opaque { name: "umilib_codec_rle_PackBitsCompressor", documentation: " A PackBits compressor." },
        Definition::Opaque {
            name: "umilib_codec_rle_PackBitsDecompressor",
            documentation: " A PackBits decompressor.",
        },
    ],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + compressor::FUNCTIONS.len() + decompressor::FUNCTIONS.len() }>(
        &[CONSTRUCTORS, compressor::FUNCTIONS, decompressor::FUNCTIONS],
    ),
    modules: &[],
};
