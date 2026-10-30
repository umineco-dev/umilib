//! The C ABI of [`crate::codec::lz4`]. Block sizes are the codes of the
//! frame format (4 for 64 KiB to 7 for 4 MiB); a null dictionary means none,
//! and an identifier is given with a flag that says whether it is present.

use crate::codec::lz4::{LZ4Block, LZ4BlockSize, LZ4Compressor, LZ4Config, LZ4Decompressor, LZ4DecompressorConfig};
use crate::ffi::{Buffer, Definition, Function, Module, Pointer, Status, ToStatus};

/// The codes of [`LZ4BlockSize`] in the C ABI: those of the frame format.
pub struct LZ4BlockSizeKind;

impl LZ4BlockSizeKind {
    pub fn decode(code: u8) -> Result<LZ4BlockSize, &'static Status> {
        match code {
            4 => Ok(LZ4BlockSize::Maximum64KiB),
            5 => Ok(LZ4BlockSize::Maximum256KiB),
            6 => Ok(LZ4BlockSize::Maximum1MiB),
            7 => Ok(LZ4BlockSize::Maximum4MiB),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes the block of the `length` bytes at `data`, with no history, encoded at `level` (0 to 12), into `out`.
    pub unsafe extern "C" fn umilib_codec_lz4_lz4_block_compress(data: *const u8, length: usize, level: u32, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let block = LZ4Block::compress(data, level).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(block)) }
        })())
    }

    /// Writes the data of the whole block of `length` bytes at `block`, of at most `limit` bytes, into `out`.
    pub unsafe extern "C" fn umilib_codec_lz4_lz4_block_decompress(block: *const u8, length: usize, limit: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let block = unsafe { Pointer::slice(block, length) }?;
            let data = LZ4Block::decompress(block, limit).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(data)) }
        })())
    }

    /// Writes a new frame compressor into `out`: `level` 0 to 12, the block size code 4 to 7, the
    /// flags of the frame, the content size if `has_content_size`, and the dictionary of
    /// `dictionary_length` bytes at `dictionary` (none if null) with its identifier if `has_dictionary_identifier`.
    pub unsafe extern "C" fn umilib_codec_lz4_lz4_compressor_new(
        level: u32,
        block_size: u8,
        independent_blocks: bool,
        block_checksum: bool,
        content_checksum: bool,
        has_content_size: bool,
        content_size: u64,
        dictionary: *const u8,
        dictionary_length: usize,
        has_dictionary_identifier: bool,
        dictionary_identifier: u32,
        out: *mut *mut LZ4Compressor,
    ) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes null or readable bytes.
            let dictionary = if dictionary.is_null() { None } else { Some(unsafe { Pointer::slice(dictionary, dictionary_length) }?.to_vec()) };
            let config = LZ4Config {
                level,
                block_size: LZ4BlockSizeKind::decode(block_size)?,
                independent_blocks,
                block_checksum,
                content_checksum,
                content_size: has_content_size.then_some(content_size),
                dictionary,
                dictionary_identifier: has_dictionary_identifier.then_some(dictionary_identifier),
            };
            let compressor = LZ4Compressor::new(config).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, compressor) }
        })())
    }

    /// Writes a new frame decompressor into `out`: blocks of at most `maximum_block_size` bytes,
    /// a series of frames if `multiple_frames`, and the dictionary of `dictionary_length` bytes at
    /// `dictionary` (none if null) that frames naming the identifier (if `has_dictionary_identifier`) get.
    pub unsafe extern "C" fn umilib_codec_lz4_lz4_decompressor_new(
        maximum_block_size: usize,
        multiple_frames: bool,
        dictionary: *const u8,
        dictionary_length: usize,
        has_dictionary_identifier: bool,
        dictionary_identifier: u32,
        out: *mut *mut LZ4Decompressor,
    ) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes null or readable bytes.
            let dictionary = if dictionary.is_null() { None } else { Some(unsafe { Pointer::slice(dictionary, dictionary_length) }?.to_vec()) };
            let config = LZ4DecompressorConfig {
                maximum_block_size,
                multiple_frames,
                dictionary,
                dictionary_identifier: has_dictionary_identifier.then_some(dictionary_identifier),
            };
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, LZ4Decompressor::new(config)) }
        })())
    }

    /// Writes the defaults: the level, the block size code, independent blocks, block and content
    /// checksums of a compressor, and the maximum block size and multiple frames of a decompressor.
    pub unsafe extern "C" fn umilib_codec_lz4_lz4_config_defaults(
        level: *mut u32,
        block_size: *mut u8,
        independent_blocks: *mut bool,
        block_checksum: *mut bool,
        content_checksum: *mut bool,
        maximum_block_size: *mut usize,
        multiple_frames: *mut bool,
    ) -> *const Status {
        Status::from_result((|| {
            let (config, limits) = (LZ4Config::default(), LZ4DecompressorConfig::default());
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(level, config.level) }?;
            unsafe { Pointer::write(block_size, config.block_size.code()) }?;
            unsafe { Pointer::write(independent_blocks, config.independent_blocks) }?;
            unsafe { Pointer::write(block_checksum, config.block_checksum) }?;
            unsafe { Pointer::write(content_checksum, config.content_checksum) }?;
            unsafe { Pointer::write(maximum_block_size, limits.maximum_block_size) }?;
            unsafe { Pointer::write(multiple_frames, limits.multiple_frames) }
        })())
    }
}

crate::ffi_compressor!(compressor; LZ4Compressor, "umilib_codec_lz4_lz4_compressor", "umilib_codec_lz4_LZ4Compressor");
crate::ffi_decompressor!(decompressor; LZ4Decompressor, "umilib_codec_lz4_lz4_decompressor", "umilib_codec_lz4_LZ4Decompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "lz4",
    definitions: &[
        Definition::Opaque { name: "umilib_codec_lz4_LZ4Compressor", documentation: " A compressor of LZ4 frames." },
        Definition::Opaque {
            name: "umilib_codec_lz4_LZ4Decompressor",
            documentation: " A decompressor of LZ4 frames.",
        },
    ],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + compressor::FUNCTIONS.len() + decompressor::FUNCTIONS.len() }>(
        &[CONSTRUCTORS, compressor::FUNCTIONS, decompressor::FUNCTIONS],
    ),
    modules: &[],
};
