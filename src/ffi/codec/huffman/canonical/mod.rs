//! The C ABI of [`crate::codec::huffman::canonical`]. Bit orders are passed
//! as [`BitOrderKind`](crate::ffi::bytes::BitOrderKind) values.

use alloc::vec::Vec;

use crate::codec::huffman::canonical::{
    CanonicalHuffmanCompressor, CanonicalHuffmanConfig, CanonicalHuffmanDecompressor, HuffmanCode, HuffmanTable,
};
use crate::ffi::{Buffer, Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for HuffmanCode {
    const TYPE: Type = Type::Named("umilib_codec_huffman_canonical_HuffmanCode");
}

impl Value for HuffmanTable {
    const TYPE: Type = Type::Named("umilib_codec_huffman_canonical_HuffmanTable");
}

crate::ffi_functions! {
    const CODE;

    /// Writes a new code of the `count` code lengths at `lengths` into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_code_from_lengths(lengths: *const u8, count: usize, out: *mut *mut HuffmanCode) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let lengths = unsafe { Pointer::slice(lengths, count) }?;
            let code = HuffmanCode::from_lengths(lengths).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, code) }
        })())
    }

    /// Writes a new optimal code of the `count` frequencies at `frequencies`, of lengths at most
    /// `maximum_length`, into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_code_from_frequencies(frequencies: *const u32, count: usize, maximum_length: u32, out: *mut *mut HuffmanCode) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes `count` readable frequencies and a writable pointer.
            let frequencies = unsafe { Pointer::slice_of(frequencies, count) }?;
            let code = HuffmanCode::from_frequencies(frequencies, maximum_length).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, code) }
        })())
    }

    /// Writes the code lengths `from_frequencies` assigns, one byte each, into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_code_lengths_from_frequencies(frequencies: *const u32, count: usize, maximum_length: u32, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes `count` readable frequencies and a writable buffer.
            let frequencies = unsafe { Pointer::slice_of(frequencies, count) }?;
            let lengths: Vec<u8> = HuffmanCode::lengths_from_frequencies(frequencies, maximum_length).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(lengths)) }
        })())
    }

    /// Releases a code. Does nothing if `code` is null.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_code_free(code: *mut HuffmanCode) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(code) }
    }

    /// Writes the number of symbols of the alphabet of `code` into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_code_symbols(code: *const HuffmanCode, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let code = unsafe { Pointer::reference(code) }?;
            unsafe { Pointer::write(out, code.symbols()) }
        })())
    }

    /// Writes the code lengths of `code`, one byte per symbol, into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_code_lengths(code: *const HuffmanCode, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let code = unsafe { Pointer::reference(code) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(code.lengths().to_vec())) }
        })())
    }

    /// Writes the length of the code of `symbol` (0 if it has none) into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_code_length(code: *const HuffmanCode, symbol: usize, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let code = unsafe { Pointer::reference(code) }?;
            if symbol >= code.symbols() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write(out, code.length(symbol)) }
        })())
    }

    /// Writes the code of `symbol`, its first bit the most significant of its length, into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_code_code(code: *const HuffmanCode, symbol: usize, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let code = unsafe { Pointer::reference(code) }?;
            if symbol >= code.symbols() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write(out, code.code(symbol)) }
        })())
    }

    /// Writes the code of `symbol` with its bits reversed, its first bit the least significant, into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_code_reversed_code(code: *const HuffmanCode, symbol: usize, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let code = unsafe { Pointer::reference(code) }?;
            if symbol >= code.symbols() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write(out, code.reversed_code(symbol)) }
        })())
    }

    /// Writes the length of the longest code into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_code_maximum_length(code: *const HuffmanCode, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let code = unsafe { Pointer::reference(code) }?;
            unsafe { Pointer::write(out, code.maximum_length()) }
        })())
    }

    /// Writes whether the codes use every sequence of bits into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_code_is_complete(code: *const HuffmanCode, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let code = unsafe { Pointer::reference(code) }?;
            unsafe { Pointer::write(out, code.is_complete()) }
        })())
    }
}

crate::ffi_functions! {
    const TABLE;

    /// Writes a new decoding table of `code` for streams of bit order `order` (0 first bit least
    /// significant, 1 most significant) into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_table_new(code: *const HuffmanCode, order: u8, out: *mut *mut HuffmanTable) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let code = unsafe { Pointer::reference(code) }?;
            let order = crate::ffi::bytes::BitOrderKind::decode(order)?;
            unsafe { Pointer::write_handle(out, HuffmanTable::new(code, order)) }
        })())
    }

    /// Releases a table. Does nothing if `table` is null.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_table_free(table: *mut HuffmanTable) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(table) }
    }

    /// Writes the number of bits to peek before decoding (the longest code) into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_table_peek_bits(table: *const HuffmanTable, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let table = unsafe { Pointer::reference(table) }?;
            unsafe { Pointer::write(out, table.peek_bits()) }
        })())
    }

    /// Decodes the code at the start of `bits`, the next peek_bits bits of a stream in the
    /// order of the table, writing its symbol into `symbol` and its length into `length`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_huffman_table_decode(table: *const HuffmanTable, bits: u64, symbol: *mut u16, length: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let table = unsafe { Pointer::reference(table) }?;
            let (decoded, decoded_length) = table.decode(bits).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(symbol, decoded) }?;
            unsafe { Pointer::write(length, decoded_length) }
        })())
    }
}

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new compressor of blocks of at most `block_size` bytes (at least 1) into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_canonical_huffman_compressor_new(block_size: usize, out: *mut *mut CanonicalHuffmanCompressor) -> *const Status {
        Status::from_result((|| {
            let compressor = CanonicalHuffmanCompressor::new(CanonicalHuffmanConfig { block_size }).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, compressor) }
        })())
    }

    /// Writes the default block size into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_canonical_huffman_config_default_block_size(out: *mut usize) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, CanonicalHuffmanConfig::default().block_size) })
    }

    /// Writes a new decompressor into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_canonical_canonical_huffman_decompressor_new(out: *mut *mut CanonicalHuffmanDecompressor) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, CanonicalHuffmanDecompressor::new()) })
    }
}

crate::ffi_compressor!(compressor; CanonicalHuffmanCompressor, "umilib_codec_huffman_canonical_canonical_huffman_compressor", "umilib_codec_huffman_canonical_CanonicalHuffmanCompressor");
crate::ffi_decompressor!(decompressor; CanonicalHuffmanDecompressor, "umilib_codec_huffman_canonical_canonical_huffman_decompressor", "umilib_codec_huffman_canonical_CanonicalHuffmanDecompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "canonical",
    definitions: &[
        Definition::Opaque {
            name: "umilib_codec_huffman_canonical_HuffmanCode",
            documentation: " A canonical prefix code.",
        },
        Definition::Opaque {
            name: "umilib_codec_huffman_canonical_HuffmanTable",
            documentation: " A table that decodes a canonical prefix code.",
        },
        Definition::Opaque {
            name: "umilib_codec_huffman_canonical_CanonicalHuffmanCompressor",
            documentation: " A compressor of the block format of canonical Huffman codes of umilib.",
        },
        Definition::Opaque {
            name: "umilib_codec_huffman_canonical_CanonicalHuffmanDecompressor",
            documentation: " A decompressor of the block format of canonical Huffman codes of umilib.",
        },
    ],
    functions: &Function::concat::<
        { CODE.len() + TABLE.len() + CONSTRUCTORS.len() + compressor::FUNCTIONS.len() + decompressor::FUNCTIONS.len() },
    >(&[CODE, TABLE, CONSTRUCTORS, compressor::FUNCTIONS, decompressor::FUNCTIONS]),
    modules: &[],
};
