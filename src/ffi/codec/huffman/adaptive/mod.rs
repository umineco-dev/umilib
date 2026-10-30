//! The C ABI of [`crate::codec::huffman::adaptive`].

use crate::codec::huffman::adaptive::{AdaptiveHuffmanCompressor, AdaptiveHuffmanDecompressor, AdaptiveHuffmanTree};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus, Type, U128, Value};

impl Value for AdaptiveHuffmanTree {
    const TYPE: Type = Type::Named("umilib_codec_huffman_adaptive_AdaptiveHuffmanTree");
}

crate::ffi_functions! {
    const TREE;

    /// Writes a new tree of an alphabet of `symbols` symbols, before any occurred, into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_adaptive_adaptive_huffman_tree_new(symbols: usize, out: *mut *mut AdaptiveHuffmanTree) -> *const Status {
        Status::from_result((|| {
            let tree = AdaptiveHuffmanTree::new(symbols).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, tree) }
        })())
    }

    /// Releases a tree. Does nothing if `tree` is null.
    pub unsafe extern "C" fn umilib_codec_huffman_adaptive_adaptive_huffman_tree_free(tree: *mut AdaptiveHuffmanTree) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(tree) }
    }

    /// Writes a copy of `tree` into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_adaptive_adaptive_huffman_tree_clone(tree: *const AdaptiveHuffmanTree, out: *mut *mut AdaptiveHuffmanTree) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let tree = unsafe { Pointer::reference(tree) }?;
            unsafe { Pointer::write_handle(out, tree.clone()) }
        })())
    }

    /// Writes the number of symbols of the alphabet of `tree` into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_adaptive_adaptive_huffman_tree_symbols(tree: *const AdaptiveHuffmanTree, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let tree = unsafe { Pointer::reference(tree) }?;
            unsafe { Pointer::write(out, tree.symbols()) }
        })())
    }

    /// Writes the code of `symbol` in the current tree (with the index of an unseen symbol) into
    /// `bits`, its first bit the least significant, and its number of bits into `length`.
    pub unsafe extern "C" fn umilib_codec_huffman_adaptive_adaptive_huffman_tree_code(tree: *const AdaptiveHuffmanTree, symbol: usize, bits: *mut U128, length: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let tree = unsafe { Pointer::reference(tree) }?;
            if symbol >= tree.symbols() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            let (code, code_length) = tree.code(symbol);
            unsafe { Pointer::write(bits, U128::from(code)) }?;
            unsafe { Pointer::write(length, code_length) }
        })())
    }

    /// Counts an occurrence of `symbol` and updates the tree.
    pub unsafe extern "C" fn umilib_codec_huffman_adaptive_adaptive_huffman_tree_update(tree: *mut AdaptiveHuffmanTree, symbol: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let tree = unsafe { Pointer::reference_mut(tree) }?;
            if symbol >= tree.symbols() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            tree.update(symbol);
            Ok(())
        })())
    }
}

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new compressor into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_adaptive_adaptive_huffman_compressor_new(out: *mut *mut AdaptiveHuffmanCompressor) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, AdaptiveHuffmanCompressor::new()) })
    }

    /// Writes a new decompressor into `out`.
    pub unsafe extern "C" fn umilib_codec_huffman_adaptive_adaptive_huffman_decompressor_new(out: *mut *mut AdaptiveHuffmanDecompressor) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, AdaptiveHuffmanDecompressor::new()) })
    }
}

crate::ffi_compressor!(compressor; AdaptiveHuffmanCompressor, "umilib_codec_huffman_adaptive_adaptive_huffman_compressor", "umilib_codec_huffman_adaptive_AdaptiveHuffmanCompressor");
crate::ffi_decompressor!(decompressor; AdaptiveHuffmanDecompressor, "umilib_codec_huffman_adaptive_adaptive_huffman_decompressor", "umilib_codec_huffman_adaptive_AdaptiveHuffmanDecompressor");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "adaptive",
    definitions: &[
        Definition::Opaque {
            name: "umilib_codec_huffman_adaptive_AdaptiveHuffmanTree",
            documentation: " The code tree of adaptive Huffman coding by Vitter's algorithm.",
        },
        Definition::Opaque {
            name: "umilib_codec_huffman_adaptive_AdaptiveHuffmanCompressor",
            documentation: " A compressor of the adaptive Huffman format of umilib.",
        },
        Definition::Opaque {
            name: "umilib_codec_huffman_adaptive_AdaptiveHuffmanDecompressor",
            documentation: " A decompressor of the adaptive Huffman format of umilib.",
        },
    ],
    functions: &Function::concat::<
        { TREE.len() + CONSTRUCTORS.len() + compressor::FUNCTIONS.len() + decompressor::FUNCTIONS.len() },
    >(&[TREE, CONSTRUCTORS, compressor::FUNCTIONS, decompressor::FUNCTIONS]),
    modules: &[],
};
