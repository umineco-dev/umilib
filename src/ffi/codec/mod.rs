//! The C ABI of [`crate::codec`].
//!
//! Every compressed format exports its compressor and decompressor types
//! with the functions of [`ffi_compressor!`](crate::ffi_compressor) and
//! [`ffi_decompressor!`](crate::ffi_decompressor), which report each call in
//! a `umilib_codec_Progress` and take [`FlushKind`] values.

mod compression_error;
mod compressor;
mod decompressor;

pub use compression_error::CompressionStatus;
pub use compressor::FlushKind;

#[cfg(umilib_feature = "codec-asn1")]
pub mod asn1;
#[cfg(umilib_feature = "codec-base")]
pub mod base;
#[cfg(umilib_feature = "codec-brotli")]
pub mod brotli;
#[cfg(umilib_feature = "codec-deflate")]
pub mod deflate;
#[cfg(umilib_feature = "codec-filter")]
pub mod filter;
#[cfg(umilib_feature = "codec-fse")]
pub mod fse;
#[cfg(umilib_feature = "codec-gzip")]
pub mod gzip;
#[cfg(umilib_feature = "codec-hpack")]
pub mod hpack;
#[cfg(umilib_feature = "codec-huffman")]
pub mod huffman;
#[cfg(umilib_feature = "codec-json")]
pub mod json;
#[cfg(umilib_feature = "codec-lz4")]
pub mod lz4;
#[cfg(umilib_feature = "codec-lz77")]
pub mod lz77;
#[cfg(umilib_feature = "codec-lz78")]
pub mod lz78;
#[cfg(umilib_feature = "codec-lzma")]
pub mod lzma;
#[cfg(umilib_feature = "codec-lzss")]
pub mod lzss;
#[cfg(umilib_feature = "codec-mail")]
pub mod mail;
#[cfg(umilib_feature = "codec-pem")]
pub mod pem;
#[cfg(umilib_feature = "codec-qpack")]
pub mod qpack;
#[cfg(umilib_feature = "codec-rle")]
pub mod rle;
#[cfg(umilib_feature = "codec-stringprep")]
pub mod stringprep;
#[cfg(umilib_feature = "codec-uri")]
pub mod uri;
#[cfg(umilib_feature = "codec-xz")]
pub mod xz;
#[cfg(umilib_feature = "codec-zlib")]
pub mod zlib;
#[cfg(umilib_feature = "codec-zstandard")]
pub mod zstandard;

use crate::codec::Progress;
use crate::ffi::{Definition, Module, Parameter, Type, Value};

impl Value for Progress {
    const TYPE: Type = Type::Named("umilib_codec_Progress");
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "codec",
    definitions: &[Definition::Structure {
        name: "umilib_codec_Progress",
        documentation: " What one call of a compressor or a decompressor did: the bytes it consumed and\n \
                        produced, and whether the stream ended.",
        fields: &[
            Parameter { name: "consumed", value: Type::USize },
            Parameter { name: "produced", value: Type::USize },
            Parameter { name: "finished", value: Type::Bool },
        ],
    }],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "codec-asn1")]
        asn1::MODULE,
        #[cfg(umilib_feature = "codec-base")]
        base::MODULE,
        #[cfg(umilib_feature = "codec-brotli")]
        brotli::MODULE,
        #[cfg(umilib_feature = "codec-deflate")]
        deflate::MODULE,
        #[cfg(umilib_feature = "codec-filter")]
        filter::MODULE,
        #[cfg(umilib_feature = "codec-fse")]
        fse::MODULE,
        #[cfg(umilib_feature = "codec-gzip")]
        gzip::MODULE,
        #[cfg(umilib_feature = "codec-hpack")]
        hpack::MODULE,
        #[cfg(umilib_feature = "codec-huffman")]
        huffman::MODULE,
        #[cfg(umilib_feature = "codec-json")]
        json::MODULE,
        #[cfg(umilib_feature = "codec-lz4")]
        lz4::MODULE,
        #[cfg(umilib_feature = "codec-lz77")]
        lz77::MODULE,
        #[cfg(umilib_feature = "codec-lz78")]
        lz78::MODULE,
        #[cfg(umilib_feature = "codec-lzma")]
        lzma::MODULE,
        #[cfg(umilib_feature = "codec-lzss")]
        lzss::MODULE,
        #[cfg(umilib_feature = "codec-mail")]
        mail::MODULE,
        #[cfg(umilib_feature = "codec-pem")]
        pem::MODULE,
        #[cfg(umilib_feature = "codec-qpack")]
        qpack::MODULE,
        #[cfg(umilib_feature = "codec-rle")]
        rle::MODULE,
        #[cfg(umilib_feature = "codec-stringprep")]
        stringprep::MODULE,
        #[cfg(umilib_feature = "codec-uri")]
        uri::MODULE,
        #[cfg(umilib_feature = "codec-xz")]
        xz::MODULE,
        #[cfg(umilib_feature = "codec-zlib")]
        zlib::MODULE,
        #[cfg(umilib_feature = "codec-zstandard")]
        zstandard::MODULE,
    ],
};
