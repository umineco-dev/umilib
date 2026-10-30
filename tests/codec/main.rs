//! Tests of `umilib::codec`, against the specifications and their test vectors.

#[cfg(all(umilib_feature = "codec-asn1", umilib_feature = "codec-base-base64"))]
mod asn1;
#[cfg(umilib_feature = "codec-base")]
mod base;
#[cfg(umilib_feature = "codec-brotli")]
mod brotli;
#[cfg(any(
    umilib_feature = "codec-brotli",
    umilib_feature = "codec-deflate",
    umilib_feature = "codec-filter",
    umilib_feature = "codec-huffman",
    umilib_feature = "codec-lz4",
    umilib_feature = "codec-lz77",
    umilib_feature = "codec-lz78",
    umilib_feature = "codec-lzma",
    umilib_feature = "codec-lzss",
    umilib_feature = "codec-rle",
    umilib_feature = "codec-xz",
    umilib_feature = "codec-zstandard"
))]
mod compression;
#[cfg(umilib_feature = "codec-deflate")]
mod deflate;
#[cfg(umilib_feature = "codec-filter")]
mod filter;
#[cfg(umilib_feature = "codec-gzip")]
mod gzip;
#[cfg(umilib_feature = "codec-hpack")]
mod hpack;
#[cfg(umilib_feature = "codec-huffman")]
mod huffman;
#[cfg(umilib_feature = "codec-json")]
mod json;
#[cfg(umilib_feature = "codec-lz4")]
mod lz4;
#[cfg(umilib_feature = "codec-lz77")]
mod lz77;
#[cfg(umilib_feature = "codec-lz78")]
mod lz78;
#[cfg(umilib_feature = "codec-lzma")]
mod lzma;
#[cfg(umilib_feature = "codec-lzss")]
mod lzss;
#[cfg(umilib_feature = "codec-mail")]
mod mail;
#[cfg(umilib_feature = "codec-pem")]
mod pem;
#[cfg(umilib_feature = "codec-qpack")]
mod qpack;
#[cfg(umilib_feature = "codec-rle")]
mod rle;
#[cfg(umilib_feature = "codec-stringprep")]
mod stringprep;
#[cfg(umilib_feature = "codec-uri")]
mod uri;
#[cfg(umilib_feature = "codec-xz")]
mod xz;
#[cfg(umilib_feature = "codec-zlib")]
mod zlib;
#[cfg(umilib_feature = "codec-zstandard")]
mod zstandard;

#[path = "../common/vectors.rs"]
mod vectors;

pub use vectors::Vectors;

/// The test vectors of RFC 4648.
pub struct RFC4648;

impl RFC4648 {
    /// The `NAME("input") = "output"` lines of section 10.
    pub fn vectors(name: &str) -> Vec<(String, String)> {
        let prefix = format!("{name}(\"");
        Vectors::read("codec/base/rfc4648.txt")
            .lines()
            .map(str::trim)
            .filter_map(|line| line.strip_prefix(prefix.as_str()))
            .map(|rest| {
                let (input, output) = rest.split_once("\") = \"").expect("RFC 4648 vector line");
                (input.to_string(), output.trim_end_matches('"').to_string())
            })
            .collect()
    }
}
