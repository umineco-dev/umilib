//! Fuzz targets of `umilib::codec`.

use umilib::platform::fuzz::{FuzzFunction, FuzzTarget};

#[cfg(umilib_feature = "codec-base")]
mod base {
    use umilib::codec::base::Encoding;

    /// Decodes the input with every strict encoding: decoding never panics, and
    /// text that decodes is the unique encoding of its bytes (re-encoding gives
    /// it back). Then encodes the input and checks that it decodes back.
    pub fn round_trips(data: &[u8]) {
        let mut strict: Vec<&dyn Encoding> = Vec::new();
        // Empty (and so not changed) when no lenient encoding is enabled.
        #[allow(unused_mut)]
        let mut lenient: Vec<&dyn Encoding> = Vec::new();
        #[cfg(umilib_feature = "codec-base-base16")]
        lenient.extend([
            &umilib::codec::base::base16::Base16::UPPER as &dyn Encoding,
            &umilib::codec::base::base16::Base16::LOWER,
        ]);
        #[cfg(umilib_feature = "codec-base-base32")]
        strict.extend([
            &umilib::codec::base::base32::Base32::STANDARD as &dyn Encoding,
            &umilib::codec::base::base32::Base32::HEX_NO_PADDING,
        ]);
        #[cfg(umilib_feature = "codec-base-base58")]
        strict.extend([
            &umilib::codec::base::base58::Base58::BITCOIN as &dyn Encoding,
            &umilib::codec::base::base58::Base58::RIPPLE,
        ]);
        #[cfg(umilib_feature = "codec-base-base64")]
        strict.extend([
            &umilib::codec::base::base64::Base64::STANDARD as &dyn Encoding,
            &umilib::codec::base::base64::Base64::URL_SAFE_NO_PADDING,
        ]);
        #[cfg(umilib_feature = "codec-base-base85")]
        {
            strict.extend([
                &umilib::codec::base::base85::Base85::Z85 as &dyn Encoding,
                &umilib::codec::base::base85::Base85::RFC1924,
            ]);
            lenient.push(&umilib::codec::base::base85::Base85::ASCII85_ADOBE);
        }
        for encoding in strict.iter().chain(&lenient) {
            if let Ok(bytes) = encoding.decode(data)
                && strict.iter().any(|candidate| core::ptr::addr_eq(*candidate, *encoding))
            {
                assert_eq!(encoding.encode(&bytes).as_bytes(), data, "decoded text must be canonical");
            }
            if let Ok(text) = encoding.try_encode(data) {
                assert!(text.len() <= encoding.maximum_encoded_length(data.len()).unwrap());
                assert_eq!(encoding.decode(text.as_bytes()).unwrap(), data);
            }
        }
    }
}

#[cfg(umilib_feature = "codec-json")]
mod json {
    use umilib::codec::json::{DuplicateKeys, JSONConfig, JSONEncoder, JSONReader, JSONValue};

    /// Parses the input: the reader and the tree agree on validity, and a
    /// parsed value survives encoding (compact, pretty and ASCII-only).
    pub fn round_trips(data: &[u8]) {
        let config = JSONConfig { duplicate_keys: DuplicateKeys::KeepAll, maximum_depth: 64, ..JSONConfig::default() };
        let valid = JSONReader::new(data, config).and_then(JSONReader::validate);
        let value = JSONValue::decode(data, config);
        assert_eq!(valid.is_ok(), value.is_ok(), "the reader and the tree must agree");
        if let Ok(value) = value {
            for encoder in [JSONEncoder::COMPACT, JSONEncoder::PRETTY, JSONEncoder { indent: None, ascii_only: true }] {
                let text = encoder.encode(&value);
                assert_eq!(JSONValue::decode(text.as_bytes(), config).unwrap(), value);
            }
        }
    }
}

#[cfg(umilib_feature = "codec-pem")]
mod pem {
    use umilib::codec::pem::{PEMConfig, PEMDocument, PEMStrictness};

    /// Parses the input with every grammar. Every document found re-encodes
    /// into strict text that decodes to the same document under every grammar,
    /// and any label and data survive encoding and decoding.
    pub fn round_trips(data: &[u8]) {
        for strictness in [PEMStrictness::Strict, PEMStrictness::Standard, PEMStrictness::Lax] {
            let config = PEMConfig { strictness, ..PEMConfig::default() };
            if let Ok(documents) = PEMDocument::decode_all(data, config) {
                for document in documents {
                    let text = document.encode();
                    for other in [PEMStrictness::Strict, PEMStrictness::Standard, PEMStrictness::Lax] {
                        let again = PEMDocument::decode(
                            text.as_bytes(),
                            PEMConfig { strictness: other, ..PEMConfig::default() },
                        );
                        assert_eq!(again.as_ref(), Ok(&document));
                    }
                }
            }
        }
        if let Ok(label) = core::str::from_utf8(&data[..data.len().min(16)])
            && let Ok(document) = PEMDocument::new(label, data.to_vec())
        {
            assert_eq!(PEMDocument::decode(document.encode().as_bytes(), PEMConfig::default()), Ok(document));
        }
    }
}

#[cfg(umilib_feature = "codec-stringprep")]
mod stringprep {
    use umilib::codec::stringprep::{
        LDAPMatching, LDAPPrep, LDAPString, NormalizationForm, StringPrepProfile, Unassigned,
    };

    /// Normalizes the input (as UTF-8, lossily) in every form: each form is
    /// idempotent, and the composed forms and the compatibility forms do not
    /// depend on the canonical form they start from (UAX #15). SASLprep and
    /// LDAPPrep return for every option, and a query allows whatever a
    /// stored string allows.
    pub fn properties(data: &[u8]) {
        let text = String::from_utf8_lossy(data);
        let [nfd, nfc, nfkd, nfkc] =
            [NormalizationForm::NFD, NormalizationForm::NFC, NormalizationForm::NFKD, NormalizationForm::NFKC]
                .map(|form| form.normalize(&text));
        assert_eq!(NormalizationForm::NFD.normalize(&nfd), nfd);
        assert_eq!(NormalizationForm::NFC.normalize(&nfc), nfc);
        assert_eq!(NormalizationForm::NFKD.normalize(&nfkd), nfkd);
        assert_eq!(NormalizationForm::NFKC.normalize(&nfkc), nfkc);
        assert_eq!(NormalizationForm::NFC.normalize(&nfd), nfc);
        assert_eq!(NormalizationForm::NFD.normalize(&nfc), nfd);
        assert_eq!(NormalizationForm::NFKC.normalize(&nfd), nfkc);
        assert_eq!(NormalizationForm::NFKD.normalize(&nfc), nfkd);
        let stored = StringPrepProfile::SASLPREP.prepare(&text, Unassigned::Prohibited);
        let query = StringPrepProfile::SASLPREP.prepare(&text, Unassigned::Allowed);
        if let Ok(stored) = stored {
            assert_eq!(query, Ok(stored));
        }
        let _ = StringPrepProfile::check_bidi(&text);
        for matching in
            [LDAPMatching::CaseIgnore, LDAPMatching::Exact, LDAPMatching::Numeric, LDAPMatching::TelephoneNumber]
        {
            for kind in
                [LDAPString::Value, LDAPString::InitialSubstring, LDAPString::AnySubstring, LDAPString::FinalSubstring]
            {
                let _ = LDAPPrep::prepare(&text, matching, kind);
            }
        }
    }
}

#[cfg(any(
    umilib_feature = "codec-brotli",
    umilib_feature = "codec-deflate",
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
pub mod compression {
    use umilib::codec::{Compressor, Decompressor};

    /// The most bytes a fuzzed stream may decompress to.
    pub const LIMIT: usize = 1 << 20;

    /// Decompresses the input as a stream (never panicking, and within the
    /// limit), whole and in pieces of 1 to 64 bytes into outputs of 1 to 64
    /// bytes, which must agree; then compresses the input and checks that it
    /// decompresses back.
    pub fn check(data: &[u8], compressor: &mut dyn Compressor, decompressor: &mut dyn Decompressor) {
        decompressor.reset();
        let whole = decompressor.decompress_to_vec(data, LIMIT);
        let piece = 1 + data.first().map_or(0, |byte| *byte as usize % 64);
        decompressor.reset();
        let pieces = Pieces::decompress(decompressor, data, piece, piece);
        match (&whole, &pieces) {
            (Ok(whole), Ok(pieces)) => assert_eq!(whole, pieces, "whole and piecewise decompression must agree"),
            (Err(_), Err(_)) => {}
            _ => panic!("whole and piecewise decompression must agree: {whole:?} {pieces:?}"),
        }
        compressor.reset();
        let stream = compressor.compress_to_vec(data).expect("compression succeeds");
        decompressor.reset();
        assert_eq!(decompressor.decompress_to_vec(&stream, data.len()).as_deref(), Ok(data), "round trip");
    }

    pub struct Pieces;

    impl Pieces {
        /// Decompresses `data` fed `piece` bytes at a time into outputs of
        /// `room` bytes, up to [`LIMIT`] bytes.
        pub fn decompress(
            decompressor: &mut dyn Decompressor,
            data: &[u8],
            piece: usize,
            room: usize,
        ) -> Result<Vec<u8>, umilib::codec::CompressionError> {
            let mut out = Vec::new();
            let mut buffer = vec![0u8; room];
            let (mut position, mut available) = (0, piece.min(data.len()));
            loop {
                let progress = decompressor.decompress(&data[position..available], &mut buffer)?;
                position += progress.consumed;
                out.extend_from_slice(&buffer[..progress.produced]);
                if out.len() > LIMIT {
                    return Err(umilib::codec::CompressionError::LimitExceeded { limit: LIMIT as u64 });
                }
                if progress.finished {
                    return Ok(out);
                }
                if progress.consumed == 0 && progress.produced == 0 {
                    if available == data.len() {
                        decompressor.finish()?;
                        return Ok(out);
                    }
                    available = (available + piece).min(data.len());
                }
            }
        }
    }
}

#[cfg(all(umilib_feature = "codec-huffman-adaptive", umilib_feature = "codec-huffman-canonical"))]
mod huffman {
    use umilib::codec::huffman::adaptive::{AdaptiveHuffmanCompressor, AdaptiveHuffmanDecompressor};
    use umilib::codec::huffman::canonical::{
        CanonicalHuffmanCompressor, CanonicalHuffmanConfig, CanonicalHuffmanDecompressor,
    };

    /// The checks of [`super::compression::check`] for both Huffman formats.
    pub fn round_trips(data: &[u8]) {
        let block_size = 1 + data.len() / 3;
        let mut canonical = CanonicalHuffmanCompressor::new(CanonicalHuffmanConfig { block_size }).unwrap();
        super::compression::check(data, &mut canonical, &mut CanonicalHuffmanDecompressor::new());
        super::compression::check(data, &mut AdaptiveHuffmanCompressor::new(), &mut AdaptiveHuffmanDecompressor::new());
    }
}

#[cfg(any(
    umilib_feature = "codec-lz77",
    umilib_feature = "codec-lz78",
    umilib_feature = "codec-lzss",
    umilib_feature = "codec-rle"
))]
mod lz {
    /// The checks of [`super::compression::check`] for LZ77, LZ78, LZSS and PackBits.
    pub fn round_trips(data: &[u8]) {
        let choice = data.first().copied().unwrap_or(0);
        #[cfg(umilib_feature = "codec-lz77")]
        {
            use umilib::codec::lz77::{LZ77Compressor, LZ77Config, LZ77Decompressor};
            let mut compressor = LZ77Compressor::new(LZ77Config { chain_limit: 1 + choice as usize % 8 }).unwrap();
            super::compression::check(data, &mut compressor, &mut LZ77Decompressor::new());
        }
        #[cfg(umilib_feature = "codec-lz78")]
        {
            use umilib::codec::lz78::{LZ78Compressor, LZ78Config, LZ78Decompressor, LZ78DecompressorConfig};
            let mut compressor = LZ78Compressor::new(LZ78Config { dictionary_bits: 1 + choice as u32 % 12 }).unwrap();
            let mut decompressor = LZ78Decompressor::new(LZ78DecompressorConfig { maximum_dictionary_bits: 12 });
            super::compression::check(data, &mut compressor, &mut decompressor);
        }
        #[cfg(umilib_feature = "codec-lzss")]
        {
            use umilib::codec::lzss::{LZSSCompressor, LZSSConfig, LZSSDecompressor};
            let config =
                if choice & 1 == 0 { LZSSConfig::default() } else { LZSSConfig { position_bits: 5, length_bits: 2 } };
            super::compression::check(
                data,
                &mut LZSSCompressor::new(config).unwrap(),
                &mut LZSSDecompressor::new(config).unwrap(),
            );
        }
        #[cfg(umilib_feature = "codec-rle")]
        {
            use umilib::codec::rle::{PackBitsCompressor, PackBitsDecompressor};
            super::compression::check(data, &mut PackBitsCompressor::new(), &mut PackBitsDecompressor::new());
        }
    }
}

#[cfg(umilib_feature = "codec-deflate")]
mod deflate {
    use umilib::codec::Decompressor;

    /// The checks of [`super::compression::check`] for Deflate (at a level
    /// chosen by the first byte), zlib and gzip; and decompression with a
    /// window of 2^9 bytes either agrees with the full window or fails with
    /// `LimitExceeded` (or as it does).
    pub fn round_trips(data: &[u8]) {
        use umilib::codec::deflate::{
            DeflateCompressor, DeflateConfig, DeflateDecompressor, DeflateDecompressorConfig,
        };
        let level = data.first().map_or(6, |byte| (*byte % 10) as u32);
        let mut compressor = DeflateCompressor::new(DeflateConfig { level, window_bits: 15 }).unwrap();
        super::compression::check(data, &mut compressor, &mut DeflateDecompressor::default());
        let full = DeflateDecompressor::default().decompress_to_vec(data, super::compression::LIMIT);
        let small = DeflateDecompressor::new(DeflateDecompressorConfig { window_bits: 9 })
            .unwrap()
            .decompress_to_vec(data, super::compression::LIMIT);
        match (&full, &small) {
            (_, Err(umilib::codec::CompressionError::LimitExceeded { .. })) => {}
            _ => assert_eq!(full, small, "a smaller window gives the same result or LimitExceeded"),
        }
        #[cfg(umilib_feature = "codec-zlib")]
        {
            use umilib::codec::zlib::{ZlibCompressor, ZlibDecompressor};
            super::compression::check(
                data,
                &mut ZlibCompressor::new(DeflateConfig { level, window_bits: 15 }).unwrap(),
                &mut ZlibDecompressor::default(),
            );
        }
        #[cfg(umilib_feature = "codec-gzip")]
        {
            use umilib::codec::gzip::{GzipCompressor, GzipConfig, GzipDecompressor};
            let config = GzipConfig { deflate: DeflateConfig { level, window_bits: 15 }, ..GzipConfig::default() };
            super::compression::check(
                data,
                &mut GzipCompressor::new(config).unwrap(),
                &mut GzipDecompressor::default(),
            );
        }
    }
}

#[cfg(umilib_feature = "codec-lz4")]
mod lz4 {
    use umilib::codec::lz4::{LZ4Block, LZ4BlockSize, LZ4Compressor, LZ4Config, LZ4Decompressor};

    /// The checks of [`super::compression::check`] for LZ4 frames (with the
    /// options chosen by the first byte); blocks decode within their limit
    /// and the encoder's blocks decode back.
    pub fn round_trips(data: &[u8]) {
        let choice = data.first().copied().unwrap_or(0);
        let config = LZ4Config {
            level: choice as u32 % 13,
            block_size: if choice & 0x10 != 0 { LZ4BlockSize::Maximum256KiB } else { LZ4BlockSize::Maximum64KiB },
            independent_blocks: choice & 0x20 != 0,
            block_checksum: choice & 0x40 != 0,
            content_checksum: choice & 0x80 != 0,
            ..LZ4Config::default()
        };
        super::compression::check(data, &mut LZ4Compressor::new(config).unwrap(), &mut LZ4Decompressor::default());
        if let Ok(decoded) = LZ4Block::decompress(data, super::compression::LIMIT) {
            assert!(decoded.len() <= super::compression::LIMIT);
        }
        let block = LZ4Block::compress(data, choice as u32 % 13).unwrap();
        assert_eq!(LZ4Block::decompress(&block, data.len()).as_deref(), Ok(data));
    }
}

#[cfg(umilib_feature = "codec-lzma")]
mod lzma {
    use umilib::codec::lzma::{
        LZMA2Compressor, LZMA2Decompressor, LZMA2DecompressorConfig, LZMACompressor, LZMAConfig, LZMADecompressor,
        LZMADecompressorConfig,
    };

    /// The checks of [`super::compression::check`] for .lzma files and raw
    /// LZMA2 streams (at a level chosen by the first byte), with small
    /// dictionaries so that inputs cannot ask for much memory.
    pub fn round_trips(data: &[u8]) {
        let level = data.first().map_or(0, |byte| (*byte % 10) as u32);
        let config = LZMAConfig { level, dictionary_size: Some(1 << 16), ..LZMAConfig::default() };
        let limits = LZMADecompressorConfig { maximum_dictionary_size: 1 << 20 };
        super::compression::check(data, &mut LZMACompressor::new(config).unwrap(), &mut LZMADecompressor::new(limits));
        let lzma2 = LZMA2DecompressorConfig { dictionary_size: 1 << 16 };
        super::compression::check(
            data,
            &mut LZMA2Compressor::new(config).unwrap(),
            &mut LZMA2Decompressor::new(lzma2).unwrap(),
        );
    }
}

#[cfg(umilib_feature = "codec-brotli")]
mod brotli {
    use umilib::codec::brotli::{BrotliCompressor, BrotliConfig, BrotliDecompressor, BrotliDecompressorConfig};

    /// The checks of [`super::compression::check`] for Brotli streams (at a
    /// level and a window chosen by the first byte), with windows of at most 1 MiB.
    pub fn round_trips(data: &[u8]) {
        let first = data.first().copied().unwrap_or(0);
        let config = BrotliConfig { level: (first % 12) as u32, window_bits: 10 + (first / 12 % 11) as u32 };
        let limits = BrotliDecompressorConfig { maximum_window_bits: 20 };
        super::compression::check(
            data,
            &mut BrotliCompressor::new(config).unwrap(),
            &mut BrotliDecompressor::new(limits).unwrap(),
        );
    }
}

#[cfg(umilib_feature = "codec-xz")]
mod xz {
    use umilib::codec::filter::bcj::BCJArchitecture;
    use umilib::codec::lzma::LZMAConfig;
    use umilib::codec::xz::{XZCheck, XZCompressor, XZConfig, XZDecompressor, XZDecompressorConfig, XZFilter};

    /// The checks of [`super::compression::check`] for .xz files (a level,
    /// check and BCJ filter chosen by the first byte), with dictionaries of at most 1 MiB.
    pub fn round_trips(data: &[u8]) {
        let first = data.first().copied().unwrap_or(0) as usize;
        let check = [XZCheck::None, XZCheck::CRC32, XZCheck::CRC64, XZCheck::SHA256][first % 4];
        let filters = match first / 4 % 3 {
            0 => Vec::new(),
            1 => vec![XZFilter::Delta { distance: 1 + (first % 7) as u16 }],
            _ => vec![XZFilter::BCJ { architecture: BCJArchitecture::ALL[first % 8], start_offset: 0 }],
        };
        let lzma = LZMAConfig { level: (first % 4) as u32, dictionary_size: Some(1 << 16), ..LZMAConfig::default() };
        let config = XZConfig { lzma, check, filters, block_size: Some(1 + (first as u64 * 37) % 4096) };
        let limits = XZDecompressorConfig { maximum_dictionary_size: 1 << 20, ..XZDecompressorConfig::default() };
        super::compression::check(data, &mut XZCompressor::new(config).unwrap(), &mut XZDecompressor::new(limits));
    }
}

#[cfg(umilib_feature = "codec-filter")]
mod filter {
    use umilib::codec::filter::Filter;

    /// Converts `data` with `filter` in pieces of `piece` bytes, as a stream.
    pub fn convert<F: Filter>(filter: &mut F, data: &[u8], piece: usize, encoding: bool) -> Vec<u8> {
        let (mut out, mut pending) = (Vec::new(), Vec::new());
        for chunk in data.chunks(piece) {
            pending.extend_from_slice(chunk);
            let done = if encoding { filter.encode(&mut pending) } else { filter.decode(&mut pending) };
            assert!(pending.len() - done <= filter.lookahead(), "at most the lookahead is left");
            out.extend(pending.drain(..done));
        }
        out.extend(pending);
        out
    }

    /// Every filter encodes the same in pieces as whole, and decodes back.
    pub fn round_trips(data: &[u8]) {
        let piece = 1 + data.first().map_or(0, |byte| *byte as usize % 64);
        #[cfg(umilib_feature = "codec-filter-bcj")]
        for architecture in umilib::codec::filter::bcj::BCJArchitecture::ALL {
            let start = architecture.alignment() * data.len() as u32;
            let filter = || umilib::codec::filter::bcj::BCJFilter::new(architecture, start).unwrap();
            let whole = convert(&mut filter(), data, data.len().max(1), true);
            assert_eq!(convert(&mut filter(), data, piece, true), whole, "{architecture:?} in pieces");
            assert_eq!(convert(&mut filter(), &whole, piece, false), data, "{architecture:?} decoding");
        }
        #[cfg(umilib_feature = "codec-filter-delta")]
        {
            let distance = 1 + data.len() % 256;
            let filter = || umilib::codec::filter::delta::DeltaFilter::new(distance).unwrap();
            let encoded = convert(&mut filter(), data, piece, true);
            assert_eq!(convert(&mut filter(), &encoded, piece + 1, false), data, "Delta");
        }
    }
}

#[cfg(umilib_feature = "codec-zstandard")]
mod zstandard {
    use umilib::codec::zstandard::{
        ZstandardCompressor, ZstandardConfig, ZstandardDecompressor, ZstandardDecompressorConfig,
    };

    /// The checks of [`super::compression::check`] for Zstandard frames (at
    /// a level chosen by the first byte), with windows of at most 1 MiB.
    pub fn round_trips(data: &[u8]) {
        let level = 1 + data.first().map_or(2, |byte| (*byte % 19) as u32);
        let config = ZstandardConfig { level, window_log: Some(17), ..ZstandardConfig::default() };
        let limits = ZstandardDecompressorConfig { maximum_window: 1 << 20, ..ZstandardDecompressorConfig::default() };
        super::compression::check(
            data,
            &mut ZstandardCompressor::new(config).unwrap(),
            &mut ZstandardDecompressor::new(limits),
        );
    }
}

#[cfg(umilib_feature = "codec-asn1")]
mod asn1 {
    use umilib::codec::asn1::ber::BERReader;
    use umilib::codec::asn1::der::DERReader;

    /// Valid DER is valid BER that converts to itself; any BER that converts
    /// gives valid DER, and converting that again changes nothing.
    pub fn conversions(data: &[u8]) {
        let depth = 32;
        let der = DERReader::validate(data, depth);
        let converted = BERReader::to_der(data, depth);
        if der.is_ok() {
            assert_eq!(converted.as_deref(), Ok(data), "DER must convert to itself");
        }
        if let Ok(converted) = converted {
            assert_eq!(DERReader::validate(&converted, depth), Ok(()), "conversion must give DER");
            assert_eq!(BERReader::to_der(&converted, depth).as_deref(), Ok(&converted[..]));
        }
    }
}

#[cfg(umilib_feature = "codec-asn1")]
pub const ASN1: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-asn1", asn1::conversions);
#[cfg(umilib_feature = "codec-base")]
pub const BASE: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-base", base::round_trips);
#[cfg(umilib_feature = "codec-brotli")]
pub const BROTLI: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-brotli", brotli::round_trips);
#[cfg(umilib_feature = "codec-deflate")]
pub const DEFLATE: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-deflate", deflate::round_trips);
#[cfg(umilib_feature = "codec-filter")]
pub const FILTER: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-filter", filter::round_trips);
/// FSE table descriptions read without panicking, and what reads writes a
/// description of the same distribution; the rest of the input, decoded with the tables
/// as a backward bitstream, decodes without panicking, and a stream read
/// exactly is what the encoder writes for its symbols from the decoder's
/// last state.
#[cfg(umilib_feature = "codec-fse")]
pub const FSE: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-fse", |data| {
    use umilib::bytes::{BackwardBitReader, BackwardBitWriter};
    use umilib::codec::fse::{FSEDecodingTable, FSEDistribution, FSEEncodingTable};
    let Ok((distribution, used)) = FSEDistribution::read(data, 15, 256) else { return };
    let mut description = Vec::new();
    distribution.write(&mut description).expect("a description that reads writes");
    // Descriptions are not unique (a 0 may follow the repeat flags of another), but the written
    // one is never longer and reads back to the same distribution.
    assert!(description.len() <= used);
    assert_eq!(FSEDistribution::read(&description, 15, 256), Ok((distribution.clone(), description.len())));
    let Some(mut reader) = BackwardBitReader::new(&data[used..]) else { return };
    let decoding = FSEDecodingTable::new(&distribution);
    let mut state = decoding.initial_state(&mut reader);
    let mut symbols = Vec::new();
    while !reader.overflowed() && symbols.len() < 4096 {
        symbols.push(decoding.entries[state].symbol as usize);
        if reader.remaining() == 0 {
            break;
        }
        state = decoding.next_state(state, &mut reader);
    }
    if !reader.is_finished() {
        return;
    }
    // A stream read exactly is the encoding of its symbols from the final state.
    let encoding = FSEEncodingTable::new(&distribution);
    let size = 1u32 << distribution.accuracy_log;
    let mut writer = BackwardBitWriter::new();
    let mut state = state as u32 + size;
    for symbol in symbols[..symbols.len() - 1].iter().rev() {
        state = encoding.encode(state, *symbol, &mut writer);
    }
    encoding.flush(state, &mut writer);
    assert_eq!(writer.finish(), data[used..], "decoding and encoding are inverse");
});
/// HPACK field blocks decode without panicking, block after block on one
/// table; what decodes encodes, with and without Huffman, to blocks a fresh
/// decoder reads back to the same fields; Huffman strings round-trip.
#[cfg(umilib_feature = "codec-hpack")]
pub const HPACK: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-hpack", |data| {
    use umilib::codec::hpack::{HPACKDecoder, HPACKDecoderConfig, HPACKEncoder, HPACKEncoderConfig, HPACKHuffman};
    let Some((&selector, rest)) = data.split_first() else { return };
    let huffman = HPACKHuffman::new();
    let mut coded = Vec::new();
    huffman.encode(rest, &mut coded);
    assert_eq!(coded.len(), huffman.encoded_length(rest));
    let mut decoded = Vec::new();
    huffman.decode(&coded, &mut decoded, rest.len()).expect("a coded string decodes");
    assert_eq!(decoded, rest);
    let mut decoder =
        HPACKDecoder::new(HPACKDecoderConfig { maximum_table_size: 256, ..HPACKDecoderConfig::default() });
    let config = HPACKEncoderConfig { huffman: selector & 1 == 1, ..HPACKEncoderConfig::default() };
    let mut encoder = HPACKEncoder::new(config, 4096);
    let mut checker = HPACKDecoder::new(HPACKDecoderConfig::default());
    for block in rest.split(|&byte| byte == selector) {
        let Ok(fields) = decoder.decode(block) else { continue };
        let mut again = Vec::new();
        encoder.encode(&fields, &mut again);
        assert_eq!(checker.decode(&again).expect("an encoded block decodes"), fields);
    }
});

/// QPACK encoder instructions and field sections decode without panicking;
/// what decodes encodes to a section and instructions another decoder
/// reads back to the same fields.
#[cfg(umilib_feature = "codec-qpack")]
pub const QPACK: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-qpack", |data| {
    use umilib::codec::qpack::{QPACKDecoded, QPACKDecoder, QPACKDecoderConfig, QPACKEncoder, QPACKEncoderConfig};
    let Some((&selector, rest)) = data.split_first() else { return };
    let mut decoder = QPACKDecoder::new(QPACKDecoderConfig::default());
    let mut encoder = QPACKEncoder::new(QPACKEncoderConfig::default());
    let mut checker = QPACKDecoder::new(QPACKDecoderConfig::default());
    encoder.set_peer_settings(4096, 16);
    for (index, part) in rest.split(|&byte| byte == selector).enumerate() {
        let stream = index as u64 * 4;
        if index % 2 == 0 {
            let _ = decoder.receive_encoder_stream(part);
            continue;
        }
        let Ok(QPACKDecoded::Fields(fields)) = decoder.decode(stream, part) else { continue };
        let section = encoder.encode(stream, &fields);
        checker.receive_encoder_stream(&encoder.take_instructions()).expect("the encoder's instructions are valid");
        match checker.decode(stream, &section).expect("an encoded section decodes") {
            QPACKDecoded::Fields(again) => assert_eq!(again, fields),
            QPACKDecoded::Blocked => panic!("a section blocked on inserts already sent"),
        }
        encoder.receive_decoder_stream(&checker.take_instructions()).expect("the decoder's instructions are valid");
    }
});

#[cfg(all(umilib_feature = "codec-huffman-adaptive", umilib_feature = "codec-huffman-canonical"))]
pub const HUFFMAN: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-huffman", huffman::round_trips);
#[cfg(umilib_feature = "codec-json")]
pub const JSON: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-json", json::round_trips);
#[cfg(any(
    umilib_feature = "codec-lz77",
    umilib_feature = "codec-lz78",
    umilib_feature = "codec-lzss",
    umilib_feature = "codec-rle"
))]
pub const LZ: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-lz", lz::round_trips);
#[cfg(umilib_feature = "codec-lz4")]
pub const LZ4: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-lz4", lz4::round_trips);
#[cfg(umilib_feature = "codec-lzma")]
pub const LZMA: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-lzma", lzma::round_trips);
#[cfg(umilib_feature = "codec-xz")]
pub const XZ: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-xz", xz::round_trips);
#[cfg(umilib_feature = "codec-zstandard")]
pub const ZSTANDARD: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-zstandard", zstandard::round_trips);
/// Messages, entities, addresses, dates, content types, encoded words and
/// quoted-printable read without panicking; what reads writes back to what
/// reads the same, and what is written reads back.
#[cfg(umilib_feature = "codec-mail")]
pub const MAIL: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-mail", |data| {
    use umilib::codec::mail::{
        MIMEContentType, MIMEEncodedWord, MIMEEntity, MIMEQuotedPrintable, MailAddress, MailConfig, MailDate,
        MailMessage,
    };
    let config = MailConfig::default();
    if let Ok(message) = MailMessage::decode(data, &config) {
        let _ = message.validate();
        assert_eq!(MailMessage::decode(&message.encode(), &config).as_ref(), Ok(&message));
    }
    if let Ok(entity) = MIMEEntity::decode(data, &config) {
        let _ = entity.data(data);
        let _ = entity.disposition();
    }
    if let Ok(addresses) = MailAddress::parse_list(data, true) {
        let text = MailAddress::format_list(&addresses);
        assert_eq!(MailAddress::parse_list(text.as_bytes(), true).as_ref(), Ok(&addresses), "{text}");
    }
    if let Ok(date) = MailDate::parse(data) {
        assert_eq!(MailDate::parse(date.format().as_bytes()), Ok(date));
    }
    // A value of no character set and octets beyond ASCII is written labelled UTF-8, so the
    // written form, not the value read, is what reads back the same.
    if let Ok(content_type) = MIMEContentType::parse(data) {
        let text = content_type.format();
        let again = MIMEContentType::parse(text.as_bytes()).expect("a written content type reads");
        assert_eq!(again.format(), text);
        assert_eq!(
            (again.kind.as_str(), again.subtype.as_str()),
            (content_type.kind.as_str(), content_type.subtype.as_str())
        );
    }
    let _ = MIMEEncodedWord::decode_text(data);
    let text = String::from_utf8_lossy(data);
    assert_eq!(
        MIMEEncodedWord::decode_text(MIMEEncodedWord::encode_text(&text).as_bytes()).as_deref(),
        Ok(text.as_ref())
    );
    let binary = MIMEQuotedPrintable::new(true);
    let mut encoded = Vec::new();
    binary.encode(data, &mut encoded);
    assert_eq!(binary.decode(&encoded), data);
    let _ = MIMEQuotedPrintable::new(false).decode(data);
});
#[cfg(umilib_feature = "codec-pem")]
pub const PEM: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-pem", pem::round_trips);
#[cfg(umilib_feature = "codec-stringprep")]
pub const STRINGPREP: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-stringprep", stringprep::properties);

/// URI references read without panicking; what reads writes back as it was, checks, normalizes
/// to a valid reference that normalizing again leaves as it is, and resolves against a base and
/// against itself to targets that read back the same. Form bodies that read write back to the
/// same pairs, and percent-encoded octets decode to themselves.
#[cfg(umilib_feature = "codec-uri")]
pub const URI: FuzzFunction<fn(&[u8])> = FuzzFunction::new("codec-uri", |data| {
    use umilib::codec::uri::{URIForm, URIPercent, URIReference};
    if let Ok(text) = core::str::from_utf8(data)
        && let Ok(reference) = URIReference::parse(text)
    {
        assert_eq!(reference.to_string(), text);
        assert_eq!(reference.check(), Ok(()));
        let normalized = reference.normalize();
        assert_eq!(normalized.check(), Ok(()), "{normalized}");
        assert_eq!(normalized.normalize(), normalized, "{text}");
        let base = URIReference::parse("http://a/b/c/d;p?q").expect("the base of RFC 3986 §5.4");
        let mut bases = vec![base];
        if reference.scheme.is_some() {
            bases.push(reference.clone());
        }
        for base in &bases {
            let target = reference.resolve(base).expect("an absolute base");
            assert_eq!(URIReference::parse(&target.to_string()).as_ref(), Ok(&target), "{text} against {base}");
        }
    }
    if let Ok(pairs) = URIForm::parse(data) {
        assert_eq!(URIForm::parse(URIForm::encode(&pairs).as_bytes()).as_ref(), Ok(&pairs));
    }
    assert_eq!(URIPercent::decode(URIPercent::encode_component(data).as_bytes()).as_deref(), Ok(data));
    let _ = URIPercent::decode(data);
});

pub const TARGETS: &[&dyn FuzzTarget] = &[
    #[cfg(umilib_feature = "codec-asn1")]
    &ASN1,
    #[cfg(umilib_feature = "codec-base")]
    &BASE,
    #[cfg(umilib_feature = "codec-brotli")]
    &BROTLI,
    #[cfg(umilib_feature = "codec-deflate")]
    &DEFLATE,
    #[cfg(umilib_feature = "codec-filter")]
    &FILTER,
    #[cfg(umilib_feature = "codec-fse")]
    &FSE,
    #[cfg(umilib_feature = "codec-hpack")]
    &HPACK,
    #[cfg(all(umilib_feature = "codec-huffman-adaptive", umilib_feature = "codec-huffman-canonical"))]
    &HUFFMAN,
    #[cfg(umilib_feature = "codec-json")]
    &JSON,
    #[cfg(any(
        umilib_feature = "codec-lz77",
        umilib_feature = "codec-lz78",
        umilib_feature = "codec-lzss",
        umilib_feature = "codec-rle"
    ))]
    &LZ,
    #[cfg(umilib_feature = "codec-lz4")]
    &LZ4,
    #[cfg(umilib_feature = "codec-lzma")]
    &LZMA,
    #[cfg(umilib_feature = "codec-mail")]
    &MAIL,
    #[cfg(umilib_feature = "codec-pem")]
    &PEM,
    #[cfg(umilib_feature = "codec-qpack")]
    &QPACK,
    #[cfg(umilib_feature = "codec-stringprep")]
    &STRINGPREP,
    #[cfg(umilib_feature = "codec-uri")]
    &URI,
    #[cfg(umilib_feature = "codec-xz")]
    &XZ,
    #[cfg(umilib_feature = "codec-zstandard")]
    &ZSTANDARD,
];
