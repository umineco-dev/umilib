use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::codec::{Compressor, Decompressor, Flush};

use super::{HTTPError, HTTPSyntax};

/// A content coding (RFC 9110 §8.4.1): those of the RFC and of RFC 7932
/// and RFC 8878, each available when its codec's feature is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HTTPContentCoding {
    /// gzip (RFC 1952), feature `codec-gzip`; "x-gzip" is its alias (RFC 9110 §8.4.1.3).
    Gzip,
    /// deflate: the zlib format (RFC 1950), feature `codec-zlib` (RFC 9110 §8.4.1.2).
    Deflate,
    /// br (RFC 7932), feature `codec-brotli`.
    Brotli,
    /// zstd (RFC 8878), feature `codec-zstandard`, within the window of 8 MiB of RFC 9659.
    Zstandard,
}

impl HTTPContentCoding {
    pub const ALL: [HTTPContentCoding; 4] =
        [HTTPContentCoding::Zstandard, HTTPContentCoding::Brotli, HTTPContentCoding::Gzip, HTTPContentCoding::Deflate];
    /// The window decoders of zstd take and encoders keep within (RFC 9659 §3).
    pub const ZSTANDARD_WINDOW: u64 = 8 << 20;

    /// The coding of `name`, compared without case (RFC 9110 §8.4.1).
    pub fn parse(name: &[u8]) -> Option<HTTPContentCoding> {
        let name = name.to_ascii_lowercase();
        match name.as_slice() {
            b"gzip" | b"x-gzip" => Some(HTTPContentCoding::Gzip),
            b"deflate" => Some(HTTPContentCoding::Deflate),
            b"br" => Some(HTTPContentCoding::Brotli),
            b"zstd" => Some(HTTPContentCoding::Zstandard),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static [u8] {
        match self {
            HTTPContentCoding::Gzip => b"gzip",
            HTTPContentCoding::Deflate => b"deflate",
            HTTPContentCoding::Brotli => b"br",
            HTTPContentCoding::Zstandard => b"zstd",
        }
    }

    /// Whether this build has the coding's codec.
    pub fn is_available(&self) -> bool {
        match self {
            HTTPContentCoding::Gzip => cfg!(umilib_feature = "codec-gzip"),
            HTTPContentCoding::Deflate => cfg!(umilib_feature = "codec-zlib"),
            HTTPContentCoding::Brotli => cfg!(umilib_feature = "codec-brotli"),
            HTTPContentCoding::Zstandard => cfg!(umilib_feature = "codec-zstandard"),
        }
    }

    /// The codings this build has, most compact first.
    pub fn available() -> Vec<HTTPContentCoding> {
        HTTPContentCoding::ALL.into_iter().filter(HTTPContentCoding::is_available).collect()
    }

    /// A decompressor of the coding; fails for one this build does not have.
    pub fn decoder(&self) -> Result<Box<dyn Decompressor + Send>, HTTPError> {
        match self {
            #[cfg(umilib_feature = "codec-gzip")]
            HTTPContentCoding::Gzip => {
                return Ok(Box::new(crate::codec::gzip::GzipDecompressor::default()));
            }
            #[cfg(umilib_feature = "codec-zlib")]
            HTTPContentCoding::Deflate => {
                let decoder = crate::codec::zlib::ZlibDecompressor::new(Default::default());
                return Ok(Box::new(decoder.map_err(HTTPContentCoding::failed)?));
            }
            #[cfg(umilib_feature = "codec-brotli")]
            HTTPContentCoding::Brotli => {
                let decoder = crate::codec::brotli::BrotliDecompressor::new(Default::default());
                return Ok(Box::new(decoder.map_err(HTTPContentCoding::failed)?));
            }
            #[cfg(umilib_feature = "codec-zstandard")]
            HTTPContentCoding::Zstandard => {
                let config = crate::codec::zstandard::ZstandardDecompressorConfig {
                    maximum_window: HTTPContentCoding::ZSTANDARD_WINDOW,
                    ..Default::default()
                };
                return Ok(Box::new(crate::codec::zstandard::ZstandardDecompressor::new(config)));
            }
            #[allow(unreachable_patterns)]
            _ => {}
        }
        Err(HTTPError::ContentCoding("a content coding this build does not have"))
    }

    /// A compressor of the coding, with the codec's default level; fails
    /// for one this build does not have.
    pub fn encoder(&self) -> Result<Box<dyn Compressor + Send>, HTTPError> {
        match self {
            #[cfg(umilib_feature = "codec-gzip")]
            HTTPContentCoding::Gzip => {
                let encoder = crate::codec::gzip::GzipCompressor::new(Default::default());
                return Ok(Box::new(encoder.map_err(HTTPContentCoding::failed)?));
            }
            #[cfg(umilib_feature = "codec-zlib")]
            HTTPContentCoding::Deflate => {
                let encoder = crate::codec::zlib::ZlibCompressor::new(Default::default());
                return Ok(Box::new(encoder.map_err(HTTPContentCoding::failed)?));
            }
            #[cfg(umilib_feature = "codec-brotli")]
            HTTPContentCoding::Brotli => {
                let encoder = crate::codec::brotli::BrotliCompressor::new(Default::default());
                return Ok(Box::new(encoder.map_err(HTTPContentCoding::failed)?));
            }
            #[cfg(umilib_feature = "codec-zstandard")]
            HTTPContentCoding::Zstandard => {
                // A window of 2 MiB, within RFC 9659's 8 MiB.
                let config = crate::codec::zstandard::ZstandardConfig { window_log: Some(21), ..Default::default() };
                let encoder = crate::codec::zstandard::ZstandardCompressor::new(config);
                return Ok(Box::new(encoder.map_err(HTTPContentCoding::failed)?));
            }
            #[allow(unreachable_patterns)]
            _ => {}
        }
        Err(HTTPError::ContentCoding("a content coding this build does not have"))
    }

    /// The error of a codec that cannot be made.
    pub fn failed(_: crate::codec::CompressionError) -> HTTPError {
        HTTPError::ContentCoding("a codec that cannot be made")
    }
}

/// The decoder of a message's content (RFC 9110 §8.4): the codings of its
/// Content-Encoding undone in the reverse order of their application,
/// streaming, the content decoded never more than `limit` bytes.
pub struct HTTPContentDecoder {
    /// The decoders, the last coding applied first.
    pub decoders: Vec<Box<dyn Decompressor + Send>>,
    pub limit: u64,
    pub produced: u64,
}

impl core::fmt::Debug for HTTPContentDecoder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("HTTPContentDecoder").field("stages", &self.decoders.len()).finish()
    }
}

impl HTTPContentDecoder {
    /// The bytes each call of a decoder writes at most.
    pub const CHUNK: usize = 16 << 10;

    /// The decoder of the codings listed in `content_encoding` (the field's
    /// lines combined); "identity" is none. Fails for a coding not available.
    pub fn new(content_encoding: &[u8], limit: u64) -> Result<HTTPContentDecoder, HTTPError> {
        let mut decoders = Vec::new();
        for name in HTTPSyntax::list(content_encoding).into_iter().rev() {
            if name.eq_ignore_ascii_case(b"identity") {
                continue;
            }
            let coding = HTTPContentCoding::parse(name).ok_or(HTTPError::ContentCoding("an unknown content coding"))?;
            decoders.push(coding.decoder()?);
        }
        Ok(HTTPContentDecoder { decoders, limit, produced: 0 })
    }

    /// Decodes the next bytes of content into `out`.
    pub fn decode(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), HTTPError> {
        let mut data = input.to_vec();
        for decoder in &mut self.decoders {
            data = HTTPContentDecoder::run(decoder.as_mut(), &data, self.limit)?;
        }
        self.produced += data.len() as u64;
        if self.produced > self.limit {
            return Err(HTTPError::TooLarge("decoded content over the limit"));
        }
        out.extend_from_slice(&data);
        Ok(())
    }

    /// The content ended: every coding must end with it.
    pub fn finish(&mut self) -> Result<(), HTTPError> {
        for decoder in &mut self.decoders {
            decoder.finish().map_err(|_| HTTPError::ContentCoding("coded content cut short"))?;
        }
        Ok(())
    }

    /// The output of one decoder for `input`, within `limit` bytes.
    pub fn run(decoder: &mut (dyn Decompressor + Send), mut input: &[u8], limit: u64) -> Result<Vec<u8>, HTTPError> {
        let mut out = Vec::new();
        let mut chunk = vec![0u8; HTTPContentDecoder::CHUNK];
        loop {
            let progress = decoder
                .decompress(input, &mut chunk)
                .map_err(|_| HTTPError::ContentCoding("content that does not decode"))?;
            input = &input[progress.consumed..];
            out.extend_from_slice(&chunk[..progress.produced]);
            if out.len() as u64 > limit {
                return Err(HTTPError::TooLarge("decoded content over the limit"));
            }
            if progress.finished {
                if !input.is_empty() {
                    return Err(HTTPError::ContentCoding("content after the end of its coding"));
                }
                return Ok(out);
            }
            if progress.consumed == 0 && progress.produced == 0 {
                return Ok(out);
            }
        }
    }
}

/// The encoder of a message's content in one coding, streaming.
pub struct HTTPContentEncoder {
    pub coding: HTTPContentCoding,
    pub encoder: Box<dyn Compressor + Send>,
}

impl core::fmt::Debug for HTTPContentEncoder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("HTTPContentEncoder").field("coding", &self.coding).finish()
    }
}

impl HTTPContentEncoder {
    pub fn new(coding: HTTPContentCoding) -> Result<HTTPContentEncoder, HTTPError> {
        Ok(HTTPContentEncoder { coding, encoder: coding.encoder()? })
    }

    /// Encodes the next bytes of content into `out`, flushing them all if
    /// `flush` (so that the peer can decode them now, as in streaming responses).
    pub fn encode(&mut self, input: &[u8], flush: bool, out: &mut Vec<u8>) -> Result<(), HTTPError> {
        self.run(input, if flush { Flush::Sync } else { Flush::None }, out)
    }

    /// Ends the content.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), HTTPError> {
        self.run(&[], Flush::Finish, out)
    }

    pub fn run(&mut self, mut input: &[u8], flush: Flush, out: &mut Vec<u8>) -> Result<(), HTTPError> {
        let mut chunk = vec![0u8; HTTPContentDecoder::CHUNK];
        loop {
            let progress = self
                .encoder
                .compress(input, &mut chunk, flush)
                .map_err(|_| HTTPError::ContentCoding("content that does not encode"))?;
            input = &input[progress.consumed..];
            out.extend_from_slice(&chunk[..progress.produced]);
            let done = match flush {
                Flush::Finish => progress.finished,
                _ => input.is_empty() && progress.produced < chunk.len(),
            };
            if done {
                return Ok(());
            }
        }
    }
}

/// An Accept-Encoding field (RFC 9110 §12.5.3): codings with their
/// weights in thousandths, "*" for any other, "identity" for none.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HTTPAcceptEncoding {
    pub codings: Vec<(Vec<u8>, u16)>,
}

impl HTTPAcceptEncoding {
    /// The codings of the field's value; malformed elements are left out.
    pub fn parse(value: &[u8]) -> HTTPAcceptEncoding {
        let mut codings = Vec::new();
        for element in HTTPSyntax::list(value) {
            let mut parts = element.split(|byte| *byte == b';');
            let name = HTTPSyntax::trim(parts.next().unwrap_or_default()).to_ascii_lowercase();
            if !HTTPSyntax::is_token(&name) {
                continue;
            }
            let mut weight = Some(1000);
            for parameter in parts {
                let parameter = HTTPSyntax::trim(parameter);
                if let Some(value) = parameter.strip_prefix(b"q=").or_else(|| parameter.strip_prefix(b"Q=")) {
                    weight = HTTPAcceptEncoding::weight(value);
                }
            }
            if let Some(weight) = weight {
                codings.push((name, weight));
            }
        }
        HTTPAcceptEncoding { codings }
    }

    /// A qvalue in thousandths (RFC 9110 §12.4.2): "0" or "1" with up to
    /// three decimals, at most 1.
    pub fn weight(value: &[u8]) -> Option<u16> {
        let (whole, fraction) = match value.iter().position(|byte| *byte == b'.') {
            Some(point) => (&value[..point], &value[point + 1..]),
            None => (value, &[][..]),
        };
        if whole.len() != 1 || fraction.len() > 3 || !fraction.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let mut thousandths = 0u16;
        for index in 0..3 {
            thousandths = thousandths * 10 + fraction.get(index).map_or(0, |digit| u16::from(digit - b'0'));
        }
        match whole[0] {
            b'0' => Some(thousandths),
            b'1' if thousandths == 0 => Some(1000),
            _ => None,
        }
    }

    /// The weight of `name`: its own, else "*"'s; identity is acceptable
    /// unless excluded (RFC 9110 §12.5.3).
    pub fn weight_of(&self, name: &[u8]) -> u16 {
        let own = self.codings.iter().find(|(coding, _)| coding.eq_ignore_ascii_case(name));
        let any = self.codings.iter().find(|(coding, _)| coding == b"*");
        match (own, any) {
            (Some((_, weight)), _) => *weight,
            (None, Some((_, weight))) => *weight,
            (None, None) if name.eq_ignore_ascii_case(b"identity") => 1,
            (None, None) => 0,
        }
    }

    /// The coding of `offered` (in this end's order of preference) with the
    /// highest weight above 0; `None` if identity, no coding, is as good.
    pub fn choose(&self, offered: &[HTTPContentCoding]) -> Option<HTTPContentCoding> {
        let identity = self.weight_of(b"identity");
        let mut best: Option<(HTTPContentCoding, u16)> = None;
        for coding in offered {
            let weight = self.weight_of(coding.name());
            if weight > 0 && weight >= identity && best.is_none_or(|(_, best)| weight > best) {
                best = Some((*coding, weight));
            }
        }
        best.map(|(coding, _)| coding)
    }
}
