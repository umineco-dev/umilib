use alloc::vec::Vec;

use super::{GzipConfig, GzipFormat};
use crate::codec::deflate::DeflateCompressor;
use crate::codec::{CompressionError, Compressor, Flush, PendingOutput, Progress};
use crate::hash::crc::{CRC, CRCCatalogue};

/// Compresses into a gzip member (RFC 1952) with a [`DeflateCompressor`].
#[derive(Clone, Debug)]
pub struct GzipCompressor {
    config: GzipConfig,
    deflate: DeflateCompressor,
    checksum: CRC<'static, u32>,
    size: u32,
    pending: PendingOutput,
    started: bool,
    finished: bool,
}

impl GzipCompressor {
    /// A compressor of the parameters `config`; fails with `InvalidParameter`
    /// outside the ranges of Deflate, for a name or comment with a zero byte
    /// or an extra field longer than 65535 bytes.
    pub fn new(config: GzipConfig) -> Result<GzipCompressor, CompressionError> {
        let header = &config.header;
        let zero_free = |field: &Option<Vec<u8>>| field.as_ref().is_none_or(|bytes| !bytes.contains(&0));
        if !zero_free(&header.name)
            || !zero_free(&header.comment)
            || header.extra.as_ref().is_some_and(|extra| extra.len() > 0xFFFF)
        {
            return Err(CompressionError::InvalidParameter);
        }
        Ok(GzipCompressor {
            deflate: DeflateCompressor::new(config.deflate)?,
            config,
            checksum: CRC::new(CRCCatalogue::CRC32_ISO_HDLC),
            size: 0,
            pending: PendingOutput::new(),
            started: false,
            finished: false,
        })
    }

    pub fn config(&self) -> &GzipConfig {
        &self.config
    }

    /// The bytes of the header of the member.
    pub fn header_bytes(&self) -> Vec<u8> {
        let header = &self.config.header;
        let mut flags = 0;
        for (present, flag) in [
            (header.text, GzipFormat::TEXT),
            (header.header_checksum, GzipFormat::HEADER_CHECKSUM),
            (header.extra.is_some(), GzipFormat::EXTRA),
            (header.name.is_some(), GzipFormat::NAME),
            (header.comment.is_some(), GzipFormat::COMMENT),
        ] {
            if present {
                flags |= flag;
            }
        }
        let extra_flags = match (header.extra_flags, self.config.deflate.level) {
            (0, 9) => GzipFormat::SLOWEST,
            (0, 1) => GzipFormat::FASTEST,
            (flags, _) => flags,
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GzipFormat::MAGIC);
        bytes.extend_from_slice(&[GzipFormat::DEFLATE, flags]);
        bytes.extend_from_slice(&header.modification_time.to_le_bytes());
        bytes.extend_from_slice(&[extra_flags, header.operating_system]);
        if let Some(extra) = &header.extra {
            bytes.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            bytes.extend_from_slice(extra);
        }
        for field in [&header.name, &header.comment].into_iter().flatten() {
            bytes.extend_from_slice(field);
            bytes.push(0);
        }
        if header.header_checksum {
            let checksum = CRC::checksum(CRCCatalogue::CRC32_ISO_HDLC, &bytes) as u16;
            bytes.extend_from_slice(&checksum.to_le_bytes());
        }
        bytes
    }
}

impl Compressor for GzipCompressor {
    fn compress(&mut self, input: &[u8], output: &mut [u8], flush: Flush) -> Result<Progress, CompressionError> {
        if !self.started {
            let header = self.header_bytes();
            self.pending.extend(&header);
            self.started = true;
        }
        let mut produced = self.pending.deliver(output);
        if !self.pending.is_empty() {
            return Ok(Progress { consumed: 0, produced, finished: false });
        }
        let mut consumed = 0;
        if !self.finished {
            let progress = self.deflate.compress(input, &mut output[produced..], flush)?;
            self.checksum.update(&input[..progress.consumed]);
            self.size = self.size.wrapping_add(progress.consumed as u32);
            consumed = progress.consumed;
            produced += progress.produced;
            if progress.finished {
                self.pending.extend(&self.checksum.value().to_le_bytes());
                self.pending.extend(&self.size.to_le_bytes());
                self.finished = true;
            }
        }
        produced += self.pending.deliver(&mut output[produced..]);
        Ok(Progress { consumed, produced, finished: self.finished && self.pending.is_empty() })
    }

    fn reset(&mut self) {
        self.deflate.reset();
        self.checksum.reset();
        self.size = 0;
        self.pending.clear();
        self.started = false;
        self.finished = false;
    }
}
