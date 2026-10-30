use alloc::vec::Vec;

use super::{GzipDecompressorConfig, GzipFormat, GzipHeader};
use crate::codec::deflate::DeflateDecompressor;
use crate::codec::{CompressionError, Decompressor, Progress};
use crate::hash::crc::{CRC, CRCCatalogue};

/// Where a [`GzipDecompressor`] is in its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GzipState {
    /// Reading the 10 bytes of the fixed part of a header.
    Header,
    /// Reading XLEN, then the extra field.
    ExtraLength,
    Extra {
        remaining: usize,
    },
    /// Reading the zero-terminated name, then the comment.
    Name,
    Comment,
    /// Reading the CRC-16 of the header.
    HeaderChecksum,
    /// Decompressing the Deflate stream.
    Data,
    /// Reading the CRC-32 and the size of the data.
    Trailer,
    /// After a member, when members may follow.
    Between,
    /// In the zero bytes after the last member.
    Padding,
    /// After the only member.
    End,
}

/// Decompresses gzip members (RFC 1952), checking their headers (the magic,
/// the method, the reserved flags, the header CRC) and their CRC-32 and
/// size. By default the input is a gzip file whose members end with it
/// ([`GzipDecompressorConfig::multiple_members`]).
#[derive(Clone, Debug)]
pub struct GzipDecompressor {
    config: GzipDecompressorConfig,
    deflate: DeflateDecompressor,
    header: GzipHeader,
    flags: u8,
    /// The CRC-32 of the header so far, then of the data.
    header_checksum: CRC<'static, u32>,
    checksum: CRC<'static, u32>,
    size: u32,
    field: [u8; 10],
    filled: usize,
    members: usize,
    state: GzipState,
}

impl GzipDecompressor {
    pub fn new(config: GzipDecompressorConfig) -> GzipDecompressor {
        GzipDecompressor {
            config,
            deflate: DeflateDecompressor::default(),
            header: GzipHeader::new(),
            flags: 0,
            header_checksum: CRC::new(CRCCatalogue::CRC32_ISO_HDLC),
            checksum: CRC::new(CRCCatalogue::CRC32_ISO_HDLC),
            size: 0,
            field: [0; 10],
            filled: 0,
            members: 0,
            state: GzipState::Header,
        }
    }

    pub fn config(&self) -> GzipDecompressorConfig {
        self.config
    }

    pub fn state(&self) -> GzipState {
        self.state
    }

    /// The header of the member being read, or of the last one.
    pub fn header(&self) -> &GzipHeader {
        &self.header
    }

    /// The number of members read completely.
    pub fn members(&self) -> usize {
        self.members
    }

    /// Fills the field to `length` bytes from `input` (adding them to the
    /// header CRC if `header`); whether it is complete.
    pub fn fill(&mut self, length: usize, input: &mut &[u8], header: bool) -> bool {
        let count = (length - self.filled).min(input.len());
        self.field[self.filled..self.filled + count].copy_from_slice(&input[..count]);
        if header {
            self.header_checksum.update(&input[..count]);
        }
        self.filled += count;
        *input = &input[count..];
        if self.filled < length {
            return false;
        }
        self.filled = 0;
        true
    }

    /// Reads a zero-terminated field into `field`; whether its end was reached.
    pub fn read_string(
        &mut self,
        input: &mut &[u8],
        field: fn(&mut GzipHeader) -> &mut Option<Vec<u8>>,
    ) -> Result<bool, CompressionError> {
        let end = input.iter().position(|byte| *byte == 0);
        let taken = end.map_or(input.len(), |end| end + 1);
        let value = field(&mut self.header).get_or_insert_with(Vec::new);
        let text = &input[..end.unwrap_or(input.len())];
        if value.len() + text.len() > self.config.maximum_field {
            return Err(CompressionError::LimitExceeded { limit: self.config.maximum_field as u64 });
        }
        value.extend_from_slice(text);
        self.header_checksum.update(&input[..taken]);
        *input = &input[taken..];
        Ok(end.is_some())
    }

    /// The optional fields of a header in their order, with the state that reads each.
    pub const FIELDS: [(u8, GzipState); 4] = [
        (GzipFormat::EXTRA, GzipState::ExtraLength),
        (GzipFormat::NAME, GzipState::Name),
        (GzipFormat::COMMENT, GzipState::Comment),
        (GzipFormat::HEADER_CHECKSUM, GzipState::HeaderChecksum),
    ];

    /// The state that reads the first field present after the field of
    /// `flag` (after the fixed part for 0); the data when none is.
    pub fn after(&self, flag: u8) -> GzipState {
        let start = GzipDecompressor::FIELDS.iter().position(|(field, _)| *field == flag).map_or(0, |index| index + 1);
        GzipDecompressor::FIELDS[start..]
            .iter()
            .find(|(field, _)| self.flags & field != 0)
            .map_or(GzipState::Data, |(_, state)| *state)
    }

    /// Starts a member: an empty header, the checksums and the Deflate stream.
    pub fn start_member(&mut self) {
        self.header = GzipHeader::new();
        self.header_checksum.reset();
        self.checksum.reset();
        self.size = 0;
        self.deflate.reset();
        self.state = GzipState::Header;
    }
}

impl Default for GzipDecompressor {
    fn default() -> GzipDecompressor {
        GzipDecompressor::new(GzipDecompressorConfig::default())
    }
}

impl Decompressor for GzipDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CompressionError> {
        let mut rest = input;
        let mut produced = 0;
        loop {
            match self.state {
                GzipState::Header => {
                    if !self.fill(10, &mut rest, true) {
                        break;
                    }
                    let field = self.field;
                    if field[..2] != GzipFormat::MAGIC {
                        return Err(CompressionError::InvalidData { reason: "not a gzip member" });
                    }
                    if field[2] != GzipFormat::DEFLATE {
                        return Err(CompressionError::InvalidData { reason: "invalid compression method" });
                    }
                    if field[3] & GzipFormat::RESERVED != 0 {
                        return Err(CompressionError::InvalidData { reason: "reserved flags set" });
                    }
                    self.flags = field[3];
                    self.header.text = self.flags & GzipFormat::TEXT != 0;
                    self.header.header_checksum = self.flags & GzipFormat::HEADER_CHECKSUM != 0;
                    self.header.modification_time = u32::from_le_bytes([field[4], field[5], field[6], field[7]]);
                    self.header.extra_flags = field[8];
                    self.header.operating_system = field[9];
                    self.state = self.after(0);
                }
                GzipState::ExtraLength => {
                    if !self.fill(2, &mut rest, true) {
                        break;
                    }
                    let length = u16::from_le_bytes([self.field[0], self.field[1]]) as usize;
                    if length > self.config.maximum_field {
                        return Err(CompressionError::LimitExceeded { limit: self.config.maximum_field as u64 });
                    }
                    self.header.extra = Some(Vec::with_capacity(length));
                    self.state = GzipState::Extra { remaining: length };
                }
                GzipState::Extra { remaining } => {
                    let count = remaining.min(rest.len());
                    self.header.extra.get_or_insert_with(Vec::new).extend_from_slice(&rest[..count]);
                    self.header_checksum.update(&rest[..count]);
                    rest = &rest[count..];
                    if count < remaining {
                        self.state = GzipState::Extra { remaining: remaining - count };
                        break;
                    }
                    self.state = self.after(GzipFormat::EXTRA);
                }
                GzipState::Name => {
                    if !self.read_string(&mut rest, |header| &mut header.name)? {
                        break;
                    }
                    self.state = self.after(GzipFormat::NAME);
                }
                GzipState::Comment => {
                    if !self.read_string(&mut rest, |header| &mut header.comment)? {
                        break;
                    }
                    self.state = self.after(GzipFormat::COMMENT);
                }
                GzipState::HeaderChecksum => {
                    let expected = self.header_checksum.value() as u16;
                    if !self.fill(2, &mut rest, false) {
                        break;
                    }
                    if u16::from_le_bytes([self.field[0], self.field[1]]) != expected {
                        return Err(CompressionError::ChecksumMismatch);
                    }
                    self.state = GzipState::Data;
                }
                GzipState::Data => {
                    let progress = self.deflate.decompress(rest, &mut output[produced..])?;
                    let data = &output[produced..produced + progress.produced];
                    self.checksum.update(data);
                    self.size = self.size.wrapping_add(data.len() as u32);
                    rest = &rest[progress.consumed..];
                    produced += progress.produced;
                    if !progress.finished {
                        break;
                    }
                    self.state = GzipState::Trailer;
                }
                GzipState::Trailer => {
                    if !self.fill(8, &mut rest, false) {
                        break;
                    }
                    let field = self.field;
                    if u32::from_le_bytes([field[0], field[1], field[2], field[3]]) != self.checksum.value()
                        || u32::from_le_bytes([field[4], field[5], field[6], field[7]]) != self.size
                    {
                        return Err(CompressionError::ChecksumMismatch);
                    }
                    self.members += 1;
                    self.state = if self.config.multiple_members { GzipState::Between } else { GzipState::End };
                }
                GzipState::Between => match rest.first() {
                    None => break,
                    Some(0) => self.state = GzipState::Padding,
                    Some(_) => self.start_member(),
                },
                GzipState::Padding => {
                    let zeros = rest.iter().take_while(|byte| **byte == 0).count();
                    rest = &rest[zeros..];
                    if !rest.is_empty() {
                        return Err(CompressionError::InvalidData {
                            reason: "data after the padding of the last member",
                        });
                    }
                    break;
                }
                GzipState::End => break,
            }
        }
        Ok(Progress { consumed: input.len() - rest.len(), produced, finished: self.state == GzipState::End })
    }

    /// The input may end after the trailer of a member (and its padding).
    fn finish(&mut self) -> Result<(), CompressionError> {
        match self.state {
            GzipState::End => Ok(()),
            GzipState::Between | GzipState::Padding => {
                self.state = GzipState::End;
                Ok(())
            }
            _ => Err(CompressionError::UnexpectedEnd),
        }
    }

    fn reset(&mut self) {
        self.start_member();
        self.filled = 0;
        self.members = 0;
    }
}
