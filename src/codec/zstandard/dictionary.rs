use alloc::vec::Vec;

use super::{ZstandardFormat, ZstandardHuffman, ZstandardOffsets, ZstandardSequenceTables};
use crate::codec::CompressionError;
use crate::codec::fse::{FSEDecodingTable, FSEDistribution};

/// A Zstandard dictionary (RFC 8878 section 5): raw content (any bytes
/// that do not start with the magic number), or a formatted dictionary
/// with an identifier, entropy tables, repeat offsets and its content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZstandardDictionary {
    /// The identifier (0 for raw content).
    pub identifier: u32,
    pub huffman: Option<ZstandardHuffman>,
    pub tables: ZstandardSequenceTables,
    pub offsets: ZstandardOffsets,
    pub content: Vec<u8>,
}

impl ZstandardDictionary {
    /// Reads a dictionary; fails with `InvalidData` for a formatted
    /// dictionary whose tables or offsets are invalid, or raw content of
    /// fewer than 8 bytes.
    pub fn new(bytes: &[u8]) -> Result<ZstandardDictionary, CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        if bytes.len() < 4
            || u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes")) != ZstandardFormat::DICTIONARY_MAGIC
        {
            if bytes.len() < 8 {
                return Err(invalid("raw dictionary of fewer than 8 bytes"));
            }
            return Ok(ZstandardDictionary {
                identifier: 0,
                huffman: None,
                tables: ZstandardSequenceTables::default(),
                offsets: ZstandardOffsets::new(),
                content: bytes.to_vec(),
            });
        }
        let identifier =
            u32::from_le_bytes(bytes.get(4..8).ok_or(invalid("truncated dictionary"))?.try_into().expect("4 bytes"));
        if identifier == 0 {
            return Err(invalid("dictionary identifier of 0"));
        }
        let mut position = 8;
        let (huffman, used) = ZstandardHuffman::read(&bytes[position..])?;
        position += used;
        let mut read = |maximum_log: u32, symbols: usize| -> Result<FSEDecodingTable, CompressionError> {
            let (distribution, used) = FSEDistribution::read(
                bytes.get(position..).ok_or(invalid("truncated dictionary"))?,
                maximum_log,
                symbols,
            )?;
            position += used;
            Ok(FSEDecodingTable::new(&distribution))
        };
        let offset = read(ZstandardFormat::OFFSET_MAXIMUM_LOG, ZstandardFormat::MAXIMUM_OFFSET_CODE as usize + 1)?;
        let match_length = read(ZstandardFormat::MATCH_LENGTH_MAXIMUM_LOG, 53)?;
        let literals_length = read(ZstandardFormat::LITERALS_LENGTH_MAXIMUM_LOG, 36)?;
        let raw = bytes.get(position..position + 12).ok_or(invalid("truncated dictionary"))?;
        let offsets = [0, 4, 8].map(|start| u32::from_le_bytes(raw[start..start + 4].try_into().expect("4 bytes")));
        let content = bytes[position + 12..].to_vec();
        if offsets.iter().any(|offset| *offset == 0 || *offset as usize > content.len()) {
            return Err(invalid("invalid repeat offset of a dictionary"));
        }
        Ok(ZstandardDictionary {
            identifier,
            huffman: Some(huffman),
            tables: ZstandardSequenceTables {
                literals_length: Some(literals_length),
                offset: Some(offset),
                match_length: Some(match_length),
            },
            offsets: ZstandardOffsets { offsets },
            content,
        })
    }
}
