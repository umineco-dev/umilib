use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::codec::hpack::{HPACKDynamicTable, HPACKError, HPACKField, HPACKHuffman, HPACKInteger, HPACKString};

use super::{QPACKDecoderConfig, QPACKDynamicTable, QPACKError, QPACKStaticTable};

/// What decoding a field section gave: its fields, or the need to wait for
/// entries not inserted yet, the stream being blocked (RFC 9204 §2.1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QPACKDecoded {
    Fields(Vec<HPACKField>),
    Blocked,
}

/// A decoder of field sections (RFC 9204 §2.2, §4.5): it reads the
/// encoder stream's instructions into its dynamic table and writes the
/// decoder stream's instructions for the caller to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QPACKDecoder {
    pub config: QPACKDecoderConfig,
    pub table: QPACKDynamicTable,
    pub huffman: HPACKHuffman,
    /// The streams blocked now.
    pub blocked: BTreeSet<u64>,
    /// The inserts the encoder has been told of (its Known Received Count).
    pub acknowledged: u64,
    /// What arrived on the encoder stream that is not a whole instruction yet.
    pub incoming: Vec<u8>,
    /// The decoder stream's instructions to send.
    pub instructions: Vec<u8>,
}

impl QPACKDecoder {
    /// The instructions' first bits (RFC 9204 §4.3, §4.4).
    pub const SECTION_ACKNOWLEDGMENT: u8 = 0x80;
    pub const STREAM_CANCELLATION: u8 = 0x40;
    pub const INSERT_COUNT_INCREMENT: u8 = 0x00;

    pub fn new(config: QPACKDecoderConfig) -> QPACKDecoder {
        QPACKDecoder {
            config,
            table: QPACKDynamicTable::new(config.maximum_table_capacity),
            huffman: HPACKHuffman::new(),
            blocked: BTreeSet::new(),
            acknowledged: 0,
            incoming: Vec::new(),
            instructions: Vec::new(),
        }
    }

    /// Takes bytes of the encoder stream (RFC 9204 §4.3): the whole
    /// instructions among what arrived change the table, the rest waits;
    /// new entries are acknowledged with Insert Count Increment.
    pub fn receive_encoder_stream(&mut self, bytes: &[u8]) -> Result<(), QPACKError> {
        self.incoming.extend_from_slice(bytes);
        let incoming = core::mem::take(&mut self.incoming);
        let mut input = &incoming[..];
        loop {
            let mut rest = input;
            match self.encoder_instruction(&mut rest) {
                Ok(()) => input = rest,
                Err(None) => break,
                Err(Some(error)) => return Err(error),
            }
        }
        // An instruction is a few integers and two strings, which fit the
        // table: at most 30 bits a byte once Huffman-coded (RFC 7541 Appendix B).
        let largest = 4 * self.config.maximum_table_capacity + 64;
        let pending = (2 * self.config.maximum_string_length + 32).min(largest);
        if input.len() > pending {
            return Err(QPACKError::EncoderStream("an instruction longer than the limits"));
        }
        // What waits stays where it is: a partial instruction is not copied again.
        let consumed = incoming.len() - input.len();
        self.incoming = incoming;
        self.incoming.drain(..consumed);
        if self.table.inserted > self.acknowledged {
            let increment = self.table.inserted - self.acknowledged;
            HPACKInteger::write(&mut self.instructions, 6, QPACKDecoder::INSERT_COUNT_INCREMENT, increment);
            self.acknowledged = self.table.inserted;
        }
        Ok(())
    }

    /// One encoder instruction from the front of `input`; `Err(None)` if it
    /// is not whole yet.
    pub fn encoder_instruction(&mut self, input: &mut &[u8]) -> Result<(), Option<QPACKError>> {
        let error = |error: HPACKError| match error {
            HPACKError::Truncated => None,
            _ => Some(QPACKError::EncoderStream("an instruction that does not decode")),
        };
        let first = *input.first().ok_or(None)?;
        let limit = self.config.maximum_string_length;
        let (name, value) = if first & 0x80 != 0 {
            // Insert with Name Reference (§4.3.2).
            let (flags, index) = HPACKInteger::read(input, 6).map_err(error)?;
            let name = if flags & 0x40 != 0 {
                QPACKStaticTable::get(index)
                    .ok_or(Some(QPACKError::EncoderStream("a static index of no entry")))?
                    .0
                    .to_vec()
            } else {
                let absolute = self.table.inserted.checked_sub(index + 1);
                let entry = absolute.and_then(|absolute| self.table.get(absolute));
                entry.ok_or(Some(QPACKError::EncoderStream("a reference to no entry")))?.name().to_vec()
            };
            let (_, value) = HPACKString::read(input, 7, &self.huffman, limit).map_err(error)?;
            (name, value)
        } else if first & 0x40 != 0 {
            // Insert with Literal Name (§4.3.3).
            let (_, name) = HPACKString::read(input, 5, &self.huffman, limit).map_err(error)?;
            let (_, value) = HPACKString::read(input, 7, &self.huffman, limit).map_err(error)?;
            (name, value)
        } else if first & 0x20 != 0 {
            // Set Dynamic Table Capacity (§4.3.1).
            let (_, capacity) = HPACKInteger::read(input, 5).map_err(error)?;
            let capacity = usize::try_from(capacity).unwrap_or(usize::MAX);
            if !self.table.set_capacity(capacity) {
                return Err(Some(QPACKError::EncoderStream("a capacity above the maximum")));
            }
            return Ok(());
        } else {
            // Duplicate (§4.3.4).
            let (_, index) = HPACKInteger::read(input, 5).map_err(error)?;
            let absolute = self.table.inserted.checked_sub(index + 1);
            let entry = absolute.and_then(|absolute| self.table.get(absolute));
            let entry = entry.ok_or(Some(QPACKError::EncoderStream("a duplicate of no entry")))?;
            (entry.name().to_vec(), entry.value().to_vec())
        };
        if !self.table.insert(&name, &value) {
            return Err(Some(QPACKError::EncoderStream("an entry larger than the capacity")));
        }
        Ok(())
    }

    /// The Required Insert Count of an encoded one (RFC 9204 §4.5.1.1).
    pub fn required_insert_count(&self, encoded: u64) -> Result<u64, QPACKError> {
        let invalid = QPACKError::DecompressionFailed("an invalid Required Insert Count");
        if encoded == 0 {
            return Ok(0);
        }
        let entries = self.table.maximum_entries();
        let full = 2 * entries;
        if encoded > full {
            return Err(invalid);
        }
        let maximum = self.table.inserted + entries;
        let wrapped = maximum / full * full;
        let mut required = wrapped + encoded - 1;
        if required > maximum {
            if required <= full {
                return Err(invalid);
            }
            required -= full;
        }
        if required == 0 {
            return Err(invalid);
        }
        Ok(required)
    }

    /// The fields of `section`, the encoded field section of `stream` (RFC
    /// 9204 §4.5), or [`QPACKDecoded::Blocked`] until the encoder stream
    /// brings the entries it needs: the caller decodes it again then. A
    /// section that refers to the dynamic table is acknowledged.
    pub fn decode(&mut self, stream: u64, section: &[u8]) -> Result<QPACKDecoded, QPACKError> {
        let section_error = QPACKError::section;
        let mut input = section;
        let (_, encoded) = HPACKInteger::read(&mut input, 8).map_err(section_error)?;
        let required = self.required_insert_count(encoded)?;
        if required > self.table.inserted {
            if !self.blocked.contains(&stream) {
                if self.blocked.len() >= self.config.blocked_streams {
                    return Err(QPACKError::DecompressionFailed("more blocked streams than allowed"));
                }
                self.blocked.insert(stream);
            }
            return Ok(QPACKDecoded::Blocked);
        }
        self.blocked.remove(&stream);
        let (sign, delta) = HPACKInteger::read(&mut input, 7).map_err(section_error)?;
        let base = if sign & 0x80 != 0 {
            // A negative Base is invalid (RFC 9204 §4.5.1.2).
            required
                .checked_sub(delta)
                .and_then(|base| base.checked_sub(1))
                .filter(|_| required > delta)
                .ok_or(QPACKError::DecompressionFailed("a negative Base"))?
        } else {
            required.checked_add(delta).ok_or(QPACKError::DecompressionFailed("a Base too large"))?
        };
        let mut fields = Vec::new();
        let mut size = 0usize;
        while !input.is_empty() {
            let room = self.config.maximum_field_list_size.saturating_sub(size);
            let (field_size, field) = self.decode_field(&mut input, required, base, room)?;
            size = size.saturating_add(field_size);
            if let Some(field) = field.filter(|_| size <= self.config.maximum_field_list_size) {
                fields.push(field);
            }
        }
        // A section too large is decoded whole and acknowledged all the
        // same, so that the encoder can release its references (RFC 9204 §2.2.2.1).
        if required > 0 {
            HPACKInteger::write(&mut self.instructions, 7, QPACKDecoder::SECTION_ACKNOWLEDGMENT, stream);
            self.acknowledged = self.acknowledged.max(required);
        }
        if size > self.config.maximum_field_list_size {
            return Err(QPACKError::FieldListTooLarge);
        }
        Ok(QPACKDecoded::Fields(fields))
    }

    /// The field line at the front of `input` of a section of `required`
    /// and `base` (RFC 9204 §4.5.2 to §4.5.6): its size, and the field if
    /// its size is at most `room`, so that a section past its limit copies no entry.
    pub fn decode_field(
        &self,
        input: &mut &[u8],
        required: u64,
        base: u64,
        room: usize,
    ) -> Result<(usize, Option<HPACKField>), QPACKError> {
        let section_error = QPACKError::section;
        let first = *input.first().ok_or(QPACKError::DecompressionFailed("a field section cut short"))?;
        let limit = self.config.maximum_string_length;
        let indexed = |(name, value): (&[u8], &[u8])| {
            let size = HPACKDynamicTable::entry_size(name, value);
            (size, (size <= room).then(|| HPACKField::new(name, value)))
        };
        let literal = |name: &[u8], value: Vec<u8>, sensitive: bool| {
            let size = HPACKDynamicTable::entry_size(name, &value);
            (size, (size <= room).then(|| HPACKField { name: name.to_vec(), value, sensitive }))
        };
        if first & 0x80 != 0 {
            // Indexed Field Line (§4.5.2).
            let (flags, index) = HPACKInteger::read(input, 6).map_err(section_error)?;
            let entry = if flags & 0x40 != 0 {
                self.entry(true, Some(index), required)?
            } else {
                self.entry(false, base.checked_sub(index + 1), required)?
            };
            Ok(indexed(entry))
        } else if first & 0x40 != 0 {
            // Literal Field Line with Name Reference (§4.5.4).
            let (flags, index) = HPACKInteger::read(input, 4).map_err(section_error)?;
            let name = if flags & 0x10 != 0 {
                self.entry(true, Some(index), required)?.0
            } else {
                self.entry(false, base.checked_sub(index + 1), required)?.0
            };
            let (_, value) = HPACKString::read(input, 7, &self.huffman, limit).map_err(section_error)?;
            Ok(literal(name, value, flags & 0x20 != 0))
        } else if first & 0x20 != 0 {
            // Literal Field Line with Literal Name (§4.5.6).
            let (flags, name) = HPACKString::read(input, 3, &self.huffman, limit).map_err(section_error)?;
            let (_, value) = HPACKString::read(input, 7, &self.huffman, limit).map_err(section_error)?;
            Ok(literal(&name, value, flags & 0x10 != 0))
        } else if first & 0x10 != 0 {
            // Indexed Field Line with Post-Base Index (§4.5.3).
            let (_, index) = HPACKInteger::read(input, 4).map_err(section_error)?;
            Ok(indexed(self.entry(false, base.checked_add(index), required)?))
        } else {
            // Literal Field Line with Post-Base Name Reference (§4.5.5).
            let (flags, index) = HPACKInteger::read(input, 3).map_err(section_error)?;
            let name = self.entry(false, base.checked_add(index), required)?.0;
            let (_, value) = HPACKString::read(input, 7, &self.huffman, limit).map_err(section_error)?;
            Ok(literal(name, value, flags & 0x08 != 0))
        }
    }

    /// The name and value of the entry of the static table (`fixed`) or of
    /// the dynamic table's absolute `index`, which must be below `required`.
    pub fn entry(&self, fixed: bool, index: Option<u64>, required: u64) -> Result<(&[u8], &[u8]), QPACKError> {
        let index = index.ok_or(QPACKError::DecompressionFailed("a relative index before the first entry"))?;
        if fixed {
            return QPACKStaticTable::get(index).ok_or(QPACKError::DecompressionFailed("a static index of no entry"));
        }
        let entry = (index < required)
            .then(|| self.table.get(index))
            .flatten()
            .ok_or(QPACKError::DecompressionFailed("a reference to no entry"))?;
        Ok((entry.name(), entry.value()))
    }

    /// The application stopped reading `stream`, or it was reset: the
    /// encoder can release its references (RFC 9204 §2.2.2.2).
    pub fn cancel_stream(&mut self, stream: u64) {
        self.blocked.remove(&stream);
        if self.config.maximum_table_capacity > 0 {
            HPACKInteger::write(&mut self.instructions, 6, QPACKDecoder::STREAM_CANCELLATION, stream);
        }
    }

    /// The decoder stream's instructions to send.
    pub fn take_instructions(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.instructions)
    }
}
