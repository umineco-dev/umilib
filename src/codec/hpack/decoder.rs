use alloc::vec::Vec;

use super::{
    HPACKDecoderConfig, HPACKDynamicTable, HPACKEncoder, HPACKError, HPACKField, HPACKHuffman, HPACKInteger,
    HPACKStaticTable, HPACKString,
};

/// A decoder of field blocks (RFC 7541 §3, §6), within its limits of the
/// dynamic table, strings and field lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HPACKDecoder {
    pub config: HPACKDecoderConfig,
    pub table: HPACKDynamicTable,
    pub huffman: HPACKHuffman,
    /// The limit of the table this end advertised (SETTINGS_HEADER_TABLE_SIZE).
    pub limit: usize,
    /// Whether the next block must start with a size update, the limit
    /// having fallen below the table's size (RFC 7541 §4.2).
    pub update_required: bool,
}

impl HPACKDecoder {
    pub fn new(config: HPACKDecoderConfig) -> HPACKDecoder {
        HPACKDecoder {
            config,
            table: HPACKDynamicTable::new(config.maximum_table_size),
            huffman: HPACKHuffman::new(),
            limit: config.maximum_table_size,
            update_required: false,
        }
    }

    /// The limit of the table changed: this end's SETTINGS_HEADER_TABLE_SIZE
    /// took effect. Below the table's size, the encoder must signal a new size first.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
        if limit < self.table.maximum {
            self.update_required = true;
        }
    }

    /// The fields of `block`. Fails with [`HPACKError::FieldListTooLarge`]
    /// after decoding all of it when its fields exceed the limit, so that
    /// the table stays in step; with any other error, the table is no
    /// longer in step with the encoder's and the connection must end.
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<HPACKField>, HPACKError> {
        let mut input = block;
        let mut fields = Vec::new();
        let mut size = 0usize;
        let mut started = false;
        while let Some(&first) = input.first() {
            if first & 0xE0 == HPACKEncoder::SIZE_UPDATE {
                let (_, maximum) = HPACKInteger::read(&mut input, 5)?;
                if started || maximum > self.limit as u64 {
                    return Err(HPACKError::InvalidTableSizeUpdate);
                }
                self.table.set_maximum(maximum as usize);
                self.update_required = false;
                continue;
            }
            if self.update_required {
                return Err(HPACKError::InvalidTableSizeUpdate);
            }
            started = true;
            // Past the limit, fields are read only to keep the table in step.
            let room = self.config.maximum_field_list_size.saturating_sub(size);
            let (field_size, field) = self.decode_field(&mut input, first, room)?;
            size = size.saturating_add(field_size);
            if let Some(field) = field.filter(|_| size <= self.config.maximum_field_list_size) {
                fields.push(field);
            }
        }
        if size > self.config.maximum_field_list_size {
            return Err(HPACKError::FieldListTooLarge);
        }
        Ok(fields)
    }

    /// The field line at the front of `input`, whose first byte is `first`:
    /// its size (RFC 7541 §4.1), and the field if its size is at most
    /// `room`, so that a block past its limit copies no entry.
    pub fn decode_field(
        &mut self,
        input: &mut &[u8],
        first: u8,
        room: usize,
    ) -> Result<(usize, Option<HPACKField>), HPACKError> {
        if first & 0x80 == HPACKEncoder::INDEXED {
            let (_, index) = HPACKInteger::read(input, 7)?;
            let (name, value) = self.entry(index)?;
            let size = HPACKDynamicTable::entry_size(name, value);
            let field = (size <= room).then(|| HPACKField::new(name, value));
            return Ok((size, field));
        }
        let (prefix, incremental, sensitive) = match first {
            _ if first & 0xC0 == HPACKEncoder::INCREMENTAL => (6, true, false),
            _ if first & 0xF0 == HPACKEncoder::NEVER_INDEXED => (4, false, true),
            _ => (4, false, false),
        };
        let (_, index) = HPACKInteger::read(input, prefix)?;
        let limit = self.config.maximum_string_length;
        let name = match index {
            0 => HPACKString::read(input, 7, &self.huffman, limit)?.1,
            index => self.entry(index)?.0.to_vec(),
        };
        let (_, value) = HPACKString::read(input, 7, &self.huffman, limit)?;
        if incremental {
            self.table.insert(&name, &value);
        }
        let size = HPACKDynamicTable::entry_size(&name, &value);
        Ok((size, (size <= room).then_some(HPACKField { name, value, sensitive })))
    }

    /// The name and value of the entry of `index` (RFC 7541 §2.3.3).
    pub fn entry(&self, index: u64) -> Result<(&[u8], &[u8]), HPACKError> {
        let index = usize::try_from(index).map_err(|_| HPACKError::InvalidIndex)?;
        if let Some((name, value)) = HPACKStaticTable::get(index) {
            return Ok((name, value));
        }
        let entry = index
            .checked_sub(HPACKStaticTable::ENTRIES.len() + 1)
            .and_then(|index| self.table.get(index))
            .ok_or(HPACKError::InvalidIndex)?;
        Ok((entry.name(), entry.value()))
    }
}
