use alloc::vec::Vec;

use super::{
    HPACKDynamicTable, HPACKEncoderConfig, HPACKField, HPACKHuffman, HPACKInteger, HPACKStaticTable, HPACKString,
};

/// An encoder of field blocks (RFC 7541 §6): fields in the tables go as
/// indices, others as literals, added to the dynamic table when they are
/// small enough and not sensitive, with names from the tables; changes of
/// the table's size go first in the next block (§4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HPACKEncoder {
    pub config: HPACKEncoderConfig,
    pub table: HPACKDynamicTable,
    pub huffman: HPACKHuffman,
    /// The decoder's limit on the dynamic table (SETTINGS_HEADER_TABLE_SIZE).
    pub limit: usize,
    /// The dynamic table size updates owed at the start of the next block:
    /// the smallest size since the last block, and the size now (§4.2).
    pub update: Option<(usize, usize)>,
}

impl HPACKEncoder {
    /// The representations' first bits and prefixes (RFC 7541 §6).
    pub const INDEXED: u8 = 0x80;
    pub const INCREMENTAL: u8 = 0x40;
    pub const SIZE_UPDATE: u8 = 0x20;
    pub const NEVER_INDEXED: u8 = 0x10;
    pub const WITHOUT_INDEXING: u8 = 0x00;

    /// An encoder whose decoder allows a table of `limit` bytes at the start
    /// (4096 in HTTP/2).
    pub fn new(config: HPACKEncoderConfig, limit: usize) -> HPACKEncoder {
        let mut encoder = HPACKEncoder {
            config,
            table: HPACKDynamicTable::new(limit),
            huffman: HPACKHuffman::new(),
            limit,
            update: None,
        };
        encoder.resize(config.maximum_table_size.min(limit));
        encoder
    }

    /// The decoder's limit changed (a new SETTINGS_HEADER_TABLE_SIZE): the
    /// table takes the configured size within it.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
        self.resize(self.config.maximum_table_size.min(limit));
    }

    /// Sets the table's size, to be signaled at the start of the next block.
    pub fn resize(&mut self, size: usize) {
        if size == self.table.maximum && self.update.is_none() {
            return;
        }
        let smallest = self.update.map_or(self.table.maximum, |(smallest, _)| smallest).min(size);
        self.update = Some((smallest, size));
        self.table.set_maximum(size);
    }

    /// Appends the block of `fields`.
    pub fn encode(&mut self, fields: &[HPACKField], out: &mut Vec<u8>) {
        if let Some((smallest, size)) = self.update.take() {
            if smallest < size {
                HPACKInteger::write(out, 5, HPACKEncoder::SIZE_UPDATE, smallest as u64);
            }
            HPACKInteger::write(out, 5, HPACKEncoder::SIZE_UPDATE, size as u64);
        }
        for field in fields {
            self.encode_field(field, out);
        }
    }

    /// Appends the representation of `field`.
    pub fn encode_field(&mut self, field: &HPACKField, out: &mut Vec<u8>) {
        let found = self.find(&field.name, &field.value);
        if let Some((index, true)) = found
            && !field.sensitive
        {
            HPACKInteger::write(out, 7, HPACKEncoder::INDEXED, index as u64);
            return;
        }
        let size = field.size();
        let indexed = !field.sensitive && size <= self.config.maximum_indexed_size && size <= self.table.maximum;
        let (prefix, flags) = match (field.sensitive, indexed) {
            (true, _) => (4, HPACKEncoder::NEVER_INDEXED),
            (false, true) => (6, HPACKEncoder::INCREMENTAL),
            (false, false) => (4, HPACKEncoder::WITHOUT_INDEXING),
        };
        let huffman = self.config.huffman.then_some(&self.huffman);
        match found {
            Some((index, _)) => HPACKInteger::write(out, prefix, flags, index as u64),
            None => {
                HPACKInteger::write(out, prefix, flags, 0);
                HPACKString::write(out, 7, 0, &field.name, huffman);
            }
        }
        HPACKString::write(out, 7, 0, &field.value, huffman);
        if indexed {
            self.table.insert(&field.name, &field.value);
        }
    }

    /// The index (static first, the dynamic table from 62) of a field of
    /// `name` and `value`, else of `name`, and whether the value matches.
    pub fn find(&self, name: &[u8], value: &[u8]) -> Option<(usize, bool)> {
        let fixed = HPACKStaticTable::find(name, value);
        if fixed.is_some_and(|(_, exact)| exact) {
            return fixed;
        }
        let dynamic =
            self.table.find(name, value).map(|(index, exact)| (index + HPACKStaticTable::ENTRIES.len() + 1, exact));
        match (fixed, dynamic) {
            (_, Some((index, true))) => Some((index, true)),
            (Some(found), _) => Some(found),
            (None, dynamic) => dynamic,
        }
    }
}
