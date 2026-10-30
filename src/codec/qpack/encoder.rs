use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::codec::hpack::{HPACKField, HPACKHuffman, HPACKInteger, HPACKString};

use super::{QPACKDecoder, QPACKDynamicTable, QPACKEncoderConfig, QPACKError, QPACKStaticTable};

/// A field section sent with references to the dynamic table, until the
/// decoder acknowledges or cancels it (RFC 9204 §2.1.4): its stream, its
/// Required Insert Count, and the absolute indices it refers to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct QPACKSection {
    pub stream: u64,
    pub required: u64,
    pub references: Vec<u64>,
}

/// How a field line goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QPACKLine {
    Static(u64),
    Dynamic(u64),
    /// A literal value, with the name of a static or dynamic entry, or literal.
    StaticName(u64),
    DynamicName(u64),
    LiteralName,
}

/// An encoder of field sections (RFC 9204 §2.1, §4.5): fields in the
/// tables go as indices, small ones not sensitive are inserted through the
/// encoder stream, whose instructions the caller sends; entries are evicted
/// only when no section the decoder has not acknowledged refers to them, and
/// references to entries not acknowledged block at most as many streams as
/// the decoder allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QPACKEncoder {
    pub config: QPACKEncoderConfig,
    pub table: QPACKDynamicTable,
    pub huffman: HPACKHuffman,
    /// The inserts the decoder acknowledged: the Known Received Count (§2.1.4).
    pub known_received: u64,
    /// The decoder's SETTINGS_QPACK_BLOCKED_STREAMS.
    pub blocked_streams: usize,
    /// The sections not acknowledged, in the order sent.
    pub sections: Vec<QPACKSection>,
    /// The references of those sections, by absolute index.
    pub references: BTreeMap<u64, u32>,
    /// What arrived on the decoder stream that is not a whole instruction yet.
    pub incoming: Vec<u8>,
    /// The encoder stream's instructions to send.
    pub instructions: Vec<u8>,
}

impl QPACKEncoder {
    /// An encoder that uses no dynamic table until the decoder's settings
    /// are known (RFC 9204 §3.2.3).
    pub fn new(config: QPACKEncoderConfig) -> QPACKEncoder {
        QPACKEncoder {
            config,
            table: QPACKDynamicTable::new(0),
            huffman: HPACKHuffman::new(),
            known_received: 0,
            blocked_streams: 0,
            sections: Vec::new(),
            references: BTreeMap::new(),
            incoming: Vec::new(),
            instructions: Vec::new(),
        }
    }

    /// The decoder's SETTINGS_QPACK_MAX_TABLE_CAPACITY and
    /// SETTINGS_QPACK_BLOCKED_STREAMS: the table takes the configured
    /// capacity within the maximum (Set Dynamic Table Capacity, §4.3.1).
    pub fn set_peer_settings(&mut self, maximum_table_capacity: usize, blocked_streams: usize) {
        self.table.maximum = maximum_table_capacity;
        self.blocked_streams = blocked_streams;
        let capacity = self.config.maximum_table_capacity.min(maximum_table_capacity);
        if capacity != self.table.capacity && self.can_evict_to(capacity) {
            self.table.set_capacity(capacity);
            HPACKInteger::write(&mut self.instructions, 5, 0x20, capacity as u64);
        }
    }

    /// Whether the entry of absolute index `index` may be evicted: the
    /// decoder has it, and no section waiting for acknowledgment refers to it (§2.1.1).
    pub fn is_evictable(&self, index: u64) -> bool {
        index < self.known_received && !self.references.contains_key(&index)
    }

    /// Whether the table can shrink to `capacity` evicting only evictable entries.
    pub fn can_evict_to(&self, capacity: usize) -> bool {
        let mut size = self.table.size;
        for (index, entry) in (self.table.first()..).zip(&self.table.entries) {
            if size <= capacity {
                return true;
            }
            if !self.is_evictable(index) {
                return false;
            }
            size -= entry.size();
        }
        size <= capacity
    }

    /// Whether an entry of `size` can be inserted evicting only evictable entries.
    pub fn can_insert(&self, size: usize) -> bool {
        match self.table.evictions(size) {
            Some(count) => {
                (self.table.first()..self.table.first() + count as u64).all(|index| self.is_evictable(index))
            }
            None => false,
        }
    }

    /// The streams that sections not acknowledged may block.
    pub fn blocking_streams(&self) -> Vec<u64> {
        let mut streams: Vec<u64> = self
            .sections
            .iter()
            .filter(|section| section.required > self.known_received)
            .map(|section| section.stream)
            .collect();
        streams.sort_unstable();
        streams.dedup();
        streams
    }

    /// The encoded field section of `fields` on `stream`, after writing to
    /// the encoder stream the inserts it uses.
    pub fn encode(&mut self, stream: u64, fields: &[HPACKField]) -> Vec<u8> {
        let streams = self.blocking_streams();
        let may_block = self.config.blocking && (streams.contains(&stream) || streams.len() < self.blocked_streams);
        let mut lines = Vec::with_capacity(fields.len());
        let mut references = Vec::new();
        for field in fields {
            let line = self.plan(field, may_block);
            if let QPACKLine::Dynamic(index) | QPACKLine::DynamicName(index) = line {
                *self.references.entry(index).or_insert(0) += 1;
                references.push(index);
            }
            lines.push(line);
        }
        let required = references.iter().max().map_or(0, |largest| largest + 1);
        let base = self.table.inserted;
        let mut out = Vec::new();
        let entries = self.table.maximum_entries();
        let encoded = if required == 0 { 0 } else { required % (2 * entries) + 1 };
        HPACKInteger::write(&mut out, 8, 0, encoded);
        HPACKInteger::write(&mut out, 7, 0, base - required);
        let huffman = self.config.huffman.then_some(&self.huffman);
        for (line, field) in lines.iter().zip(fields) {
            let never = if field.sensitive { 0x20 } else { 0 };
            match *line {
                QPACKLine::Static(index) => HPACKInteger::write(&mut out, 6, 0xC0, index),
                QPACKLine::Dynamic(index) => HPACKInteger::write(&mut out, 6, 0x80, base - 1 - index),
                QPACKLine::StaticName(index) => HPACKInteger::write(&mut out, 4, 0x50 | never, index),
                QPACKLine::DynamicName(index) => HPACKInteger::write(&mut out, 4, 0x40 | never, base - 1 - index),
                QPACKLine::LiteralName => HPACKString::write(&mut out, 3, 0x20 | never >> 1, &field.name, huffman),
            }
            if !matches!(line, QPACKLine::Static(_) | QPACKLine::Dynamic(_)) {
                HPACKString::write(&mut out, 7, 0, &field.value, huffman);
            }
        }
        if required > 0 {
            self.sections.push(QPACKSection { stream, required, references });
        }
        out
    }

    /// How `field` goes, inserting it first when that is worth it and allowed.
    pub fn plan(&mut self, field: &HPACKField, may_block: bool) -> QPACKLine {
        let known = self.known_received;
        let usable = |index: u64| index < known || may_block;
        let fixed = QPACKStaticTable::find(&field.name, &field.value);
        if !field.sensitive {
            if let Some((index, true)) = fixed {
                return QPACKLine::Static(index);
            }
            if let Some((index, true)) = self.table.find(&field.name, &field.value, usable) {
                return QPACKLine::Dynamic(index);
            }
        }
        let dynamic = self.table.find(&field.name, &[], usable).map(|(index, _)| index);
        let size = crate::codec::hpack::HPACKDynamicTable::entry_size(&field.name, &field.value);
        let insert = !field.sensitive && size <= self.config.maximum_indexed_size && self.can_insert(size);
        if insert {
            let huffman = self.config.huffman.then_some(&self.huffman);
            // The name of the entry referred to is copied before the insert may evict it (§3.2.2).
            match (fixed, self.table.find(&field.name, &[], |_| true)) {
                (Some((index, _)), _) => HPACKInteger::write(&mut self.instructions, 6, 0xC0, index),
                (None, Some((index, _))) => {
                    HPACKInteger::write(&mut self.instructions, 6, 0x80, self.table.inserted - 1 - index)
                }
                (None, None) => HPACKString::write(&mut self.instructions, 5, 0x40, &field.name, huffman),
            }
            HPACKString::write(&mut self.instructions, 7, 0, &field.value, huffman);
            self.table.insert(&field.name, &field.value);
            if may_block {
                return QPACKLine::Dynamic(self.table.inserted - 1);
            }
        }
        match (fixed, dynamic) {
            (Some((index, _)), _) => QPACKLine::StaticName(index),
            (None, Some(index)) if self.table.get(index).is_some() => QPACKLine::DynamicName(index),
            _ => QPACKLine::LiteralName,
        }
    }

    /// Takes bytes of the decoder stream (RFC 9204 §4.4): acknowledgments
    /// release the references of sections and raise the Known Received Count.
    pub fn receive_decoder_stream(&mut self, bytes: &[u8]) -> Result<(), QPACKError> {
        self.incoming.extend_from_slice(bytes);
        let incoming = core::mem::take(&mut self.incoming);
        let mut input = &incoming[..];
        while let Some(&first) = input.first() {
            let mut rest = input;
            let prefix = if first & 0x80 != 0 { 7 } else { 6 };
            let value = match HPACKInteger::read(&mut rest, prefix) {
                Ok((_, value)) => value,
                Err(crate::codec::hpack::HPACKError::Truncated) => break,
                Err(_) => return Err(QPACKError::DecoderStream("an instruction that does not decode")),
            };
            input = rest;
            if first & 0x80 == QPACKDecoder::SECTION_ACKNOWLEDGMENT {
                let position = self
                    .sections
                    .iter()
                    .position(|section| section.stream == value)
                    .ok_or(QPACKError::DecoderStream("an acknowledgment of no section"))?;
                let section = self.sections.remove(position);
                self.known_received = self.known_received.max(section.required);
                self.release(&section.references);
            } else if first & 0x40 == QPACKDecoder::STREAM_CANCELLATION {
                let (cancelled, kept): (Vec<QPACKSection>, Vec<QPACKSection>) =
                    core::mem::take(&mut self.sections).into_iter().partition(|section| section.stream == value);
                self.sections = kept;
                for section in cancelled {
                    self.release(&section.references);
                }
            } else {
                let known = self.known_received.checked_add(value).filter(|known| *known <= self.table.inserted);
                match known {
                    Some(known) if value > 0 => self.known_received = known,
                    _ => return Err(QPACKError::DecoderStream("an invalid Insert Count Increment")),
                }
            }
        }
        self.incoming = input.to_vec();
        Ok(())
    }

    /// Releases the references of a section.
    pub fn release(&mut self, references: &[u64]) {
        for index in references {
            if let Some(count) = self.references.get_mut(index) {
                *count -= 1;
                if *count == 0 {
                    self.references.remove(index);
                }
            }
        }
    }

    /// The encoder stream's instructions to send.
    pub fn take_instructions(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.instructions)
    }
}
