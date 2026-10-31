use alloc::vec::Vec;

use super::ZstandardFormat;
use crate::bytes::{BackwardBitReader, BackwardBitWriter};
use crate::codec::CompressionError;
use crate::codec::fse::{FSEDecodingTable, FSEDistribution, FSEEncodingTable};

/// A sequence of a compressed block: `literals_length` literals, then a
/// match of `match_length` bytes at the offset of `offset_value` (an
/// offset plus 3, or a repeat code of 1 to 3; RFC 8878 section 3.1.1.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZstandardSequence {
    pub literals_length: u32,
    pub offset_value: u32,
    pub match_length: u32,
}

/// The three repeat offsets and their updates (section 3.1.1.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZstandardOffsets {
    pub offsets: [u32; 3],
}

impl ZstandardOffsets {
    pub const fn new() -> ZstandardOffsets {
        ZstandardOffsets { offsets: ZstandardFormat::INITIAL_OFFSETS }
    }

    /// The offset of `offset_value` for a sequence of `literals_length`
    /// literals, after which the repeat offsets are updated; fails with
    /// `InvalidData` for the repeat code that gives 0.
    pub fn resolve(&mut self, offset_value: u32, literals_length: u32) -> Result<u32, CompressionError> {
        if offset_value > 3 {
            let offset = offset_value - 3;
            self.offsets = [offset, self.offsets[0], self.offsets[1]];
            return Ok(offset);
        }
        // Without literals the codes shift by one: 1 is the second offset, 3 the first less one byte.
        let index = (offset_value - 1 + (literals_length == 0) as u32) as usize;
        let offsets = self.offsets;
        match index {
            0 => Ok(offsets[0]),
            1 => {
                self.offsets = [offsets[1], offsets[0], offsets[2]];
                Ok(offsets[1])
            }
            2 => {
                self.offsets = [offsets[2], offsets[0], offsets[1]];
                Ok(offsets[2])
            }
            _ => {
                let offset = offsets[0]
                    .checked_sub(1)
                    .filter(|offset| *offset > 0)
                    .ok_or(CompressionError::InvalidData { reason: "repeat offset of 0" })?;
                self.offsets = [offset, offsets[0], offsets[1]];
                Ok(offset)
            }
        }
    }

    /// The offset value (repeat code if possible) of `offset` for a sequence of `literals_length` literals.
    pub fn encode(&self, offset: u32, literals_length: u32) -> u32 {
        let candidates: [Option<u32>; 3] = if literals_length > 0 {
            [Some(self.offsets[0]), Some(self.offsets[1]), Some(self.offsets[2])]
        } else {
            [Some(self.offsets[1]), Some(self.offsets[2]), self.offsets[0].checked_sub(1)]
        };
        match candidates.iter().position(|candidate| *candidate == Some(offset)) {
            Some(index) => index as u32 + 1,
            None => offset + 3,
        }
    }
}

impl Default for ZstandardOffsets {
    fn default() -> ZstandardOffsets {
        ZstandardOffsets::new()
    }
}

/// The decoding tables of the three kinds of codes of the sequences,
/// kept for the repeat mode of later blocks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZstandardSequenceTables {
    pub literals_length: Option<FSEDecodingTable>,
    pub offset: Option<FSEDecodingTable>,
    pub match_length: Option<FSEDecodingTable>,
}

/// The sequences section of a compressed block (section 3.1.1.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZstandardSequences;

impl ZstandardSequences {
    /// Reads the table of `mode` from `bytes` at `position` (updating
    /// `previous`): predefined, RLE, FSE-compressed or repeated.
    pub fn read_table(
        mode: u8,
        bytes: &[u8],
        position: &mut usize,
        previous: &mut Option<FSEDecodingTable>,
        default: (&[i16], u32),
        maximum_log: u32,
        symbols: usize,
    ) -> Result<(), CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        *previous = Some(match mode {
            ZstandardFormat::PREDEFINED_MODE => {
                FSEDecodingTable::new(&FSEDistribution { accuracy_log: default.1, probabilities: default.0.to_vec() })
            }
            ZstandardFormat::RLE_MODE => {
                let symbol = *bytes.get(*position).ok_or(invalid("truncated sequences section"))?;
                *position += 1;
                if symbol as usize >= symbols {
                    return Err(invalid("invalid symbol of an RLE table"));
                }
                FSEDecodingTable::single(symbol)
            }
            ZstandardFormat::FSE_MODE => {
                let (distribution, used) = FSEDistribution::read(&bytes[*position..], maximum_log, symbols)?;
                *position += used;
                FSEDecodingTable::new(&distribution)
            }
            _ => previous.take().ok_or(invalid("repeat mode without a previous table"))?,
        });
        Ok(())
    }

    /// Decodes the sequences section `bytes` (with the tables of earlier
    /// blocks in `tables`) into `out`.
    pub fn decode(
        bytes: &[u8],
        tables: &mut ZstandardSequenceTables,
        out: &mut Vec<ZstandardSequence>,
    ) -> Result<(), CompressionError> {
        let invalid = |reason| CompressionError::InvalidData { reason };
        out.clear();
        let first = *bytes.first().ok_or(invalid("truncated sequences section"))? as usize;
        let (count, mut position) = match first {
            0 => {
                if bytes.len() != 1 {
                    return Err(invalid("data after an empty sequences section"));
                }
                return Ok(());
            }
            1..=127 => (first, 1),
            128..=254 => {
                (((first - 128) << 8) + *bytes.get(1).ok_or(invalid("truncated sequences section"))? as usize, 2)
            }
            _ => {
                let more = bytes.get(1..3).ok_or(invalid("truncated sequences section"))?;
                (more[0] as usize + ((more[1] as usize) << 8) + 0x7F00, 3)
            }
        };
        let modes = *bytes.get(position).ok_or(invalid("truncated sequences section"))?;
        position += 1;
        if modes & 3 != 0 {
            return Err(invalid("reserved bits of the compression modes set"));
        }
        ZstandardSequences::read_table(
            modes >> 6,
            bytes,
            &mut position,
            &mut tables.literals_length,
            (&ZstandardFormat::LITERALS_LENGTH_DEFAULT, ZstandardFormat::LITERALS_LENGTH_DEFAULT_LOG),
            ZstandardFormat::LITERALS_LENGTH_MAXIMUM_LOG,
            36,
        )?;
        ZstandardSequences::read_table(
            (modes >> 4) & 3,
            bytes,
            &mut position,
            &mut tables.offset,
            (&ZstandardFormat::OFFSET_DEFAULT, ZstandardFormat::OFFSET_DEFAULT_LOG),
            ZstandardFormat::OFFSET_MAXIMUM_LOG,
            ZstandardFormat::MAXIMUM_OFFSET_CODE as usize + 1,
        )?;
        ZstandardSequences::read_table(
            (modes >> 2) & 3,
            bytes,
            &mut position,
            &mut tables.match_length,
            (&ZstandardFormat::MATCH_LENGTH_DEFAULT, ZstandardFormat::MATCH_LENGTH_DEFAULT_LOG),
            ZstandardFormat::MATCH_LENGTH_MAXIMUM_LOG,
            53,
        )?;
        let (literals_table, offset_table, match_table) = (
            tables.literals_length.as_ref().expect("read above"),
            tables.offset.as_ref().expect("read above"),
            tables.match_length.as_ref().expect("read above"),
        );
        let stream = bytes.get(position..).ok_or(invalid("truncated sequences section"))?;
        let mut reader = BackwardBitReader::new(stream).ok_or(invalid("bitstream without its final bit"))?;
        let mut literals_state = literals_table.initial_state(&mut reader);
        let mut offset_state = offset_table.initial_state(&mut reader);
        let mut match_state = match_table.initial_state(&mut reader);
        for index in 0..count {
            let offset_code = offset_table.entries[offset_state].symbol as u32;
            let match_code = match_table.entries[match_state].symbol as usize;
            let literals_code = literals_table.entries[literals_state].symbol as usize;
            if offset_code > ZstandardFormat::MAXIMUM_OFFSET_CODE {
                return Err(invalid("offset code too large"));
            }
            let offset_value = (1u32 << offset_code) + reader.read(offset_code);
            let match_length = ZstandardFormat::MATCH_LENGTH_BASELINES[match_code]
                + reader.read(ZstandardFormat::MATCH_LENGTH_BITS[match_code] as u32);
            let literals_length = ZstandardFormat::LITERALS_LENGTH_BASELINES[literals_code]
                + reader.read(ZstandardFormat::LITERALS_LENGTH_BITS[literals_code] as u32);
            out.push(ZstandardSequence { literals_length, offset_value, match_length });
            if index + 1 < count {
                literals_state = literals_table.next_state(literals_state, &mut reader);
                match_state = match_table.next_state(match_state, &mut reader);
                offset_state = offset_table.next_state(offset_state, &mut reader);
            }
            if reader.overflowed() {
                return Err(invalid("sequences beyond their bitstream"));
            }
        }
        if !reader.is_finished() {
            return Err(invalid("sequences bitstream not consumed exactly"));
        }
        Ok(())
    }

    /// The code of a literals length, a match length (3 or more) and an offset value.
    pub fn codes(sequence: &ZstandardSequence) -> (usize, usize, u32) {
        (
            ZstandardFormat::code(sequence.literals_length, &ZstandardFormat::LITERALS_LENGTH_BASELINES),
            ZstandardFormat::code(sequence.match_length, &ZstandardFormat::MATCH_LENGTH_BASELINES),
            31 - sequence.offset_value.leading_zeros(),
        )
    }

    /// The mode and table of the codes `codes` of one kind: RLE for a single
    /// code, the predefined table when it is cheaper or few codes are used and
    /// it holds them, otherwise an FSE-compressed table (written to `out`).
    pub fn choose_table(
        codes: &[usize],
        symbols: usize,
        default: (&[i16], u32),
        maximum_log: u32,
        out: &mut Vec<u8>,
    ) -> (u8, FSEEncodingTable) {
        let mut counts = alloc::vec![0u32; symbols];
        for code in codes {
            counts[*code] += 1;
        }
        let present = counts.iter().filter(|count| **count > 0).count();
        if present == 1 {
            let symbol = counts.iter().position(|count| *count > 0).expect("a present code");
            out.push(symbol as u8);
            // A table of one state: no bits.
            let table = FSEEncodingTable::new(&FSEDistribution {
                accuracy_log: 0,
                probabilities: alloc::vec![0; symbol].into_iter().chain([1]).collect(),
            });
            return (ZstandardFormat::RLE_MODE, table);
        }
        let predefined = FSEDistribution { accuracy_log: default.1, probabilities: default.0.to_vec() };
        let representable = counts.iter().enumerate().all(|(code, count)| {
            *count == 0 || predefined.probabilities.get(code).is_some_and(|probability| *probability != 0)
        });
        if representable && codes.len() < 64 {
            return (ZstandardFormat::PREDEFINED_MODE, FSEEncodingTable::new(&predefined));
        }
        // An accuracy log fit to the number of codes, within the limits.
        let wanted = (usize::BITS - codes.len().leading_zeros()).saturating_sub(2);
        let needed = usize::BITS - present.leading_zeros();
        let log = wanted.clamp(FSEDistribution::MINIMUM_LOG, maximum_log).max(needed);
        let distribution = FSEDistribution::normalize(&counts, log)
            .expect("2 or more codes, at most 2^log, of an accuracy log of 5 to 9");
        distribution.write(out).expect("an accuracy log of 5 to 9");
        (ZstandardFormat::FSE_MODE, FSEEncodingTable::new(&distribution))
    }

    /// Encodes `sequences` (at least one) as a sequences section.
    pub fn encode(sequences: &[ZstandardSequence], out: &mut Vec<u8>) {
        let count = sequences.len();
        match count {
            0..=127 => out.push(count as u8),
            128..=0x7EFF => out.extend_from_slice(&[(count >> 8) as u8 + 128, count as u8]),
            _ => out.extend_from_slice(&[255, (count - 0x7F00) as u8, ((count - 0x7F00) >> 8) as u8]),
        }
        let codes: Vec<(usize, usize, u32)> = sequences.iter().map(ZstandardSequences::codes).collect();
        let literals_codes: Vec<usize> = codes.iter().map(|codes| codes.0).collect();
        let match_codes: Vec<usize> = codes.iter().map(|codes| codes.1).collect();
        let offset_codes: Vec<usize> = codes.iter().map(|codes| codes.2 as usize).collect();
        let modes_position = out.len();
        out.push(0);
        let (literals_mode, literals_table) = ZstandardSequences::choose_table(
            &literals_codes,
            36,
            (&ZstandardFormat::LITERALS_LENGTH_DEFAULT, ZstandardFormat::LITERALS_LENGTH_DEFAULT_LOG),
            ZstandardFormat::LITERALS_LENGTH_MAXIMUM_LOG,
            out,
        );
        let (offset_mode, offset_table) = ZstandardSequences::choose_table(
            &offset_codes,
            ZstandardFormat::MAXIMUM_OFFSET_CODE as usize + 1,
            (&ZstandardFormat::OFFSET_DEFAULT, ZstandardFormat::OFFSET_DEFAULT_LOG),
            ZstandardFormat::OFFSET_MAXIMUM_LOG,
            out,
        );
        let (match_mode, match_table) = ZstandardSequences::choose_table(
            &match_codes,
            53,
            (&ZstandardFormat::MATCH_LENGTH_DEFAULT, ZstandardFormat::MATCH_LENGTH_DEFAULT_LOG),
            ZstandardFormat::MATCH_LENGTH_MAXIMUM_LOG,
            out,
        );
        out[modes_position] = literals_mode << 6 | offset_mode << 4 | match_mode << 2;
        // The reverse of the decoder's order (as the reference encoder writes it).
        let mut writer = BackwardBitWriter::new();
        let last = count - 1;
        let mut match_state = match_table.initial_state(codes[last].1);
        let mut offset_state = offset_table.initial_state(codes[last].2 as usize);
        let mut literals_state = literals_table.initial_state(codes[last].0);
        ZstandardSequences::write_extra(&sequences[last], &codes[last], &mut writer);
        for index in (0..last).rev() {
            offset_state = offset_table.encode(offset_state, codes[index].2 as usize, &mut writer);
            match_state = match_table.encode(match_state, codes[index].1, &mut writer);
            literals_state = literals_table.encode(literals_state, codes[index].0, &mut writer);
            ZstandardSequences::write_extra(&sequences[index], &codes[index], &mut writer);
        }
        match_table.flush(match_state, &mut writer);
        offset_table.flush(offset_state, &mut writer);
        literals_table.flush(literals_state, &mut writer);
        out.extend(writer.finish());
    }

    /// Writes the extra bits of a sequence: literals length, match length, offset.
    pub fn write_extra(sequence: &ZstandardSequence, codes: &(usize, usize, u32), writer: &mut BackwardBitWriter) {
        let (literals, matches, offset) = *codes;
        writer.write(
            sequence.literals_length - ZstandardFormat::LITERALS_LENGTH_BASELINES[literals],
            ZstandardFormat::LITERALS_LENGTH_BITS[literals] as u32,
        );
        writer.write(
            sequence.match_length - ZstandardFormat::MATCH_LENGTH_BASELINES[matches],
            ZstandardFormat::MATCH_LENGTH_BITS[matches] as u32,
        );
        writer.write(sequence.offset_value - (1 << offset), offset);
    }
}
