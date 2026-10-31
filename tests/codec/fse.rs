//! Finite State Entropy (RFC 8878 section 4.1): the decoding tables of
//! Appendix A, the table descriptions of section 4.1.1 against an encoder
//! written here from the text, the inverse relation of the encoding and
//! decoding tables, and round trips over backward bitstreams.

use umilib::bytes::{BackwardBitReader, BackwardBitWriter};
use umilib::codec::CompressionError;
use umilib::codec::fse::{FSEDecodingEntry, FSEDecodingTable, FSEDistribution, FSEEncodingTable};

use crate::Vectors;
use crate::compression::Samples;

/// The predefined distributions of RFC 8878 and the decoding tables of its Appendix A.
pub struct RFC8878;

impl RFC8878 {
    /// The distributions of sections 3.1.1.3.2.2.1 to 3.1.1.3.2.2.3 (literals
    /// length, match length, offset codes) and their accuracy logs, in the
    /// order of the tables of Appendix A.
    pub const PREDEFINED: [(&'static [i16], u32); 3] = [
        (
            &[
                4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1,
                -1, -1,
            ],
            6,
        ),
        (
            &[
                1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
            ],
            6,
        ),
        (&[1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1], 5),
    ];

    /// The rows (state, symbol, bits, base) of each table of Appendix A, without the first row
    /// (the header example).
    pub fn appendix_tables() -> Vec<Vec<(usize, u8, u8, u16)>> {
        let text = Vectors::read("codec/zstandard/rfc8878-appendix-a.txt");
        let mut tables: Vec<Vec<(usize, u8, u8, u16)>> = Vec::new();
        for line in text.lines() {
            if line.contains("| State |") {
                tables.push(Vec::new());
                continue;
            }
            let fields: Vec<&str> = line.split('|').map(str::trim).filter(|field| !field.is_empty()).collect();
            if fields.len() == 4 && fields.iter().all(|field| field.parse::<u32>().is_ok()) {
                let values: Vec<u32> = fields.iter().map(|field| field.parse().unwrap()).collect();
                tables.last_mut().unwrap().push((
                    values[0] as usize,
                    values[1] as u8,
                    values[2] as u8,
                    values[3] as u16,
                ));
            }
        }
        tables.into_iter().map(|table| table[1..].to_vec()).collect()
    }

    /// A table description of `probabilities` on a scale of 2^`log`, written from the text of
    /// section 4.1.1: 4 bits of accuracy log - 5; then per symbol, until the total reaches the
    /// scale, the probability + 1 in log2sup(remaining + 1) bits, the values below
    /// 2^bits - 1 - (remaining + 1) in one bit less, the others above 2^(bits - 1) - 1 offset by
    /// that count; after a 0, 2-bit repeat flags of more zeros (3: another flag follows). Bits
    /// are packed least significant first, the last byte padded with zeros.
    pub fn describe(log: u32, probabilities: &[i16]) -> Vec<u8> {
        let mut bits: Vec<bool> = Vec::new();
        let mut put = |value: u32, count: u32| bits.extend((0..count).map(|bit| value >> bit & 1 == 1));
        put(log - 5, 4);
        let mut remaining = 1i32 << log;
        let mut symbol = 0;
        while remaining > 0 {
            let probability = probabilities[symbol] as i32;
            let maximum = remaining + 1;
            // log2sup(maximum): the smallest T with 2^T > maximum.
            let mut width = 0;
            while (1 << width) <= maximum {
                width += 1;
            }
            let low = (1 << width) - 1 - maximum;
            let value = probability + 1;
            if value < low {
                put(value as u32, width - 1);
            } else if value < 1 << (width - 1) {
                put(value as u32, width);
            } else {
                put((value + low) as u32, width);
            }
            remaining -= if probability == -1 { 1 } else { probability };
            symbol += 1;
            if probability == 0 {
                let mut zeros = probabilities[symbol..].iter().take_while(|probability| **probability == 0).count();
                symbol += zeros;
                loop {
                    let flag = zeros.min(3);
                    put(flag as u32, 2);
                    zeros -= flag;
                    if flag < 3 {
                        break;
                    }
                }
            }
        }
        bits.chunks(8)
            .map(|byte| byte.iter().enumerate().fold(0u8, |value, (index, bit)| value | (*bit as u8) << index))
            .collect()
    }

    /// The total of `probabilities` (-1 counting as 1).
    pub fn total(probabilities: &[i16]) -> i32 {
        probabilities.iter().map(|probability| if *probability == -1 { 1 } else { *probability as i32 }).sum()
    }
}

#[test]
fn decoding_tables_follow_appendix_a() {
    let tables = RFC8878::appendix_tables();
    assert_eq!(tables.len(), 3);
    for (rows, (probabilities, log)) in tables.iter().zip(RFC8878::PREDEFINED) {
        let distribution = FSEDistribution::new(log, probabilities.to_vec()).unwrap();
        let table = FSEDecodingTable::new(&distribution);
        assert_eq!(table.accuracy_log, log);
        assert_eq!(rows.len(), 1 << log);
        assert_eq!(table.entries.len(), 1 << log);
        for (state, symbol, bits, base) in rows {
            assert_eq!(
                table.entries[*state],
                FSEDecodingEntry { symbol: *symbol, bits: *bits, baseline: *base },
                "state {state} of the table of log {log}"
            );
        }
        // The spread holds each symbol as many times as its probability ("less than 1": once).
        let spread = distribution.spread();
        for (symbol, probability) in probabilities.iter().enumerate() {
            let count = spread.iter().filter(|spread_symbol| **spread_symbol as usize == symbol).count();
            assert_eq!(count as i32, RFC8878::total(&[*probability]), "symbol {symbol}");
        }
    }
}

#[test]
fn less_than_one_symbols_take_the_last_states_with_a_full_reset() {
    // Section 4.1.1: "less than 1" symbols are placed at the end of the table, the first such
    // symbol in the last state; their state is reset by reading accuracy_log bits from 0.
    let distribution = FSEDistribution::new(5, vec![-1, 10, -1, 20]).unwrap();
    let table = FSEDecodingTable::new(&distribution);
    assert_eq!(table.entries[31], FSEDecodingEntry { symbol: 0, bits: 5, baseline: 0 });
    assert_eq!(table.entries[30], FSEDecodingEntry { symbol: 2, bits: 5, baseline: 0 });
    // The other states of a symbol, in order, split the table among themselves (section
    // 4.1.1): the lowest states read one bit more, and the baselines cover every state once.
    for symbol in [1u8, 3] {
        let mut covered: Vec<usize> = Vec::new();
        for entry in table.entries.iter().filter(|entry| entry.symbol == symbol) {
            covered.extend((0..1usize << entry.bits).map(|value| entry.next_state(value as u32)));
        }
        covered.sort_unstable();
        assert_eq!(covered, (0..32).collect::<Vec<_>>(), "symbol {symbol}");
    }
}

#[test]
fn single_symbol_tables_read_no_bits() {
    let table = FSEDecodingTable::single(7);
    assert_eq!(table.accuracy_log, 0);
    assert_eq!(table.entries, [FSEDecodingEntry { symbol: 7, bits: 0, baseline: 0 }]);
    // The same table as that of the distribution of probability 1 on a scale of 2^0.
    let distribution = FSEDistribution::new(0, vec![0, 0, 0, 0, 0, 0, 0, 1]).unwrap();
    assert_eq!(FSEDecodingTable::new(&distribution), table);
}

#[test]
fn table_descriptions_follow_section_4_1_1() {
    // The predefined distributions and normalized ones of every shape, with runs of zeros of
    // every length (each 3 needs another repeat flag).
    let mut distributions: Vec<FSEDistribution> = RFC8878::PREDEFINED
        .iter()
        .map(|(probabilities, log)| FSEDistribution::new(*log, probabilities.to_vec()).unwrap())
        .collect();
    let mut samples = Samples::new(8);
    for round in 0..300 {
        let symbols = 2 + samples.below(80) as usize;
        let counts: Vec<u32> = (0..symbols)
            .map(|index| match samples.below(5) {
                0 if index % 7 != 0 => 0,
                _ => 1 + samples.below(1 << (round % 14)) as u32,
            })
            .collect();
        let present = counts.iter().filter(|count| **count > 0).count();
        if present < 2 {
            continue;
        }
        let log = (5 + samples.below(11) as u32).max(usize::BITS - present.leading_zeros());
        let distribution = FSEDistribution::normalize(&counts, log).unwrap();
        assert_eq!(RFC8878::total(&distribution.probabilities), 1 << log);
        assert_eq!(distribution.accuracy_log, log);
        // Every present symbol keeps a probability; absent ones have none.
        for (count, probability) in counts.iter().zip(&distribution.probabilities) {
            assert_eq!(*count == 0, *probability == 0);
        }
        distributions.push(distribution);
    }
    for distribution in distributions {
        let expected = RFC8878::describe(distribution.accuracy_log, &distribution.probabilities);
        let mut written = Vec::new();
        distribution.write(&mut written).unwrap();
        assert_eq!(written, expected, "{distribution:?}");
        let mut bytes = expected.clone();
        bytes.push(0xAA);
        let (read, used) = FSEDistribution::read(&bytes, 15, 256).unwrap();
        assert_eq!(read, distribution);
        assert_eq!(used, expected.len());
    }
}

#[test]
fn table_descriptions_read_values_of_table_20() {
    // Section 4.1.1, Table 20: with an accuracy log of 8 and 100 points distributed, values 0 to
    // 157 are read in 7 bits (0 to 97) or 8 bits (98 to 127, and 128 to 157 as 226 to 255).
    for decoded in [0i16, 1, 97, 98, 127, 128, 156, 157] {
        let second = decoded - 1;
        let mut probabilities = vec![100, second];
        let rest = 256 - 100 - RFC8878::total(&[second]) as i16;
        if rest > 0 {
            probabilities.push(rest);
        }
        let bytes = RFC8878::describe(8, &probabilities);
        let (read, _) = FSEDistribution::read(&bytes, 8, 256).unwrap();
        assert_eq!(read.probabilities, probabilities, "decoded value {decoded}");
        // The field starts after 4 + 8 bits (the first value, 101, is below 254 of 257 + 1).
        let field = (u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]) >> 12) & 0xFF;
        match decoded {
            0..=97 => assert_eq!(field & 0x7F, decoded as u32),
            98..=127 => assert_eq!(field, decoded as u32),
            _ => assert_eq!(field, decoded as u32 + 98),
        }
    }
}

#[test]
fn table_descriptions_refuse_what_section_4_1_1_forbids() {
    let invalid = |result: Result<(FSEDistribution, usize), CompressionError>| {
        matches!(result, Err(CompressionError::InvalidData { .. }))
    };
    // An accuracy log above the caller's maximum, and above 15 whatever the caller allows.
    assert!(invalid(FSEDistribution::read(&RFC8878::describe(10, &[512, 512]), 9, 256)));
    assert!(invalid(FSEDistribution::read(&[0x0B, 0xFF, 0xFF, 0xFF], 30, 256)));
    // More symbols than the caller's maximum.
    let probabilities = RFC8878::PREDEFINED[0].0;
    let description = RFC8878::describe(6, probabilities);
    assert!(invalid(FSEDistribution::read(&description, 9, 35)));
    assert!(FSEDistribution::read(&description, 9, 36).is_ok());
    // One present symbol; an empty or truncated description.
    assert!(invalid(FSEDistribution::read(&RFC8878::describe(5, &[0, 0, 32]), 9, 256)));
    assert!(invalid(FSEDistribution::read(&[], 9, 256)));
    assert!(invalid(FSEDistribution::read(&description[..description.len() - 1], 9, 256)));
}

#[test]
fn distributions_refuse_invalid_parameters() {
    let parameter = Err(CompressionError::InvalidParameter);
    // Totals other than the scale, probabilities below -1, accuracy logs above 15, more than 256 symbols.
    assert_eq!(FSEDistribution::new(5, vec![16, 15]), parameter);
    assert_eq!(FSEDistribution::new(5, vec![16, 17]), parameter);
    assert_eq!(FSEDistribution::new(5, vec![-2, 34]), parameter);
    assert_eq!(FSEDistribution::new(16, vec![i16::MAX, i16::MAX, 2]), parameter);
    let mut many = vec![1i16; 256];
    many.push(0);
    assert_eq!(FSEDistribution::new(8, many), parameter);
    assert!(FSEDistribution::new(8, vec![1; 256]).is_ok());
    // Normalization needs 2 present symbols, at most the scale of them, an accuracy log of at most 15.
    assert_eq!(FSEDistribution::normalize(&[0, 5, 0], 5), parameter);
    assert_eq!(FSEDistribution::normalize(&[], 5), parameter);
    assert_eq!(FSEDistribution::normalize(&[1; 33], 5), parameter);
    assert_eq!(FSEDistribution::normalize(&[1, 1], 16), parameter);
    assert!(FSEDistribution::normalize(&[1; 32], 5).is_ok());
    // Only accuracy logs of 5 to 15 have a description.
    let small = FSEDistribution::new(2, vec![2, 2]).unwrap();
    assert_eq!(small.write(&mut Vec::new()), Err(CompressionError::InvalidParameter));
}

#[test]
fn encoding_tables_invert_decoding_tables() {
    // From an encoder state S (2^log + decoder state) for a symbol x, the encoder writes the low
    // n bits of S and moves to P; the decoder in P - 2^log decodes x, reads n bits and returns
    // to S - 2^log.
    let mut distributions: Vec<FSEDistribution> = RFC8878::PREDEFINED
        .iter()
        .map(|(probabilities, log)| FSEDistribution::new(*log, probabilities.to_vec()).unwrap())
        .collect();
    distributions.push(FSEDistribution::new(5, vec![-1, 10, -1, 0, 20]).unwrap());
    distributions.push(FSEDistribution::new(0, vec![0, 1]).unwrap());
    for distribution in distributions {
        let decoding = FSEDecodingTable::new(&distribution);
        let encoding = FSEEncodingTable::new(&distribution);
        let size = 1u32 << distribution.accuracy_log;
        assert!(!encoding.is_state(size - 1) && !encoding.is_state(2 * size));
        for (symbol, probability) in distribution.probabilities.iter().enumerate() {
            assert_eq!(encoding.contains(symbol), *probability != 0);
            if *probability == 0 {
                continue;
            }
            let first = encoding.initial_state(symbol);
            assert!(encoding.is_state(first));
            assert_eq!(decoding.entries[(first - size) as usize].symbol as usize, symbol);
            for state in size..2 * size {
                let (bits, previous) = encoding.transition(state, symbol);
                assert!(encoding.is_state(previous));
                let entry = decoding.entries[(previous - size) as usize];
                assert_eq!(entry.symbol as usize, symbol);
                assert_eq!(entry.bits as u32, bits);
                assert_eq!(entry.next_state(state & ((1 << bits) - 1)), (state - size) as usize);
            }
        }
        assert!(!encoding.contains(distribution.probabilities.len()));
    }
}

#[test]
fn symbols_round_trip_through_backward_bitstreams() {
    let mut samples = Samples::new(3);
    for round in 0..100 {
        let symbols = 2 + samples.below(40) as usize;
        let counts: Vec<u32> = (0..symbols).map(|_| samples.below(1 << (round % 10)) as u32).collect();
        let present = counts.iter().filter(|count| **count > 0).count();
        if present < 2 {
            continue;
        }
        let log = (5 + samples.below(8) as u32).max(usize::BITS - present.leading_zeros());
        let distribution = FSEDistribution::normalize(&counts, log).unwrap();
        let alphabet: Vec<usize> = (0..symbols).filter(|symbol| counts[*symbol] > 0).collect();
        let message: Vec<usize> =
            (0..1 + samples.below(500)).map(|_| alphabet[samples.below(alphabet.len() as u64) as usize]).collect();
        // Encoded from the last symbol to the first; the decoder reads the final state first.
        let encoding = FSEEncodingTable::new(&distribution);
        let mut writer = BackwardBitWriter::new();
        let mut state = encoding.initial_state(*message.last().unwrap());
        for symbol in message[..message.len() - 1].iter().rev() {
            state = encoding.encode(state, *symbol, &mut writer);
        }
        encoding.flush(state, &mut writer);
        let stream = writer.finish();
        let decoding = FSEDecodingTable::new(&distribution);
        let mut reader = BackwardBitReader::new(&stream).unwrap();
        let mut state = decoding.initial_state(&mut reader);
        let mut decoded = Vec::new();
        for index in 0..message.len() {
            decoded.push(decoding.entries[state].symbol as usize);
            if index + 1 < message.len() {
                state = decoding.next_state(state, &mut reader);
            }
        }
        assert_eq!(decoded, message);
        assert!(reader.is_finished(), "the stream holds exactly the bits of its symbols");
    }
}
