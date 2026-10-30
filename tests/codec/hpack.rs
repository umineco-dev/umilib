//! HPACK (RFC 7541): the examples of Appendix C decoded, the code of
//! Appendix B, and every rule that makes a block invalid; the encoder's
//! blocks decoded back, its tables in step with the decoder's.

use umilib::codec::hpack::{
    HPACKDecoder, HPACKDecoderConfig, HPACKDynamicTable, HPACKEncoder, HPACKEncoderConfig, HPACKError, HPACKField,
    HPACKHuffman, HPACKInteger, HPACKStaticTable, HPACKString,
};

use crate::Vectors;

const PATH: &str = "codec/hpack/rfc7541.txt";

/// The lines of the RFC without page breaks.
fn lines() -> Vec<String> {
    Vectors::read(PATH)
        .lines()
        .filter(|line| {
            !(line.starts_with("Peon & Ruellan") || line.starts_with("RFC 7541") || line.starts_with('\u{c}'))
        })
        .map(String::from)
        .collect()
}

/// An example of Appendix C: the fields, the block, and the dynamic table
/// after it (each entry as "name: value", its size), and its size.
struct Example {
    name: String,
    fields: Vec<(Vec<u8>, Vec<u8>)>,
    block: Vec<u8>,
    table: Vec<(String, usize)>,
    size: usize,
}

impl Example {
    /// The examples of section `section` (such as "C.3."), in order.
    fn all(section: &str) -> Vec<Example> {
        let lines = lines();
        let mut examples = Vec::new();
        let starts: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| {
                line.starts_with(section) && line[section.len()..].starts_with(|c: char| c.is_ascii_digit())
            })
            .map(|(index, _)| index)
            .collect();
        for (number, start) in starts.iter().enumerate() {
            let end = starts.get(number + 1).copied().unwrap_or(lines.len());
            let end = lines[start + 1..end]
                .iter()
                .position(|line| {
                    line.starts_with("C.") || line.starts_with("Appendix") || line.starts_with("Acknowledgments")
                })
                .map_or(end, |offset| start + 1 + offset);
            examples.push(Example::parse(&lines[*start..end]));
        }
        examples
    }

    fn parse(lines: &[String]) -> Example {
        let after = |label: &str| lines.iter().position(|line| line.trim() == label).map(|index| index + 1);
        let block_start = after("Hex dump of encoded data:").unwrap();
        let block: String = lines[block_start..]
            .iter()
            .take_while(|line| !line.trim().starts_with("Decoding process:"))
            .filter_map(|line| line.split('|').next())
            .collect();
        let mut table = Vec::new();
        let mut size = 0;
        if let Some(start) = after("Dynamic Table (after decoding):") {
            for line in &lines[start..] {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("Table size:") {
                    size = rest.trim().parse().unwrap();
                    break;
                }
                if line.is_empty() {
                    continue;
                }
                if line.starts_with('[') {
                    let (_, rest) = line.split_once("(s =").unwrap();
                    let (entry_size, text) = rest.split_once(')').unwrap();
                    table.push((text.trim().to_string(), entry_size.trim().parse().unwrap()));
                } else if let Some(last) = table.last_mut() {
                    last.0.push(' ');
                    last.0.push_str(line);
                }
            }
        }
        let start = after("Decoded header list:").unwrap();
        let fields = lines[start..]
            .iter()
            .map(|line| line.trim())
            .skip_while(|line| line.is_empty())
            .take_while(|line| !line.is_empty())
            .map(|line| {
                // A pseudo-header's name starts with its colon.
                let split = line[1..].find(": ").unwrap() + 1;
                (line.as_bytes()[..split].to_vec(), line.as_bytes()[split + 2..].to_vec())
            })
            .collect();
        Example { name: lines[0].clone(), fields, block: Vectors::hex(&block), table, size }
    }
}

fn texts(fields: &[HPACKField]) -> Vec<(Vec<u8>, Vec<u8>)> {
    fields.iter().map(|field| (field.name.clone(), field.value.clone())).collect()
}

fn table_of(table: &HPACKDynamicTable) -> Vec<(String, usize)> {
    table
        .entries
        .iter()
        .map(|entry| {
            let text = format!("{}: {}", String::from_utf8_lossy(entry.name()), String::from_utf8_lossy(entry.value()));
            (text, entry.size())
        })
        .collect()
}

#[test]
fn integers_of_appendix_c1() {
    // C.1.1: 10 with a 5-bit prefix; C.1.2: 1337 with a 5-bit prefix; C.1.3: 42 at an octet boundary.
    for (prefix, value, bytes) in [(5, 10, vec![0x0A]), (5, 1337, vec![0x1F, 0x9A, 0x0A]), (8, 42, vec![0x2A])] {
        let mut out = Vec::new();
        HPACKInteger::write(&mut out, prefix, 0xE0, value);
        let flags = if prefix == 8 { 0 } else { 0xE0 & !((1u8 << prefix) - 1) };
        assert_eq!(out[0] & !((1u16 << prefix) - 1) as u8, flags);
        let mut plain = out.clone();
        plain[0] &= ((1u16 << prefix) - 1) as u8;
        assert_eq!(plain, bytes);
        assert_eq!(HPACKInteger::length(prefix, value), bytes.len());
        let mut input = &out[..];
        assert_eq!(HPACKInteger::read(&mut input, prefix), Ok((flags, value)));
        assert!(input.is_empty());
    }
}

#[test]
fn integers_cut_short_or_too_large() {
    // RFC 7541 §5.1: decoders must handle integers past their limits as errors.
    assert_eq!(HPACKInteger::read(&mut &[0x1F, 0x9A][..], 5), Err(HPACKError::Truncated));
    assert_eq!(HPACKInteger::read(&mut &[][..], 5), Err(HPACKError::Truncated));
    let mut huge = vec![0x1F];
    huge.extend([0xFF; 9]);
    huge.push(0x01);
    assert_eq!(HPACKInteger::read(&mut &huge[..], 5), Err(HPACKError::IntegerOverflow));
    let mut largest = Vec::new();
    HPACKInteger::write(&mut largest, 5, 0, HPACKInteger::MAXIMUM);
    assert_eq!(HPACKInteger::read(&mut &largest[..], 5), Ok((0, HPACKInteger::MAXIMUM)));
}

#[test]
fn the_huffman_code_of_appendix_b() {
    // Each row: the symbol, its code aligned to the LSB in hexadecimal, its length.
    let huffman = HPACKHuffman::new();
    let mut rows = 0;
    for line in lines() {
        let line = line.trim();
        let symbol = if let Some(rest) = line.strip_prefix("EOS (256)") {
            Some((256, rest))
        } else if line.starts_with('(') && line.contains(")  |") {
            let (number, rest) = line[1..].split_once(')').unwrap();
            Some((number.trim().parse::<usize>().unwrap(), rest))
        } else {
            line.split_once(" (").and_then(|(_, rest)| {
                let (number, rest) = rest.split_once(')')?;
                number.trim().parse::<usize>().ok().filter(|_| rest.trim_start().starts_with('|')).map(|n| (n, rest))
            })
        };
        let Some((symbol, rest)) = symbol else { continue };
        let (before, length) = rest.rsplit_once('[').unwrap();
        let length: u32 = length.trim_end_matches(']').trim().parse().unwrap();
        let code = u32::from_str_radix(before.split_whitespace().last().unwrap(), 16).unwrap();
        assert_eq!((huffman.code.code(symbol), huffman.code.length(symbol)), (code, length), "symbol {symbol}");
        rows += 1;
    }
    assert_eq!(rows, 257);
}

#[test]
fn huffman_strings() {
    // C.4.1: "www.example.com" coded; §5.2: EOS, long padding and padding
    // not of ones are errors.
    let huffman = HPACKHuffman::new();
    let mut out = Vec::new();
    huffman.encode(b"www.example.com", &mut out);
    assert_eq!(out, Vectors::hex("f1e3 c2e5 f23a 6ba0 ab90 f4ff"));
    let mut decoded = Vec::new();
    huffman.decode(&out, &mut decoded, 100).unwrap();
    assert_eq!(decoded, b"www.example.com");
    let all: Vec<u8> = (0..=255).collect();
    let mut coded = Vec::new();
    huffman.encode(&all, &mut coded);
    let mut back = Vec::new();
    huffman.decode(&coded, &mut back, 1000).unwrap();
    assert_eq!(back, all);
    // EOS, its 30 bits and 2 bits of padding.
    assert_eq!(huffman.decode(&[0xFF, 0xFF, 0xFF, 0xFF], &mut Vec::new(), 10), Err(HPACKError::InvalidHuffman));
    // "0" (00000) then 11 bits of ones: padding of more than 7 bits.
    assert_eq!(huffman.decode(&[0x07, 0xFF], &mut Vec::new(), 10), Err(HPACKError::InvalidHuffman));
    // "0" then padding of zeros.
    assert_eq!(huffman.decode(&[0x00], &mut Vec::new(), 10), Err(HPACKError::InvalidHuffman));
    assert_eq!(huffman.decode(&out, &mut Vec::new(), 14), Err(HPACKError::StringTooLong));
}

#[test]
fn strings_of_any_prefix() {
    // RFC 9204 §4.1.2 uses the strings of RFC 7541 §5.2 with other prefixes.
    let huffman = HPACKHuffman::new();
    for prefix in [3, 5, 7] {
        for (bytes, code) in [(&b"custom-key"[..], Some(&huffman)), (b"\x00\x01", Some(&huffman)), (b"plain", None)] {
            let mut out = Vec::new();
            HPACKString::write(&mut out, prefix, 0xFF, bytes, code);
            let mut input = &out[..];
            let (flags, read) = HPACKString::read(&mut input, prefix, &huffman, 100).unwrap();
            assert_eq!((read.as_slice(), input.len()), (bytes, 0));
            assert_eq!(u16::from(flags), 0xFF & !((1u16 << (prefix + 1)) - 1));
        }
    }
    let mut out = Vec::new();
    HPACKString::write(&mut out, 7, 0, &[b'a'; 20], None);
    assert_eq!(HPACKString::read(&mut &out[..], 7, &huffman, 19), Err(HPACKError::StringTooLong));
    assert_eq!(HPACKString::read(&mut &out[..10], 7, &huffman, 100), Err(HPACKError::Truncated));
}

#[test]
fn the_static_table() {
    assert_eq!(HPACKStaticTable::get(1), Some((&b":authority"[..], &b""[..])));
    assert_eq!(HPACKStaticTable::get(61), Some((&b"www-authenticate"[..], &b""[..])));
    assert_eq!((HPACKStaticTable::get(0), HPACKStaticTable::get(62)), (None, None));
    assert_eq!(HPACKStaticTable::find(b":method", b"POST"), Some((3, true)));
    assert_eq!(HPACKStaticTable::find(b":method", b"PUT"), Some((2, false)));
}

/// Decodes the examples of `section` in order with one decoder whose
/// table is `size` bytes, and checks the fields and the table after each.
fn decode_examples(section: &str, size: usize) {
    let examples = Example::all(section);
    assert_eq!(examples.len(), 3, "{section}");
    let config = HPACKDecoderConfig { maximum_table_size: size, ..HPACKDecoderConfig::default() };
    let mut decoder = HPACKDecoder::new(config);
    for example in &examples {
        let fields = decoder.decode(&example.block).unwrap();
        assert_eq!(texts(&fields), example.fields, "{}", example.name);
        assert_eq!(table_of(&decoder.table), example.table, "{}", example.name);
        assert_eq!(decoder.table.size, example.size, "{}", example.name);
    }
}

#[test]
fn requests_and_responses_of_appendix_c() {
    decode_examples("C.3.", 4096);
    decode_examples("C.4.", 4096);
    // C.5 and C.6: SETTINGS_HEADER_TABLE_SIZE of 256, with evictions.
    decode_examples("C.5.", 256);
    decode_examples("C.6.", 256);
}

#[test]
fn representations_of_appendix_c2() {
    // C.2.1 to C.2.4, each with a fresh decoder; C.2.3 is never indexed.
    let examples = Example::all("C.2.");
    assert_eq!(examples.len(), 4);
    for example in &examples {
        let mut decoder = HPACKDecoder::new(HPACKDecoderConfig::default());
        let fields = decoder.decode(&example.block).unwrap();
        assert_eq!(texts(&fields), example.fields, "{}", example.name);
        assert_eq!(table_of(&decoder.table), example.table, "{}", example.name);
        assert_eq!(fields[0].sensitive, example.name.contains("Never Indexed"), "{}", example.name);
    }
}

#[test]
fn the_encoder_in_step_with_the_decoder() {
    // The header lists of Appendix C through an encoder and back: the same
    // fields, and both tables alike after each block (RFC 7541 §2.3.2).
    for (section, size, huffman) in
        [("C.3.", 4096, false), ("C.4.", 4096, true), ("C.5.", 256, false), ("C.6.", 256, true)]
    {
        let config = HPACKEncoderConfig { maximum_table_size: size, huffman, ..HPACKEncoderConfig::default() };
        let mut encoder = HPACKEncoder::new(config, size);
        let mut decoder =
            HPACKDecoder::new(HPACKDecoderConfig { maximum_table_size: size, ..HPACKDecoderConfig::default() });
        for example in Example::all(section) {
            let fields: Vec<HPACKField> =
                example.fields.iter().map(|(name, value)| HPACKField::new(name, value)).collect();
            let mut block = Vec::new();
            encoder.encode(&fields, &mut block);
            assert_eq!(decoder.decode(&block).unwrap(), fields, "{}", example.name);
            assert_eq!(encoder.table, decoder.table, "{}", example.name);
            assert!(block.len() <= example.block.len() + 8, "{}: {} bytes", example.name, block.len());
        }
    }
}

#[test]
fn sensitive_fields_are_never_indexed() {
    // RFC 7541 §6.2.3, §7.1.3: a never-indexed field stays out of the
    // tables, even when it is in the static table, and is reported so.
    let mut encoder = HPACKEncoder::new(HPACKEncoderConfig::default(), 4096);
    let mut decoder = HPACKDecoder::new(HPACKDecoderConfig::default());
    let fields = [HPACKField::sensitive(b"authorization", b"secret"), HPACKField::sensitive(b":method", b"GET")];
    let mut block = Vec::new();
    encoder.encode(&fields, &mut block);
    assert!(encoder.table.entries.is_empty());
    assert_eq!(block[0] & 0xF0, 0x10);
    assert_eq!(decoder.decode(&block).unwrap(), fields);
    assert!(decoder.table.entries.is_empty());
}

#[test]
fn indices_of_no_entry() {
    // RFC 7541 §6.1: index 0 is an error, as is one past the tables (§2.3.3).
    let mut decoder = HPACKDecoder::new(HPACKDecoderConfig::default());
    assert_eq!(decoder.decode(&[0x80]), Err(HPACKError::InvalidIndex));
    assert_eq!(decoder.decode(&[0xBE]), Err(HPACKError::InvalidIndex));
    assert_eq!(decoder.decode(&[0x7E, 0x01, b'x']), Err(HPACKError::InvalidIndex));
    assert_eq!(decoder.decode(&[0x82, 0x40]), Err(HPACKError::Truncated));
}

#[test]
fn dynamic_table_size_updates() {
    // RFC 7541 §4.2, §6.3: an update above the limit or after a field line
    // is an error; after the limit fell below the table's size, the next
    // block must start with one.
    let mut decoder = HPACKDecoder::new(HPACKDecoderConfig::default());
    assert_eq!(decoder.decode(&[0x3F, 0xE2, 0x1F]), Err(HPACKError::InvalidTableSizeUpdate));
    let mut decoder = HPACKDecoder::new(HPACKDecoderConfig::default());
    assert_eq!(decoder.decode(&[0x82, 0x20]), Err(HPACKError::InvalidTableSizeUpdate));
    let mut decoder = HPACKDecoder::new(HPACKDecoderConfig::default());
    decoder.set_limit(100);
    assert_eq!(decoder.decode(&[0x82]), Err(HPACKError::InvalidTableSizeUpdate));
    let mut decoder = HPACKDecoder::new(HPACKDecoderConfig::default());
    decoder.set_limit(100);
    // Two updates (0, then 100) and a field.
    assert_eq!(decoder.decode(&[0x20, 0x3F, 0x45, 0x82]).unwrap().len(), 1);
    assert_eq!(decoder.table.maximum, 100);
}

#[test]
fn the_encoder_signals_sizes() {
    // RFC 7541 §4.2: the smallest size since the last block, then the final one.
    let mut encoder = HPACKEncoder::new(HPACKEncoderConfig::default(), 4096);
    let mut decoder = HPACKDecoder::new(HPACKDecoderConfig::default());
    let fields = [HPACKField::new(b"x-a", b"1")];
    let mut block = Vec::new();
    encoder.encode(&fields, &mut block);
    decoder.decode(&block).unwrap();
    encoder.set_limit(0);
    decoder.set_limit(0);
    encoder.set_limit(4096);
    decoder.set_limit(4096);
    let mut block = Vec::new();
    encoder.encode(&fields, &mut block);
    assert_eq!(&block[..4], &[0x20, 0x3F, 0xE1, 0x1F]);
    assert_eq!(decoder.decode(&block).unwrap(), fields);
    assert_eq!(encoder.table, decoder.table);
    // A configured size below the limit is signaled in the first block.
    let config = HPACKEncoderConfig { maximum_table_size: 1000, ..HPACKEncoderConfig::default() };
    let mut encoder = HPACKEncoder::new(config, 4096);
    let mut block = Vec::new();
    encoder.encode(&fields, &mut block);
    let mut decoder = HPACKDecoder::new(HPACKDecoderConfig::default());
    decoder.decode(&block).unwrap();
    assert_eq!(decoder.table.maximum, 1000);
}

#[test]
fn entries_larger_than_the_table() {
    // RFC 7541 §4.4: an entry larger than the maximum size empties the table.
    let mut table = HPACKDynamicTable::new(100);
    table.insert(b"a", b"b");
    table.insert(&[b'n'; 40], &[b'v'; 40]);
    assert!(table.entries.is_empty() && table.size == 0);
    table.insert(b"name", b"value");
    assert_eq!(table.size, 41);
    table.set_maximum(40);
    assert!(table.entries.is_empty());
}

#[test]
fn field_lists_too_large() {
    // RFC 9113 §6.5.2: a block over the limit of a field list is still
    // decoded, so that the next one decodes in step.
    let mut encoder = HPACKEncoder::new(HPACKEncoderConfig::default(), 4096);
    let config = HPACKDecoderConfig { maximum_field_list_size: 100, ..HPACKDecoderConfig::default() };
    let mut decoder = HPACKDecoder::new(config);
    let large = [HPACKField::new(b"x-large", &[b'v'; 80]), HPACKField::new(b"x-small", b"1")];
    let mut block = Vec::new();
    encoder.encode(&large, &mut block);
    assert_eq!(decoder.decode(&block), Err(HPACKError::FieldListTooLarge));
    let small = [HPACKField::new(b"x-small", b"1")];
    let mut block = Vec::new();
    encoder.encode(&small, &mut block);
    assert_eq!(block, [0xBE]);
    assert_eq!(decoder.decode(&block).unwrap(), small);
}
