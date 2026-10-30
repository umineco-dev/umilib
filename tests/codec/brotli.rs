//! Brotli (RFC 7932): the static dictionary, context lookup tables and
//! word transformations against the checks of the RFC, its trivial
//! compressor, hand-made streams, the streams of the brotli tool, and round trips.

use umilib::bytes::{BitQueue, BitWriter};
use umilib::codec::brotli::{
    BrotliBlockSwitch, BrotliCompressor, BrotliConfig, BrotliContextMap, BrotliContextMapReader, BrotliDecompressor,
    BrotliDecompressorConfig, BrotliDistances, BrotliFormat, BrotliPrefixCode, BrotliPrefixReader, BrotliTransformKind,
};
use umilib::codec::{CompressionError, Compressor, Decompressor};

use crate::Vectors;
use crate::compression::{Ending, Samples, Streaming};

/// The CRC-32 of Appendix C.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in bytes {
        let mut c = (crc ^ *byte as u32) & 0xFF;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
        crc = c ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// BrotliCompressTrivial of section 11.1.
fn trivial(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![6];
    }
    let mut stream = vec![12];
    let mut index = 0;
    while index + 65535 < data.len() {
        stream.extend([248, 255, 15]);
        stream.extend_from_slice(&data[index..index + 65536]);
        index += 65536;
    }
    if index < data.len() {
        let rest = data.len() - index - 1;
        stream.extend([((rest & 31) << 3) as u8, (rest >> 5) as u8, (8 + (rest >> 13)) as u8]);
        stream.extend_from_slice(&data[index..]);
    }
    stream.push(3);
    stream
}

fn decode(stream: &[u8]) -> Result<Vec<u8>, CompressionError> {
    BrotliDecompressor::default().decompress_to_vec(stream, 1 << 20)
}

fn invalid(reason: &'static str) -> Result<Vec<u8>, CompressionError> {
    Err(CompressionError::InvalidData { reason })
}

#[test]
fn static_dictionary_follows_appendix_a() {
    assert_eq!(BrotliFormat::DICTIONARY.len(), 122_784);
    assert_eq!(crc32(BrotliFormat::DICTIONARY), 0x5136_cb04);
    // NDBITS: the words of each length fill the dictionary in order.
    let total: usize = (4..=24).map(|length| length << BrotliFormat::DICTIONARY_BITS[length]).sum();
    assert_eq!(total, BrotliFormat::DICTIONARY.len());
    assert_eq!(BrotliFormat::word_offset(25), BrotliFormat::DICTIONARY.len());
    assert_eq!(BrotliFormat::word(4, 0), b"time");
    assert_eq!(BrotliFormat::word(4, 3), b"left");
}

#[test]
fn context_lookup_tables_follow_section_7_1() {
    assert_eq!(crc32(&BrotliFormat::LUT0), 0x8e91_efb7);
    assert_eq!(crc32(&BrotliFormat::LUT1), 0xd01a_32f4);
    assert_eq!(crc32(&BrotliFormat::LUT2), 0x0dd7_a0d6);
    // The four context modes.
    assert_eq!(BrotliFormat::literal_context(0, 0xFF, 0), 0x3F);
    assert_eq!(BrotliFormat::literal_context(1, 0xFF, 0), 0x3F);
    assert_eq!(
        BrotliFormat::literal_context(2, b'a', b' '),
        (BrotliFormat::LUT0[b'a' as usize] | BrotliFormat::LUT1[b' ' as usize]) as usize
    );
    assert_eq!(BrotliFormat::literal_context(3, 0xFF, 0), 7 << 3);
}

#[test]
fn word_transforms_follow_appendix_b() {
    // The serialization of Appendix B: prefix, 0, the transform's value, suffix, 0.
    let mut bytes = Vec::new();
    for transform in &BrotliFormat::TRANSFORMS {
        bytes.extend_from_slice(transform.prefix);
        bytes.push(0);
        bytes.push(match transform.kind {
            BrotliTransformKind::Identity => 0,
            BrotliTransformKind::FermentFirst => 1,
            BrotliTransformKind::FermentAll => 2,
            BrotliTransformKind::OmitFirst(count) => 2 + count,
            BrotliTransformKind::OmitLast(count) => 11 + count,
        });
        bytes.extend_from_slice(transform.suffix);
        bytes.push(0);
    }
    assert_eq!(bytes.len(), 648);
    assert_eq!(crc32(&bytes), 0x3d96_5f81);
    let apply = |id: usize, word: &[u8]| {
        let mut out = [0u8; 38];
        let length = BrotliFormat::transform(&BrotliFormat::TRANSFORMS[id], word, &mut out);
        out[..length].to_vec()
    };
    assert_eq!(apply(0, b"time"), b"time");
    assert_eq!(apply(9, b"time"), b"Time");
    assert_eq!(apply(44, b"time"), b"TIME");
    assert_eq!(apply(73, b"time"), b" the time of the ");
    assert_eq!(apply(3, b"time"), b"ime");
    assert_eq!(apply(12, b"time"), b"tim");
    assert_eq!(apply(54, b"time"), b"");
    // Ferment of section 8: a 2-byte character flips bit 5 of its second byte, a 3-byte one bit 0 and 2 of its third.
    assert_eq!(apply(44, "aé€".as_bytes()), [b'A', 0xC3, 0xA9 ^ 32, 0xE2, 0x82, 0xAC ^ 5]);
    assert_eq!(apply(9, "é".as_bytes()), [0xC3, 0xA9 ^ 32]);
}

#[test]
fn distances_follow_section_4() {
    let mut distances = BrotliDistances::new();
    assert_eq!(distances.last, [4, 11, 15, 16]);
    let short: Vec<u32> = (0..16).map(|code| distances.decode(code, 0).unwrap()).collect();
    assert_eq!(short, [4, 11, 15, 16, 3, 5, 2, 6, 1, 7, 10, 12, 9, 13, 8, 14]);
    distances.push(2);
    assert_eq!(distances.last, [2, 4, 11, 15]);
    // Last distance - 3 is not positive.
    assert!(distances.decode(8, 0).is_err());
    // Without postfix bits and direct codes: code 16 + x has 1 + x / 2 extra bits.
    assert_eq!(distances.extra_bits(16), 1);
    assert_eq!(distances.decode(16, 0).unwrap(), 1);
    assert_eq!(distances.decode(17, 0).unwrap(), 3);
    assert_eq!(distances.decode(18, 3).unwrap(), 8);
    // NPOSTFIX 2 and NDIRECT 8: direct codes first, then the postfix bits in the low bits.
    let coding = BrotliDistances { last: [1, 2, 3, 4], postfix: 2, direct: 8 };
    assert_eq!(coding.alphabet_size(), 16 + 8 + (48 << 2));
    assert_eq!(coding.decode(16, 0).unwrap(), 1);
    assert_eq!(coding.decode(23, 0).unwrap(), 8);
    assert_eq!(coding.decode(24, 0).unwrap(), 9);
    assert_eq!(coding.decode(25, 0).unwrap(), 10);
    assert_eq!(coding.decode(24, 1).unwrap(), 13);
    // Encoding inverts decoding for every distance tried.
    for coding in [BrotliDistances::new(), coding, BrotliDistances { last: [100, 50, 7, 9], postfix: 3, direct: 120 }] {
        for distance in (1..5000).chain([(1 << 24) - 16, 1 << 20, 123_456]) {
            let (code, extra, bits) = coding.encode(distance);
            assert_eq!(coding.extra_bits(code), bits);
            assert!((code as usize) < coding.alphabet_size());
            assert_eq!(coding.decode(code, extra).unwrap(), distance);
        }
    }
}

#[test]
fn commands_follow_section_5() {
    // The cells of the insert-and-copy length codes.
    assert_eq!(BrotliFormat::command(0), (0, 0, true));
    assert_eq!(BrotliFormat::command(63), (7, 7, true));
    assert_eq!(BrotliFormat::command(64), (0, 8, true));
    assert_eq!(BrotliFormat::command(128), (0, 0, false));
    assert_eq!(BrotliFormat::command(192), (0, 8, false));
    assert_eq!(BrotliFormat::command(256), (8, 0, false));
    assert_eq!(BrotliFormat::command(320), (8, 8, false));
    assert_eq!(BrotliFormat::command(384), (0, 16, false));
    assert_eq!(BrotliFormat::command(448), (16, 0, false));
    assert_eq!(BrotliFormat::command(512), (8, 16, false));
    assert_eq!(BrotliFormat::command(576), (16, 8, false));
    assert_eq!(BrotliFormat::command(703), (23, 23, false));
    for symbol in 0..704u16 {
        let (insert, copy, implicit) = BrotliFormat::command(symbol);
        assert_eq!(BrotliFormat::command_symbol(insert, copy, implicit), symbol);
    }
    // The bases and extra bits are contiguous ranges.
    for (bases, bits, last) in [
        (&BrotliFormat::INSERT_BASES, &BrotliFormat::INSERT_BITS, 22594 + (1 << 24) - 1),
        (&BrotliFormat::COPY_BASES, &BrotliFormat::COPY_BITS, 2118 + (1 << 24) - 1),
    ] {
        for code in 0..23 {
            assert_eq!(bases[code] + (1 << bits[code]), bases[code + 1]);
        }
        assert_eq!(bases[23] + (1 << bits[23]) - 1, last);
    }
    for code in 0..25 {
        let (bases, bits) = (&BrotliFormat::BLOCK_COUNT_BASES, &BrotliFormat::BLOCK_COUNT_BITS);
        assert_eq!(bases[code] + (1 << bits[code]), bases[code + 1]);
    }
    assert_eq!(BrotliFormat::insert_code(5), (5, 0));
    assert_eq!(BrotliFormat::insert_code(7), (6, 1));
    assert_eq!(BrotliFormat::copy_code(2), (0, 0));
    assert_eq!(BrotliFormat::copy_code(2118), (23, 0));
    assert_eq!(BrotliBlockSwitch::count_code(1), (0, 0));
    assert_eq!(BrotliBlockSwitch::count_code(16625), (25, 0));
}

/// Reads `bytes` with a reader from `make`, given them all at once, then
/// one byte at a time to a second reader; both must read the same value.
fn read_both<R, T: PartialEq + core::fmt::Debug>(
    bytes: &[u8],
    make: impl Fn() -> R,
    read: impl Fn(&mut R, &mut BitQueue, &mut &[u8]) -> Result<Option<T>, CompressionError>,
) -> T {
    let (mut reader, mut queue) = (make(), BitQueue::new());
    let whole = read(&mut reader, &mut queue, &mut &bytes[..]).unwrap().expect("the bytes hold all of it");
    let (mut reader, mut queue) = (make(), BitQueue::new());
    for index in 0..bytes.len() {
        let mut input = &bytes[index..index + 1];
        if let Some(value) = read(&mut reader, &mut queue, &mut input).unwrap() {
            assert_eq!(value, whole);
            return whole;
        }
        assert!(input.is_empty(), "a reader that ran out took its input");
    }
    panic!("the bytes end before the value");
}

#[test]
fn prefix_codes_follow_section_3() {
    // Simple codes: NSYM 2 of the symbols 5 and 2 (ALPHABET_BITS 3 for 8 symbols).
    let mut writer = BitWriter::new();
    writer.write(1, 2);
    writer.write(1, 2);
    writer.write(5, 3);
    writer.write(2, 3);
    let bytes = writer.finish();
    let mut queue = BitQueue::new();
    let code = BrotliPrefixReader::new(8).read(&mut queue, &mut &bytes[..]).unwrap().unwrap();
    // Symbol 2 gets code 0 and symbol 5 code 1 (sorted by value).
    assert_eq!(code.read(&mut BitQueue::new(), &mut &[0b10][..]).unwrap(), Some(2));
    assert_eq!(code.read(&mut BitQueue::new(), &mut &[0b01][..]).unwrap(), Some(5));
    // A repeated symbol, a symbol beyond the alphabet.
    for (first, second) in [(3u64, 3u64), (1, 9)] {
        let mut writer = BitWriter::new();
        writer.write(1, 2);
        writer.write(1, 2);
        writer.write(first, 4);
        writer.write(second, 4);
        let bytes = writer.finish();
        assert!(BrotliPrefixReader::new(9).read(&mut BitQueue::new(), &mut &bytes[..]).is_err());
    }
    // NSYM 1: a code without bits.
    let mut writer = BitWriter::new();
    writer.write(1, 2);
    writer.write(0, 2);
    writer.write(200, 8);
    let bytes = writer.finish();
    assert_eq!(
        BrotliPrefixReader::new(256).read(&mut BitQueue::new(), &mut &bytes[..]).unwrap(),
        Some(BrotliPrefixCode::Single(200))
    );
    // Descriptions of many shapes round trip, read whole and byte by byte.
    let mut samples = Samples::new(11);
    for round in 0..300 {
        let size = [26, 64, 256, 704, 4, 10][round % 6];
        let used = 1 + samples.below(size as u64) as usize;
        let mut frequencies = vec![0u32; size];
        for _ in 0..used {
            frequencies[samples.below(size as u64) as usize] += 1 + samples.below(1 << (round % 16)) as u32;
        }
        let lengths = BrotliPrefixCode::lengths(&frequencies);
        let mut writer = BitWriter::new();
        BrotliPrefixCode::write(&lengths, size, &mut writer);
        writer.write(0x5A, 8);
        let bytes = writer.finish();
        let code =
            read_both(&bytes, || BrotliPrefixReader::new(size), |reader, queue, input| reader.read(queue, input));
        // Every symbol decodes from its code.
        let codes = BrotliPrefixCode::codes(&lengths);
        for symbol in (0..size).filter(|symbol| lengths[*symbol] > 0) {
            let mut writer = BitWriter::new();
            writer.write(codes[symbol].0 as u64, codes[symbol].1 as u32);
            writer.write(0, 16);
            let bytes = writer.finish();
            assert_eq!(code.read(&mut BitQueue::new(), &mut &bytes[..]).unwrap(), Some(symbol as u16));
        }
    }
}

#[test]
fn context_maps_follow_section_7_3() {
    let mut values = [1u8, 1, 0, 2, 2, 0];
    BrotliContextMap::move_to_front(&mut values);
    assert_eq!(values, [1, 0, 1, 2, 0, 1]);
    BrotliContextMap::inverse_move_to_front(&mut values);
    assert_eq!(values, [1, 1, 0, 2, 2, 0]);
    let mut samples = Samples::new(3);
    for round in 0..100 {
        let trees = 2 + samples.below(30) as usize;
        let size = [64, 4, 256, 640][round % 4];
        let map: Vec<u8> =
            (0..size).map(|_| if samples.below(3) == 0 { samples.below(trees as u64) as u8 } else { 0 }).collect();
        let mut writer = BitWriter::new();
        BrotliContextMap::write(&map, trees, &mut writer);
        let bytes = writer.finish();
        let read = read_both(
            &bytes,
            || BrotliContextMapReader::new(size, trees),
            |reader, queue, input| reader.read(queue, input),
        );
        assert_eq!(read, map);
    }
}

#[test]
fn block_type_counts_follow_section_9_2() {
    // NBLTYPES: 0 is 1, 0001 is 2, x0011 is 3 and 4, ..., xxxxxxx1111 is 129 to 256.
    for types in 1..=256 {
        let mut writer = BitWriter::new();
        BrotliBlockSwitch::write_types(types, &mut writer);
        let expected = match types {
            1 => 1,
            2 => 4,
            _ => 4 + (usize::BITS - 1 - (types - 1).leading_zeros()) as usize,
        };
        assert_eq!(writer.bit_length(), expected, "{types}");
        let bytes = writer.finish();
        let read = read_both(&bytes, || (), |_, queue, input| Ok(BrotliBlockSwitch::read_types(queue, input)));
        assert_eq!(read, types);
    }
    // The example of the RFC: 0110111 is 12.
    assert_eq!(BrotliBlockSwitch::read_types(&mut BitQueue::new(), &mut &[0b0110111][..]), Some(12));
}

#[test]
fn trivial_streams_of_section_11_1_decompress() {
    let mut samples = Samples::new(5);
    for length in [0usize, 1, 2, 100, 65535, 65536, 65537, 140_000] {
        let data = samples.random(length);
        let stream = trivial(&data);
        assert!(stream.len() <= length + 3 * (length >> 16) + 5);
        let mut decompressor = BrotliDecompressor::default();
        Streaming::check(&mut decompressor, &stream, &data, Ending::Marked);
    }
}

/// A stream of WBITS 16 and one last compressed meta-block of `length`
/// bytes: one block type, simple prefix codes of the literal `literal`, the
/// command `command` and the distance code 0, then the bits of `data`.
fn hand_made(length: u64, literal: u8, command: u16, data: &dyn Fn(&mut BitWriter)) -> Vec<u8> {
    let mut writer = BitWriter::new();
    writer.write(0, 1); // WBITS 16
    writer.write(0b01, 2); // ISLAST, not ISLASTEMPTY
    writer.write(0, 2); // MNIBBLES 4
    writer.write(length - 1, 16);
    writer.write(0, 3); // NBLTYPESL, NBLTYPESI, NBLTYPESD: 1
    writer.write(0, 6); // NPOSTFIX, NDIRECT
    writer.write(0, 2); // the context mode LSB6
    writer.write(0, 2); // NTREESL, NTREESD: 1
    for (symbol, bits) in [(literal as u64, 8), (command as u64, 10), (0, 6)] {
        writer.write(1, 2);
        writer.write(0, 2);
        writer.write(symbol, bits);
    }
    data(&mut writer);
    writer.finish()
}

#[test]
fn hand_made_streams_follow_section_9() {
    // A command of insert code 2 (2 literals, copy ignored): "aa".
    assert_eq!(decode(&hand_made(2, b'a', 2 << 3, &|_| {})).unwrap(), b"aa");
    assert_eq!(decode(&hand_made(1, b'a', 2 << 3, &|_| {})), invalid("insert beyond the meta-block"));
    // Copy length 4 at the implicit distance 4 before any data: the dictionary word 4 - 0 - 1 = 3 of length 4.
    assert_eq!(decode(&hand_made(4, b'a', 2, &|_| {})).unwrap(), b"left");
    assert_eq!(decode(&hand_made(3, b'a', 2, &|_| {})), invalid("dictionary word beyond the meta-block"));
    // One literal, then a copy of 3 bytes at the implicit distance 4, beyond the 1 byte so far: a
    // dictionary reference, but the dictionary has no words of 3 bytes.
    assert_eq!(decode(&hand_made(4, b'a', 1 << 3 | 1, &|_| {})), invalid("dictionary reference of an invalid length"));
    // Non-zero fill bits after the last meta-block.
    let mut stream = hand_made(2, b'a', 2 << 3, &|_| {});
    *stream.last_mut().unwrap() |= 0x80;
    assert_eq!(decode(&stream), invalid("fill bits not zero"));
}

#[test]
fn brotli_decompressors_check_headers() {
    // WBITS: 1000100 is invalid (the large-window extension, not in RFC 7932).
    assert_eq!(decode(&[0x11, 0x03]), invalid("invalid window size"));
    // WBITS 24 (1111) with ISLAST and ISLASTEMPTY: within the default limit, beyond a limit of 16.
    assert_eq!(decode(&[0x3F]).unwrap(), b"");
    let limited = BrotliDecompressorConfig { maximum_window_bits: 16 };
    assert_eq!(
        BrotliDecompressor::new(limited).unwrap().decompress_to_vec(&[0x3F], 10),
        Err(CompressionError::LimitExceeded { limit: (1 << 16) - 16 })
    );
    assert!(BrotliDecompressor::new(BrotliDecompressorConfig { maximum_window_bits: 25 }).is_err());
    // WBITS 17 (1000000) and 10 (1000010), then ISLAST and ISLASTEMPTY.
    for (stream, window) in [([0x81u8, 0x01], (1 << 17) - 16), ([0xA1, 0x01], (1 << 10) - 16)] {
        let mut decompressor = BrotliDecompressor::default();
        assert_eq!(decompressor.decompress_to_vec(&stream, 10).unwrap(), b"");
        assert_eq!(decompressor.window_size(), window);
    }
    // The empty stream of section 11.1, and with a fill bit set.
    assert_eq!(decode(&[0x06]).unwrap(), b"");
    assert_eq!(decode(&[0x0E]), invalid("fill bits not zero"));
    // Metadata (WBITS 16, ISLAST 0, MNIBBLES 0): the reserved bit, MSKIPBYTES 2 with a zero last
    // byte, a fill bit, and 3 bytes of metadata skipped before the end of the stream.
    let metadata = |reserved: u64, bytes: u32, length: u64, fill: u64, content: &[u8]| {
        let mut writer = BitWriter::new();
        writer.write(0b1100, 4);
        writer.write(reserved, 1);
        writer.write(bytes as u64, 2);
        writer.write(length, 8 * bytes);
        writer.write(fill, 1);
        let mut stream = writer.finish();
        stream.extend_from_slice(content);
        stream.push(0x03);
        stream
    };
    assert_eq!(decode(&metadata(1, 0, 0, 0, b"")), invalid("reserved bit set"));
    assert_eq!(decode(&metadata(0, 2, 0x0005, 0, b"")), invalid("metadata length with a superfluous zero byte"));
    assert_eq!(decode(&metadata(0, 1, 2, 1, b"xyz")), invalid("fill bits not zero"));
    assert_eq!(decode(&metadata(0, 1, 2, 0, b"xyz")).unwrap(), b"");
    assert_eq!(decode(&metadata(0, 0, 0, 0, b"")).unwrap(), b"");
    // MNIBBLES 5 with a zero last nibble; an uncompressed meta-block with an ignored bit set.
    assert_eq!(decode(&[0b0000_0100, 0, 0, 0]), invalid("meta-block length with a superfluous zero nibble"));
    let mut uncompressed = trivial(b"abc");
    uncompressed[3] |= 0x10;
    assert_eq!(decode(&uncompressed), invalid("ignored bits not zero"));
}

const STREAMS: [(&str, &str); 14] = [
    ("text.quality0", "text"),
    ("text.quality1", "text"),
    ("text.quality5", "text"),
    ("text.quality9", "text"),
    ("text.quality11", "text"),
    ("text.window10", "text"),
    ("text.window24", "text"),
    ("repetitive.quality11", "repetitive"),
    ("random.quality5", "random"),
    ("zeros.quality11", "zeros"),
    ("empty", "empty"),
    ("one", "one"),
    ("mixed.window16", "mixed"),
    ("mixed.quality11", "mixed"),
];

/// The input of a stream of the brotli tool: a file of ../deflate, or "mixed", four of them in a row.
fn input(name: &str) -> Vec<u8> {
    if name == "mixed" {
        return ["text", "random", "repetitive", "zeros"].iter().flat_map(|name| input(name)).collect();
    }
    Vectors::bytes(&format!("codec/deflate/{name}.bin"))
}

#[test]
fn brotli_decompressors_read_the_streams_of_brotli() {
    for (file, name) in STREAMS {
        let data = input(name);
        let stream = Vectors::bytes(&format!("codec/brotli/{file}.br"));
        Streaming::check(&mut BrotliDecompressor::default(), &stream, &data, Ending::Marked);
    }
    // Corrupt streams fail or decode to something else, without panicking.
    let stream = Vectors::bytes("codec/brotli/text.quality11.br");
    let text = input("text");
    for position in (0..stream.len()).step_by(7) {
        let mut corrupt = stream.clone();
        corrupt[position] ^= 0x24;
        if let Ok(data) = BrotliDecompressor::default().decompress_to_vec(&corrupt, 1 << 20) {
            assert!(data != text || corrupt == stream);
        }
    }
}

#[test]
fn brotli_streams_round_trip() {
    for (level, window_bits) in [(0, 22), (1, 10), (6, 16), (9, 22), (11, 24)] {
        let mut compressor = BrotliCompressor::new(BrotliConfig { level, window_bits }).unwrap();
        Streaming::round_trip(&mut compressor, &mut BrotliDecompressor::default(), Ending::Marked, true);
    }
    for invalid in [
        BrotliConfig { level: 12, ..BrotliConfig::default() },
        BrotliConfig { window_bits: 9, ..BrotliConfig::default() },
        BrotliConfig { window_bits: 25, ..BrotliConfig::default() },
    ] {
        assert!(BrotliCompressor::new(invalid).is_err());
    }
    // The stream header: WBITS 16 and the empty stream of section 11.1.
    let config = BrotliConfig { window_bits: 16, ..BrotliConfig::default() };
    assert_eq!(BrotliCompressor::new(config).unwrap().compress_to_vec(b"").unwrap(), [6]);
    // A window of 10 bits limits the distances: a decompressor limited to it reads the stream.
    let mixed = input("mixed");
    let stream =
        BrotliCompressor::new(BrotliConfig { level: 6, window_bits: 10 }).unwrap().compress_to_vec(&mixed).unwrap();
    let limited = BrotliDecompressorConfig { maximum_window_bits: 10 };
    assert_eq!(BrotliDecompressor::new(limited).unwrap().decompress_to_vec(&stream, usize::MAX).unwrap(), mixed);
    // Random data is stored in uncompressed meta-blocks.
    let random = input("random");
    let stream = BrotliCompressor::default().compress_to_vec(&random).unwrap();
    assert!(stream.len() <= random.len() + 8, "{}", stream.len());
}

#[test]
fn brotli_compression_is_comparable_to_brotli() {
    // Level 11 against the brotli tool at quality 11 (which also models contexts): at most an eighth larger.
    for name in ["text", "repetitive"] {
        let data = input(name);
        let reference = Vectors::bytes(&format!("codec/brotli/{name}.quality11.br"));
        let config = BrotliConfig { level: 11, window_bits: 22 };
        let ours = BrotliCompressor::new(config).unwrap().compress_to_vec(&data).unwrap();
        assert!(
            ours.len() <= reference.len() + reference.len() / 8,
            "{name}: {} against {}",
            ours.len(),
            reference.len()
        );
    }
}
