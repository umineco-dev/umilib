//! LZ77: the history window and the match finder against their definitions
//! (by brute force), and the triples of the LZ77 format.

use umilib::codec::lz77::{
    LZ77Compressor, LZ77Config, LZ77Decompressor, LZ77Format, LZ77MatchFinder, LZ77MatchFinderConfig, LZ77Window,
};
use umilib::codec::{CompressionError, Compressor, Decompressor};

use crate::compression::{Ending, Samples, Streaming};

#[test]
fn windows_copy_matches_as_byte_by_byte_copies() {
    let mut samples = Samples::new(5);
    for capacity in [1usize, 7, 64, 1000] {
        let mut window = LZ77Window::new(capacity);
        let mut history: Vec<u8> = Vec::new();
        for _ in 0..400 {
            if history.is_empty() || samples.below(3) == 0 {
                let length = samples.below(50) as usize;
                let bytes = samples.random(length);
                window.extend(&bytes);
                history.extend(&bytes);
            } else {
                let distance = 1 + samples.below(history.len().min(capacity) as u64) as usize;
                let length = samples.below(300) as usize;
                let room = samples.below(400) as usize;
                let mut output = vec![0u8; room];
                let copied = window.copy(distance, length, &mut output).unwrap();
                assert_eq!(copied, length.min(room));
                for produced in &output[..copied] {
                    let byte = history[history.len() - distance];
                    assert_eq!(*produced, byte, "capacity {capacity} distance {distance}");
                    history.push(byte);
                }
            }
            assert_eq!(window.len(), history.len().min(capacity));
            assert_eq!(window.total(), history.len() as u64);
            for distance in 1..=window.len() {
                assert_eq!(window.byte(distance), Some(history[history.len() - distance]));
            }
        }
        assert_eq!(window.byte(window.len() + 1), None);
        assert!(matches!(window.copy(window.len() + 1, 1, &mut [0]), Err(CompressionError::InvalidData { .. })));
        assert!(matches!(window.copy(0, 1, &mut [0]), Err(CompressionError::InvalidData { .. })));
    }
    let window = LZ77Window::with_dictionary(4, b"abcdef");
    assert_eq!((window.len(), window.byte(1), window.byte(4)), (4, Some(b'f'), Some(b'c')));
}

/// The longest match at `position` by brute force, newest first among the longest.
fn longest(data: &[u8], position: usize, config: &LZ77MatchFinderConfig) -> Option<(usize, usize)> {
    let limit = config.maximum_length.min(data.len() - position);
    let mut best: Option<(usize, usize)> = None;
    for distance in 1..=config.maximum_distance.min(position) {
        let length = (0..limit).take_while(|k| data[position - distance + k] == data[position + k]).count();
        if length >= config.minimum_length && best.is_none_or(|(_, best)| length > best) {
            best = Some((distance, length));
        }
    }
    best
}

#[test]
fn match_finders_find_the_longest_match_within_their_limits() {
    let mut samples = Samples::new(9);
    for (minimum_length, maximum_distance) in [(2usize, 300usize), (3, 256), (4, 1000)] {
        let config = LZ77MatchFinderConfig {
            window_bits: 10,
            chain_bits: 10,
            hash_bits: 12,
            maximum_distance,
            minimum_length,
            maximum_length: 40,
            chain_limit: usize::MAX,
            nice_length: usize::MAX,
        };
        let mut finder = LZ77MatchFinder::new(config).unwrap();
        let data = samples.repetitive(5000);
        finder.append(&data);
        let mut position = 0;
        while position < data.len() {
            let found = finder.find(position, usize::MAX).map(|found| (found.distance, found.length));
            let expected = longest(&data, position, &config);
            // Every match is real; with an unlimited chain, the longest one is found.
            assert_eq!(found.map(|(_, length)| length), expected.map(|(_, length)| length), "position {position}");
            if let Some((distance, length)) = found {
                assert!(distance <= maximum_distance && length >= minimum_length);
                assert_eq!(data[position - distance..position - distance + length], data[position..position + length]);
            }
            position += found.map_or(1, |(_, length)| length);
        }
    }
    let invalid = LZ77MatchFinderConfig {
        window_bits: 4,
        ..LZ77MatchFinderConfig {
            window_bits: 10,
            chain_bits: 10,
            hash_bits: 12,
            maximum_distance: 10,
            minimum_length: 3,
            maximum_length: 10,
            chain_limit: 1,
            nice_length: 10,
        }
    };
    assert_eq!(LZ77MatchFinder::new(invalid), Err(CompressionError::InvalidParameter));
}

#[test]
fn match_finders_keep_finding_after_discarding() {
    let config = LZ77MatchFinderConfig {
        window_bits: 8,
        chain_bits: 8,
        hash_bits: 10,
        maximum_distance: 256,
        minimum_length: 3,
        maximum_length: 64,
        chain_limit: usize::MAX,
        nice_length: usize::MAX,
    };
    let mut finder = LZ77MatchFinder::new(config).unwrap();
    let mut samples = Samples::new(2);
    let data = samples.repetitive(4000);
    let (mut position, mut offset) = (0usize, 0usize);
    for chunk in data.chunks(97) {
        finder.append(chunk);
        while position + 64 < finder.data().len() {
            let absolute = position + offset;
            let found = finder.find(position, usize::MAX).map(|found| found.length);
            assert_eq!(
                found,
                longest(&data[..absolute + finder.data().len() - position], absolute, &config)
                    .map(|(_, length)| length)
            );
            position += 1;
        }
        let dropped = finder.discard(position);
        assert!(position - dropped >= 256 || dropped == 0);
        position -= dropped;
        offset += dropped;
        assert_eq!(finder.data(), &data[offset..offset + finder.data().len()]);
    }
}

#[test]
fn lz77_streams_follow_their_format() {
    // "abcabcabcd": a, b, c as literals, then a match of 6 bytes 3 back followed by d.
    let mut compressor = LZ77Compressor::new(LZ77Config::default()).unwrap();
    let stream = compressor.compress_to_vec(b"abcabcabcd").unwrap();
    assert_eq!(stream, [0, 0, b'a', 0, 0, b'b', 0, 0, b'c', 0x00, 0x26, b'd', 0xFF, 0xF0]);
    let mut decompressor = LZ77Decompressor::new();
    assert_eq!(decompressor.decompress_to_vec(&stream, 100).unwrap(), b"abcabcabcd");
    // A match of 15 bytes 4096 back.
    let mut data = vec![0u8; 4096];
    data[0] = 1;
    let mut stream = vec![0, 0, 1];
    for _ in 0..4095 {
        stream.extend([0, 0, 0]);
    }
    stream.extend([0xFF, 0xFF, 7, 0xFF, 0xF0]);
    data.extend(vec![1].into_iter().chain([0; 14]).chain([7]));
    decompressor.reset();
    assert_eq!(decompressor.decompress_to_vec(&stream, 10000).unwrap(), data);
    assert_eq!(LZ77Format::END, 0xFFF);
}

#[test]
fn lz77_decompressors_reject_invalid_streams() {
    let mut decompressor = LZ77Decompressor::new();
    for (stream, error) in [
        (&[0x00, 0x10, b'x'][..], CompressionError::InvalidData { reason: "invalid token" }),
        (&[0x00, 0x01, b'x'][..], CompressionError::InvalidData { reason: "match distance beyond the history" }),
        (&[0x00, 0x00][..], CompressionError::UnexpectedEnd),
    ] {
        decompressor.reset();
        assert_eq!(decompressor.decompress_to_vec(stream, 100), Err(error));
    }
}

#[test]
fn lz77_streams_round_trip() {
    for chain_limit in [1, 64] {
        let mut compressor = LZ77Compressor::new(LZ77Config { chain_limit }).unwrap();
        Streaming::round_trip(&mut compressor, &mut LZ77Decompressor::new(), Ending::Marked, true);
    }
    assert_eq!(LZ77Compressor::new(LZ77Config { chain_limit: 0 }), Err(CompressionError::InvalidParameter));
}
