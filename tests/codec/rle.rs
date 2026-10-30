//! PackBits against Apple Technical Note TN1023.

use umilib::codec::rle::{PackBitsCompressor, PackBitsDecompressor};
use umilib::codec::{CompressionError, Compressor, Decompressor};

use crate::Vectors;
use crate::compression::{Ending, Streaming};

/// The unpacked and packed bytes of the example of TN1023.
fn example() -> (Vec<u8>, Vec<u8>) {
    let text = Vectors::read("codec/rle/tn1023.txt");
    let line =
        |prefix: &str| Vectors::hex(&text.lines().find_map(|line| line.strip_prefix(prefix)).unwrap().replace(' ', ""));
    (line("Unpacked data: "), line("After being packed by PackBits: "))
}

#[test]
fn packbits_follows_tn1023() {
    let (unpacked, packed) = example();
    assert_eq!(PackBitsCompressor::new().compress_to_vec(&unpacked).unwrap(), packed);
    let mut decompressor = PackBitsDecompressor::new();
    assert_eq!(decompressor.decompress_to_vec(&packed, unpacked.len()).unwrap(), unpacked);
    Streaming::check(&mut decompressor, &packed, &unpacked, Ending::Input);
    // UnpackBits skips the flag-counter byte -128.
    let mut with_no_operations = vec![0x80];
    with_no_operations.extend(&packed[..2]);
    with_no_operations.push(0x80);
    with_no_operations.extend(&packed[2..]);
    decompressor.reset();
    assert_eq!(decompressor.decompress_to_vec(&with_no_operations, unpacked.len()).unwrap(), unpacked);
}

/// The runs of a PackBits stream: (repeat, bytes).
fn runs(stream: &[u8]) -> Vec<(bool, Vec<u8>)> {
    let mut runs = Vec::new();
    let mut position = 0;
    while position < stream.len() {
        let header = stream[position];
        assert_ne!(header, 0x80, "PackBits never writes -128");
        if header < 0x80 {
            let count = header as usize + 1;
            runs.push((false, stream[position + 1..position + 1 + count].to_vec()));
            position += 1 + count;
        } else {
            runs.push((true, vec![stream[position + 1]; 257 - header as usize]));
            position += 2;
        }
    }
    runs
}

#[test]
fn packbits_packs_runs_of_three_or_more() {
    let data = [vec![7u8; 128], vec![8u8; 129], (0..=255u8).collect(), vec![9; 2], vec![1, 9, 9, 9, 9]].concat();
    let stream = PackBitsCompressor::new().compress_to_vec(&data).unwrap();
    let runs = runs(&stream);
    assert_eq!(runs.iter().flat_map(|(_, bytes)| bytes.clone()).collect::<Vec<u8>>(), data);
    for (repeat, bytes) in &runs {
        assert!(bytes.len() <= 128);
        if *repeat {
            assert!(bytes.len() >= 3, "a repeat of fewer than three bytes");
        } else {
            assert!(
                !bytes.windows(3).any(|window| window[0] == window[1] && window[1] == window[2]),
                "three equal bytes copied"
            );
        }
    }
    // Runs of 128 equal bytes take one repeat.
    assert_eq!(&stream[..4], [0x81, 7, 0x81, 8]);
    // A truncated run fails; a stream may end between runs.
    let mut decompressor = PackBitsDecompressor::new();
    assert_eq!(decompressor.decompress_to_vec(&[2, 1, 2], 10), Err(CompressionError::UnexpectedEnd));
    decompressor.reset();
    assert_eq!(decompressor.decompress_to_vec(&[0xFF], 10), Err(CompressionError::UnexpectedEnd));
    decompressor.reset();
    assert_eq!(decompressor.decompress_to_vec(&[], 10).unwrap(), b"");
}

#[test]
fn packbits_streams_round_trip() {
    Streaming::round_trip(&mut PackBitsCompressor::new(), &mut PackBitsDecompressor::new(), Ending::Input, true);
}
