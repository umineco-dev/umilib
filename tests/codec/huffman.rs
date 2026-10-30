//! Huffman coding: canonical codes against RFC 1951 section 3.2.2 and
//! exhaustive searches, decoding tables, Vitter's algorithm Λ against the
//! invariants of its paper and optimal codes, and the two stream formats.

use umilib::bytes::{BitOrder, BitQueue, BitWriter};
use umilib::codec::huffman::HuffmanError;
use umilib::codec::huffman::adaptive::{
    AdaptiveHuffmanCompressor, AdaptiveHuffmanDecompressor, AdaptiveHuffmanFormat, AdaptiveHuffmanNode,
    AdaptiveHuffmanTree,
};
use umilib::codec::huffman::canonical::{
    CanonicalHuffmanCompressor, CanonicalHuffmanConfig, CanonicalHuffmanDecompressor, CanonicalHuffmanFormat,
    HuffmanCode, HuffmanTable,
};
use umilib::codec::{CompressionError, Compressor, Decompressor};

use crate::compression::{Ending, Samples, Streaming};

/// The code of `symbol` as a string of bits, first bit first.
fn bits(code: &HuffmanCode, symbol: usize) -> String {
    let length = code.length(symbol);
    (0..length).rev().map(|bit| if code.code(symbol) >> bit & 1 == 1 { '1' } else { '0' }).collect()
}

#[test]
fn canonical_codes_follow_rfc1951_section_3_2_2() {
    // The example of the section: lengths (3, 3, 3, 3, 3, 2, 4, 4) for A to H.
    let code = HuffmanCode::from_lengths(&[3, 3, 3, 3, 3, 2, 4, 4]).unwrap();
    let expected = ["010", "011", "100", "101", "110", "00", "1110", "1111"];
    for (symbol, bits_of) in expected.iter().enumerate() {
        assert_eq!(bits(&code, symbol), *bits_of);
    }
    assert!(code.is_complete());

    // The fixed literal/length code of section 3.2.6.
    let mut lengths = vec![8u8; 144];
    lengths.extend([9; 112]);
    lengths.extend([7; 24]);
    lengths.extend([8; 8]);
    let code = HuffmanCode::from_lengths(&lengths).unwrap();
    for (range, first) in [(0..144, 0b0011_0000u32), (144..256, 0b1_1001_0000), (256..280, 0), (280..288, 0b1100_0000)]
    {
        for (offset, symbol) in range.enumerate() {
            assert_eq!(code.code(symbol), first + offset as u32, "symbol {symbol}");
        }
    }
    assert_eq!(code.reversed_code(0), 0b0000_1100);
}

#[test]
fn canonical_codes_check_their_lengths() {
    assert_eq!(HuffmanCode::from_lengths(&[1, 1, 1]), Err(HuffmanError::InvalidLengths { maximum: 32 }));
    assert_eq!(HuffmanCode::from_lengths(&[33, 1]), Err(HuffmanError::InvalidLengths { maximum: 32 }));
    assert!(HuffmanCode::from_lengths(&[32, 1]).is_ok());
    assert!(matches!(HuffmanCode::from_lengths(&[]), Err(HuffmanError::InvalidAlphabet { .. })));
    let incomplete = HuffmanCode::from_lengths(&[1, 0, 2]).unwrap();
    assert!(!incomplete.is_complete());
    assert_eq!((bits(&incomplete, 0), bits(&incomplete, 2)), ("0".into(), "10".into()));
    assert!(!HuffmanCode::from_lengths(&[0, 0]).unwrap().is_complete());
}

/// The least cost Σ f l of the codes of `frequencies` with lengths at most `limit`, by exhaustive search.
fn least_cost(frequencies: &[u32], limit: u32) -> u64 {
    let used: Vec<u64> = frequencies.iter().filter(|f| **f > 0).map(|f| *f as u64).collect();
    if used.len() <= 1 {
        return used.iter().sum();
    }
    let mut best = u64::MAX;
    let mut lengths = vec![1u32; used.len()];
    loop {
        let space: u64 = lengths.iter().map(|length| 1u64 << (limit - length)).sum();
        if space <= 1 << limit {
            best = best.min(lengths.iter().zip(&used).map(|(length, f)| *length as u64 * f).sum());
        }
        let mut index = 0;
        while index < lengths.len() && lengths[index] == limit {
            lengths[index] = 1;
            index += 1;
        }
        if index == lengths.len() {
            return best;
        }
        lengths[index] += 1;
    }
}

#[test]
fn codes_from_frequencies_are_optimal_within_their_limit() {
    let mut samples = Samples::new(7);
    for _ in 0..300 {
        let count = 1 + samples.below(6) as usize;
        let frequencies: Vec<u32> =
            (0..count).map(|_| if samples.below(5) == 0 { 0 } else { 1 + samples.below(1000) as u32 }).collect();
        for limit in 1..=5u32 {
            let used = frequencies.iter().filter(|f| **f > 0).count();
            match HuffmanCode::lengths_from_frequencies(&frequencies, limit) {
                Ok(lengths) => {
                    assert!(used <= 1 << limit);
                    let cost: u64 =
                        lengths.iter().zip(&frequencies).map(|(length, f)| *length as u64 * *f as u64).sum();
                    assert_eq!(cost, least_cost(&frequencies, limit), "{frequencies:?} limit {limit}");
                    for (length, f) in lengths.iter().zip(&frequencies) {
                        assert_eq!(*length == 0, *f == 0);
                        assert!(*length as u32 <= limit);
                    }
                    let code = HuffmanCode::from_lengths(&lengths).unwrap();
                    assert!(code.is_complete() || used <= 1);
                }
                Err(error) => {
                    assert!(used > 1 << limit, "{frequencies:?} limit {limit}");
                    assert_eq!(error, HuffmanError::InvalidLengths { maximum: limit });
                }
            }
        }
    }
    // Skewed frequencies of a large alphabet stay within 15 bits and complete.
    let frequencies: Vec<u32> = (0..300).map(|index| 1 + (1u32 << (index % 31))).collect();
    let code = HuffmanCode::from_frequencies(&frequencies, 15).unwrap();
    assert!(code.maximum_length() <= 15 && code.is_complete());
    assert_eq!(HuffmanCode::lengths_from_frequencies(&[0, 9, 0], 15).unwrap(), vec![0, 1, 0]);
}

#[test]
fn tables_decode_every_code_in_both_bit_orders() {
    let mut samples = Samples::new(11);
    for round in 0..40 {
        let count = 2 + samples.below(600) as usize;
        let frequencies: Vec<u32> = (0..count)
            .map(|_| if samples.below(4) == 0 { 0 } else { 1 + (samples.below(1 << (round % 20)) as u32) })
            .collect();
        if frequencies.iter().filter(|f| **f > 0).count() < 2 {
            continue;
        }
        let code = HuffmanCode::from_frequencies(&frequencies, 15).unwrap();
        let least = HuffmanTable::new(&code, BitOrder::LeastSignificantFirst);
        let most = HuffmanTable::new(&code, BitOrder::MostSignificantFirst);
        let peek = code.maximum_length();
        assert_eq!(least.peek_bits(), peek);
        for symbol in 0..count {
            let length = code.length(symbol);
            if length == 0 {
                continue;
            }
            // Whatever bits follow the code.
            let after = samples.next() & ((1 << (peek - length)) - 1);
            let first_least = code.reversed_code(symbol) as u64 | after << length;
            assert_eq!(least.decode(first_least), Ok((symbol as u16, length)));
            let first_most = (code.code(symbol) as u64) << (peek - length) | after;
            assert_eq!(most.decode(first_most), Ok((symbol as u16, length)));
        }
    }
    // An incomplete code leaves bits without a code.
    let table = HuffmanTable::from_lengths(&[1, 0, 2], BitOrder::LeastSignificantFirst).unwrap();
    assert_eq!(table.decode(0b11), Err(HuffmanError::InvalidCode));
    assert_eq!(table.decode(0b01), Ok((2, 2)));
}

#[test]
fn tables_read_codes_from_queues_without_taking_bytes_past_them() {
    let code = HuffmanCode::from_lengths(&[3, 3, 3, 3, 3, 2, 4, 4]).unwrap();
    for order in [BitOrder::LeastSignificantFirst, BitOrder::MostSignificantFirst] {
        let table = HuffmanTable::new(&code, order);
        let mut writer = BitWriter::new();
        let message = [5usize, 0, 7, 6, 1, 2, 3, 4, 5];
        for symbol in message {
            writer.write(code.reversed_code(symbol) as u64, code.length(symbol));
        }
        let mut stream = writer.finish();
        let length = stream.len();
        stream.push(0xFF);
        let (mut queue, mut input) = (BitQueue::new(), &stream[..]);
        for symbol in message {
            assert_eq!(table.read(&mut queue, &mut input), Ok(Some(symbol as u16)));
        }
        assert_eq!(stream.len() - input.len(), length);
        assert!(queue.count() < 8);
        // One byte at a time.
        let mut queue = BitQueue::new();
        let mut decoded = Vec::new();
        for byte in &stream[..length] {
            let mut input = core::slice::from_ref(byte);
            while let Ok(Some(symbol)) = table.read(&mut queue, &mut input) {
                decoded.push(symbol as usize);
                if decoded.len() == message.len() {
                    break;
                }
            }
        }
        assert_eq!(decoded, message);
    }
}

/// The least cost Σ w d of a binary tree over the leaf weights `weights` (Huffman's algorithm).
fn huffman_cost(weights: &[u64]) -> u64 {
    let mut weights = weights.to_vec();
    let mut cost = 0;
    while weights.len() > 1 {
        weights.sort_unstable_by(|a, b| b.cmp(a));
        let (a, b) = (weights.pop().unwrap(), weights.pop().unwrap());
        cost += a + b;
        weights.push(a + b);
    }
    cost
}

/// Checks the invariants of the implicit numbering of algorithm Λ and that the tree is optimal.
fn check_tree(tree: &AdaptiveHuffmanTree, counts: &[u64]) {
    let root = tree.root();
    let mut lowest = root;
    while lowest > 0 && tree.node(lowest - 1) != AdaptiveHuffmanNode::Unused {
        lowest -= 1;
    }
    assert_eq!(tree.node(lowest), AdaptiveHuffmanNode::Unseen);
    assert_eq!(lowest, tree.unseen());
    let mut leaves = Vec::new();
    for position in lowest..=root {
        if position < root {
            // Weights do not decrease with the position; at one weight, leaves come first.
            let (here, next) = (tree.weight(position), tree.weight(position + 1));
            assert!(here <= next, "weights ordered at {position}");
            if here == next {
                let internal = matches!(tree.node(position), AdaptiveHuffmanNode::Internal { .. });
                assert!(
                    !internal || matches!(tree.node(position + 1), AdaptiveHuffmanNode::Internal { .. }),
                    "leaves precede internal nodes of weight {here}"
                );
            }
            assert_eq!(tree.child(tree.parent(position), position & 1), position);
        }
        match tree.node(position) {
            AdaptiveHuffmanNode::Internal { left } => {
                assert_eq!(left % 2, 0);
                assert_eq!(tree.weight(position), tree.weight(left) + tree.weight(left + 1));
            }
            AdaptiveHuffmanNode::Leaf { symbol } => {
                assert_eq!(tree.position(symbol as usize), Some(position));
                assert_eq!(tree.weight(position), counts[symbol as usize]);
                leaves.push(position);
            }
            AdaptiveHuffmanNode::Unseen => assert_eq!(tree.weight(position), 0),
            AdaptiveHuffmanNode::Unused => panic!("unused node inside the tree"),
        }
    }
    for (symbol, count) in counts.iter().enumerate() {
        assert_eq!(tree.position(symbol).is_some(), *count > 0);
    }
    // Σ weight × depth over the leaves is that of a Huffman tree of the weights and the unseen leaf.
    let depth = |mut position: u32| {
        let mut depth = 0;
        while position != root {
            position = tree.parent(position);
            depth += 1;
        }
        depth
    };
    let cost: u64 = leaves.iter().map(|leaf| tree.weight(*leaf) * depth(*leaf)).sum();
    let mut weights: Vec<u64> = counts.iter().copied().filter(|count| *count > 0).collect();
    weights.push(0);
    assert_eq!(cost, huffman_cost(&weights));
}

#[test]
fn vitter_trees_keep_the_invariants_of_algorithm_lambda() {
    let mut samples = Samples::new(3);
    for symbols in [2usize, 3, 5, 26, 258] {
        let mut tree = AdaptiveHuffmanTree::new(symbols).unwrap();
        let mut counts = vec![0u64; symbols];
        check_tree(&tree, &counts);
        for step in 0..3000 {
            // Skewed toward small symbols, with phases.
            let symbol = (samples.below(symbols as u64) * samples.below(symbols as u64) / symbols as u64 + step / 500)
                as usize
                % symbols;
            tree.update(symbol);
            counts[symbol] += 1;
            if step < 300 || step % 97 == 0 {
                check_tree(&tree, &counts);
            }
        }
        check_tree(&tree, &counts);
    }
    assert!(AdaptiveHuffmanTree::new(1).is_err());
}

#[test]
fn vitter_trees_code_unseen_symbols_by_their_index() {
    // 258 = 2^8 + 2: the symbols 0 to 3 in 9 bits, the others less 2 in 8 bits.
    let tree = AdaptiveHuffmanTree::new(258).unwrap();
    assert_eq!(tree.index_parameters(), (8, 2));
    assert_eq!(tree.index(0), (0, 9));
    assert_eq!(tree.index(3), (3, 9));
    assert_eq!(tree.index(4), (2, 8));
    assert_eq!(tree.index(257), (255, 8));
    for symbol in 0..258 {
        let (value, count) = tree.index(symbol);
        assert_eq!(tree.symbol_of_index(value, count), Some(symbol));
    }
    // The first code is the index alone (the unseen leaf is the root), most significant bit first.
    assert_eq!(tree.code(4), (0b0100_0000, 8));
    let tree = AdaptiveHuffmanTree::new(256).unwrap();
    assert_eq!(tree.index_parameters(), (8, 0));
    assert_eq!(tree.index(255), (255, 8));
}

#[test]
fn canonical_huffman_streams_round_trip() {
    for block_size in [37usize, 1000, 1 << 16] {
        let mut compressor = CanonicalHuffmanCompressor::new(CanonicalHuffmanConfig { block_size }).unwrap();
        Streaming::round_trip(&mut compressor, &mut CanonicalHuffmanDecompressor::new(), Ending::Marked, true);
    }
    assert_eq!(
        CanonicalHuffmanCompressor::new(CanonicalHuffmanConfig { block_size: 0 }),
        Err(CompressionError::InvalidParameter)
    );
}

#[test]
fn canonical_huffman_streams_follow_their_format() {
    // An empty stream: one last block whose code has END alone (1 bit, code 0).
    let stream =
        CanonicalHuffmanCompressor::new(CanonicalHuffmanConfig::default()).unwrap().compress_to_vec(b"").unwrap();
    let mut expected = BitWriter::new();
    expected.write(1, 1);
    for symbol in 0..CanonicalHuffmanFormat::SYMBOLS {
        expected.write((symbol == 256) as u64, 4);
    }
    expected.write(0, 1);
    assert_eq!(stream, expected.finish());
    // Two bytes of one value: the byte and END get codes 0 and 1.
    let stream =
        CanonicalHuffmanCompressor::new(CanonicalHuffmanConfig::default()).unwrap().compress_to_vec(b"aa").unwrap();
    let mut expected = BitWriter::new();
    expected.write(1, 1);
    for symbol in 0..CanonicalHuffmanFormat::SYMBOLS {
        expected.write((symbol == 97 || symbol == 256) as u64, 4);
    }
    expected.write(0b100, 3);
    assert_eq!(stream, expected.finish());
}

/// A stream of one last block with the code `lengths` and the codes `codes` (bits, length) after them.
fn canonical_stream(lengths: &[(usize, u8)], codes: &[(u64, u32)], padding: u64) -> Vec<u8> {
    let mut writer = BitWriter::new();
    writer.write(1, 1);
    let mut all = [0u8; 257];
    for (symbol, length) in lengths {
        all[*symbol] = *length;
    }
    for length in all {
        writer.write(length as u64, 4);
    }
    for (bits, length) in codes {
        writer.write(*bits, *length);
    }
    let pad = (8 - writer.bit_length() % 8) % 8;
    writer.write(padding, pad as u32);
    writer.finish()
}

#[test]
fn canonical_huffman_decompressors_reject_invalid_streams() {
    let mut decompressor = CanonicalHuffmanDecompressor::new();
    let mut check = |stream: Vec<u8>, reason: &'static str| {
        decompressor.reset();
        assert_eq!(decompressor.decompress_to_vec(&stream, 100), Err(CompressionError::InvalidData { reason }));
    };
    // END without a code, over-subscribed and incomplete codes.
    check(canonical_stream(&[(65, 1)], &[(0, 1)], 0), "no code for the end of the block");
    check(canonical_stream(&[(65, 1), (66, 1), (256, 1)], &[], 0), "over-subscribed code lengths");
    check(canonical_stream(&[(65, 1), (256, 2)], &[(1, 2)], 0), "incomplete code lengths");
    // Nonzero padding after END (code 1 of "a" 0, END 1).
    check(canonical_stream(&[(97, 1), (256, 1)], &[(0, 1), (1, 1)], 0b11), "nonzero padding");
    decompressor.reset();
    assert_eq!(
        decompressor.decompress_to_vec(&canonical_stream(&[(97, 1), (256, 1)], &[(0, 1), (1, 1)], 0), 100).unwrap(),
        b"a"
    );
}

#[test]
fn adaptive_huffman_streams_round_trip() {
    Streaming::round_trip(
        &mut AdaptiveHuffmanCompressor::new(),
        &mut AdaptiveHuffmanDecompressor::new(),
        Ending::Marked,
        true,
    );
}

#[test]
fn adaptive_huffman_streams_follow_their_format() {
    // "a", then END: the index of 97 (95 in 8 bits) from the root; then the
    // unseen leaf (bit 0) and the index of END (254 in 8 bits); then padding.
    let stream = AdaptiveHuffmanCompressor::new().compress_to_vec(b"a").unwrap();
    let mut expected = BitWriter::new();
    for bit in (0..8).rev() {
        expected.write((95 >> bit) & 1, 1);
    }
    expected.write(0, 1);
    for bit in (0..8).rev() {
        expected.write((254 >> bit) & 1, 1);
    }
    assert_eq!(stream, expected.finish());
    assert_eq!(AdaptiveHuffmanFormat::SYMBOLS, 258);
    // A nonzero padding bit is rejected.
    let mut invalid = stream.clone();
    *invalid.last_mut().unwrap() |= 0x80;
    assert_eq!(
        AdaptiveHuffmanDecompressor::new().decompress_to_vec(&invalid, 10),
        Err(CompressionError::InvalidData { reason: "nonzero padding" })
    );
}

#[test]
fn long_codes_decode_in_both_orders() {
    // Codes beyond the lengths tables hold (here up to 30 bits, as HPACK's):
    // a code of length n for symbol n, for n of 1 to 29, and two of 30.
    let mut lengths: Vec<u8> = (1..=29).collect();
    lengths.insert(0, 30);
    lengths.push(30);
    let code = HuffmanCode::from_lengths(&lengths).unwrap();
    assert!(code.is_complete() && code.maximum_length() == 30);
    for order in [BitOrder::MostSignificantFirst, BitOrder::LeastSignificantFirst] {
        let table = HuffmanTable::new(&code, order);
        assert_eq!(table.peek_bits(), 30);
        let mut writer = BitWriter::with_order(order);
        let message: Vec<usize> = (0..lengths.len()).rev().chain(0..lengths.len()).collect();
        for symbol in &message {
            let value = match order {
                BitOrder::MostSignificantFirst => code.code(*symbol),
                BitOrder::LeastSignificantFirst => code.reversed_code(*symbol),
            };
            writer.write(u64::from(value), code.length(*symbol));
        }
        let bytes = writer.finish();
        let mut queue = BitQueue::with_order(order);
        let mut input = &bytes[..];
        for symbol in &message {
            assert_eq!(table.read(&mut queue, &mut input).unwrap(), Some(*symbol as u16), "{order:?}");
        }
    }
}
