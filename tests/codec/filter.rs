//! Filters: Delta against the code of the .xz format specification
//! (section 5.3.3.1), BCJ conversions of single instructions, and chains.

use umilib::codec::CompressionError;
use umilib::codec::filter::bcj::{BCJArchitecture, BCJFilter};
use umilib::codec::filter::delta::DeltaFilter;
use umilib::codec::filter::{Filter, FilterChain};

use crate::Vectors;
use crate::compression::Samples;

/// The Delta filter as the code of section 5.3.3.1 writes it.
fn reference_delta(data: &[u8], distance: usize, encoding: bool) -> Vec<u8> {
    let mut position = 0u8;
    let mut delta = [0u8; 256];
    let mut out = Vec::new();
    for &byte in data {
        let mut value = delta[(distance as u8).wrapping_add(position) as usize];
        if encoding {
            value = byte.wrapping_sub(value);
            delta[position as usize] = byte;
        } else {
            value = byte.wrapping_add(value);
            delta[position as usize] = value;
        }
        out.push(value);
        position = position.wrapping_sub(1);
    }
    out
}

/// Converts `data` with `filter` in pieces of the given sizes (cycled), as a stream; `end` at its end.
fn convert<F: Filter>(filter: &mut F, data: &[u8], pieces: &[usize], encoding: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    let mut position = 0;
    let mut piece = 0;
    while position < data.len() {
        let end = (position + pieces[piece % pieces.len()]).min(data.len());
        piece += 1;
        pending.extend_from_slice(&data[position..end]);
        position = end;
        let done = if encoding { filter.encode(&mut pending) } else { filter.decode(&mut pending) };
        assert!(pending.len() - done <= filter.lookahead(), "at most the lookahead is left");
        out.extend(pending.drain(..done));
    }
    out.extend(pending);
    out
}

#[test]
fn delta_filters_follow_section_5_3_3() {
    let mut samples = Samples::new(1);
    let data = samples.text(3000);
    for distance in [1, 2, 4, 7, 100, 255, 256] {
        let encoded = reference_delta(&data, distance, true);
        let mut filter = DeltaFilter::new(distance).unwrap();
        assert_eq!(convert(&mut filter, &data, &[1, 13, 600], true), encoded, "distance {distance}");
        let mut filter = DeltaFilter::new(distance).unwrap();
        assert_eq!(convert(&mut filter, &encoded, &[3000], false), data);
        assert_eq!(reference_delta(&encoded, distance, false), data);
    }
    // The distance is 1 to 256.
    assert_eq!(DeltaFilter::new(0), Err(CompressionError::InvalidParameter));
    assert_eq!(DeltaFilter::new(257), Err(CompressionError::InvalidParameter));
    // A distance of 1 stores differences of consecutive bytes, the first against 0.
    let mut filter = DeltaFilter::new(1).unwrap();
    let mut bytes = [5, 7, 7, 1];
    assert_eq!(filter.encode(&mut bytes), 4);
    assert_eq!(bytes, [5, 2, 0, 0xFA]);
}

/// Encodes `input` at `start` with a fresh filter of `architecture`; checks the output and its decoding.
fn instruction(architecture: BCJArchitecture, start: u32, input: &[u8], output: &[u8]) {
    let mut data = input.to_vec();
    let done = BCJFilter::new(architecture, start).unwrap().encode(&mut data);
    assert!(done > 0, "{architecture:?} converts the instruction");
    assert_eq!(data, output, "{architecture:?}");
    BCJFilter::new(architecture, start).unwrap().decode(&mut data);
    assert_eq!(data, input, "{architecture:?} decoding");
}

#[test]
fn bcj_filters_convert_relative_addresses_to_absolute_ones() {
    // x86 CALL rel32 at address 0: the target 0 + 5 + 0; at 0x100 a displacement of -5: the target 0x100.
    instruction(BCJArchitecture::X86, 0, &[0xE8, 0, 0, 0, 0, 0x90], &[0xE8, 5, 0, 0, 0, 0x90]);
    instruction(BCJArchitecture::X86, 0x100, &[0xE8, 0xFB, 0xFF, 0xFF, 0xFF, 0x90], &[0xE8, 0, 1, 0, 0, 0x90]);
    // ARM BL at 0x1000 of 0x10 words: the target 0x1000 + 8 + 0x40, in words.
    instruction(BCJArchitecture::ARM, 0x1000, &[0x10, 0, 0, 0xEB], &[0x12, 0x04, 0, 0xEB]);
    // ARM Thumb BL at 0 of 0x100 halfwords: the target 0 + 4 + 0x200, in halfwords.
    instruction(BCJArchitecture::ARMThumb, 0, &[0x00, 0xF0, 0x00, 0xF9], &[0x00, 0xF0, 0x02, 0xF9]);
    // ARM64 BL at 0x2000 of 4 words: the target 0x2000 / 4 + 4.
    instruction(BCJArchitecture::ARM64, 0x2000, &0x9400_0004u32.to_le_bytes(), &0x9400_0804u32.to_le_bytes());
    // PowerPC BL at 0x100 of 0x10 bytes: the target 0x110.
    instruction(BCJArchitecture::PowerPC, 0x100, &0x4800_0011u32.to_be_bytes(), &0x4800_0111u32.to_be_bytes());
    // SPARC CALL at 0x40 of 4 words: the target 0x50, in words.
    instruction(BCJArchitecture::SPARC, 0x40, &0x4000_0004u32.to_be_bytes(), &0x4000_0014u32.to_be_bytes());
    // RISC-V JAL ra at 0x10 of 0x100: the target 0x110, stored big endian in the immediate's bytes.
    instruction(
        BCJArchitecture::RISCV,
        0x10,
        &[0xEF, 0x00, 0x00, 0x10, 0, 0, 0, 0],
        &[0xEF, 0x00, 0x00, 0x88, 0, 0, 0, 0],
    );
    // Start offsets are multiples of the alignment.
    for (architecture, alignment) in [
        (BCJArchitecture::X86, 1),
        (BCJArchitecture::PowerPC, 4),
        (BCJArchitecture::IA64, 16),
        (BCJArchitecture::ARM, 4),
        (BCJArchitecture::ARMThumb, 2),
        (BCJArchitecture::SPARC, 4),
        (BCJArchitecture::ARM64, 4),
        (BCJArchitecture::RISCV, 2),
    ] {
        assert_eq!(architecture.alignment(), alignment);
        assert!(BCJFilter::new(architecture, alignment * 3).is_ok());
        if alignment > 1 {
            assert_eq!(BCJFilter::new(architecture, alignment + 1), Err(CompressionError::InvalidParameter));
        }
    }
}

#[test]
fn bcj_filters_are_reversible_in_any_pieces() {
    let data = Vectors::bytes("codec/xz/bcj.bin");
    let mut samples = Samples::new(2);
    let random = samples.random(5000);
    for architecture in BCJArchitecture::ALL {
        for start in [0, architecture.alignment() * 1000, 0u32.wrapping_sub(architecture.alignment() * 4)] {
            let mut filter = BCJFilter::new(architecture, start).unwrap();
            let encoded = convert(&mut filter, &data, &[data.len()], true);
            assert_ne!(encoded, data, "{architecture:?} converts instructions of bcj.bin");
            for pieces in [&[1usize][..], &[7, 3, 100][..], &[4096][..]] {
                let mut filter = BCJFilter::new(architecture, start).unwrap();
                assert_eq!(convert(&mut filter, &data, pieces, true), encoded, "{architecture:?} pieces {pieces:?}");
                let mut filter = BCJFilter::new(architecture, start).unwrap();
                assert_eq!(convert(&mut filter, &encoded, pieces, false), data, "{architecture:?} decoding");
            }
            // Any data, not only code, comes back.
            let mut filter = BCJFilter::new(architecture, start).unwrap();
            let encoded = convert(&mut filter, &random, &[333], true);
            filter.reset();
            assert_eq!(convert(&mut filter, &encoded, &[1000], false), random);
        }
    }
}

#[test]
fn filter_chains_apply_filters_in_order_and_reverse() {
    let data = Vectors::bytes("codec/xz/bcj.bin");
    let filters = || {
        vec![
            ChainFilter::Delta(Box::new(DeltaFilter::new(4).unwrap())),
            ChainFilter::Branch(BCJFilter::new(BCJArchitecture::X86, 0).unwrap()),
        ]
    };
    // Encoding applies Delta, then x86.
    let mut expected = data.clone();
    DeltaFilter::new(4).unwrap().encode(&mut expected);
    let mut x86 = BCJFilter::new(BCJArchitecture::X86, 0).unwrap();
    let done = x86.encode(&mut expected);
    assert!(expected.len() - done <= 5);
    let mut chain = FilterChain::new(filters());
    let mut encoded = Vec::new();
    for piece in data.chunks(777) {
        chain.extend(piece);
        chain.encode(false);
        encoded.extend_from_slice(chain.ready());
        let ready = chain.ready().len();
        chain.consume(ready);
        assert!(chain.len() <= chain.lookahead());
    }
    chain.encode(true);
    encoded.extend_from_slice(chain.ready());
    assert_eq!(encoded, expected);
    // Decoding reverses them.
    let mut chain = FilterChain::new(filters());
    let mut decoded = Vec::new();
    for piece in encoded.chunks(1000) {
        chain
            .fill(piece.len(), |room| {
                room.copy_from_slice(piece);
                Ok::<usize, ()>(piece.len())
            })
            .unwrap();
        chain.decode(false);
        decoded.extend_from_slice(chain.ready());
        let ready = chain.ready().len();
        chain.consume(ready);
    }
    chain.decode(true);
    decoded.extend_from_slice(chain.ready());
    assert_eq!(decoded, data);
}

/// The filters of a chain of the tests (the history of Delta boxed, as in `XZFilterCoder`).
#[derive(Clone, Debug)]
enum ChainFilter {
    Delta(Box<DeltaFilter>),
    Branch(BCJFilter),
}

impl Filter for ChainFilter {
    fn lookahead(&self) -> usize {
        match self {
            ChainFilter::Delta(filter) => filter.lookahead(),
            ChainFilter::Branch(filter) => filter.lookahead(),
        }
    }

    fn encode(&mut self, data: &mut [u8]) -> usize {
        match self {
            ChainFilter::Delta(filter) => filter.encode(data),
            ChainFilter::Branch(filter) => filter.encode(data),
        }
    }

    fn decode(&mut self, data: &mut [u8]) -> usize {
        match self {
            ChainFilter::Delta(filter) => filter.decode(data),
            ChainFilter::Branch(filter) => filter.decode(data),
        }
    }

    fn reset(&mut self) {
        match self {
            ChainFilter::Delta(filter) => filter.reset(),
            ChainFilter::Branch(filter) => filter.reset(),
        }
    }
}
