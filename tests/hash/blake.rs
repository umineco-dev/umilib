#[cfg(umilib_feature = "hash-blake-v2")]
mod v2 {
    use umilib::hash::blake::v2::*;
    use umilib::hash::{Digest, HashError};

    use crate::Vectors;

    /// The entries of blake2-kat.json: hash, input, key and output, read
    /// with a scanner for its fixed layout of string fields.
    fn known_answers() -> Vec<[String; 4]> {
        let text = Vectors::read("hash/blake/v2/blake2-kat.json");
        let mut fields = text.split('"').skip(1).step_by(2).map(String::from);
        let mut entries = Vec::new();
        while let Some(name) = fields.next() {
            assert_eq!(name, "hash");
            let mut entry: [String; 4] = Default::default();
            entry[0] = fields.next().unwrap();
            for (index, label) in ["in", "key", "out"].into_iter().enumerate() {
                assert_eq!(fields.next().as_deref(), Some(label));
                entry[index + 1] = fields.next().unwrap();
            }
            entries.push(entry);
        }
        entries
    }

    #[test]
    fn blake2_follows_the_reference_known_answers() {
        let entries = known_answers();
        assert_eq!(entries.len(), 12 * 256);
        for [name, input, key, output] in entries {
            let (input, key, expected) = (Vectors::hex(&input), Vectors::hex(&key), Vectors::hex(&output));
            let mut out = vec![0u8; expected.len()];
            match name.as_str() {
                "blake2b" => {
                    let mut hash = BLAKE2b::with_key(&key, out.len()).unwrap();
                    input.chunks(97).for_each(|piece| hash.update(piece));
                    hash.finalize_into(&mut out).unwrap();
                }
                "blake2s" => {
                    let mut hash = BLAKE2s::with_key(&key, out.len()).unwrap();
                    input.chunks(97).for_each(|piece| hash.update(piece));
                    hash.finalize_into(&mut out).unwrap();
                }
                "blake2bp" => {
                    let mut hash = BLAKE2bp::with_key(&key, out.len()).unwrap();
                    input.chunks(97).for_each(|piece| hash.update(piece));
                    hash.finalize_into(&mut out).unwrap();
                }
                "blake2sp" => {
                    let mut hash = BLAKE2sp::with_key(&key, out.len()).unwrap();
                    input.chunks(97).for_each(|piece| hash.update(piece));
                    hash.finalize_into(&mut out).unwrap();
                }
                "blake2xb" => {
                    let mut hash = BLAKE2Xb::with_key(&key, out.len() as u32).unwrap();
                    hash.update(&input);
                    hash.finalize_into(&mut out).unwrap();
                }
                "blake2xs" => {
                    let mut hash = BLAKE2Xs::with_key(&key, out.len() as u16).unwrap();
                    hash.update(&input);
                    hash.finalize_into(&mut out).unwrap();
                }
                other => panic!("unknown function {other}"),
            }
            assert_eq!(out, expected, "{name} input {} bytes, key {} bytes", input.len(), key.len());
        }
    }

    #[test]
    fn blake2_follows_the_examples_of_rfc7693() {
        let text = Vectors::read("hash/blake/v2/rfc7693.txt");
        let example = |label: &str, length: usize| {
            let start = text.find(label).unwrap() + label.len();
            let digits: String = text[start..].chars().filter(|c| c.is_ascii_hexdigit()).take(2 * length).collect();
            Vectors::hex(&digits)
        };
        assert_eq!(BLAKE2b512::digest(b"abc").to_vec(), example("BLAKE2b-512(\"abc\") =", 64));
        assert_eq!(BLAKE2s256::digest(b"abc").to_vec(), example("BLAKE2s-256(\"abc\") =", 32));
    }

    /// The sequence of RFC 7693 appendix E.
    fn sequence(length: usize, seed: u32) -> Vec<u8> {
        let (mut a, mut b) = (0xDEAD4BADu32.wrapping_mul(seed), 1u32);
        (0..length)
            .map(|_| {
                let t = a.wrapping_add(b);
                a = b;
                b = t;
                (t >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn blake2_passes_the_self_test_of_rfc7693() {
        // Appendix E: a hash of hashes over output and input lengths, keyed and unkeyed.
        let mut grand = BLAKE2b::new(32).unwrap();
        for output in [20, 32, 48, 64] {
            for input in [0usize, 3, 128, 129, 255, 1024] {
                let message = sequence(input, input as u32);
                for key in [Vec::new(), sequence(output, output as u32)] {
                    let mut hash = BLAKE2b::with_key(&key, output).unwrap();
                    hash.update(&message);
                    let mut digest = vec![0u8; output];
                    hash.finalize_into(&mut digest).unwrap();
                    grand.update(&digest);
                }
            }
        }
        let mut result = [0u8; 32];
        grand.finalize_into(&mut result).unwrap();
        assert_eq!(result.to_vec(), Vectors::hex("C23A7800D98123BD10F506C61E29DA5603D763B8BBAD2E737F5E765A7BCCD475"));
        let mut grand = BLAKE2s::new(32).unwrap();
        for output in [16, 20, 28, 32] {
            for input in [0usize, 3, 64, 65, 255, 1024] {
                let message = sequence(input, input as u32);
                for key in [Vec::new(), sequence(output, output as u32)] {
                    let mut hash = BLAKE2s::with_key(&key, output).unwrap();
                    hash.update(&message);
                    let mut digest = vec![0u8; output];
                    hash.finalize_into(&mut digest).unwrap();
                    grand.update(&digest);
                }
            }
        }
        grand.finalize_into(&mut result).unwrap();
        assert_eq!(result.to_vec(), Vectors::hex("6A411F08CE25ADCDFB02ABA641451CEC53C598B24F4FC787FBDC88797F4C1DFE"));
    }

    #[test]
    fn blake2_parameters_are_checked() {
        assert_eq!(BLAKE2b::new(0).unwrap_err(), HashError::OutputLength { length: 0, minimum: 1, maximum: 64 });
        assert_eq!(BLAKE2s::new(33).unwrap_err(), HashError::OutputLength { length: 33, minimum: 1, maximum: 32 });
        assert_eq!(
            BLAKE2b::with_key(&[0; 65], 64).unwrap_err(),
            HashError::KeyLength { length: 65, minimum: 0, maximum: 64 }
        );
        let mut parameters = BLAKE2bParameters::new(32);
        parameters.key_length = 3;
        assert_eq!(BLAKE2b::with_parameters(&parameters, b"ab").unwrap_err(), HashError::InvalidParameter);
        let mut hash = BLAKE2b::new(32).unwrap();
        assert!(hash.finalize_into(&mut [0; 31]).is_err());
        assert!(BLAKE2Xb::new(0).is_err());
        let mut xof = BLAKE2Xs::new(BLAKE2Xs::UNKNOWN_LENGTH).unwrap();
        let mut long = [0u8; 100];
        xof.finalize_into(&mut long).unwrap();
        assert!(BLAKE2Xb::new(10).unwrap().finalize_into(&mut [0; 11]).is_err());
        // The salt and the personalization change the result.
        let mut salted = BLAKE2bParameters::new(32);
        salted.salt[0] = 1;
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        BLAKE2b::with_parameters(&salted, &[]).unwrap().finalize_into(&mut a).unwrap();
        BLAKE2b::new(32).unwrap().finalize_into(&mut b).unwrap();
        assert_ne!(a, b);
        assert_eq!(BLAKE2bParameters::new(64).to_bytes()[..4], [64, 0, 1, 1]);
        assert_eq!((BLAKE2b512::OUTPUT_SIZE, BLAKE2b512::BLOCK_SIZE, BLAKE2s128::OUTPUT_SIZE), (64, 128, 16));
    }
}

#[cfg(umilib_feature = "hash-blake-v3")]
mod v3 {
    use umilib::hash::blake::v3::*;
    use umilib::hash::{Digest, ExtendableOutput, XOFReader};

    use crate::Vectors;

    /// The value of the string field `name` after `from` in the JSON text.
    fn field<'a>(text: &'a str, from: usize, name: &str) -> (&'a str, usize) {
        let label = format!("\"{name}\": ");
        let start = text[from..].find(&label).unwrap() + from + label.len();
        let value = &text[start..];
        let value = value.strip_prefix('"').unwrap_or(value);
        let end = value.find(['"', ',', '\n']).unwrap();
        (&value[..end], start + end)
    }

    #[test]
    fn blake3_follows_the_official_test_vectors() {
        let text = Vectors::read("hash/blake/v3/test_vectors.json");
        let key: [u8; 32] = field(&text, 0, "key").0.as_bytes().try_into().unwrap();
        let context = field(&text, 0, "context_string").0.as_bytes().to_vec();
        let mut position = 0;
        let mut cases = 0;
        while text[position..].contains("\"input_len\"") {
            let (length, next) = field(&text, position, "input_len");
            let input: Vec<u8> = (0..length.parse::<usize>().unwrap()).map(|index| (index % 251) as u8).collect();
            let (hash, next) = field(&text, next, "hash");
            let (keyed, next) = field(&text, next, "keyed_hash");
            let (derived, next) = field(&text, next, "derive_key");
            position = next;
            cases += 1;
            for (mut state, expected) in
                [(BLAKE3::new(), hash), (BLAKE3::with_key(&key), keyed), (BLAKE3::with_context(&context), derived)]
            {
                let expected = Vectors::hex(expected);
                // Pieces that cross block and chunk boundaries at odd places.
                input.chunks(1023).for_each(|piece| state.update(piece));
                let mut out = vec![0u8; expected.len()];
                state.clone().finalize_xof().read(&mut out);
                assert_eq!(out, expected, "input of {} bytes", input.len());
                assert_eq!(state.clone().finalize().to_vec(), expected[..32]);
                // Reading in pieces and from a position gives the same bytes.
                let mut reader = state.root().reader();
                let mut pieces = vec![0u8; expected.len()];
                for piece in pieces.chunks_mut(7) {
                    reader.read(piece);
                }
                assert_eq!(pieces, expected);
                reader.set_position(65);
                let mut tail = vec![0u8; expected.len() - 65];
                reader.read(&mut tail);
                assert_eq!(tail, expected[65..]);
            }
            assert_eq!(BLAKE3::digest(&input).to_vec(), Vectors::hex(hash)[..32]);
            assert_eq!(BLAKE3::keyed_hash(&key, &input).to_vec(), Vectors::hex(keyed)[..32]);
            assert_eq!(BLAKE3::derive_key(&context, &input).to_vec(), Vectors::hex(derived)[..32]);
            let mut xof = [0u8; 40];
            BLAKE3::digest_xof(&input, &mut xof);
            assert_eq!(xof.to_vec(), Vectors::hex(hash)[..40]);
        }
        assert_eq!(cases, 35);
    }

    #[test]
    fn blake3_reset_keeps_the_mode() {
        let key = [7u8; 32];
        let mut state = BLAKE3::with_key(&key);
        state.update(&[1; 5000]);
        state.reset();
        state.update(b"abc");
        assert_eq!(state.finalize(), BLAKE3::keyed_hash(&key, b"abc"));
        let mut digest = BLAKE3::new();
        Digest::update(&mut digest, b"abc");
        assert_eq!(Digest::finalize_reset(&mut digest), BLAKE3::digest(b"abc"));
        assert_eq!(Digest::finalize(digest), BLAKE3::digest(b""));
        assert_eq!((<BLAKE3 as Digest>::OUTPUT_SIZE, BLAKE3::CHUNK_SIZE), (32, 1024));
        assert_eq!(format!("{:?}", BLAKE3::new()), "BLAKE3(..)");
    }
}

#[cfg(umilib_feature = "hash-blake-v2")]
mod v2_layout {
    use umilib::hash::blake::v2::*;

    #[test]
    fn blake2_parameter_blocks_round_trip() {
        let mut b = BLAKE2bParameters::new(48);
        b.key_length = 9;
        b.fanout = 4;
        b.depth = 2;
        b.leaf_length = 0x01020304;
        b.node_offset = 0x05060708;
        b.xof_length = 0x090A0B0C;
        b.node_depth = 3;
        b.inner_length = 64;
        b.salt = [7; 16];
        b.personal = [8; 16];
        let block = b.to_bytes();
        // RFC 7693 section 2.8: lengths, fanout and depth first, words little-endian.
        assert_eq!(block[..18], [48, 9, 4, 2, 4, 3, 2, 1, 8, 7, 6, 5, 0x0C, 0x0B, 0x0A, 9, 3, 64]);
        assert_eq!(BLAKE2bParameters::from_bytes(&block), Ok(b));
        let mut reserved = block;
        reserved[20] = 1;
        assert!(BLAKE2bParameters::from_bytes(&reserved).is_err());
        let mut s = BLAKE2sParameters::new(20);
        s.xof_length = 0x0102;
        s.salt = [1; 8];
        assert_eq!(BLAKE2sParameters::from_bytes(&s.to_bytes()), s);
    }

    #[test]
    fn blake2_parallel_and_xof_reset() {
        let mut parallel = BLAKE2bp::with_key(b"key", 64).unwrap();
        parallel.update(&[1; 1000]);
        parallel.reset();
        parallel.update(b"abc");
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        parallel.finalize_into(&mut a).unwrap();
        let mut fresh = BLAKE2bp::with_key(b"key", 64).unwrap();
        fresh.update(b"abc");
        fresh.finalize_into(&mut b).unwrap();
        assert_eq!(a, b);
        let mut xof = BLAKE2Xs::new(100).unwrap();
        xof.update(&[2; 99]);
        xof.reset();
        xof.update(b"abc");
        let (mut c, mut d) = ([0u8; 100], [0u8; 100]);
        xof.finalize_into(&mut c).unwrap();
        let mut fresh = BLAKE2Xs::new(100).unwrap();
        fresh.update(b"abc");
        fresh.finalize_into(&mut d).unwrap();
        assert_eq!(c, d);
    }
}

#[cfg(umilib_feature = "hash-blake-v2")]
mod v2_readers {
    use umilib::hash::XOFReader;
    use umilib::hash::blake::v2::*;

    #[test]
    fn blake2x_readers_equal_finalize_into() {
        for length in [1u32, 63, 64, 65, 128, 1000] {
            let mut declared = BLAKE2Xb::with_key(b"key", length).unwrap();
            declared.update(b"message");
            let mut whole = vec![0u8; length as usize];
            declared.clone().finalize_into(&mut whole).unwrap();
            let mut reader = declared.finalize_xof();
            let mut pieces = vec![0u8; length as usize];
            for piece in pieces.chunks_mut(13) {
                reader.read(piece);
            }
            assert_eq!(pieces, whole, "{length}");
            assert_eq!((reader.position(), reader.len()), (length as u64, length as u64));
        }
        // With an unknown length every node is whole, so multiples of the node size agree.
        let mut open = BLAKE2Xs::new(BLAKE2Xs::UNKNOWN_LENGTH).unwrap();
        open.update(b"message");
        let mut whole = vec![0u8; 3 * BLAKE2Xs::NODE_SIZE];
        open.clone().finalize_into(&mut whole).unwrap();
        let mut streamed = vec![0u8; 3 * BLAKE2Xs::NODE_SIZE];
        open.finalize_xof().read(&mut streamed);
        assert_eq!(streamed, whole);
    }

    #[test]
    #[should_panic(expected = "ends after its length")]
    fn blake2x_readers_end_after_their_length() {
        let mut reader = BLAKE2Xb::new(10).unwrap().finalize_xof();
        reader.read(&mut [0; 11]);
    }

    #[test]
    fn blake2x_parameters_reach_every_node() {
        let mut salted = BLAKE2bParameters::new(64);
        salted.xof_length = 200;
        salted.salt = [7; 16];
        salted.personal = [8; 16];
        let mut with = BLAKE2Xb::with_parameters(&salted, &[]).unwrap();
        let mut without = BLAKE2Xb::new(200).unwrap();
        let (mut a, mut b) = ([0u8; 200], [0u8; 200]);
        with.finalize_into(&mut a).unwrap();
        without.finalize_into(&mut b).unwrap();
        // Every node depends on the salt, not only the first.
        for (x, y) in a.chunks(64).zip(b.chunks(64)) {
            assert_ne!(x, y);
        }
        let mut wrong = salted;
        wrong.digest_length = 32;
        assert!(BLAKE2Xb::with_parameters(&wrong, &[]).is_err());
        let mut inner = BLAKE2bParameters::new(32);
        inner.inner_length = 65;
        assert!(BLAKE2b::with_parameters(&inner, &[]).is_err());
    }
}
