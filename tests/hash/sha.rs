#[cfg(umilib_feature = "hash-sha-v1")]
mod v1 {
    use umilib::hash::Digest;
    use umilib::hash::sha::v1::SHA1;

    use crate::{Shavs, Vectors};

    #[test]
    fn sha1_follows_shavs() {
        Shavs::check::<SHA1>("hash/sha/v1/SHA1");
    }

    #[test]
    fn sha1_follows_the_tests_of_rfc3174() {
        // Section 7.3: the test strings, repeated, and their digests.
        let text = Vectors::read("hash/sha/v1/rfc3174.txt");
        let results: Vec<Vec<u8>> = text
            .lines()
            .filter(|line| line.trim().starts_with("\"") && line.contains(" 9"))
            .map(|line| Vectors::hex(line.trim().trim_matches(|c| c == '"' || c == ',')))
            .collect();
        let tests: [(&[u8], usize); 4] = [
            (b"abc", 1),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1),
            (b"a", 1_000_000),
            (b"0123456701234567012345670123456701234567012345670123456701234567", 10),
        ];
        assert_eq!(results.len(), 4);
        for ((message, count), expected) in tests.into_iter().zip(results) {
            let mut hash = SHA1::new();
            for _ in 0..count {
                hash.update(message);
            }
            assert_eq!(hash.finalize().to_vec(), expected);
        }
        assert_eq!((SHA1::OUTPUT_SIZE, SHA1::BLOCK_SIZE), (20, 64));
    }
}

#[cfg(umilib_feature = "hash-sha-v2")]
mod v2 {
    use umilib::hash::Digest;
    use umilib::hash::sha::v2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};

    use crate::Shavs;

    #[test]
    fn sha224_follows_shavs() {
        Shavs::check::<SHA224>("hash/sha/v2/SHA224");
    }

    #[test]
    fn sha256_follows_shavs() {
        Shavs::check::<SHA256>("hash/sha/v2/SHA256");
    }

    #[test]
    fn sha384_follows_shavs() {
        Shavs::check::<SHA384>("hash/sha/v2/SHA384");
    }

    #[test]
    fn sha512_follows_shavs() {
        Shavs::check::<SHA512>("hash/sha/v2/SHA512");
    }

    #[test]
    fn sha512_224_follows_shavs() {
        Shavs::check::<SHA512_224>("hash/sha/v2/SHA512_224");
    }

    #[test]
    fn sha512_256_follows_shavs() {
        Shavs::check::<SHA512_256>("hash/sha/v2/SHA512_256");
    }

    #[test]
    fn truncated_initial_values_follow_section_5_3_6() {
        assert_eq!(SHA512::truncated_initial_state(224), Some(SHA512_224::INITIAL_STATE));
        assert_eq!(SHA512::truncated_initial_state(256), Some(SHA512_256::INITIAL_STATE));
        for invalid in [0, 384, 512, 1000] {
            assert_eq!(SHA512::truncated_initial_state(invalid), None);
        }
    }

    #[test]
    fn sizes_follow_fips_180_4() {
        assert_eq!((SHA224::OUTPUT_SIZE, SHA224::BLOCK_SIZE), (28, 64));
        assert_eq!((SHA256::OUTPUT_SIZE, SHA256::BLOCK_SIZE), (32, 64));
        assert_eq!((SHA384::OUTPUT_SIZE, SHA384::BLOCK_SIZE), (48, 128));
        assert_eq!((SHA512::OUTPUT_SIZE, SHA512::BLOCK_SIZE), (64, 128));
        assert_eq!((SHA512_224::OUTPUT_SIZE, SHA512_256::OUTPUT_SIZE), (28, 32));
        assert_eq!(format!("{:?}", SHA256::new()), "SHA256(..)");
    }
}

#[cfg(umilib_feature = "hash-sha-v3")]
mod v3 {
    use umilib::hash::sha::v3::*;
    use umilib::hash::{Digest, ExtendableOutput, XOFReader};

    use crate::{Record, Vectors};

    #[test]
    fn the_permutation_follows_the_keccak_reference() {
        let text = Vectors::read("hash/sha/v3/KeccakF-1600-IntermediateValues.txt");
        let constants: Vec<u64> = text
            .lines()
            .filter(|line| line.starts_with("RC["))
            .map(|line| u64::from_str_radix(line.split('=').nth(1).unwrap().trim(), 16).unwrap())
            .collect();
        assert_eq!(constants, KeccakF1600::ROUND_CONSTANTS);
        let offsets: Vec<(usize, usize, u32)> = text
            .lines()
            .filter_map(|line| line.strip_prefix("RhoOffset["))
            .map(|rest| {
                let (x, rest) = rest.split_once("][").unwrap();
                let (y, value) = rest.split_once("] =").unwrap();
                (x.parse().unwrap(), y.parse().unwrap(), value.trim().parse().unwrap())
            })
            .collect();
        assert_eq!(offsets.len(), 25);
        for (x, y, offset) in offsets {
            assert_eq!(KeccakF1600::ROTATIONS[x + 5 * y], offset, "({x}, {y})");
        }
        // The all-zero state, then the output again, through the permutation.
        let lines: Vec<&str> = text.lines().collect();
        let mut state = [0u64; 25];
        for (index, _) in lines.iter().enumerate().filter(|(_, line)| line.starts_with("State after permutation:")) {
            KeccakF1600::permute(&mut state);
            let bytes = Vectors::hex(lines[index + 1]);
            let expected: Vec<u64> = bytes.chunks(8).map(|lane| u64::from_le_bytes(lane.try_into().unwrap())).collect();
            assert_eq!(state.to_vec(), expected);
        }
    }

    /// Checks the SHA3VS files of a fixed-length function `{prefix}`: every
    /// message and the Monte Carlo test of section 6.2.3.
    fn check_sha3<H: Digest + Default>(prefix: &str) {
        for kind in ["ShortMsg", "LongMsg"] {
            for record in Record::all(&format!("{prefix}{kind}.rsp")) {
                let message = record.message();
                let expected = record.bytes("MD");
                assert_eq!(H::digest(&message).as_ref(), expected, "{prefix}{kind} Len = {}", record.field("Len"));
                let mut hash = H::default();
                for piece in message.chunks(41) {
                    hash.update(piece);
                }
                assert_eq!(hash.finalize_reset().as_ref(), expected);
            }
        }
        let records = Record::all(&format!("{prefix}Monte.rsp"));
        let mut digest = records[0].bytes("Seed");
        for record in &records[1..] {
            for _ in 0..1000 {
                digest = H::digest(&digest).as_ref().to_vec();
            }
            assert_eq!(digest, record.bytes("MD"), "{prefix}Monte COUNT = {}", record.field("COUNT"));
        }
    }

    #[test]
    fn sha3_follows_sha3vs() {
        check_sha3::<SHA3_224>("hash/sha/v3/SHA3_224");
        check_sha3::<SHA3_256>("hash/sha/v3/SHA3_256");
        check_sha3::<SHA3_384>("hash/sha/v3/SHA3_384");
        check_sha3::<SHA3_512>("hash/sha/v3/SHA3_512");
        assert_eq!((SHA3_256::OUTPUT_SIZE, SHA3_256::BLOCK_SIZE), (32, 136));
    }

    /// Checks the SHA3VS files of an extendable-output function `{prefix}`.
    fn check_shake<X: ExtendableOutput + Default>(prefix: &str) {
        for kind in ["ShortMsg", "LongMsg", "VariableOut"] {
            for record in Record::all(&format!("{prefix}{kind}.rsp")) {
                let message = record.bytes("Msg");
                let message = match record.get("Len") {
                    Some(_) => record.message(),
                    None => message,
                };
                let expected = record.bytes("Output");
                let mut output = vec![0; expected.len()];
                X::digest_xof(&message, &mut output);
                assert_eq!(output, expected, "{prefix}{kind} {:?}", record.get("COUNT").or(record.get("Len")));
                // Reading in pieces gives the same stream.
                let mut function = X::default();
                function.update(&message);
                let mut reader = function.finalize_xof();
                let mut pieces = vec![0; expected.len()];
                for piece in pieces.chunks_mut(7) {
                    reader.read(piece);
                }
                assert_eq!(pieces, expected);
            }
        }
        // Section 6.3.3.
        let records = Record::all(&format!("{prefix}Monte.rsp"));
        let header = &records[0].header;
        let minimum: usize = header["Minimum Output Length (bits)"].parse::<usize>().unwrap().div_ceil(8);
        let maximum: usize = header["Maximum Output Length (bits)"].parse::<usize>().unwrap() / 8;
        let mut output = records[0].bytes("Msg");
        let mut length = maximum;
        for record in &records[1..] {
            let mut checkpoint_length = 0;
            for i in 1..=1000 {
                let mut message = output.clone();
                message.resize(16, 0);
                message.truncate(16);
                output = vec![0; length];
                X::digest_xof(&message, &mut output);
                if i == 1000 {
                    checkpoint_length = length;
                }
                let rightmost = u16::from_be_bytes([output[output.len() - 2], output[output.len() - 1]]) as usize;
                length = minimum + rightmost % (maximum - minimum + 1);
            }
            assert_eq!(checkpoint_length * 8, record.field("Outputlen").parse::<usize>().unwrap());
            assert_eq!(output, record.bytes("Output"), "{prefix}Monte COUNT = {}", record.field("COUNT"));
        }
    }

    #[test]
    fn shake_follows_sha3vs() {
        check_shake::<SHAKE128>("hash/sha/v3/SHAKE128");
        check_shake::<SHAKE256>("hash/sha/v3/SHAKE256");
        assert_eq!((SHAKE128::BLOCK_SIZE, SHAKE256::BLOCK_SIZE), (168, 136));
    }

    #[test]
    fn keccak_follows_the_submission_known_answers() {
        fn check<H: Digest + Default>(bits: usize) {
            let records = Record::all(&format!("hash/sha/v3/KeccakShortMsgKAT_{bits}.txt"));
            let mut checked = 0;
            for record in records.iter().filter(|record| record.field("Len").parse::<usize>().unwrap() % 8 == 0) {
                assert_eq!(
                    H::digest(&record.message()).as_ref(),
                    record.bytes("MD"),
                    "Keccak-{bits} Len = {}",
                    record.field("Len")
                );
                checked += 1;
            }
            assert!(checked > 200);
        }
        check::<Keccak224>(224);
        check::<Keccak256>(256);
        check::<Keccak384>(384);
        check::<Keccak512>(512);
    }

    #[test]
    fn sp800185_functions_follow_the_nist_samples() {
        let text = Vectors::read("hash/sha/v3/sp800185.txt");
        let mut checked = 0;
        for line in text.lines().filter(|line| !line.starts_with('#')) {
            let fields: Vec<&str> = line.split(' ').collect();
            let field = |index: usize| if fields[index] == "-" { Vec::new() } else { Vectors::hex(fields[index]) };
            let (function, strength) = (fields[0], fields[1]);
            let (name, customization) = (field(2), field(3));
            let block_size: usize = fields[4].parse().unwrap();
            let mut output = vec![0; fields[5].parse::<usize>().unwrap() / 8];
            let expected = field(7);
            match (function, strength) {
                ("cSHAKE", "128") => {
                    let mut cshake = CSHAKE128::new(&name, &customization);
                    cshake.update(&field(6));
                    cshake.finalize_xof().read(&mut output);
                }
                ("cSHAKE", "256") => {
                    let mut cshake = CSHAKE256::new(&name, &customization);
                    cshake.update(&field(6));
                    cshake.finalize_xof().read(&mut output);
                }
                ("TupleHash", strength) => {
                    let elements: Vec<Vec<u8>> = fields[6].split(',').map(Vectors::hex).collect();
                    if strength == "128" {
                        let mut tuple = TupleHash128::new(&customization);
                        elements.iter().for_each(|element| tuple.push(element));
                        tuple.finalize(&mut output);
                    } else {
                        let mut tuple = TupleHash256::new(&customization);
                        elements.iter().for_each(|element| tuple.push(element));
                        tuple.finalize(&mut output);
                    }
                }
                ("ParallelHash", "128") => {
                    let mut parallel = ParallelHash128::new(block_size, &customization).unwrap();
                    field(6).chunks(5).for_each(|piece| parallel.update(piece));
                    parallel.finalize(&mut output);
                }
                ("ParallelHash", "256") => {
                    let mut parallel = ParallelHash256::new(block_size, &customization).unwrap();
                    parallel.update(&field(6));
                    parallel.finalize(&mut output);
                }
                ("KMAC" | "KMACXOF", strength) => {
                    // SP 800-185 section 4.3: cSHAKE(bytepad(encode_string(K), rate) || X || right_encode(L), L, "KMAC", S).
                    let rate = if strength == "128" { 168 } else { 136 };
                    let mut prefix = Vec::new();
                    let (encoded, length) = SP800185::left_encode(rate as u128);
                    prefix.extend_from_slice(&encoded[..length]);
                    let (encoded, length) = SP800185::left_encode(name.len() as u128 * 8);
                    prefix.extend_from_slice(&encoded[..length]);
                    prefix.extend_from_slice(&name);
                    prefix.resize(prefix.len().div_ceil(rate) * rate, 0);
                    let bits = if function == "KMAC" { output.len() as u128 * 8 } else { 0 };
                    let (length_encoding, size) = SP800185::right_encode(bits);
                    if strength == "128" {
                        let mut cshake = CSHAKE128::new(b"KMAC", &customization);
                        cshake.update(&prefix);
                        cshake.update(&field(6));
                        cshake.update(&length_encoding[..size]);
                        cshake.finalize_xof().read(&mut output);
                    } else {
                        let mut cshake = CSHAKE256::new(b"KMAC", &customization);
                        cshake.update(&prefix);
                        cshake.update(&field(6));
                        cshake.update(&length_encoding[..size]);
                        cshake.finalize_xof().read(&mut output);
                    }
                }
                ("TupleHashXOF", strength) => {
                    let elements: Vec<Vec<u8>> = fields[6].split(',').map(Vectors::hex).collect();
                    if strength == "128" {
                        let mut tuple = TupleHash128::new(&customization);
                        elements.iter().for_each(|element| tuple.push(element));
                        tuple.finalize_xof().read(&mut output);
                    } else {
                        let mut tuple = TupleHash256::new(&customization);
                        elements.iter().for_each(|element| tuple.push(element));
                        tuple.finalize_xof().read(&mut output);
                    }
                }
                ("ParallelHashXOF", "128") => {
                    let mut parallel = ParallelHash128::new(block_size, &customization).unwrap();
                    parallel.update(&field(6));
                    let mut reader = parallel.finalize_xof();
                    let (first, rest) = output.split_at_mut(7);
                    reader.read(first);
                    reader.read(rest);
                }
                ("ParallelHashXOF", "256") => {
                    let mut parallel = ParallelHash256::new(block_size, &customization).unwrap();
                    parallel.update(&field(6));
                    parallel.finalize_xof().read(&mut output);
                }
                other => panic!("unknown sample {other:?}"),
            }
            assert_eq!(output, expected, "{line}");
            checked += 1;
        }
        assert_eq!(checked, 40);
        assert_eq!(ParallelHash128::new(0, b"").unwrap_err(), umilib::hash::HashError::InvalidParameter);
    }

    #[test]
    fn cshake_without_name_or_customization_is_shake() {
        // SP 800-185 section 3.3: cSHAKE(X, L, "", "") = SHAKE(X, L).
        for data in [&b""[..], b"abc", &[0x5A; 300]] {
            let (mut a, mut b) = ([0u8; 100], [0u8; 100]);
            let mut cshake = CSHAKE128::new(b"", b"");
            cshake.update(data);
            cshake.finalize_xof().read(&mut a);
            SHAKE128::digest_xof(data, &mut b);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn sp800185_encodings_follow_section_2_3() {
        let left = |x: u128| {
            let (bytes, length) = SP800185::left_encode(x);
            bytes[..length].to_vec()
        };
        let right = |x: u128| {
            let (bytes, length) = SP800185::right_encode(x);
            bytes[..length].to_vec()
        };
        assert_eq!(left(0), [1, 0]);
        assert_eq!(left(168), [1, 168]);
        assert_eq!(left(256), [2, 1, 0]);
        assert_eq!(right(0), [0, 1]);
        assert_eq!(right(256), [1, 0, 2]);
        assert_eq!(left(u128::MAX)[0], 16);
    }
}

#[cfg(umilib_feature = "hash-sha-v3")]
#[test]
fn parallel_hash_reset_returns_to_the_empty_input() {
    use umilib::hash::sha::v3::ParallelHash128;
    let mut hash = ParallelHash128::new(8, b"custom").unwrap();
    hash.update(&[1; 30]);
    hash.reset();
    hash.update(b"abc");
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    hash.finalize(&mut a);
    let mut fresh = ParallelHash128::new(8, b"custom").unwrap();
    fresh.update(b"abc");
    fresh.finalize(&mut b);
    assert_eq!(a, b);
}
