//! Fuzz targets of `umilib::hash`.

use umilib::platform::fuzz::{FuzzFunction, FuzzTarget};

/// Splits an input into pieces whose lengths come from its first byte, so
/// that the pieces cross block and buffer boundaries at varied places.
pub struct Pieces;

impl Pieces {
    pub fn split(data: &[u8]) -> (u8, Vec<&[u8]>) {
        let Some((&seed, mut rest)) = data.split_first() else {
            return (0, Vec::new());
        };
        let mut pieces = Vec::new();
        let mut state = seed as u32 | 1;
        while !rest.is_empty() {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            let length = match state >> 28 {
                0 => 0,
                1..=4 => (state >> 16) as usize % 8,
                5..=12 => (state >> 16) as usize % 300,
                _ => (state >> 16) as usize % 2000,
            }
            .min(rest.len());
            let (piece, tail) = rest.split_at(length);
            pieces.push(piece);
            rest = tail;
        }
        (seed, pieces)
    }
}

/// Checks that the hash of the input fed in pieces equals the one-shot hash, for every `Digest`.
#[cfg(umilib_feature = "hash")]
pub fn streaming(data: &[u8]) {
    use umilib::hash::Digest;
    let (_, pieces) = Pieces::split(data);
    let message: Vec<u8> = pieces.concat();
    fn check<H: Digest + Default>(pieces: &[&[u8]], message: &[u8]) {
        let mut state = H::default();
        for piece in pieces {
            state.update(piece);
        }
        let expected = H::digest(message);
        assert_eq!(state.finalize_reset().as_ref(), expected.as_ref());
        state.update(message);
        assert_eq!(state.finalize().as_ref(), expected.as_ref());
    }
    #[cfg(umilib_feature = "hash-sha-v1")]
    check::<umilib::hash::sha::v1::SHA1>(&pieces, &message);
    #[cfg(umilib_feature = "hash-sha-v2")]
    {
        check::<umilib::hash::sha::v2::SHA256>(&pieces, &message);
        check::<umilib::hash::sha::v2::SHA512_224>(&pieces, &message);
    }
    #[cfg(umilib_feature = "hash-sha-v3")]
    check::<umilib::hash::sha::v3::SHA3_384>(&pieces, &message);
    #[cfg(umilib_feature = "hash-md-v4")]
    check::<umilib::hash::md::v4::MD4>(&pieces, &message);
    #[cfg(umilib_feature = "hash-md-v5")]
    check::<umilib::hash::md::v5::MD5>(&pieces, &message);
    #[cfg(umilib_feature = "hash-ripemd")]
    check::<umilib::hash::ripemd::RIPEMD320>(&pieces, &message);
    #[cfg(umilib_feature = "hash-sm3")]
    check::<umilib::hash::sm3::SM3>(&pieces, &message);
    #[cfg(umilib_feature = "hash-streebog")]
    if message.len() < 600 {
        check::<umilib::hash::streebog::Streebog512>(&pieces, &message);
    }
    #[cfg(umilib_feature = "hash-blake-v2")]
    {
        check::<umilib::hash::blake::v2::BLAKE2b512>(&pieces, &message);
        check::<umilib::hash::blake::v2::BLAKE2s128>(&pieces, &message);
        // The parallel modes deal blocks to their leaves; pieces must not change that.
        let mut parallel = umilib::hash::blake::v2::BLAKE2sp::new(32).unwrap();
        pieces.iter().for_each(|piece| parallel.update(piece));
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        parallel.finalize_into(&mut a).unwrap();
        parallel.update(&message);
        parallel.finalize_into(&mut b).unwrap();
        assert_eq!(a, b);
    }
    #[cfg(umilib_feature = "hash-blake-v3")]
    check::<umilib::hash::blake::v3::BLAKE3>(&pieces, &message);
    #[cfg(umilib_feature = "hash-ascon")]
    check::<umilib::hash::ascon::AsconHash256>(&pieces, &message);
    #[cfg(umilib_feature = "hash-xxhash-xxh32")]
    check::<umilib::hash::xxhash::xxh32::XXH32>(&pieces, &message);
    #[cfg(umilib_feature = "hash-xxhash-xxh64")]
    check::<umilib::hash::xxhash::xxh64::XXH64>(&pieces, &message);
    #[cfg(umilib_feature = "hash-xxhash-xxh3")]
    {
        check::<umilib::hash::xxhash::xxh3::XXH3_64>(&pieces, &message);
        check::<umilib::hash::xxhash::xxh3::XXH3_128>(&pieces, &message);
        // A custom secret of any valid length changes the block size of XXH3.
        let secret: Vec<u8> = (0..136 + message.len() % 120).map(|index| (index * 31) as u8).collect();
        let mut state = umilib::hash::xxhash::xxh3::XXH3_128::with_secret(&secret).unwrap();
        pieces.iter().for_each(|piece| state.update(piece));
        let mut whole = umilib::hash::xxhash::xxh3::XXH3_128::with_secret(&secret).unwrap();
        whole.update(&message);
        assert_eq!(state.value(), whole.value());
    }
    #[cfg(umilib_feature = "hash-siphash")]
    {
        let mut state = umilib::hash::siphash::SipHash24::new(&[9; 16]);
        pieces.iter().for_each(|piece| state.update(piece));
        let mut whole = umilib::hash::siphash::SipHash24::new(&[9; 16]);
        whole.update(&message);
        assert_eq!(state.output(), whole.output());
    }
}

/// Checks that extendable outputs read in pieces, or from a position, equal one read.
#[cfg(any(umilib_feature = "hash-sha-v3", umilib_feature = "hash-blake-v3", umilib_feature = "hash-ascon"))]
pub fn readers(data: &[u8]) {
    use umilib::hash::{ExtendableOutput, XOFReader};
    let (seed, pieces) = Pieces::split(data);
    let message: Vec<u8> = pieces.concat();
    let length = 1 + seed as usize * 3;
    fn check<X: ExtendableOutput>(mut state: X, message: &[u8], length: usize) {
        let mut whole = vec![0u8; length];
        state.update(message);
        state.clone().finalize_xof().read(&mut whole);
        let mut reader = state.finalize_xof();
        let mut pieces = vec![0u8; length];
        for chunk in pieces.chunks_mut(1 + length / 7) {
            reader.read(chunk);
        }
        assert_eq!(pieces, whole);
    }
    #[cfg(umilib_feature = "hash-sha-v3")]
    {
        check(umilib::hash::sha::v3::SHAKE128::default(), &message, length);
        check(umilib::hash::sha::v3::CSHAKE256::new(&message[..message.len().min(9)], b"fuzz"), &message, length);
    }
    #[cfg(umilib_feature = "hash-ascon")]
    {
        check(umilib::hash::ascon::AsconXOF128::new(), &message, length);
        let customization = &message[..message.len().min(seed as usize)];
        check(umilib::hash::ascon::AsconCXOF128::new(customization).unwrap(), &message, length);
    }
    #[cfg(umilib_feature = "hash-blake-v3")]
    {
        use umilib::hash::blake::v3::BLAKE3;
        check(BLAKE3::new(), &message, length);
        let mut whole = vec![0u8; length + 70];
        BLAKE3::digest_xof(&message, &mut whole);
        let mut hash = BLAKE3::new();
        hash.update(&message);
        let mut reader = hash.finalize_xof();
        reader.set_position(70);
        let mut tail = vec![0u8; length];
        reader.read(&mut tail);
        assert_eq!(tail, whole[70..]);
    }
}

/// Checks the CRC of fuzzed parameters against the definition, polynomial
/// division one bit at a time, and the 64-bit register against the 128-bit one.
#[cfg(umilib_feature = "hash-crc")]
pub fn crc(data: &[u8]) {
    use umilib::hash::crc::{CRC, CRCParameters, CRCTable};
    if data.len() < 26 {
        return;
    }
    let width = 1 + (data[0] % 64) as u32;
    let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
    let word = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()) & mask;
    let parameters = CRCParameters {
        name: "",
        width,
        polynomial: word(1),
        initial: word(9),
        reflect_input: data[25] & 1 == 1,
        reflect_output: data[25] & 2 == 2,
        xor_output: word(17),
        check: 0,
        residue: 0,
    };
    // The definition: polynomial division one bit at a time.
    let bitwise = |message: &[u8]| {
        let mut register = parameters.initial;
        for &byte in message {
            for bit in 0..8 {
                let input = if parameters.reflect_input { (byte >> bit) & 1 } else { (byte >> (7 - bit)) & 1 };
                let top = (register >> (width - 1)) & 1;
                register = (register << 1) & mask;
                if top ^ input as u64 == 1 {
                    register ^= parameters.polynomial;
                }
            }
        }
        if parameters.reflect_output {
            register = register.reverse_bits() >> (64 - width);
        }
        register ^ parameters.xor_output
    };
    let parameters = CRCParameters { check: bitwise(b"123456789"), ..parameters };
    let message = &data[26..];
    let expected = bitwise(message);
    let table = CRCTable::<u64>::new(parameters).unwrap();
    assert_eq!(CRC::checksum(&table, message), expected);
    let wide = CRCTable::<u128>::new(CRCParameters {
        name: "",
        width,
        polynomial: parameters.polynomial as u128,
        initial: parameters.initial as u128,
        reflect_input: parameters.reflect_input,
        reflect_output: parameters.reflect_output,
        xor_output: parameters.xor_output as u128,
        check: parameters.check as u128,
        residue: 0,
    })
    .unwrap();
    assert_eq!(CRC::checksum(&wide, message), expected as u128);
}

#[cfg(umilib_feature = "hash")]
pub const STREAMING: FuzzFunction<fn(&[u8])> = FuzzFunction::new("hash-streaming", streaming);
#[cfg(any(umilib_feature = "hash-sha-v3", umilib_feature = "hash-blake-v3", umilib_feature = "hash-ascon"))]
pub const READERS: FuzzFunction<fn(&[u8])> = FuzzFunction::new("hash-readers", readers);
#[cfg(umilib_feature = "hash-crc")]
pub const CRC: FuzzFunction<fn(&[u8])> = FuzzFunction::new("hash-crc", crc);

pub const TARGETS: &[&dyn FuzzTarget] = &[
    #[cfg(umilib_feature = "hash")]
    &STREAMING,
    #[cfg(any(umilib_feature = "hash-sha-v3", umilib_feature = "hash-blake-v3", umilib_feature = "hash-ascon"))]
    &READERS,
    #[cfg(umilib_feature = "hash-crc")]
    &CRC,
];
