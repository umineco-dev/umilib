use std::ptr;

use super::Check;

#[cfg(umilib_feature = "hash-sha-v2")]
#[test]
fn sha256_through_the_c_abi() {
    use umilib::ffi::hash::sha::v2::sha256;
    // FIPS 180-4 example: SHA-256("abc").
    let expected = Check::hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    unsafe {
        assert_eq!((sha256::output_size(), sha256::block_size()), (32, 64));
        let mut out = [0u8; 32];
        Check::ok(sha256::digest(b"abc".as_ptr(), 3, out.as_mut_ptr(), 32));
        assert_eq!(out.to_vec(), expected);
        Check::fails(sha256::digest(b"abc".as_ptr(), 3, out.as_mut_ptr(), 31), "hash", "OutputLength");
        let mut state = ptr::null_mut();
        Check::ok(sha256::new(&mut state));
        Check::ok(sha256::update(state, b"a".as_ptr(), 1));
        let mut copy = ptr::null_mut();
        Check::ok(sha256::clone(state, &mut copy));
        Check::ok(sha256::update(state, b"bc".as_ptr(), 2));
        Check::ok(sha256::finalize_reset(state, out.as_mut_ptr(), 32));
        assert_eq!(out.to_vec(), expected);
        // After the reset the state hashes the empty input.
        Check::ok(sha256::update(copy, b"bc".as_ptr(), 2));
        Check::ok(sha256::reset(copy));
        Check::ok(sha256::update(copy, b"abc".as_ptr(), 3));
        // A failed finalize keeps the state; a successful one releases it.
        let mut long = [0u8; 33];
        Check::fails(sha256::finalize(copy, long.as_mut_ptr(), 33), "hash", "OutputLength");
        Check::ok(sha256::finalize(copy, out.as_mut_ptr(), 32));
        assert_eq!(out.to_vec(), expected);
        Check::fails(sha256::update(ptr::null_mut(), b"a".as_ptr(), 1), "ffi", "NullPointer");
        Check::fails(sha256::update(state, ptr::null(), 1), "ffi", "NullPointer");
        Check::ok(sha256::update(state, ptr::null(), 0));
        Check::ok(sha256::finalize(state, out.as_mut_ptr(), 32));
        assert_eq!(out.to_vec(), Check::hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        sha256::free(ptr::null_mut());
    }
}

#[cfg(umilib_feature = "hash-sha-v3")]
#[test]
fn shake_and_sp800185_through_the_c_abi() {
    use umilib::ffi::hash::sha::v3::*;
    unsafe {
        // FIPS 202 / NIST examples: SHAKE128("") starts 7f9c2ba4e88f827d616045507605853e.
        let mut out = [0u8; 16];
        Check::ok(shake128::digest_xof(ptr::null(), 0, out.as_mut_ptr(), 16));
        assert_eq!(out.to_vec(), Check::hex("7f9c2ba4e88f827d616045507605853e"));
        let mut state = ptr::null_mut();
        Check::ok(shake128::new(&mut state));
        let mut reader = ptr::null_mut();
        Check::ok(shake128::finalize_xof(state, &mut reader));
        let mut pieces = [0u8; 16];
        Check::ok(sponge168::read(reader, pieces.as_mut_ptr(), 5));
        let mut rest = ptr::null_mut();
        Check::ok(sponge168::clone(reader, &mut rest));
        Check::ok(sponge168::read(rest, pieces[5..].as_mut_ptr(), 11));
        assert_eq!(pieces, out);
        sponge168::free(reader);
        sponge168::free(rest);
        // cSHAKE128 sample 1 of SP 800-185: data 00010203, S = "Email Signature".
        let mut cshake = ptr::null_mut();
        let customization = b"Email Signature";
        Check::ok(cshake128::new(ptr::null(), 0, customization.as_ptr(), customization.len(), &mut cshake));
        Check::ok(cshake128::update(cshake, [0u8, 1, 2, 3].as_ptr(), 4));
        let mut reader = ptr::null_mut();
        Check::ok(cshake128::finalize_xof(cshake, &mut reader));
        let mut output = [0u8; 32];
        Check::ok(sponge168::read(reader, output.as_mut_ptr(), 32));
        assert_eq!(output.to_vec(), Check::hex("c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5"));
        sponge168::free(reader);
        // TupleHash128 sample 1: (000102, 101112131415), no customization, 256 bits.
        let mut tuple = ptr::null_mut();
        Check::ok(tuple_hash128::new(ptr::null(), 0, &mut tuple));
        Check::ok(tuple_hash128::push(tuple, [0u8, 1, 2].as_ptr(), 3));
        Check::ok(tuple_hash128::push(tuple, [0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15].as_ptr(), 6));
        Check::ok(tuple_hash128::finalize(tuple, output.as_mut_ptr(), 32));
        assert_eq!(output.to_vec(), Check::hex("c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1"));
        // ParallelHash rejects blocks of 0 bytes.
        let mut parallel = ptr::null_mut();
        Check::fails(parallel_hash128::new(0, ptr::null(), 0, &mut parallel), "hash", "InvalidParameter");
        Check::ok(parallel_hash128::new(8, ptr::null(), 0, &mut parallel));
        let mut size = 0;
        Check::ok(parallel_hash128::block_size(parallel, &mut size));
        assert_eq!(size, 8);
        parallel_hash128::free(parallel);
        // Keccak-f[1600] of the zero state (KeccakF-1600-IntermediateValues.txt).
        let mut lanes = [0u64; 25];
        Check::ok(umilib_hash_sha_v3_keccak_f1600_permute(lanes.as_mut_ptr()));
        assert_eq!(lanes[0], 0xF1258F7940E1DDE7);
    }
}

#[cfg(umilib_feature = "hash-blake-v2")]
#[test]
fn blake2_through_the_c_abi() {
    use umilib::ffi::hash::blake::v2::*;
    use umilib::hash::blake::v2::BLAKE2bParameters;
    unsafe {
        // RFC 7693 appendix A: BLAKE2b-512("abc").
        let expected = Check::hex(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        );
        let mut out = [0u8; 64];
        Check::ok(blake2b512::digest(b"abc".as_ptr(), 3, out.as_mut_ptr(), 64));
        assert_eq!(out.to_vec(), expected);
        let mut engine = ptr::null_mut();
        Check::fails(blake2b::new(65, &mut engine), "hash", "OutputLength");
        Check::ok(blake2b::new(64, &mut engine));
        Check::ok(blake2b::update(engine, b"abc".as_ptr(), 3));
        let mut length = 0;
        Check::ok(blake2b::output_length(engine, &mut length));
        assert_eq!(length, 64);
        Check::fails(blake2b::finalize_into(engine, out.as_mut_ptr(), 63), "hash", "OutputLength");
        Check::ok(blake2b::finalize_into(engine, out.as_mut_ptr(), 64));
        assert_eq!(out.to_vec(), expected);
        blake2b::free(engine);
        // The parameter structure has the layout of the Rust type and round-trips through its block.
        let parameters = umilib_hash_blake_v2_blake2b_parameters_new(64);
        assert_eq!(parameters, BLAKE2bParameters::new(64));
        let mut block = [0u8; 64];
        Check::ok(umilib_hash_blake_v2_blake2b_parameters_to_bytes(&parameters, block.as_mut_ptr(), 64));
        assert_eq!(block[..4], [64, 0, 1, 1]);
        let mut decoded = umilib_hash_blake_v2_blake2b_parameters_new(1);
        Check::ok(umilib_hash_blake_v2_blake2b_parameters_from_bytes(block.as_ptr(), 64, &mut decoded));
        assert_eq!(decoded, parameters);
        block[31] = 1;
        Check::fails(
            umilib_hash_blake_v2_blake2b_parameters_from_bytes(block.as_ptr(), 64, &mut decoded),
            "hash",
            "InvalidParameter",
        );
        let mut engine = ptr::null_mut();
        Check::ok(blake2b::with_parameters(&parameters, ptr::null(), 0, &mut engine));
        Check::ok(blake2b::update(engine, b"abc".as_ptr(), 3));
        Check::ok(blake2b::finalize_into(engine, out.as_mut_ptr(), 64));
        assert_eq!(out.to_vec(), expected);
        let mut keyed = parameters;
        keyed.key_length = 1;
        let mut other = ptr::null_mut();
        Check::fails(blake2b::with_parameters(&keyed, ptr::null(), 0, &mut other), "hash", "InvalidParameter");
        blake2b::free(engine);
    }
}

#[cfg(umilib_feature = "hash-blake-v3")]
#[test]
fn blake3_through_the_c_abi() {
    use umilib::ffi::hash::blake::v3::*;
    unsafe {
        // The official vectors: the empty input in the hash mode.
        let expected = Check::hex(
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050",
        );
        let mut out = [0u8; 48];
        Check::ok(umilib_hash_blake_v3_blake3_digest_xof(ptr::null(), 0, out.as_mut_ptr(), 48));
        assert_eq!(out.to_vec(), expected);
        let mut state = ptr::null_mut();
        Check::ok(blake3::new(&mut state));
        let mut reader = ptr::null_mut();
        Check::ok(umilib_hash_blake_v3_blake3_finalize_xof(state, &mut reader));
        Check::ok(umilib_hash_blake_v3_blake3_reader_set_position(reader, 16));
        let mut tail = [0u8; 32];
        Check::ok(blake3_reader::read(reader, tail.as_mut_ptr(), 32));
        assert_eq!(tail.to_vec(), expected[16..]);
        let mut position = 0;
        Check::ok(umilib_hash_blake_v3_blake3_reader_position(reader, &mut position));
        assert_eq!(position, 48);
        blake3_reader::free(reader);
        let mut keyed = ptr::null_mut();
        Check::fails(umilib_hash_blake_v3_blake3_with_key([0u8; 31].as_ptr(), 31, &mut keyed), "hash", "KeyLength");
        let key = b"whats the Elvish word for friend";
        let mut tag = [0u8; 32];
        Check::ok(umilib_hash_blake_v3_blake3_keyed_hash(key.as_ptr(), 32, ptr::null(), 0, tag.as_mut_ptr(), 32));
        assert_eq!(tag.to_vec(), Check::hex("92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"));
    }
}

#[cfg(umilib_feature = "hash-siphash")]
#[test]
fn siphash_through_the_c_abi() {
    use umilib::ffi::hash::siphash::*;
    unsafe {
        let key: Vec<u8> = (0..16).collect();
        let mut state = ptr::null_mut();
        Check::fails(sip_hash24::new(key.as_ptr(), 15, &mut state), "hash", "KeyLength");
        Check::ok(sip_hash24::new(key.as_ptr(), 16, &mut state));
        let message: Vec<u8> = (0..15).collect();
        Check::ok(sip_hash24::update(state, message.as_ptr(), 15));
        let mut out = [0u8; 8];
        Check::ok(sip_hash24::finalize(state, out.as_mut_ptr(), 8));
        // Appendix A of the SipHash paper.
        assert_eq!(u64::from_le_bytes(out), 0xA129CA6149BE45E5);
        assert_eq!((half_sip_hash24::key_size(), half_sip_hash64_13::output_size()), (8, 8));
    }
}

#[cfg(all(
    umilib_feature = "hash-xxhash-xxh32",
    umilib_feature = "hash-xxhash-xxh64",
    umilib_feature = "hash-xxhash-xxh3"
))]
#[test]
fn xxhash_through_the_c_abi() {
    use umilib::ffi::hash::xxhash::xxh3::{xxh3_64, xxh3_128};
    use umilib::ffi::hash::xxhash::xxh32::{
        umilib_hash_xxhash_xxh32_xxh32_digest, umilib_hash_xxhash_xxh32_xxh32_with_seed, xxh32,
    };
    unsafe {
        // The values of the empty input with the seed 0 (xxHash reference).
        let mut value32 = 0u32;
        Check::ok(xxh32::hash(0, ptr::null(), 0, &mut value32));
        assert_eq!(value32, 0x02CC5D05);
        let mut state = ptr::null_mut();
        Check::ok(umilib_hash_xxhash_xxh32_xxh32_with_seed(0, &mut state));
        let mut bytes = [0u8; 4];
        Check::ok(xxh32::finalize(state, bytes.as_mut_ptr(), 4));
        assert_eq!(bytes, 0x02CC5D05u32.to_be_bytes());
        Check::ok(umilib_hash_xxhash_xxh32_xxh32_digest(ptr::null(), 0, bytes.as_mut_ptr(), 4));
        assert_eq!(bytes, 0x02CC5D05u32.to_be_bytes());
        // Hashing a buffer into itself is rejected rather than aliased.
        let mut buffer = [7u8; 4];
        let pointer = buffer.as_mut_ptr();
        Check::fails(umilib_hash_xxhash_xxh32_xxh32_digest(pointer, 4, pointer, 4), "ffi", "InvalidArgument");
        let mut value64 = 0u64;
        Check::ok(xxh3_64::hash(0, ptr::null(), 0, &mut value64));
        assert_eq!(value64, 0x2D06800538D394C2);
        let mut value128 = umilib::ffi::U128::default();
        Check::ok(xxh3_128::hash(0, ptr::null(), 0, &mut value128));
        assert_eq!(u128::from(value128), 0x99AA06D3014798D86001C324468D497F);
        let mut keyed = ptr::null_mut();
        Check::fails(xxh3_64::with_secret([0u8; 135].as_ptr(), 135, &mut keyed), "hash", "KeyLength");
    }
}

#[cfg(umilib_feature = "hash-crc")]
#[test]
fn crc_through_the_c_abi() {
    use umilib::ffi::hash::crc::*;
    use umilib::ffi::{Buffer, U128};
    unsafe {
        let mut table = ptr::null_mut();
        let name = b"CRC-32/ISO-HDLC";
        Check::ok(umilib_hash_crc_crc_catalogue_find(name.as_ptr(), name.len(), &mut table));
        let mut value = U128::default();
        Check::ok(umilib_hash_crc_crc_checksum(table, b"123456789".as_ptr(), 9, &mut value));
        assert_eq!(u128::from(value), 0xCBF43926);
        let mut parameters = std::mem::zeroed::<CRCParameters>();
        Check::ok(umilib_hash_crc_crc_table_parameters(table, &mut parameters));
        assert_eq!((parameters.width, u128::from(parameters.polynomial)), (32, 0x04C11DB7));
        let mut text = Buffer::EMPTY;
        Check::ok(umilib_hash_crc_crc_table_name(table, &mut text));
        assert_eq!(text.as_slice(), name);
        umilib::ffi::umilib_ffi_buffer_free(&mut text);
        Check::ok(umilib_hash_crc_crc_catalogue_names(&mut text));
        assert_eq!(text.as_slice().iter().filter(|&&byte| byte == b'\n').count(), 113);
        umilib::ffi::umilib_ffi_buffer_free(&mut text);
        Check::fails(umilib_hash_crc_crc_catalogue_find(b"CRC-1".as_ptr(), 5, &mut table), "ffi", "InvalidArgument");
        // A table from parameters: CRC-82/DARC needs the 128-bit register.
        let mut darc = parameters;
        darc.width = 82;
        darc.polynomial = U128::from(0x0308C0111011401440411u128);
        darc.initial = U128::from(0);
        darc.reflect_input = true;
        darc.reflect_output = true;
        darc.xor_output = U128::from(0);
        darc.check = U128::from(0x09EA83F625023801FD612u128);
        darc.residue = U128::from(0);
        let mut custom = ptr::null_mut();
        Check::ok(umilib_hash_crc_crc_table_new(&darc, &mut custom));
        let mut state = ptr::null_mut();
        Check::ok(umilib_hash_crc_crc_new(custom, &mut state));
        Check::ok(umilib_hash_crc_crc_update(state, b"123456789".as_ptr(), 9));
        Check::ok(umilib_hash_crc_crc_value(state, &mut value));
        assert_eq!(u128::from(value), 0x09EA83F625023801FD612);
        umilib_hash_crc_crc_free(state);
        umilib_hash_crc_crc_table_free(custom);
        darc.width = 0;
        Check::fails(umilib_hash_crc_crc_table_new(&darc, &mut custom), "hash", "InvalidParameter");
        darc.width = 3;
        Check::fails(umilib_hash_crc_crc_table_new(&darc, &mut custom), "hash", "InvalidParameter");
        umilib_hash_crc_crc_table_free(table);
    }
}

#[cfg(umilib_all_features)]
#[test]
fn ascon_through_the_c_abi() {
    use umilib::ffi::hash::ascon::*;

    use crate::vectors::Record;
    // Every seventeenth record; under Miri, which is thousands of times slower, every hundred and seventieth.
    let step = if cfg!(miri) { 170 } else { 17 };
    unsafe {
        // Ascon-Hash256 against the known answers of the reference implementation.
        for record in Record::all("hash/ascon/LWC_HASH_KAT_128_256.txt").iter().step_by(step) {
            let (message, expected) = (record.bytes("Msg"), record.bytes("MD"));
            let mut out = [0u8; 32];
            Check::ok(ascon_hash256::digest(message.as_ptr(), message.len(), out.as_mut_ptr(), 32));
            assert_eq!(out.to_vec(), expected, "Count = {}", record.field("Count"));
            let mut state = ptr::null_mut();
            Check::ok(ascon_hash256::new(&mut state));
            for piece in message.chunks(3) {
                Check::ok(ascon_hash256::update(state, piece.as_ptr(), piece.len()));
            }
            Check::ok(ascon_hash256::finalize(state, out.as_mut_ptr(), 32));
            assert_eq!(out.to_vec(), expected);
        }
        // Ascon-XOF128, read in pieces.
        for record in Record::all("hash/ascon/LWC_XOF_KAT_128_512.txt").iter().step_by(step) {
            let (message, expected) = (record.bytes("Msg"), record.bytes("MD"));
            let mut out = vec![0u8; expected.len()];
            Check::ok(ascon_xof128::digest_xof(message.as_ptr(), message.len(), out.as_mut_ptr(), out.len()));
            assert_eq!(out, expected, "Count = {}", record.field("Count"));
            let mut state = ptr::null_mut();
            Check::ok(ascon_xof128::new(&mut state));
            Check::ok(ascon_xof128::update(state, message.as_ptr(), message.len()));
            let mut reader = ptr::null_mut();
            Check::ok(ascon_xof128::finalize_xof(state, &mut reader));
            let mut pieces = vec![0u8; expected.len()];
            for piece in pieces.chunks_mut(7) {
                Check::ok(ascon_reader::read(reader, piece.as_mut_ptr(), piece.len()));
            }
            ascon_reader::free(reader);
            assert_eq!(pieces, expected);
        }
        // Ascon-CXOF128 with its customization string.
        for record in Record::all("hash/ascon/LWC_CXOF_KAT_128_512.txt").iter().step_by(step) {
            let (message, customization, expected) = (record.bytes("Msg"), record.bytes("Z"), record.bytes("MD"));
            let mut state = ptr::null_mut();
            Check::ok(ascon_cxof128::umilib_hash_ascon_ascon_cxof128_new(
                customization.as_ptr(),
                customization.len(),
                &mut state,
            ));
            Check::ok(ascon_cxof128::update(state, message.as_ptr(), message.len()));
            let mut reader = ptr::null_mut();
            Check::ok(ascon_cxof128::finalize_xof(state, &mut reader));
            let mut out = vec![0u8; expected.len()];
            Check::ok(ascon_reader::read(reader, out.as_mut_ptr(), out.len()));
            ascon_reader::free(reader);
            assert_eq!(out, expected, "Count = {}", record.field("Count"));
        }
        // Section 5.2: a customization string has at most 2048 bits.
        let mut state = ptr::null_mut();
        Check::fails(
            ascon_cxof128::umilib_hash_ascon_ascon_cxof128_new([0u8; 257].as_ptr(), 257, &mut state),
            "hash",
            "InvalidParameter",
        );
        // Table 12 of SP 800-232: Ascon-p[12] of the IV of Ascon-Hash256 and zeros.
        let mut words = [0x0000_0801_00cc_0002u64, 0, 0, 0, 0];
        Check::ok(umilib_hash_ascon_ascon_permutation_permute(words.as_mut_ptr(), 12));
        assert_eq!(
            words,
            [0x9b1e5494e934d681, 0x4bc3a01e333751d2, 0xae65396c6b34b81a, 0x3c7fd4a4d56a4db3, 0x1a5c464906c5976d]
        );
        Check::fails(umilib_hash_ascon_ascon_permutation_permute(words.as_mut_ptr(), 0), "ffi", "InvalidArgument");
        Check::fails(umilib_hash_ascon_ascon_permutation_permute(words.as_mut_ptr(), 17), "ffi", "InvalidArgument");
    }
}
