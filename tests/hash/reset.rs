//! Every hash type returns to its start with `reset` and `finalize_reset`,
//! keeping its parameters (keys, seeds, initial values, customization).

use umilib::hash::Digest;

/// Checks that `state`, after some input and a reset, hashes `message` as a fresh one does.
fn check<H: Digest>(fresh: impl Fn() -> H, label: &str) {
    let message = b"the message after the reset";
    let mut expected = fresh();
    expected.update(message);
    let expected = expected.finalize();
    let mut state = fresh();
    state.update(&[0xA5; 300]);
    state.reset();
    state.update(message);
    assert_eq!(state.finalize_reset().as_ref(), expected.as_ref(), "{label} after reset");
    state.update(message);
    assert_eq!(state.finalize().as_ref(), expected.as_ref(), "{label} after finalize_reset");
}

#[test]
fn digests_reset_to_their_parameters() {
    #[cfg(umilib_feature = "hash-sha-v1")]
    check(umilib::hash::sha::v1::SHA1::new, "SHA1");
    #[cfg(umilib_feature = "hash-sha-v2")]
    {
        use umilib::hash::sha::v2::*;
        check(SHA224::new, "SHA224");
        check(SHA256::new, "SHA256");
        check(SHA512_224::new, "SHA512/224");
        // A custom initial value is a parameter too: SHA-512/200 built from section 5.3.6.
        let initial = SHA512::truncated_initial_state(200).unwrap();
        check(|| SHA512::with_state(initial), "SHA512 with a custom initial value");
        let mut custom = SHA512::with_state(initial);
        custom.update(b"abc");
        custom.reset();
        custom.update(b"abc");
        assert_ne!(custom.finalize(), SHA512::digest(b"abc"));
        // finalize_truncated writes the leftmost bytes and checks the length.
        let mut out = [0u8; 25];
        let mut state = SHA512::with_state(initial);
        state.update(b"abc");
        state.clone().finalize_truncated(&mut out).unwrap();
        assert_eq!(out[..], state.clone().finalize()[..25]);
        assert!(state.clone().finalize_truncated(&mut [0; 65]).is_err());
        assert!(state.finalize_truncated(&mut []).is_err());
    }
    #[cfg(umilib_feature = "hash-sha-v3")]
    check(umilib::hash::sha::v3::Keccak256::new, "Keccak256");
    #[cfg(umilib_feature = "hash-md-v4")]
    check(umilib::hash::md::v4::MD4::new, "MD4");
    #[cfg(umilib_feature = "hash-md-v5")]
    check(umilib::hash::md::v5::MD5::new, "MD5");
    #[cfg(umilib_feature = "hash-ripemd")]
    check(umilib::hash::ripemd::RIPEMD256::new, "RIPEMD256");
    #[cfg(umilib_feature = "hash-sm3")]
    check(umilib::hash::sm3::SM3::new, "SM3");
    #[cfg(umilib_feature = "hash-streebog")]
    check(umilib::hash::streebog::Streebog256::new, "Streebog256");
    #[cfg(umilib_feature = "hash-blake-v2")]
    {
        use umilib::hash::blake::v2::*;
        check(|| BLAKE2b256::with_key(b"key").unwrap(), "keyed BLAKE2b256");
        check(|| BLAKE2s128::with_key(&[9; 32]).unwrap(), "keyed BLAKE2s128");
    }
    #[cfg(umilib_feature = "hash-blake-v3")]
    {
        use umilib::hash::blake::v3::BLAKE3;
        check(|| BLAKE3::with_key(&[3; 32]), "keyed BLAKE3");
        check(|| BLAKE3::with_context(b"context"), "BLAKE3 key derivation");
    }
    #[cfg(umilib_feature = "hash-siphash")]
    {
        use umilib::hash::siphash::*;
        check(|| SipHash24::new(&[1; 16]), "SipHash24");
        check(|| HalfSipHash64_13::new(&[1; 8]), "HalfSipHash64-1-3");
    }
    #[cfg(umilib_feature = "hash-xxhash")]
    {
        use umilib::hash::xxhash::{xxh3::*, xxh32::*, xxh64::*};
        check(|| XXH32::with_seed(77), "XXH32");
        check(|| XXH64::with_seed(77), "XXH64");
        check(|| XXH3_64::with_seed(77), "XXH3_64");
        check(|| XXH3_128::with_secret(&[5; 200]).unwrap(), "XXH3_128 with a secret");
    }
    #[cfg(umilib_feature = "hash-crc")]
    {
        use umilib::hash::crc::{CRC, CRCCatalogue};
        check(|| CRC::new(CRCCatalogue::CRC64_XZ), "CRC-64/XZ");
    }
}

#[cfg(all(umilib_feature = "hash-sha-v3", umilib_feature = "hash-blake-v2"))]
#[test]
fn variable_and_extendable_outputs_reset_to_their_parameters() {
    use umilib::hash::blake::v2::*;
    use umilib::hash::sha::v3::*;
    use umilib::hash::{ExtendableOutput, XOFReader};
    fn check_xof<X: ExtendableOutput>(fresh: impl Fn() -> X, label: &str) {
        let (mut a, mut b) = ([0u8; 100], [0u8; 100]);
        let mut expected = fresh();
        expected.update(b"message");
        expected.finalize_xof().read(&mut a);
        let mut state = fresh();
        state.update(&[1; 500]);
        state.reset();
        state.update(b"message");
        state.finalize_xof().read(&mut b);
        assert_eq!(a, b, "{label}");
    }
    check_xof(|| CSHAKE128::new(b"name", b"customization"), "cSHAKE128");
    check_xof(|| ParallelHash256::new(7, b"customization").unwrap(), "ParallelHash256");
    check_xof(|| BLAKE2Xb::with_key(b"key", 100).unwrap(), "keyed BLAKE2Xb");
    let mut tuple = TupleHash128::new(b"customization");
    tuple.push(b"element");
    tuple.reset();
    tuple.push(b"x");
    let mut fresh = TupleHash128::new(b"customization");
    fresh.push(b"x");
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    tuple.finalize(&mut a);
    fresh.finalize(&mut b);
    assert_eq!(a, b);
    for output in [1, 33, 64] {
        let mut engine = BLAKE2b::with_key(b"key", output).unwrap();
        let mut expected = vec![0u8; output];
        engine.update(b"message");
        engine.finalize_into(&mut expected).unwrap();
        // finalize_into returned the engine to its start, keyed.
        engine.update(&[2; 300]);
        engine.reset();
        engine.update(b"message");
        let mut out = vec![0u8; output];
        engine.finalize_into(&mut out).unwrap();
        assert_eq!(out, expected);
    }
}
