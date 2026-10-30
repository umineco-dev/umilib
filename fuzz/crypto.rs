//! Fuzz targets of `umilib::crypto`.

use umilib::platform::fuzz::{FuzzFunction, FuzzTarget};

/// Checks HMAC with a key and a message taken from the input: streaming
/// equals one-shot, its own tag verifies and any other does not.
#[cfg(all(umilib_feature = "crypto-hmac", umilib_feature = "hash-sha-v2"))]
pub fn hmac(data: &[u8]) {
    use umilib::crypto::hmac::HMAC;
    use umilib::hash::sha::v2::{SHA256, SHA384};
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let (key, message) = rest.split_at((split as usize * 2).min(rest.len()));
    let tag = HMAC::<SHA256>::mac(key, message);
    let mut state = HMAC::<SHA256>::new(key);
    for piece in message.chunks(1 + split as usize % 70) {
        state.update(piece);
    }
    assert_eq!(state.clone().finalize(), tag);
    assert!(state.clone().verify(&tag));
    assert!(state.clone().verify_truncated(&tag[..16]));
    let mut wrong = tag;
    wrong[split as usize % 32] ^= 1 << (split % 8);
    assert!(!state.clone().verify(&wrong));
    assert!(!state.verify(&tag[..31]));
    // SHA-384 has a 128-byte block: keys around it are hashed or padded.
    let long = HMAC::<SHA384>::mac(key, message);
    let mut state = HMAC::<SHA384>::new(key);
    state.update(message);
    assert_eq!(state.finalize_reset(), long);
}

/// Checks that a DRBG fills any length as requests of the maximum size, and
/// that reseeding with the same input gives the same bytes.
#[cfg(all(umilib_feature = "crypto-random", umilib_feature = "hash-sha-v2"))]
pub fn drbg(data: &[u8]) {
    use umilib::crypto::random::{DRBG, DRBGConfig, HashDRBG, Random};
    use umilib::hash::sha::v2::SHA256;
    // Entropy of 3/2 of the security strength needs no nonce (SP 800-90A section 8.6.7).
    if data.len() < 50 {
        return;
    }
    let (entropy, rest) = data.split_at(48);
    let maximum = 1 + rest[0] as usize;
    let length = rest[1] as usize * 3;
    let config = DRBGConfig { reseed_interval: 1000, maximum_request: maximum };
    let mut first = HashDRBG::<SHA256>::with_config(config, entropy, &rest[2..], &[]).unwrap();
    let mut second = HashDRBG::<SHA256>::with_config(config, entropy, &rest[2..], &[]).unwrap();
    let mut filled = vec![0u8; length];
    first.fill(&mut filled).unwrap();
    let mut requested = vec![0u8; length];
    for chunk in requested.chunks_mut(maximum) {
        second.generate(chunk, &[]).unwrap();
    }
    assert_eq!(filled, requested);
    first.reseed(entropy, rest).unwrap();
    second.reseed(entropy, rest).unwrap();
    // One request of at most the maximum size, which a longer one must exceed.
    let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
    let size = maximum.min(16);
    first.generate(&mut a[..size], rest).unwrap();
    second.generate(&mut b[..size], rest).unwrap();
    assert_eq!(a, b);
    if maximum < 16 {
        assert!(first.generate(&mut a, &[]).is_err());
    }
}

/// The parts of a fuzz input: a selector byte, then a key, then data.
pub struct Parts;

impl Parts {
    /// The selector, `key_length` bytes of key (padded with zeros) and the rest.
    pub fn split(data: &[u8], key_length: usize) -> (u8, Vec<u8>, &[u8]) {
        let Some((&selector, rest)) = data.split_first() else {
            return (0, vec![0; key_length], &[]);
        };
        let (key, rest) = rest.split_at(key_length.min(rest.len()));
        let mut padded = key.to_vec();
        padded.resize(key_length, 0);
        (selector, padded, rest)
    }
}

/// Checks every block cipher: decryption inverts encryption, and many blocks
/// at once equal the blocks one by one.
#[cfg(any(
    umilib_feature = "crypto-aes",
    umilib_feature = "crypto-aria",
    umilib_feature = "crypto-camellia",
    umilib_feature = "crypto-des",
    umilib_feature = "crypto-gost",
    umilib_feature = "crypto-idea",
    umilib_feature = "crypto-rc2",
    umilib_feature = "crypto-seed",
    umilib_feature = "crypto-sm4"
))]
pub fn block_cipher(data: &[u8]) {
    use umilib::crypto::{BlockCipher, KeyInit};
    fn check<C: BlockCipher + KeyInit>(key: &[u8], data: &[u8]) {
        let Ok(cipher) = C::new_from_slice(key) else {
            return;
        };
        let mut blocks: Vec<C::Block> = data
            .chunks_exact(C::BLOCK_SIZE)
            .map(|chunk| {
                let mut block = C::Block::default();
                block.as_mut().copy_from_slice(chunk);
                block
            })
            .collect();
        let original = blocks.clone();
        cipher.encrypt_blocks(&mut blocks);
        for (encrypted, plain) in blocks.iter().zip(&original) {
            let mut single = *plain;
            cipher.encrypt_block(&mut single);
            assert_eq!(single.as_ref(), encrypted.as_ref());
        }
        cipher.decrypt_blocks(&mut blocks);
        assert!(blocks.iter().zip(&original).all(|(a, b)| a.as_ref() == b.as_ref()));
    }
    let (selector, key, rest) = Parts::split(data, 32);
    let key = &key[..[8, 16, 24, 32][selector as usize % 4]];
    match selector / 4 % 16 {
        #[cfg(umilib_feature = "crypto-aes")]
        0 => check::<umilib::crypto::aes::AES128>(key, rest),
        #[cfg(umilib_feature = "crypto-aes")]
        1 => check::<umilib::crypto::aes::AES256>(key, rest),
        #[cfg(umilib_feature = "crypto-aria")]
        2 => check::<umilib::crypto::aria::ARIA192>(key, rest),
        #[cfg(umilib_feature = "crypto-camellia")]
        3 => check::<umilib::crypto::camellia::Camellia128>(key, rest),
        #[cfg(umilib_feature = "crypto-camellia")]
        4 => check::<umilib::crypto::camellia::Camellia256>(key, rest),
        #[cfg(umilib_feature = "crypto-des")]
        5 => check::<umilib::crypto::des::DES>(key, rest),
        #[cfg(umilib_feature = "crypto-des")]
        6 => check::<umilib::crypto::des::TDES>(key, rest),
        #[cfg(umilib_feature = "crypto-gost-magma")]
        7 => check::<umilib::crypto::gost::magma::Magma>(key, rest),
        #[cfg(umilib_feature = "crypto-gost-kuznyechik")]
        8 => check::<umilib::crypto::gost::kuznyechik::Kuznyechik>(key, rest),
        #[cfg(umilib_feature = "crypto-idea")]
        9 => check::<umilib::crypto::idea::IDEA>(key, rest),
        #[cfg(umilib_feature = "crypto-rc2")]
        10 => check::<umilib::crypto::rc2::RC2>(key, rest),
        #[cfg(umilib_feature = "crypto-seed")]
        11 => check::<umilib::crypto::seed::SEED>(key, rest),
        #[cfg(umilib_feature = "crypto-sm4")]
        12 => check::<umilib::crypto::sm4::SM4>(key, rest),
        #[cfg(umilib_feature = "crypto-aria")]
        13 => check::<umilib::crypto::aria::ARIA128>(key, rest),
        _ => {}
    }
}

/// Checks the modes over AES: data in pieces equals data at once, decryption
/// inverts encryption, PKCS #7 padding round-trips and arbitrary padding is
/// judged without panicking.
#[cfg(all(
    umilib_feature = "crypto-mode-cbc",
    umilib_feature = "crypto-mode-cfb",
    umilib_feature = "crypto-mode-ctr",
    umilib_feature = "crypto-mode-ofb",
    umilib_feature = "crypto-mode-xts",
    umilib_feature = "crypto-aes"
))]
pub fn mode(data: &[u8]) {
    use umilib::crypto::aes::AES128;
    use umilib::crypto::mode::PKCS7;
    use umilib::crypto::mode::cbc::CBC;
    use umilib::crypto::mode::cfb::{CFB, CFB1, CFB8};
    use umilib::crypto::mode::ctr::CTR;
    use umilib::crypto::mode::ofb::OFB;
    use umilib::crypto::mode::xts::XTS;
    use umilib::crypto::{KeyInit, StreamCipher};
    let (selector, key, rest) = Parts::split(data, 32);
    let (key, iv): ([u8; 16], [u8; 16]) = (key[..16].try_into().unwrap(), key[16..].try_into().unwrap());
    let cut = (selector as usize * 7).min(rest.len());
    let aes = || AES128::new(&key);
    // Streams: two pieces equal one, and decryption inverts encryption.
    let mut whole = rest.to_vec();
    let mut pieces = rest.to_vec();
    match selector % 4 {
        0 => {
            CFB::new(aes(), &iv).encrypt(&mut whole);
            let mut cfb = CFB::new(aes(), &iv);
            cfb.encrypt(&mut pieces[..cut]);
            cfb.encrypt(&mut pieces[cut..]);
            assert_eq!(pieces, whole);
            CFB::new(aes(), &iv).decrypt(&mut whole);
        }
        1 => {
            CFB8::new(aes(), &iv).encrypt(&mut whole);
            let mut cfb = CFB8::new(aes(), &iv);
            cfb.encrypt(&mut pieces[..cut]);
            cfb.encrypt(&mut pieces[cut..]);
            assert_eq!(pieces, whole);
            CFB8::new(aes(), &iv).decrypt(&mut whole);
        }
        2 => {
            OFB::new(aes(), &iv).apply(&mut whole);
            let mut ofb = OFB::new(aes(), &iv);
            ofb.apply(&mut pieces[..cut]);
            ofb.apply(&mut pieces[cut..]);
            assert_eq!(pieces, whole);
            OFB::new(aes(), &iv).apply(&mut whole);
        }
        _ => {
            // A counter of the last 8 bits: at most 256 blocks before it repeats.
            let bits = 8 + selector as u32 % 121;
            let Ok(mut ctr) = CTR::with_counter_bits(aes(), &iv, bits) else {
                return;
            };
            let remaining = ctr.remaining_bytes();
            let result = ctr.apply_keystream(&mut whole);
            assert_eq!(result.is_ok(), remaining.is_none_or(|left| left >= whole.len() as u128));
            if result.is_err() {
                assert_eq!(whole, rest);
                return;
            }
            let mut ctr = CTR::with_counter_bits(aes(), &iv, bits).unwrap();
            ctr.apply_keystream(&mut pieces[..cut]).unwrap();
            ctr.apply_keystream(&mut pieces[cut..]).unwrap();
            assert_eq!(pieces, whole);
            CTR::with_counter_bits(aes(), &iv, bits).unwrap().apply_keystream(&mut whole).unwrap();
        }
    }
    assert_eq!(whole, rest);
    // CFB1 on the bits of the input, and CBC with PKCS #7.
    let bits = (selector as usize * 3).min(8 * rest.len());
    let mut segment = rest.to_vec();
    CFB1::new(aes(), &iv).encrypt_bits(&mut segment, bits).unwrap();
    CFB1::new(aes(), &iv).decrypt_bits(&mut segment, bits).unwrap();
    assert_eq!(segment, rest);
    let mut padded = rest.to_vec();
    PKCS7::pad(&mut padded, 16).unwrap();
    CBC::new(aes(), &iv).encrypt(&mut padded).unwrap();
    CBC::new(aes(), &iv).decrypt(&mut padded).unwrap();
    assert_eq!(PKCS7::unpad_length(&padded, 16), Ok(rest.len()));
    if let Ok(length) = PKCS7::unpad_length(rest, 1 + selector as usize % 32) {
        assert!(length < rest.len());
    }
    // XTS: a data unit of at least a block round-trips; the keys must differ.
    if let Ok(xts) = XTS::<AES128>::new_from_slice(&[key, iv].concat()) {
        let mut unit = rest.to_vec();
        let result = xts.encrypt(&iv, &mut unit);
        assert_eq!(result.is_ok(), rest.len() >= 16);
        if result.is_ok() {
            xts.decrypt(&iv, &mut unit).unwrap();
            assert_eq!(unit, rest);
        }
    }
}

/// Checks every AEAD: decryption inverts encryption, and any changed bit of
/// the ciphertext, the tag or the associated data is refused, leaving the
/// ciphertext (or zeros, for AEGIS). Nonces of any length are refused or used.
#[cfg(all(
    umilib_feature = "crypto-mode-gcm",
    umilib_feature = "crypto-mode-ccm",
    umilib_feature = "crypto-mode-siv",
    umilib_feature = "crypto-mode-gcmsiv",
    umilib_feature = "crypto-aes",
    umilib_feature = "crypto-chacha20poly1305",
    umilib_feature = "crypto-aegis",
    umilib_feature = "crypto-ascon"
))]
pub fn aead(data: &[u8]) {
    use umilib::crypto::aes::AES128;
    use umilib::crypto::{AEAD, KeyInit};
    fn check<A: AEAD + KeyInit>(
        key: &[u8],
        nonce: &[u8],
        associated: &[u8],
        message: &[u8],
        flip: usize,
        zeroes: bool,
    ) {
        let Ok(aead) = A::new_from_slice(&key[..A::MINIMUM_KEY_SIZE]) else {
            return;
        };
        let mut buffer = message.to_vec();
        let Ok(tag) = aead.encrypt_in_place(nonce, associated, &mut buffer) else {
            return;
        };
        let ciphertext = buffer.clone();
        aead.decrypt_in_place(nonce, associated, &mut buffer, tag.as_ref()).unwrap();
        assert_eq!(buffer, message);
        let mut tag = tag.as_ref().to_vec();
        let mut buffer = ciphertext.clone();
        let mut associated = associated.to_vec();
        let length = buffer.len() + tag.len() + associated.len();
        let bit = flip % (8 * length);
        let (byte, mask) = (bit / 8, 1u8 << (bit % 8));
        if byte < buffer.len() {
            buffer[byte] ^= mask;
        } else if byte < buffer.len() + tag.len() {
            tag[byte - buffer.len()] ^= mask;
        } else {
            associated[byte - buffer.len() - tag.len()] ^= mask;
        }
        let tampered = buffer.clone();
        assert!(aead.decrypt_in_place(nonce, &associated, &mut buffer, &tag).is_err());
        if zeroes {
            assert!(buffer.iter().all(|&byte| byte == 0));
        } else {
            assert_eq!(buffer, tampered);
        }
    }
    let (selector, key, rest) = Parts::split(data, 32);
    let Some((&nonce_length, rest)) = rest.split_first() else {
        return;
    };
    let (nonce, rest) = rest.split_at((nonce_length as usize % 40).min(rest.len()));
    let (associated, message) = rest.split_at((selector as usize % 50).min(rest.len()));
    let flip = selector as usize * 131 + message.len();
    match selector % 9 {
        0 => check::<umilib::crypto::mode::gcm::GCM<AES128, 16>>(&key, nonce, associated, message, flip, false),
        1 => check::<umilib::crypto::mode::gcm::GCM<AES128, 4>>(&key, nonce, associated, message, flip, false),
        2 => check::<umilib::crypto::mode::ccm::CCM<AES128, 8>>(&key, nonce, associated, message, flip, false),
        3 => check::<umilib::crypto::mode::siv::SIV<AES128>>(&key, nonce, associated, message, flip, false),
        4 => check::<umilib::crypto::mode::gcmsiv::GCMSIV<AES128>>(&key, nonce, associated, message, flip, false),
        5 => check::<umilib::crypto::chacha20poly1305::ChaCha20Poly1305>(&key, nonce, associated, message, flip, false),
        6 => {
            check::<umilib::crypto::chacha20poly1305::XChaCha20Poly1305>(&key, nonce, associated, message, flip, false)
        }
        7 => check::<umilib::crypto::aegis::AEGIS128X<2, 32>>(&key, nonce, associated, message, flip, true),
        _ => check::<umilib::crypto::ascon::AsconAEAD128<16>>(&key, nonce, associated, message, flip, false),
    }
}

/// Checks the MACs and the stream ciphers: input in pieces equals input at once.
#[cfg(all(
    umilib_feature = "crypto-cmac",
    umilib_feature = "crypto-aes",
    umilib_feature = "crypto-poly1305",
    umilib_feature = "crypto-aegis",
    umilib_feature = "crypto-chacha20",
    umilib_feature = "crypto-rc4"
))]
pub fn streaming(data: &[u8]) {
    use umilib::crypto::aegis::AEGISMAC256X;
    use umilib::crypto::aes::AES128;
    use umilib::crypto::chacha20::{ChaCha20, XChaCha20};
    use umilib::crypto::cmac::CMAC;
    use umilib::crypto::poly1305::Poly1305;
    use umilib::crypto::rc4::RC4;
    use umilib::crypto::{KeyInit, MAC, StreamCipher};
    fn mac<M: MAC>(state: M, message: &[u8], cut: usize) {
        let mut whole = state.clone();
        whole.update(message);
        let mut pieces = state;
        pieces.update(&message[..cut]);
        pieces.update(&message[cut..]);
        let tag = whole.finalize();
        assert!(pieces.verify(tag.as_ref()));
    }
    fn stream<S: StreamCipher + Clone>(cipher: S, message: &[u8], cut: usize) {
        let mut whole = message.to_vec();
        cipher.clone().apply_keystream(&mut whole).unwrap();
        let mut pieces = message.to_vec();
        let mut split = cipher;
        split.apply_keystream(&mut pieces[..cut]).unwrap();
        split.apply_keystream(&mut pieces[cut..]).unwrap();
        assert_eq!(pieces, whole);
    }
    let (selector, key, message) = Parts::split(data, 32);
    let key: [u8; 32] = key.try_into().unwrap();
    let cut = (selector as usize * 5).min(message.len());
    match selector % 6 {
        0 => mac(CMAC::new(AES128::new_from_slice(&key[..16]).unwrap()), message, cut),
        1 => mac(Poly1305::new(&key), message, cut),
        2 => mac(AEGISMAC256X::<4, 16>::new(&key, &key), message, cut),
        3 => {
            stream(ChaCha20::new(&key, &[selector; 12], u32::MAX - 3), &message[..message.len().min(256)], cut.min(256))
        }
        4 => stream(XChaCha20::with_64_bit_counter(&key, &[selector; 24], 7), message, cut),
        _ => stream(RC4::new(&key[..1 + selector as usize % 32]).unwrap(), message, cut),
    }
}

/// Checks the key derivation functions on fuzzed parameters: they refuse or
/// derive without panicking, and a shorter output is a prefix of a longer one
/// where the specifications make it so (HKDF, KBKDF in counter mode).
#[cfg(all(
    umilib_feature = "crypto-hkdf",
    umilib_feature = "crypto-kbkdf",
    umilib_feature = "crypto-kdftree",
    umilib_feature = "crypto-scrypt",
    umilib_feature = "crypto-argon2",
    umilib_feature = "hash-sha-v2"
))]
pub fn kdf(data: &[u8]) {
    use umilib::crypto::argon2::{Argon2, Argon2Type};
    use umilib::crypto::hkdf::HKDF;
    use umilib::crypto::hmac::HMAC;
    use umilib::crypto::kbkdf::{KBKDF, KBKDFCounter};
    use umilib::crypto::kdftree::KDFTree;
    use umilib::crypto::scrypt::Scrypt;
    use umilib::hash::sha::v2::SHA256;
    let (selector, key, rest) = Parts::split(data, 16);
    let length = selector as usize * 41;
    let mut long = vec![0u8; length];
    let mut short = vec![0u8; length / 2];
    match selector % 5 {
        0 => {
            if HKDF::<SHA256>::derive(&key, rest, b"info", &mut long).is_ok() {
                HKDF::<SHA256>::derive(&key, rest, b"info", &mut short).unwrap();
                assert_eq!(short, long[..short.len()]);
            }
        }
        1 => {
            let bits = [8, 16, 24, 32, 12][selector as usize / 5 % 5];
            if let Ok(kbkdf) = KBKDF::new(HMAC::<SHA256>::new(&key), bits)
                && kbkdf.counter(&[], rest, &mut long).is_ok()
            {
                kbkdf.counter(&[], rest, &mut short).unwrap();
                assert_eq!(short, long[..short.len()]);
                let location = [KBKDFCounter::Absent, KBKDFCounter::AfterFixed][selector as usize % 2];
                let _ = kbkdf.feedback(&key, rest, location, &mut long);
                let _ = kbkdf.double_pipeline(rest, location, &mut long);
            }
        }
        2 => {
            if let Ok(tree) = KDFTree::new(HMAC::<SHA256>::new(&key), 1 + selector as usize / 5 % 5) {
                let _ = tree.derive(rest, &key, &mut long);
            }
        }
        3 => {
            // Small costs: N up to 2^6, r and p up to 4.
            let n = 1u64 << (selector / 5 % 7);
            if let Ok(scrypt) = Scrypt::new(n, 1 + selector as u32 % 4, 1 + selector as u32 / 64) {
                let size = short.len().min(64);
                scrypt.derive(&key, rest, &mut short[..size]).unwrap();
            }
        }
        _ => {
            let variant = [Argon2Type::Argon2d, Argon2Type::Argon2i, Argon2Type::Argon2id][selector as usize % 3];
            let lanes = 1 + selector as u32 % 3;
            if let Ok(argon2) = Argon2::new(variant, 8 * lanes + selector as u32 % 16, 1 + selector as u32 % 2, lanes) {
                let size = short.len().min(64);
                let result = argon2.derive(&key, rest, &[], &[], &mut short[..size]);
                assert_eq!(result.is_ok(), size >= Argon2::MINIMUM_TAG);
            }
        }
    }
}

#[cfg(any(
    umilib_feature = "crypto-aes",
    umilib_feature = "crypto-aria",
    umilib_feature = "crypto-camellia",
    umilib_feature = "crypto-des",
    umilib_feature = "crypto-gost",
    umilib_feature = "crypto-idea",
    umilib_feature = "crypto-rc2",
    umilib_feature = "crypto-seed",
    umilib_feature = "crypto-sm4"
))]
pub const BLOCK_CIPHER: FuzzFunction<fn(&[u8])> = FuzzFunction::new("crypto-block-cipher", block_cipher);
#[cfg(all(
    umilib_feature = "crypto-mode-cbc",
    umilib_feature = "crypto-mode-cfb",
    umilib_feature = "crypto-mode-ctr",
    umilib_feature = "crypto-mode-ofb",
    umilib_feature = "crypto-mode-xts",
    umilib_feature = "crypto-aes"
))]
pub const MODE: FuzzFunction<fn(&[u8])> = FuzzFunction::new("crypto-mode", mode);
#[cfg(all(
    umilib_feature = "crypto-mode-gcm",
    umilib_feature = "crypto-mode-ccm",
    umilib_feature = "crypto-mode-siv",
    umilib_feature = "crypto-mode-gcmsiv",
    umilib_feature = "crypto-aes",
    umilib_feature = "crypto-chacha20poly1305",
    umilib_feature = "crypto-aegis",
    umilib_feature = "crypto-ascon"
))]
pub const AEAD: FuzzFunction<fn(&[u8])> = FuzzFunction::new("crypto-aead", aead);
#[cfg(all(
    umilib_feature = "crypto-cmac",
    umilib_feature = "crypto-aes",
    umilib_feature = "crypto-poly1305",
    umilib_feature = "crypto-aegis",
    umilib_feature = "crypto-chacha20",
    umilib_feature = "crypto-rc4"
))]
pub const STREAMING: FuzzFunction<fn(&[u8])> = FuzzFunction::new("crypto-streaming", streaming);
#[cfg(all(
    umilib_feature = "crypto-hkdf",
    umilib_feature = "crypto-kbkdf",
    umilib_feature = "crypto-kdftree",
    umilib_feature = "crypto-scrypt",
    umilib_feature = "crypto-argon2",
    umilib_feature = "hash-sha-v2"
))]
pub const KDF: FuzzFunction<fn(&[u8])> = FuzzFunction::new("crypto-kdf", kdf);
#[cfg(all(umilib_feature = "crypto-hmac", umilib_feature = "hash-sha-v2"))]
pub const HMAC: FuzzFunction<fn(&[u8])> = FuzzFunction::new("crypto-hmac", hmac);
#[cfg(all(umilib_feature = "crypto-random", umilib_feature = "hash-sha-v2"))]
pub const DRBG: FuzzFunction<fn(&[u8])> = FuzzFunction::new("crypto-random", drbg);

/// Checks key wrapping (SP 800-38F): KW, KWP and TKW unwrap what they wrap,
/// and an arbitrary wrapping unwraps, if it does, to a key that wraps back
/// to it.
#[cfg(all(umilib_feature = "crypto-mode-kw", umilib_feature = "crypto-aes", umilib_feature = "crypto-des"))]
pub fn kw(data: &[u8]) {
    use umilib::crypto::KeyInit;
    use umilib::crypto::aes::AES128;
    use umilib::crypto::des::TDES;
    use umilib::crypto::mode::kw::{KW, KWP};
    let (selector, key, rest) = Parts::split(data, 24);
    match selector % 3 {
        0 => {
            let kw = KW::new(AES128::new_from_slice(&key[..16]).unwrap()).unwrap();
            if let Ok(length) = KW::<AES128>::wrapped_length(rest.len()) {
                let mut wrapped = vec![0u8; length];
                kw.wrap(rest, &mut wrapped).unwrap();
                let mut unwrapped = vec![0u8; rest.len()];
                kw.unwrap(&wrapped, &mut unwrapped).unwrap();
                assert_eq!(unwrapped, rest);
            }
            if rest.len() >= 8 {
                let mut unwrapped = vec![0u8; rest.len() - 8];
                if kw.unwrap(rest, &mut unwrapped).is_ok() {
                    let mut wrapped = vec![0u8; rest.len()];
                    kw.wrap(&unwrapped, &mut wrapped).unwrap();
                    assert_eq!(wrapped, rest);
                }
            }
        }
        1 => {
            let kwp = KWP::new(AES128::new_from_slice(&key[..16]).unwrap()).unwrap();
            if let Ok(length) = KWP::<AES128>::wrapped_length(rest.len()) {
                let mut wrapped = vec![0u8; length];
                kwp.wrap(rest, &mut wrapped).unwrap();
                let mut unwrapped = vec![0u8; length - 8];
                let unwrapped_length = kwp.unwrap(&wrapped, &mut unwrapped).unwrap();
                assert_eq!(&unwrapped[..unwrapped_length], rest);
            }
            let mut unwrapped = vec![0u8; rest.len()];
            if let Ok(length) = kwp.unwrap(rest, &mut unwrapped) {
                let mut wrapped = vec![0u8; rest.len()];
                kwp.wrap(&unwrapped[..length], &mut wrapped).unwrap();
                assert_eq!(wrapped, rest);
            }
        }
        _ => {
            // TDES refuses keys whose parts repeat (SP 800-67 §3.3).
            let Ok(cipher) = TDES::new_from_slice(&key) else { return };
            let tkw = KW::new(cipher).unwrap();
            if rest.len() >= 4 {
                let mut unwrapped = vec![0u8; rest.len() - 4];
                if tkw.unwrap(rest, &mut unwrapped).is_ok() {
                    let mut wrapped = vec![0u8; rest.len()];
                    tkw.wrap(&unwrapped, &mut wrapped).unwrap();
                    assert_eq!(wrapped, rest);
                }
            }
        }
    }
}

#[cfg(all(umilib_feature = "crypto-mode-kw", umilib_feature = "crypto-aes", umilib_feature = "crypto-des"))]
pub const KW: FuzzFunction<fn(&[u8])> = FuzzFunction::new("crypto-kw", kw);

/// Checks the one-step KDF (SP 800-56C Rev. 2): a shorter output is a
/// prefix of a longer one, over a hash function and over HMAC.
#[cfg(all(umilib_feature = "crypto-concatkdf", umilib_feature = "hash-sha-v2"))]
pub fn concatkdf(data: &[u8]) {
    use umilib::crypto::concatkdf::{ConcatKDF, HashFunction};
    use umilib::crypto::hmac::HMAC;
    use umilib::hash::sha::v2::SHA256;
    let (selector, salt, rest) = Parts::split(data, 16);
    let (z, fixed_info) = rest.split_at(rest.len() / 2);
    let mut long = vec![0u8; selector as usize * 7];
    let mut short = vec![0u8; long.len() / 2];
    if selector % 2 == 0 {
        let kdf = ConcatKDF::<HashFunction<SHA256>>::hash();
        kdf.derive(z, fixed_info, &mut long).unwrap();
        kdf.derive(z, fixed_info, &mut short).unwrap();
    } else {
        let kdf = ConcatKDF::new(HMAC::<SHA256>::new(&salt));
        kdf.derive(z, fixed_info, &mut long).unwrap();
        kdf.derive(z, fixed_info, &mut short).unwrap();
    }
    assert_eq!(short, long[..short.len()]);
}

#[cfg(all(umilib_feature = "crypto-concatkdf", umilib_feature = "hash-sha-v2"))]
pub const CONCATKDF: FuzzFunction<fn(&[u8])> = FuzzFunction::new("crypto-concatkdf", concatkdf);

/// Checks SM9 (GM/T 0044.3 and 0044.4) on arbitrary bytes with a fixed key:
/// the decodings of points of G_1 and G_2 give back their bytes, the KDF
/// stream cipher and SM4 in CBC mode with the padding of annex D decrypt
/// what they encrypt and reject other ciphertexts without panicking, and
/// the decryption, the decapsulation and the key exchange never panic on
/// the encapsulations, ciphertexts and points of the input.
#[cfg(all(
    umilib_feature = "crypto-sm9",
    umilib_feature = "crypto-sm4",
    umilib_feature = "crypto-mode-cbc",
    umilib_feature = "hash-sm3"
))]
pub fn sm9(data: &[u8]) {
    use umilib::crypto::sm4::SM4;
    use umilib::crypto::sm9::{
        SM9BlockCipher, SM9Cipher, SM9Encoding, SM9EncryptMasterKey, SM9KEM, SM9KEP, SM9PKE, SM9Role, SM9StreamCipher,
    };
    use umilib::hash::sm3::SM3;
    use umilib::math::ec::FieldElement;
    use umilib::math::pairing::SM9BN256;
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let key = || {
        let master = SM9EncryptMasterKey::<SM9BN256>::new(FieldElement::from_be_bytes(&[7; 32]).unwrap()).unwrap();
        master.extract::<SM3>(b"Bob", 0x03).unwrap()
    };
    match selector % 6 {
        0 => {
            if let Ok(point) = SM9Encoding::<SM9BN256>::g1_from_bytes(rest) {
                assert_eq!(SM9Encoding::<SM9BN256>::g1(&point).unwrap(), rest);
            }
        }
        1 => {
            if let Ok(point) = SM9Encoding::<SM9BN256>::g2_from_bytes(rest) {
                assert_eq!(SM9Encoding::<SM9BN256>::g2(&point).unwrap(), rest);
            }
        }
        2 => {
            let (cipher_key, message) = rest.split_at(16.min(rest.len()));
            let Ok(encrypted) = SM9BlockCipher::<SM4>::encrypt(cipher_key, message) else {
                assert_ne!(cipher_key.len(), 16);
                return;
            };
            assert_eq!(encrypted.len(), (message.len() / 16 + 1) * 16);
            assert_eq!(SM9BlockCipher::<SM4>::decrypt(cipher_key, &encrypted).unwrap(), message);
            // Any ciphertext decrypts to its message or fails, as a padding check must.
            let _ = SM9BlockCipher::<SM4>::decrypt(cipher_key, message);
        }
        3 => {
            let (mask, message) = rest.split_at(rest.len() / 2);
            let message = &message[..mask.len()];
            let encrypted = SM9StreamCipher::encrypt(mask, message).unwrap();
            assert_eq!(SM9StreamCipher::decrypt(mask, &encrypted).unwrap(), message);
        }
        4 => {
            let key = key();
            let _ = SM9PKE::<SM9BN256, SM3>::decrypt(&key, rest);
            let _ = SM9PKE::<SM9BN256, SM3, SM9BlockCipher<SM4>>::decrypt(&key, rest);
        }
        _ => {
            let key = key();
            let Ok(point) = SM9Encoding::<SM9BN256>::g1_from_bytes(rest.get(..64).unwrap_or(rest)) else {
                return;
            };
            let mut out = [0u8; 32];
            let _ = SM9KEM::<SM9BN256, SM3>::decapsulate(&key, &point, &mut out);
            let side = SM9KEP::<SM9BN256, SM3>::new(
                SM9Role::Responder,
                key,
                b"Alice",
                FieldElement::from_be_bytes(&[3; 32]).unwrap(),
            )
            .unwrap();
            side.agree(&point, &mut out).unwrap();
        }
    }
}

/// Checks the post-quantum schemes on arbitrary bytes with fixed keys: the
/// encodings of keys of ML-KEM, ML-DSA, SLH-DSA and the hybrids are read
/// back to themselves when accepted; decapsulation of any ciphertext of the
/// right length gives a secret (implicit rejection) and refuses the others;
/// verification of any signature never panics and refuses changed ones.
#[cfg(all(
    umilib_feature = "crypto-mlkem",
    umilib_feature = "crypto-mldsa",
    umilib_feature = "crypto-slhdsa",
    umilib_feature = "crypto-hybrid",
    umilib_feature = "hash-sha-v2"
))]
pub fn pqc(data: &[u8]) {
    use umilib::crypto::hybrid::{HybridKEM, X25519MLKEM768};
    use umilib::crypto::mldsa::{MLDSA, MLDSA44};
    use umilib::crypto::mlkem::{MLKEM, MLKEM512};
    use umilib::crypto::random::HMACDRBG;
    use umilib::crypto::slhdsa::{SLHDSA, SLHDSA_SHAKE_128f};
    use umilib::crypto::{CryptoError, KeyEncapsulation, SignatureScheme};
    use umilib::hash::sha::v2::SHA256;
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let mut random = HMACDRBG::<SHA256>::new(&[1; 32], &[2; 16], b"fuzz").unwrap();
    match selector % 7 {
        0 => {
            type Scheme = MLKEM<MLKEM512>;
            if let Ok(key) = Scheme::encapsulation_key_from_bytes(rest) {
                let mut out = vec![0u8; Scheme::ENCAPSULATION_KEY_SIZE];
                Scheme::write_encapsulation_key(&key, &mut out).unwrap();
                assert_eq!(out, rest);
            }
            if let Ok(key) = Scheme::decapsulation_key_from_bytes(rest) {
                let mut shared = [0u8; 32];
                Scheme::decapsulate(&key, &[0u8; 768], &mut shared).unwrap();
            }
        }
        1 => {
            type Scheme = MLKEM<MLKEM512>;
            let key = Scheme::decapsulation_key_from_seed(&[7u8; 64]).unwrap();
            let mut shared = [0u8; 32];
            match Scheme::decapsulate(&key, rest, &mut shared) {
                Ok(()) => assert_eq!(rest.len(), Scheme::CIPHERTEXT_SIZE),
                Err(error) => assert_eq!(error, CryptoError::InputLength { length: rest.len() }),
            }
        }
        2 => {
            type Scheme = MLDSA<MLDSA44>;
            if let Ok(key) = Scheme::verifying_key_from_bytes(rest) {
                let mut out = vec![0u8; Scheme::VERIFYING_KEY_SIZE];
                Scheme::write_verifying_key(&key, &mut out).unwrap();
                assert_eq!(out, rest);
            }
            if let Ok(key) = Scheme::signing_key_from_bytes(rest) {
                let mut out = vec![0u8; Scheme::SIGNING_KEY_SIZE];
                Scheme::write_signing_key(&key, &mut out).unwrap();
                assert_eq!(out, rest);
            }
        }
        3 => {
            type Scheme = MLDSA<MLDSA44>;
            let key = Scheme::signing_key_from_seed(&[7u8; 32]).unwrap();
            let public = Scheme::verifying_key(&key);
            let mut signature = vec![0u8; Scheme::SIGNATURE_SIZE];
            let length = signature.len().min(rest.len());
            signature[..length].copy_from_slice(&rest[..length]);
            let _ = Scheme::verify(&public, b"fuzz", &signature);
            Scheme::sign(&key, rest, &mut signature).unwrap();
            Scheme::verify(&public, rest, &signature).unwrap();
            let index = selector as usize % signature.len();
            signature[index] ^= 1 << (selector % 8);
            assert!(Scheme::verify(&public, rest, &signature).is_err());
        }
        4 => {
            type Scheme = SLHDSA<SLHDSA_SHAKE_128f>;
            let public = Scheme::verifying_key_from_bytes(&[[7u8; 16]; 2].concat()).unwrap();
            let mut signature = vec![0u8; Scheme::SIGNATURE_SIZE];
            let length = signature.len().min(rest.len());
            signature[..length].copy_from_slice(&rest[..length]);
            // A signature for a key of a random-looking root cannot be found by chance.
            assert!(Scheme::verify(&public, b"fuzz", &signature).is_err());
        }
        5 => {
            type Scheme = HybridKEM<X25519MLKEM768>;
            if let Ok(key) = Scheme::encapsulation_key_from_bytes(rest) {
                let mut out = vec![0u8; Scheme::ENCAPSULATION_KEY_SIZE];
                Scheme::write_encapsulation_key(&key, &mut out).unwrap();
                assert_eq!(out, rest);
                let (mut ciphertext, mut shared) = (vec![0u8; Scheme::CIPHERTEXT_SIZE], vec![0u8; 64]);
                // A share of small order gives the X25519 secret zero, which TLS refuses.
                if let Err(error) = Scheme::encapsulate(&key, &mut random, &mut ciphertext, &mut shared) {
                    assert_eq!(error, CryptoError::InvalidKey);
                    assert!(shared.iter().all(|byte| *byte == 0));
                }
            }
        }
        _ => {
            type Scheme = HybridKEM<X25519MLKEM768>;
            let key = Scheme::generate(&mut random).unwrap();
            let mut shared = vec![0u8; 64];
            if Scheme::decapsulate(&key, rest, &mut shared).is_err() {
                assert!(shared.iter().all(|byte| *byte == 0));
            }
        }
    }
}

/// Checks the decoders of public-key encodings on arbitrary bytes: SEC 1
/// points, X25519 and Ed25519 keys, DER signatures of ECDSA, PKCS #1 keys of
/// RSA, encapsulations of HPKE, commits of Dragonfly and the signatures and
/// master public keys of SM9 never panic, and an
/// accepted DER encoding is the one its value encodes to (DER is canonical).
#[cfg(all(
    umilib_feature = "crypto-ecdh",
    umilib_feature = "crypto-ecdsa",
    umilib_feature = "crypto-eddsa",
    umilib_feature = "crypto-rsa",
    umilib_feature = "crypto-hpke",
    umilib_feature = "crypto-dragonfly",
    umilib_feature = "crypto-curve-p256",
    umilib_feature = "crypto-curve-curve25519",
    umilib_feature = "crypto-chacha20poly1305",
    umilib_feature = "crypto-ibs-sm9",
    umilib_feature = "codec-asn1-der",
    umilib_feature = "hash-sha-v2",
    umilib_feature = "hash-sm3"
))]
pub fn public_key(data: &[u8]) {
    use umilib::crypto::chacha20poly1305::ChaCha20Poly1305;
    use umilib::crypto::curve::p256::P256;
    use umilib::crypto::dragonfly::DragonflyCommit;
    use umilib::crypto::ecdh::{ECDH, X25519};
    use umilib::crypto::ecdsa::ECDSASignature;
    use umilib::crypto::eddsa::Ed25519;
    use umilib::crypto::hpke::{DHKEM, HPKE, HPKEKEM};
    use umilib::crypto::rsa::{RSAPrivateKey, RSAPublicKey};
    use umilib::crypto::{KeyAgreement, SignatureScheme};
    use umilib::hash::sha::v2::SHA256;
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    match selector % 8 {
        0 => {
            if let Ok(key) = ECDH::<P256>::public_key_from_bytes(rest) {
                let mut encoded = [0u8; 65];
                ECDH::<P256>::write_public_key(&key, &mut encoded).unwrap();
                assert_eq!(ECDH::<P256>::public_key_from_bytes(&encoded).unwrap(), key);
            }
        }
        1 => {
            if let Ok(key) = X25519::public_key_from_bytes(rest) {
                let private = X25519::private_key_from_bytes(&[9; 32]).unwrap();
                let mut shared = [0u8; 32];
                // A key of small order gives the zero secret, which agree refuses.
                let _ = X25519::agree(&private, &key, &mut shared);
            }
        }
        2 => {
            if let Ok(key) = Ed25519::verifying_key_from_bytes(rest.get(..32).unwrap_or(rest)) {
                let signature = rest.get(32..96).unwrap_or(&[]);
                let _ = Ed25519::verify(&key, rest.get(96..).unwrap_or(&[]), signature);
            }
        }
        3 => {
            if let Ok(signature) = ECDSASignature::<P256>::from_der(rest) {
                assert_eq!(signature.to_der(), rest);
                let mut bytes = [0u8; 64];
                signature.write_bytes(&mut bytes).unwrap();
                assert_eq!(ECDSASignature::<P256>::from_bytes(&bytes).unwrap().to_der(), rest);
            }
        }
        4 => {
            if let Ok(key) = RSAPublicKey::from_pkcs1_der(rest) {
                assert_eq!(key.to_pkcs1_der(), rest);
            }
            if let Ok(key) = RSAPrivateKey::from_pkcs1_der(rest)
                && let Ok(der) = key.to_pkcs1_der()
            {
                assert_eq!(der, rest);
            }
        }
        5 => {
            type Kem = DHKEM<X25519, SHA256>;
            let (recipient, _) = Kem::derive_key_pair(b"fuzz").unwrap();
            let (encapsulated, ciphertext) = rest.split_at(32.min(rest.len()));
            if let Ok(mut context) =
                HPKE::<Kem, SHA256, ChaCha20Poly1305>::setup_receiver(encapsulated, &recipient, b"", None, None)
            {
                assert!(context.open(b"", ciphertext).is_err());
            }
        }
        6 => {
            if let Ok(commit) = DragonflyCommit::<P256>::from_bytes(rest) {
                assert_eq!(commit.to_bytes(), rest);
            }
        }
        _ => {
            use umilib::crypto::ibs::sm9::{SM9, SM9Signature};
            use umilib::crypto::ibs::{IBSSignature, IdentityBasedSignature};
            use umilib::hash::sm3::SM3;
            use umilib::math::pairing::SM9BN256;
            if let Ok(signature) = SM9Signature::<SM9BN256>::from_bytes(rest) {
                assert_eq!(signature.to_bytes(), rest);
            }
            if let Ok(key) = SM9::<SM9BN256, SM3>::master_public_key_from_bytes(rest) {
                assert_eq!(SM9::<SM9BN256, SM3>::master_public_key_to_bytes(&key), rest);
            }
        }
    }
}

/// Checks that keys taken from the input sign messages taken from it, that
/// the signatures verify and that any changed bit makes them fail: ECDSA
/// on P-256, Ed25519 and SM2.
#[cfg(all(
    umilib_feature = "crypto-ecdsa",
    umilib_feature = "crypto-eddsa",
    umilib_feature = "crypto-sm2",
    umilib_feature = "crypto-curve-p256",
    umilib_feature = "crypto-curve-curve25519",
    umilib_feature = "hash-sha-v2"
))]
pub fn signature(data: &[u8]) {
    use umilib::crypto::SignatureScheme;
    use umilib::crypto::curve::p256::P256;
    use umilib::crypto::curve::sm2::SM2;
    use umilib::crypto::ecdsa::ECDSA;
    use umilib::crypto::eddsa::Ed25519;
    use umilib::crypto::sm2::SM2DSA;
    use umilib::hash::sha::v2::SHA256;
    use umilib::hash::sm3::SM3;
    fn check<S: SignatureScheme>(key: &[u8], message: &[u8], flip: usize) {
        let Ok(key) = S::signing_key_from_bytes(key) else {
            return;
        };
        let verifying = S::verifying_key(&key);
        let mut signature = vec![0u8; S::SIGNATURE_SIZE];
        S::sign(&key, message, &mut signature).unwrap();
        assert_eq!(S::verify(&verifying, message, &signature), Ok(()));
        let index = flip % (8 * signature.len());
        signature[index / 8] ^= 1 << (index % 8);
        assert!(S::verify(&verifying, message, &signature).is_err());
    }
    if data.len() < 34 {
        return;
    }
    let (key, rest) = data.split_at(32);
    let flip = u16::from_le_bytes([rest[0], rest[1]]) as usize;
    let message = &rest[2..];
    check::<ECDSA<P256, SHA256>>(key, message, flip);
    check::<Ed25519>(key, message, flip);
    check::<SM2DSA<SM2, SM3>>(key, message, flip);
}

#[cfg(all(
    umilib_feature = "crypto-ecdh",
    umilib_feature = "crypto-ecdsa",
    umilib_feature = "crypto-eddsa",
    umilib_feature = "crypto-rsa",
    umilib_feature = "crypto-hpke",
    umilib_feature = "crypto-dragonfly",
    umilib_feature = "crypto-curve-p256",
    umilib_feature = "crypto-curve-curve25519",
    umilib_feature = "crypto-chacha20poly1305",
    umilib_feature = "crypto-ibs-sm9",
    umilib_feature = "codec-asn1-der",
    umilib_feature = "hash-sha-v2",
    umilib_feature = "hash-sm3"
))]
pub const PUBLIC_KEY: FuzzFunction<fn(&[u8])> = FuzzFunction::new("crypto-public-key", public_key);
#[cfg(all(
    umilib_feature = "crypto-ecdsa",
    umilib_feature = "crypto-eddsa",
    umilib_feature = "crypto-sm2",
    umilib_feature = "crypto-curve-p256",
    umilib_feature = "crypto-curve-curve25519",
    umilib_feature = "hash-sha-v2"
))]
pub const SIGNATURE: FuzzFunction<fn(&[u8])> = FuzzFunction::new("crypto-signature", signature);
#[cfg(all(
    umilib_feature = "crypto-mlkem",
    umilib_feature = "crypto-mldsa",
    umilib_feature = "crypto-slhdsa",
    umilib_feature = "crypto-hybrid",
    umilib_feature = "hash-sha-v2"
))]
pub const PQC: FuzzFunction<fn(&[u8])> = FuzzFunction::new("crypto-pqc", pqc);
#[cfg(all(
    umilib_feature = "crypto-sm9",
    umilib_feature = "crypto-sm4",
    umilib_feature = "crypto-mode-cbc",
    umilib_feature = "hash-sm3"
))]
pub const SM9: FuzzFunction<fn(&[u8])> = FuzzFunction::new("crypto-sm9", sm9);

pub const TARGETS: &[&dyn FuzzTarget] = &[
    #[cfg(any(
        umilib_feature = "crypto-aes",
        umilib_feature = "crypto-aria",
        umilib_feature = "crypto-camellia",
        umilib_feature = "crypto-des",
        umilib_feature = "crypto-gost",
        umilib_feature = "crypto-idea",
        umilib_feature = "crypto-rc2",
        umilib_feature = "crypto-seed",
        umilib_feature = "crypto-sm4"
    ))]
    &BLOCK_CIPHER,
    #[cfg(all(
        umilib_feature = "crypto-mode-cbc",
        umilib_feature = "crypto-mode-cfb",
        umilib_feature = "crypto-mode-ctr",
        umilib_feature = "crypto-mode-ofb",
        umilib_feature = "crypto-mode-xts",
        umilib_feature = "crypto-aes"
    ))]
    &MODE,
    #[cfg(all(
        umilib_feature = "crypto-mode-gcm",
        umilib_feature = "crypto-mode-ccm",
        umilib_feature = "crypto-mode-siv",
        umilib_feature = "crypto-mode-gcmsiv",
        umilib_feature = "crypto-aes",
        umilib_feature = "crypto-chacha20poly1305",
        umilib_feature = "crypto-aegis",
        umilib_feature = "crypto-ascon"
    ))]
    &AEAD,
    #[cfg(all(
        umilib_feature = "crypto-cmac",
        umilib_feature = "crypto-aes",
        umilib_feature = "crypto-poly1305",
        umilib_feature = "crypto-aegis",
        umilib_feature = "crypto-chacha20",
        umilib_feature = "crypto-rc4"
    ))]
    &STREAMING,
    #[cfg(all(
        umilib_feature = "crypto-hkdf",
        umilib_feature = "crypto-kbkdf",
        umilib_feature = "crypto-kdftree",
        umilib_feature = "crypto-scrypt",
        umilib_feature = "crypto-argon2",
        umilib_feature = "hash-sha-v2"
    ))]
    &KDF,
    #[cfg(all(umilib_feature = "crypto-hmac", umilib_feature = "hash-sha-v2"))]
    &HMAC,
    #[cfg(all(umilib_feature = "crypto-mode-kw", umilib_feature = "crypto-aes", umilib_feature = "crypto-des"))]
    &KW,
    #[cfg(all(umilib_feature = "crypto-concatkdf", umilib_feature = "hash-sha-v2"))]
    &CONCATKDF,
    #[cfg(all(umilib_feature = "crypto-random", umilib_feature = "hash-sha-v2"))]
    &DRBG,
    #[cfg(all(
        umilib_feature = "crypto-ecdh",
        umilib_feature = "crypto-ecdsa",
        umilib_feature = "crypto-eddsa",
        umilib_feature = "crypto-rsa",
        umilib_feature = "crypto-hpke",
        umilib_feature = "crypto-dragonfly",
        umilib_feature = "crypto-curve-p256",
        umilib_feature = "crypto-curve-curve25519",
        umilib_feature = "crypto-chacha20poly1305",
        umilib_feature = "crypto-ibs-sm9",
        umilib_feature = "codec-asn1-der",
        umilib_feature = "hash-sha-v2",
        umilib_feature = "hash-sm3"
    ))]
    &PUBLIC_KEY,
    #[cfg(all(
        umilib_feature = "crypto-ecdsa",
        umilib_feature = "crypto-eddsa",
        umilib_feature = "crypto-sm2",
        umilib_feature = "crypto-curve-p256",
        umilib_feature = "crypto-curve-curve25519",
        umilib_feature = "hash-sha-v2"
    ))]
    &SIGNATURE,
    #[cfg(all(
        umilib_feature = "crypto-sm9",
        umilib_feature = "crypto-sm4",
        umilib_feature = "crypto-mode-cbc",
        umilib_feature = "hash-sm3"
    ))]
    &SM9,
    #[cfg(all(
        umilib_feature = "crypto-mlkem",
        umilib_feature = "crypto-mldsa",
        umilib_feature = "crypto-slhdsa",
        umilib_feature = "crypto-hybrid",
        umilib_feature = "hash-sha-v2"
    ))]
    &PQC,
];
