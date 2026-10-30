//! Benchmarks of `umilib::crypto`: the block ciphers, modes, AEADs and stream
//! ciphers over 1 KiB (a typical record), the MACs of short messages, as in
//! protocols, the key derivation functions with small costs, and random
//! generation in requests of 1 KiB, and the operations of the public-key
//! schemes, one at a time.

use std::hint::black_box;

use umilib::platform::bench::{Bench, Throughput};

pub struct Benchmarks;

impl Benchmarks {
    /// The bytes processed by the throughput benchmarks.
    pub const LENGTH: usize = 1024;

    pub fn run(bench: &mut Bench) {
        let mut data = [0xA5u8; Benchmarks::LENGTH];
        let throughput = Some(Throughput::Bytes(Benchmarks::LENGTH as u64));
        // Measures `encrypt_blocks` of `LENGTH` bytes with the block cipher `$type` and a key of `$key` bytes,
        // 0, 1, 2, ... (so that the keys of Triple DES differ).
        #[allow(unused_macros)]
        macro_rules! block_cipher {
            ($name:literal, $type:ty, $key:literal) => {{
                use umilib::crypto::{BlockCipher, KeyInit};
                let key: [u8; $key] = core::array::from_fn(|index| index as u8);
                let cipher = <$type>::new_from_slice(&key).unwrap();
                bench.run($name, throughput, || {
                    let blocks = data.as_chunks_mut::<{ <$type as BlockCipher>::BLOCK_SIZE }>().0;
                    cipher.encrypt_blocks(black_box(blocks));
                });
            }};
        }
        // Measures `encrypt_in_place` of `LENGTH` bytes with the AEAD `$aead`.
        #[allow(unused_macros)]
        macro_rules! aead {
            ($name:literal, $aead:expr, $nonce:literal) => {{
                use umilib::crypto::AEAD;
                let aead = $aead;
                bench.run($name, throughput, || {
                    black_box(aead.encrypt_in_place(&[1u8; $nonce], &[2u8; 13], black_box(&mut data)).unwrap());
                });
            }};
        }
        #[cfg(umilib_feature = "crypto-aes")]
        {
            block_cipher!("crypto-aes-aes128-1-kib", umilib::crypto::aes::AES128, 16);
            block_cipher!("crypto-aes-aes256-1-kib", umilib::crypto::aes::AES256, 32);
        }
        #[cfg(umilib_feature = "crypto-aria")]
        block_cipher!("crypto-aria-aria128-1-kib", umilib::crypto::aria::ARIA128, 16);
        #[cfg(umilib_feature = "crypto-camellia")]
        block_cipher!("crypto-camellia-camellia128-1-kib", umilib::crypto::camellia::Camellia128, 16);
        #[cfg(umilib_feature = "crypto-seed")]
        block_cipher!("crypto-seed-seed-1-kib", umilib::crypto::seed::SEED, 16);
        #[cfg(umilib_feature = "crypto-sm4")]
        block_cipher!("crypto-sm4-sm4-1-kib", umilib::crypto::sm4::SM4, 16);
        #[cfg(umilib_feature = "crypto-gost-kuznyechik")]
        block_cipher!("crypto-gost-kuznyechik-1-kib", umilib::crypto::gost::kuznyechik::Kuznyechik, 32);
        #[cfg(umilib_feature = "crypto-gost-magma")]
        block_cipher!("crypto-gost-magma-1-kib", umilib::crypto::gost::magma::Magma, 32);
        #[cfg(umilib_feature = "crypto-des")]
        block_cipher!("crypto-des-tdes-1-kib", umilib::crypto::des::TDES, 24);
        #[cfg(umilib_feature = "crypto-idea")]
        block_cipher!("crypto-idea-idea-1-kib", umilib::crypto::idea::IDEA, 16);
        #[cfg(umilib_feature = "crypto-rc2")]
        block_cipher!("crypto-rc2-rc2-1-kib", umilib::crypto::rc2::RC2, 16);
        #[cfg(all(umilib_feature = "crypto-mode", umilib_feature = "crypto-aes"))]
        {
            use umilib::crypto::KeyInit;
            use umilib::crypto::aes::AES128;
            bench.run("crypto-mode-cbc-aes128-encrypt-1-kib", throughput, || {
                let mut cbc = umilib::crypto::mode::cbc::CBC::new(AES128::new(&[7; 16]), &[1; 16]);
                cbc.encrypt(black_box(&mut data)).unwrap();
            });
            bench.run("crypto-mode-ctr-aes128-1-kib", throughput, || {
                use umilib::crypto::StreamCipher;
                let mut ctr = umilib::crypto::mode::ctr::CTR::new(AES128::new(&[7; 16]), &[0; 16]);
                ctr.apply_keystream(black_box(&mut data)).unwrap();
            });
            let xts =
                umilib::crypto::mode::xts::XTS::<AES128>::new_from_slice(&[[7u8; 16], [8u8; 16]].concat()).unwrap();
            bench.run("crypto-mode-xts-aes128-512-bytes", Some(Throughput::Bytes(512)), || {
                xts.encrypt(&[3; 16], black_box(&mut data[..512])).unwrap();
            });
            aead!(
                "crypto-mode-gcm-aes128-1-kib",
                umilib::crypto::mode::gcm::GCM::<AES128, 16>::new(AES128::new(&[7; 16])),
                12
            );
            aead!(
                "crypto-mode-ccm-aes128-1-kib",
                umilib::crypto::mode::ccm::CCM::<AES128, 16>::new(AES128::new(&[7; 16])),
                12
            );
            aead!(
                "crypto-mode-gcmsiv-aes128-1-kib",
                umilib::crypto::mode::gcmsiv::GCMSIV::<AES128>::new_from_slice(&[7; 16]).unwrap(),
                12
            );
            aead!(
                "crypto-mode-siv-aes128-1-kib",
                umilib::crypto::mode::siv::SIV::<AES128>::new_from_slice(&[7; 32]).unwrap(),
                12
            );
        }
        #[cfg(umilib_feature = "crypto-chacha20poly1305")]
        aead!("crypto-chacha20poly1305-1-kib", umilib::crypto::chacha20poly1305::ChaCha20Poly1305::new(&[7; 32]), 12);
        #[cfg(umilib_feature = "crypto-aegis")]
        {
            use umilib::crypto::aegis::{AEGIS128X, AEGIS256X};
            aead!("crypto-aegis-aegis128l-1-kib", AEGIS128X::<1, 16>::new(&[7; 16]), 16);
            aead!("crypto-aegis-aegis128x2-1-kib", AEGIS128X::<2, 16>::new(&[7; 16]), 16);
            aead!("crypto-aegis-aegis128x4-1-kib", AEGIS128X::<4, 16>::new(&[7; 16]), 16);
            aead!("crypto-aegis-aegis256-1-kib", AEGIS256X::<1, 16>::new(&[7; 32]), 32);
        }
        #[cfg(umilib_feature = "crypto-ascon")]
        aead!("crypto-ascon-ascon-aead128-1-kib", umilib::crypto::ascon::AsconAEAD128::<16>::new(&[7; 16]), 16);
        #[cfg(umilib_feature = "crypto-chacha20")]
        bench.run("crypto-chacha20-1-kib", throughput, || {
            use umilib::crypto::StreamCipher;
            let mut chacha = umilib::crypto::chacha20::ChaCha20::new(&[7; 32], &[1; 12], 1);
            chacha.apply_keystream(black_box(&mut data)).unwrap();
        });
        #[cfg(umilib_feature = "crypto-rc4")]
        bench.run("crypto-rc4-1-kib", throughput, || {
            use umilib::crypto::StreamCipher;
            let mut rc4 = umilib::crypto::rc4::RC4::new(&[7; 16]).unwrap();
            rc4.apply_keystream(black_box(&mut data)).unwrap();
        });
        #[cfg(all(umilib_feature = "crypto-cmac", umilib_feature = "crypto-aes"))]
        bench.run("crypto-cmac-aes128-64-bytes", Some(Throughput::Bytes(64)), || {
            use umilib::crypto::KeyInit;
            black_box(umilib::crypto::cmac::CMAC::mac(
                umilib::crypto::aes::AES128::new_from_slice(&[7; 16]).unwrap(),
                black_box(&data[..64]),
            ));
        });
        #[cfg(umilib_feature = "crypto-poly1305")]
        bench.run("crypto-poly1305-1-kib", throughput, || {
            black_box(umilib::crypto::poly1305::Poly1305::mac(&[7; 32], black_box(&data)));
        });
        #[cfg(all(umilib_feature = "crypto-hmac", umilib_feature = "hash-sha-v2"))]
        bench.run("crypto-hmac-sha256-64-bytes", Some(Throughput::Bytes(64)), || {
            use umilib::crypto::hmac::HMAC;
            use umilib::hash::sha::v2::SHA256;
            black_box(HMAC::<SHA256>::mac(black_box(&[1; 32]), black_box(&[2; 64])));
        });
        #[cfg(all(umilib_feature = "crypto-hkdf", umilib_feature = "hash-sha-v2"))]
        bench.run("crypto-hkdf-sha256-derive-32-bytes", Some(Throughput::Elements(1)), || {
            let mut okm = [0u8; 32];
            umilib::crypto::hkdf::HKDF::<umilib::hash::sha::v2::SHA256>::derive(&[1; 32], &[2; 32], b"info", &mut okm)
                .unwrap();
            black_box(okm);
        });
        #[cfg(all(umilib_feature = "crypto-concatkdf", umilib_feature = "hash-sha-v2"))]
        bench.run("crypto-concatkdf-sha256-derive-32-bytes", Some(Throughput::Elements(1)), || {
            use umilib::crypto::concatkdf::{ConcatKDF, HashFunction};
            use umilib::hash::sha::v2::SHA256;
            let mut out = [0u8; 32];
            ConcatKDF::<HashFunction<SHA256>>::hash()
                .derive(black_box(&[1; 32]), black_box(&[2; 31]), &mut out)
                .unwrap();
            black_box(out);
        });
        #[cfg(all(umilib_feature = "crypto-mode-kw", umilib_feature = "crypto-aes"))]
        {
            use umilib::crypto::KeyInit;
            use umilib::crypto::aes::AES128;
            use umilib::crypto::mode::kw::KW;
            let kw = KW::new(AES128::new_from_slice(&[3; 16]).unwrap()).unwrap();
            let mut wrapped = [0u8; 40];
            bench.run("crypto-mode-kw-aes128-wrap-32-bytes", Some(Throughput::Bytes(32)), || {
                kw.wrap(black_box(&[4; 32]), &mut wrapped).unwrap();
                black_box(&wrapped);
            });
            let mut unwrapped = [0u8; 32];
            bench.run("crypto-mode-kw-aes128-unwrap-32-bytes", Some(Throughput::Bytes(32)), || {
                kw.unwrap(black_box(&wrapped), &mut unwrapped).unwrap();
                black_box(&unwrapped);
            });
        }
        #[cfg(all(umilib_feature = "crypto-pbkdf2", umilib_feature = "hash-sha-v2"))]
        bench.run("crypto-pbkdf2-sha256-1000-iterations", Some(Throughput::Elements(1)), || {
            let mut out = [0u8; 32];
            umilib::crypto::pbkdf2::PBKDF2::<umilib::hash::sha::v2::SHA256>::derive(
                b"password",
                b"salt",
                1000,
                &mut out,
            )
            .unwrap();
            black_box(out);
        });
        #[cfg(umilib_feature = "crypto-scrypt")]
        {
            let scrypt = umilib::crypto::scrypt::Scrypt::new(1024, 8, 1).unwrap();
            bench.run("crypto-scrypt-n1024-r8-p1", Some(Throughput::Elements(1)), || {
                let mut out = [0u8; 32];
                scrypt.derive(b"password", b"salt", &mut out).unwrap();
                black_box(out);
            });
        }
        #[cfg(umilib_feature = "crypto-argon2")]
        {
            use umilib::crypto::argon2::{Argon2, Argon2Type};
            let argon2 = Argon2::new(Argon2Type::Argon2id, 1024, 1, 1).unwrap();
            bench.run("crypto-argon2id-1-mib-1-pass", Some(Throughput::Elements(1)), || {
                let mut out = [0u8; 32];
                argon2.derive(b"password", b"saltsalt", &[], &[], &mut out).unwrap();
                black_box(out);
            });
        }
        #[cfg(all(umilib_feature = "crypto-random", umilib_feature = "hash-sha-v2"))]
        {
            use umilib::crypto::random::{DRBG, HMACDRBG, HashDRBG};
            use umilib::hash::sha::v2::SHA256;
            let mut out = [0u8; 1024];
            let mut hmac = HMACDRBG::<SHA256>::new(&[3; 32], &[4; 16], &[]).unwrap();
            bench.run("crypto-random-hmac-drbg-sha256-1-kib", Some(Throughput::Bytes(1024)), || {
                hmac.generate(black_box(&mut out), &[]).unwrap();
                black_box(&out);
            });
            let mut hash = HashDRBG::<SHA256>::new(&[3; 32], &[4; 16], &[]).unwrap();
            bench.run("crypto-random-hash-drbg-sha256-1-kib", Some(Throughput::Bytes(1024)), || {
                hash.generate(black_box(&mut out), &[]).unwrap();
                black_box(&out);
            });
        }
        #[cfg(all(umilib_feature = "crypto-random", umilib_feature = "crypto-aes"))]
        {
            use umilib::crypto::random::{CTRDRBG, DRBG};
            let mut out = [0u8; 1024];
            let mut ctr = CTRDRBG::<umilib::crypto::aes::AES256>::new(&[3; 32], &[4; 16], &[]).unwrap();
            bench.run("crypto-random-ctr-drbg-aes256-1-kib", Some(Throughput::Bytes(1024)), || {
                ctr.generate(black_box(&mut out), &[]).unwrap();
                black_box(&out);
            });
        }
        Benchmarks::run_public_key(bench);
    }

    /// The operations of the public-key schemes, each on one message or key.
    pub fn run_public_key(bench: &mut Bench) {
        let once = Some(Throughput::Elements(1));
        // Silences the unused warnings when no scheme is enabled.
        let _ = (&bench, once);
        #[cfg(all(
            umilib_feature = "crypto-ecdh",
            umilib_feature = "crypto-curve-p256",
            umilib_feature = "hash-sha-v2"
        ))]
        {
            use umilib::crypto::KeyAgreement;
            use umilib::crypto::curve::p256::P256;
            use umilib::crypto::ecdh::ECDH;
            use umilib::crypto::random::HMACDRBG;
            let mut random = HMACDRBG::<umilib::hash::sha::v2::SHA256>::new(&[5; 32], &[6; 16], b"ecdh").unwrap();
            let private = ECDH::<P256>::generate(&mut random).unwrap();
            let public = ECDH::<P256>::public_key(&ECDH::<P256>::generate(&mut random).unwrap());
            let mut shared = [0u8; 32];
            bench.run("crypto-ecdh-p256-agree", once, || {
                ECDH::<P256>::agree(black_box(&private), black_box(&public), &mut shared).unwrap();
                black_box(&shared);
            });
            bench.run("crypto-ecdh-p256-public-key", once, || {
                black_box(ECDH::<P256>::public_key(black_box(&private)));
            });
        }
        #[cfg(all(
            umilib_feature = "crypto-ecdh",
            umilib_feature = "crypto-curve-curve25519",
            umilib_feature = "hash-sha-v2"
        ))]
        {
            use umilib::crypto::KeyAgreement;
            use umilib::crypto::ecdh::X25519;
            use umilib::crypto::random::HMACDRBG;
            let mut random = HMACDRBG::<umilib::hash::sha::v2::SHA256>::new(&[5; 32], &[6; 16], b"x25519").unwrap();
            let private = X25519::generate(&mut random).unwrap();
            let public = X25519::public_key(&X25519::generate(&mut random).unwrap());
            let mut shared = [0u8; 32];
            bench.run("crypto-ecdh-x25519-agree", once, || {
                X25519::agree(black_box(&private), black_box(&public), &mut shared).unwrap();
                black_box(&shared);
            });
        }
        #[cfg(all(umilib_feature = "crypto-dh", umilib_feature = "hash-sha-v2"))]
        {
            use umilib::crypto::KeyAgreement;
            use umilib::crypto::dh::{DH, FFDHE2048};
            use umilib::crypto::random::HMACDRBG;
            let mut random = HMACDRBG::<umilib::hash::sha::v2::SHA256>::new(&[5; 32], &[6; 16], b"dh").unwrap();
            let private = DH::<FFDHE2048>::generate(&mut random).unwrap();
            let public = DH::<FFDHE2048>::public_key(&DH::<FFDHE2048>::generate(&mut random).unwrap());
            let mut shared = [0u8; 256];
            bench.run("crypto-dh-ffdhe2048-agree", once, || {
                DH::<FFDHE2048>::agree(black_box(&private), black_box(&public), &mut shared).unwrap();
                black_box(&shared);
            });
        }
        // Measures `sign` and `verify` of a 32-byte message with the signature scheme `$scheme`.
        #[allow(unused_macros)]
        macro_rules! signature_scheme {
            ($name:literal, $scheme:ty) => {{
                use umilib::crypto::SignatureScheme;
                use umilib::crypto::random::HMACDRBG;
                let mut random =
                    HMACDRBG::<umilib::hash::sha::v2::SHA256>::new(&[5; 32], &[6; 16], $name.as_bytes()).unwrap();
                let key = <$scheme>::generate(&mut random).unwrap();
                let verifying = <$scheme>::verifying_key(&key);
                let mut signature = vec![0u8; <$scheme as SignatureScheme>::SIGNATURE_SIZE];
                bench.run(concat!($name, "-sign"), once, || {
                    <$scheme as SignatureScheme>::sign(black_box(&key), black_box(&[7u8; 32]), &mut signature).unwrap();
                });
                bench.run(concat!($name, "-verify"), once, || {
                    <$scheme>::verify(black_box(&verifying), black_box(&[7u8; 32]), black_box(&signature)).unwrap();
                });
            }};
        }
        #[cfg(all(
            umilib_feature = "crypto-ecdsa",
            umilib_feature = "crypto-curve-p256",
            umilib_feature = "hash-sha-v2"
        ))]
        signature_scheme!(
            "crypto-ecdsa-p256-sha256",
            umilib::crypto::ecdsa::ECDSA<umilib::crypto::curve::p256::P256, umilib::hash::sha::v2::SHA256>
        );
        #[cfg(all(
            umilib_feature = "crypto-eddsa",
            umilib_feature = "crypto-curve-curve25519",
            umilib_feature = "hash-sha-v2"
        ))]
        signature_scheme!("crypto-eddsa-ed25519", umilib::crypto::eddsa::Ed25519);
        #[cfg(all(
            umilib_feature = "crypto-eddsa",
            umilib_feature = "crypto-curve-curve448",
            umilib_feature = "hash-sha-v2"
        ))]
        signature_scheme!("crypto-eddsa-ed448", umilib::crypto::eddsa::Ed448);
        #[cfg(all(umilib_feature = "crypto-rsa", umilib_feature = "hash-sha-v2"))]
        {
            use umilib::crypto::random::HMACDRBG;
            use umilib::crypto::rsa::{RSAPKCS1v15, RSAPrivateKey};
            use umilib::hash::sha::v2::SHA256;
            use umilib::math::bigint::BoxedUint;
            let mut random = HMACDRBG::<SHA256>::new(&[5; 32], &[6; 16], b"rsa").unwrap();
            let e = BoxedUint::from_u64(65537, 64).unwrap();
            let key = RSAPrivateKey::generate(2048, &e, &mut random).unwrap();
            let public = key.public_key().clone();
            let signature = RSAPKCS1v15::<SHA256>::sign(&key, &[7u8; 32], &mut random).unwrap();
            bench.run("crypto-rsa-2048-pkcs1v15-sign", once, || {
                black_box(RSAPKCS1v15::<SHA256>::sign(black_box(&key), black_box(&[7u8; 32]), &mut random).unwrap());
            });
            bench.run("crypto-rsa-2048-pkcs1v15-verify", once, || {
                RSAPKCS1v15::<SHA256>::verify(black_box(&public), black_box(&[7u8; 32]), black_box(&signature))
                    .unwrap();
            });
        }
        #[cfg(all(umilib_feature = "crypto-ibs-sm9", umilib_feature = "hash-sm3", umilib_feature = "hash-sha-v2"))]
        {
            use umilib::crypto::ibs::IdentityBasedSignature;
            use umilib::crypto::ibs::sm9::SM9;
            use umilib::crypto::random::HMACDRBG;
            use umilib::hash::sm3::SM3;
            use umilib::math::pairing::SM9BN256;
            type Scheme = SM9<SM9BN256, SM3>;
            let mut random = HMACDRBG::<umilib::hash::sha::v2::SHA256>::new(&[5; 32], &[6; 16], b"sm9").unwrap();
            let master = Scheme::setup(&mut random).unwrap();
            let key = Scheme::extract(&master, b"Alice").unwrap();
            let signature = Scheme::sign(&key, &[7u8; 32], &mut random).unwrap();
            bench.run("crypto-ibs-sm9-sign", once, || {
                black_box(Scheme::sign(black_box(&key), black_box(&[7u8; 32]), &mut random).unwrap());
            });
            bench.run("crypto-ibs-sm9-verify", once, || {
                Scheme::verify(master.public_key(), b"Alice", black_box(&[7u8; 32]), black_box(&signature)).unwrap();
            });
        }
        #[cfg(all(umilib_feature = "crypto-sm9", umilib_feature = "hash-sm3", umilib_feature = "hash-sha-v2"))]
        {
            use umilib::crypto::random::HMACDRBG;
            use umilib::crypto::sm9::{SM9EncryptMasterKey, SM9KEM, SM9KEP, SM9PKE, SM9Role};
            use umilib::hash::sm3::SM3;
            use umilib::math::pairing::SM9BN256;
            let mut random =
                HMACDRBG::<umilib::hash::sha::v2::SHA256>::new(&[5; 32], &[6; 16], b"sm9 encryption").unwrap();
            let master = SM9EncryptMasterKey::<SM9BN256>::generate(&mut random).unwrap();
            let alice = || master.extract::<SM3>(b"Alice", 0x03).unwrap();
            let bob = master.extract::<SM3>(b"Bob", 0x03).unwrap();
            let initiator =
                SM9KEP::<SM9BN256, SM3>::generate(SM9Role::Initiator, alice(), b"Bob", &mut random).unwrap();
            let responder = SM9KEP::<SM9BN256, SM3>::generate(
                SM9Role::Responder,
                master.extract::<SM3>(b"Bob", 0x03).unwrap(),
                b"Alice",
                &mut random,
            )
            .unwrap();
            let mut key = [0u8; 16];
            bench.run("crypto-sm9-kep-agree", once, || {
                black_box(initiator.agree(black_box(responder.ephemeral_public_key()), &mut key).unwrap());
            });
            let mut key = [0u8; 32];
            let encapsulated =
                SM9KEM::<SM9BN256, SM3>::encapsulate(master.public_key(), b"Bob", 0x03, &mut key, &mut random).unwrap();
            bench.run("crypto-sm9-kem-encapsulate", once, || {
                black_box(
                    SM9KEM::<SM9BN256, SM3>::encapsulate(master.public_key(), b"Bob", 0x03, &mut key, &mut random)
                        .unwrap(),
                );
            });
            bench.run("crypto-sm9-kem-decapsulate", once, || {
                SM9KEM::<SM9BN256, SM3>::decapsulate(black_box(&bob), black_box(&encapsulated), &mut key).unwrap();
            });
            let ciphertext =
                SM9PKE::<SM9BN256, SM3>::encrypt(master.public_key(), b"Bob", 0x03, &[7u8; 32], &mut random).unwrap();
            bench.run("crypto-sm9-pke-encrypt", once, || {
                black_box(
                    SM9PKE::<SM9BN256, SM3>::encrypt(
                        master.public_key(),
                        b"Bob",
                        0x03,
                        black_box(&[7u8; 32]),
                        &mut random,
                    )
                    .unwrap(),
                );
            });
            bench.run("crypto-sm9-pke-decrypt", once, || {
                black_box(SM9PKE::<SM9BN256, SM3>::decrypt(black_box(&bob), black_box(&ciphertext)).unwrap());
            });
        }
        #[cfg(all(umilib_feature = "crypto-mlkem", umilib_feature = "crypto-hybrid", umilib_feature = "hash-sha-v2"))]
        {
            use umilib::crypto::KeyEncapsulation;
            use umilib::crypto::hybrid::{HybridKEM, X25519MLKEM768};
            use umilib::crypto::mlkem::{MLKEM, MLKEM512, MLKEM768, MLKEM1024};
            use umilib::crypto::random::HMACDRBG;
            let mut random = HMACDRBG::<umilib::hash::sha::v2::SHA256>::new(&[5; 32], &[6; 16], b"kem").unwrap();
            macro_rules! kem {
                ($name:literal, $scheme:ty) => {{
                    let key = <$scheme>::generate(&mut random).unwrap();
                    let public = <$scheme>::encapsulation_key(&key);
                    let mut ciphertext = vec![0u8; <$scheme>::CIPHERTEXT_SIZE];
                    let mut shared = vec![0u8; <$scheme>::SHARED_SECRET_SIZE];
                    <$scheme>::encapsulate(&public, &mut random, &mut ciphertext, &mut shared).unwrap();
                    bench.run(concat!($name, "-generate"), once, || {
                        black_box(<$scheme>::generate(&mut random).unwrap());
                    });
                    bench.run(concat!($name, "-encapsulate"), once, || {
                        <$scheme>::encapsulate(black_box(&public), &mut random, &mut ciphertext, &mut shared).unwrap();
                    });
                    bench.run(concat!($name, "-decapsulate"), once, || {
                        <$scheme>::decapsulate(black_box(&key), black_box(&ciphertext), &mut shared).unwrap();
                    });
                }};
            }
            kem!("crypto-mlkem-512", MLKEM<MLKEM512>);
            kem!("crypto-mlkem-768", MLKEM<MLKEM768>);
            kem!("crypto-mlkem-1024", MLKEM<MLKEM1024>);
            kem!("crypto-hybrid-x25519mlkem768", HybridKEM<X25519MLKEM768>);
        }
        #[cfg(all(umilib_feature = "crypto-mldsa", umilib_feature = "crypto-slhdsa"))]
        {
            use umilib::crypto::SignatureScheme;
            use umilib::crypto::mldsa::{MLDSA, MLDSA44, MLDSA65, MLDSA87};
            use umilib::crypto::random::HMACDRBG;
            use umilib::crypto::slhdsa::{SLHDSA, SLHDSA_SHA2_128f, SLHDSA_SHA2_128s, SLHDSA_SHAKE_128f};
            let mut random = HMACDRBG::<umilib::hash::sha::v2::SHA256>::new(&[5; 32], &[6; 16], b"signatures").unwrap();
            macro_rules! signature {
                ($name:literal, $scheme:ty, $generate:literal) => {{
                    let key = <$scheme>::generate(&mut random).unwrap();
                    let public = <$scheme>::verifying_key(&key);
                    let mut signature = vec![0u8; <$scheme>::SIGNATURE_SIZE];
                    <$scheme as SignatureScheme>::sign(&key, &[7u8; 32], &mut signature).unwrap();
                    if $generate {
                        bench.run(concat!($name, "-generate"), once, || {
                            black_box(<$scheme>::generate(&mut random).unwrap());
                        });
                        bench.run(concat!($name, "-sign"), once, || {
                            <$scheme as SignatureScheme>::sign(black_box(&key), black_box(&[7u8; 32]), &mut signature)
                                .unwrap();
                        });
                    }
                    bench.run(concat!($name, "-verify"), once, || {
                        <$scheme as SignatureScheme>::verify(
                            black_box(&public),
                            black_box(&[7u8; 32]),
                            black_box(&signature),
                        )
                        .unwrap();
                    });
                }};
            }
            signature!("crypto-mldsa-44", MLDSA<MLDSA44>, true);
            signature!("crypto-mldsa-65", MLDSA<MLDSA65>, true);
            signature!("crypto-mldsa-87", MLDSA<MLDSA87>, true);
            signature!("crypto-slhdsa-sha2-128f", SLHDSA<SLHDSA_SHA2_128f>, true);
            signature!("crypto-slhdsa-shake-128f", SLHDSA<SLHDSA_SHAKE_128f>, true);
            // Signing with a small parameter set takes long; its verification is fast.
            signature!("crypto-slhdsa-sha2-128s", SLHDSA<SLHDSA_SHA2_128s>, false);
        }
        #[cfg(all(
            umilib_feature = "crypto-hpke",
            umilib_feature = "crypto-curve-curve25519",
            umilib_feature = "hash-sha-v2",
            umilib_feature = "crypto-chacha20poly1305"
        ))]
        {
            use umilib::crypto::chacha20poly1305::ChaCha20Poly1305;
            use umilib::crypto::ecdh::X25519;
            use umilib::crypto::hpke::{DHKEM, HPKE, HPKEKEM};
            use umilib::crypto::random::HMACDRBG;
            use umilib::hash::sha::v2::SHA256;
            type Suite = HPKE<DHKEM<X25519, SHA256>, SHA256, ChaCha20Poly1305>;
            let mut random = HMACDRBG::<SHA256>::new(&[5; 32], &[6; 16], b"hpke").unwrap();
            let (_, recipient) = DHKEM::<X25519, SHA256>::generate_key_pair(&mut random).unwrap();
            bench.run("crypto-hpke-x25519-chacha20poly1305-seal-64-b", once, || {
                black_box(
                    Suite::seal(black_box(&recipient), b"info", b"", &[7u8; 64], None, None, &mut random).unwrap(),
                );
            });
        }
    }
}
