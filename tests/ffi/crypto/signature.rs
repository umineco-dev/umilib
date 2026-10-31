//! The signature schemes of the C ABI: ECDSA, EdDSA, DSA and RSA against the
//! Project Wycheproof vectors, ECCSI against RFC 6507 appendix A, and GOST
//! R 34.10, SM2 and the identity-based signatures against `umilib::crypto`.

use std::ptr;

use umilib::crypto::SignatureScheme;
use umilib::crypto::curve::gost::GOST256A;
use umilib::crypto::curve::sm2::SM2;
use umilib::crypto::gostr3410::GOSTR3410;
use umilib::crypto::ibs::chacheon::ChaCheon;
use umilib::crypto::ibs::hess::Hess;
use umilib::crypto::ibs::sm9::SM9;
use umilib::crypto::ibs::{IBSSignature, IdentityBasedSignature};
use umilib::crypto::sm2::SM2DSA;
use umilib::ffi::crypto::dsa::der::*;
use umilib::ffi::crypto::dsa::*;
use umilib::ffi::crypto::eccsi::*;
use umilib::ffi::crypto::ecdsa::ecdsa;
use umilib::ffi::crypto::ecdsa::ecdsa::der::*;
use umilib::ffi::crypto::eddsa::eddsa;
use umilib::ffi::crypto::gostr3410::gostr3410;
use umilib::ffi::crypto::ibs::chacheon::chacheon;
use umilib::ffi::crypto::ibs::hess::hess;
use umilib::ffi::crypto::ibs::sm9::sm9;
use umilib::ffi::crypto::ibs::*;
use umilib::ffi::crypto::rsa::*;
use umilib::ffi::crypto::sm2::sm2dsa;
use umilib::ffi::{Buffer, Status};
use umilib::hash::sha::v2::SHA256;
use umilib::hash::sm3::SM3;
use umilib::hash::streebog::Streebog256;
use umilib::math::pairing::{BLS12381, BN254, G2Affine, PairingCurve, SM9BN256};

use super::{Bytes, Generator};
use crate::Check;
use crate::vectors::{JSON, Vectors, Wycheproof};

/// The C type name of the hash function of a Wycheproof file.
fn hash_name(sha: &str) -> &'static [u8] {
    match sha {
        "SHA-1" => b"umilib_hash_sha_v1_SHA1",
        "SHA-224" => b"umilib_hash_sha_v2_SHA224",
        "SHA-256" => b"umilib_hash_sha_v2_SHA256",
        "SHA-384" => b"umilib_hash_sha_v2_SHA384",
        "SHA-512" => b"umilib_hash_sha_v2_SHA512",
        "SHA-512/224" => b"umilib_hash_sha_v2_SHA512_224",
        "SHA-512/256" => b"umilib_hash_sha_v2_SHA512_256",
        "SHA3-224" => b"umilib_hash_sha_v3_SHA3_224",
        "SHA3-256" => b"umilib_hash_sha_v3_SHA3_256",
        "SHA3-384" => b"umilib_hash_sha_v3_SHA3_384",
        "SHA3-512" => b"umilib_hash_sha_v3_SHA3_512",
        other => panic!("hash function {other}"),
    }
}

/// The expectation of a Wycheproof test on the outcome of a verification.
fn check_result(test: &JSON, verified: bool, label: &str) {
    match test.field("result").as_str() {
        "valid" => assert!(verified, "{label}: refused"),
        "invalid" => assert!(!verified, "{label}: accepted"),
        _ => {}
    }
}

type Sizes = unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut usize) -> *const Status;
type Generate = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *mut core::ffi::c_void,
    *const u8,
    usize,
    *mut u8,
    usize,
) -> *const Status;
type VerifyingKey =
    unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize, *mut u8, usize) -> *const Status;
type Sign = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
) -> *const Status;
type Verify = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
) -> *const Status;

/// The functions of a signature scheme of the C ABI chosen by a curve and a hash function.
struct Scheme {
    sizes: Sizes,
    generate: Generate,
    verifying_key: VerifyingKey,
    sign: Sign,
    verify: Verify,
}

impl Scheme {
    const ECDSA: Scheme = Scheme {
        sizes: ecdsa::sizes,
        generate: ecdsa::generate,
        verifying_key: ecdsa::verifying_key,
        sign: ecdsa::sign,
        verify: ecdsa::verify,
    };
    const GOSTR3410: Scheme = Scheme {
        sizes: gostr3410::sizes,
        generate: gostr3410::generate,
        verifying_key: gostr3410::verifying_key,
        sign: gostr3410::sign,
        verify: gostr3410::verify,
    };
    const SM2DSA: Scheme = Scheme {
        sizes: sm2dsa::sizes,
        generate: sm2dsa::generate,
        verifying_key: sm2dsa::verifying_key,
        sign: sm2dsa::sign,
        verify: sm2dsa::verify,
    };

    fn sizes(&self, curve: &[u8], hash: &[u8]) -> [usize; 3] {
        let mut sizes = [0; 3];
        Check::ok(unsafe { (self.sizes)(curve.as_ptr(), curve.len(), hash.as_ptr(), hash.len(), sizes.as_mut_ptr()) });
        sizes
    }

    fn verify(&self, curve: &[u8], hash: &[u8], key: &[u8], message: &[u8], signature: &[u8]) -> *const Status {
        unsafe {
            (self.verify)(
                curve.as_ptr(),
                curve.len(),
                hash.as_ptr(),
                hash.len(),
                key.as_ptr(),
                key.len(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
            )
        }
    }

    /// Keys and signatures of the C ABI are those of `S` of `umilib::crypto`, and a signature of another
    /// message is refused.
    fn check_against<S: SignatureScheme>(&self, curve: &[u8], hash: &[u8]) {
        let [signing_size, verifying_size, signature_size] = self.sizes(curve, hash);
        assert_eq!(
            [signing_size, verifying_size, signature_size],
            [S::SIGNING_KEY_SIZE, S::VERIFYING_KEY_SIZE, S::SIGNATURE_SIZE]
        );
        let generator = Generator::new(b"signature");
        let (mut key, mut public, mut signature) =
            (vec![0; signing_size], vec![0; verifying_size], vec![0; signature_size]);
        unsafe {
            Check::ok((self.generate)(
                curve.as_ptr(),
                curve.len(),
                hash.as_ptr(),
                hash.len(),
                generator.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                key.as_mut_ptr(),
                key.len(),
            ));
            Check::ok((self.verifying_key)(
                curve.as_ptr(),
                curve.len(),
                hash.as_ptr(),
                hash.len(),
                key.as_ptr(),
                key.len(),
                public.as_mut_ptr(),
                public.len(),
            ));
            Check::ok((self.sign)(
                curve.as_ptr(),
                curve.len(),
                hash.as_ptr(),
                hash.len(),
                key.as_ptr(),
                key.len(),
                b"message".as_ptr(),
                7,
                signature.as_mut_ptr(),
                signature.len(),
            ));
        }
        let rust = S::signing_key_from_bytes(&key).unwrap();
        let mut expected = vec![0; verifying_size];
        S::write_verifying_key(&S::verifying_key(&rust), &mut expected).unwrap();
        assert_eq!(public, expected);
        let mut expected = vec![0; signature_size];
        S::sign(&rust, b"message", &mut expected).unwrap();
        assert_eq!(signature, expected);
        Check::ok(self.verify(curve, hash, &public, b"message", &signature));
        Check::fails(self.verify(curve, hash, &public, b"massage", &signature), "crypto", "InvalidSignature");
        Check::fails(
            self.verify(b"umilib_crypto_curve_unknown_Unknown", hash, &public, b"message", &signature),
            "ffi",
            "InvalidArgument",
        );
    }
}

/// The C type name of the curve of a Wycheproof file of ECDSA.
fn ecdsa_curve(name: &str) -> &'static [u8] {
    match name {
        "secp256r1" => b"umilib_crypto_curve_p256_P256",
        "secp384r1" => b"umilib_crypto_curve_p384_P384",
        "secp521r1" => b"umilib_crypto_curve_p521_P521",
        "secp256k1" => b"umilib_crypto_curve_secp256k1_Secp256k1",
        "brainpoolP256r1" => b"umilib_crypto_curve_brainpool_p256r1_BrainpoolP256r1",
        "brainpoolP384r1" => b"umilib_crypto_curve_brainpool_p384r1_BrainpoolP384r1",
        "brainpoolP512r1" => b"umilib_crypto_curve_brainpool_p512r1_BrainpoolP512r1",
        other => panic!("curve {other}"),
    }
}

/// Every Wycheproof file of ECDSA: signatures r || s directly, DER through
/// `umilib_crypto_ecdsa_ecdsa_signature_from_der`, whose result converts back.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn ecdsa_wycheproof() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/crypto/ecdsa");
    let mut files: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".json"))
        .collect();
    files.sort();
    assert_eq!(files.len(), 31);
    for file in &files {
        let p1363 = file.contains("_p1363_");
        for (group, test) in Wycheproof::tests(&format!("crypto/ecdsa/{file}")) {
            let label = format!("{file} {}", test.field("tcId").as_usize());
            let curve = ecdsa_curve(group.field("publicKey").field("curve").as_str());
            let hash = hash_name(group.field("sha").as_str());
            let key = group.field("publicKey").bytes("uncompressed");
            let size = Scheme::ECDSA.sizes(curve, hash)[2];
            let signature = if p1363 {
                Some(test.bytes("sig"))
            } else {
                let der = test.bytes("sig");
                let mut buffer = Buffer::default();
                let status = unsafe {
                    umilib_crypto_ecdsa_ecdsa_signature_from_der(
                        curve.as_ptr(),
                        curve.len(),
                        der.as_ptr(),
                        der.len(),
                        &mut buffer,
                    )
                };
                status.is_null().then(|| {
                    let raw = Bytes::take(buffer);
                    assert_eq!(raw.len(), size, "{label}");
                    let mut buffer = Buffer::default();
                    Check::ok(unsafe {
                        umilib_crypto_ecdsa_ecdsa_signature_to_der(
                            curve.as_ptr(),
                            curve.len(),
                            raw.as_ptr(),
                            raw.len(),
                            &mut buffer,
                        )
                    });
                    assert_eq!(Bytes::take(buffer), der, "{label}: DER round trip");
                    raw
                })
            };
            let verified = signature.is_some_and(|signature| {
                Scheme::ECDSA.verify(curve, hash, &key, &test.bytes("msg"), &signature).is_null()
            });
            check_result(&test, verified, &label);
        }
    }
    Scheme::ECDSA.check_against::<umilib::crypto::ecdsa::ECDSA<umilib::crypto::curve::p256::P256, SHA256>>(
        b"umilib_crypto_curve_p256_P256",
        b"umilib_hash_sha_v2_SHA256",
    );
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn eddsa_wycheproof() {
    for (curve, file) in [
        (&b"umilib_crypto_curve_curve25519_Edwards25519"[..], "ed25519_test.json"),
        (b"umilib_crypto_curve_curve448_Edwards448", "ed448_test.json"),
    ] {
        for (group, test) in Wycheproof::tests(&format!("crypto/eddsa/{file}")) {
            let label = format!("{file} {}", test.field("tcId").as_usize());
            let key = group.field("publicKey").bytes("pk");
            let (message, signature) = (test.bytes("msg"), test.bytes("sig"));
            let status = unsafe {
                eddsa::verify(
                    curve.as_ptr(),
                    curve.len(),
                    key.as_ptr(),
                    key.len(),
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                )
            };
            check_result(&test, status.is_null(), &label);
        }
    }
}

/// The DSA handles of the domain parameters and the key of a Wycheproof group, released when dropped.
struct DSAKey {
    parameters: *mut umilib::crypto::dsa::DSAParameters,
    key: *mut umilib::crypto::dsa::DSAVerifyingKey,
}

impl DSAKey {
    fn new(group: &JSON) -> DSAKey {
        let public = group.field("publicKey");
        let (p, q, g, y) = (public.bytes("p"), public.bytes("q"), public.bytes("g"), public.bytes("y"));
        let (mut parameters, mut key) = (ptr::null_mut(), ptr::null_mut());
        unsafe {
            Check::ok(umilib_crypto_dsa_dsa_parameters_new(
                p.as_ptr(),
                p.len(),
                q.as_ptr(),
                q.len(),
                g.as_ptr(),
                g.len(),
                &mut parameters,
            ));
            Check::ok(umilib_crypto_dsa_dsa_verifying_key_new(parameters, y.as_ptr(), y.len(), &mut key));
        }
        DSAKey { parameters, key }
    }
}

impl Drop for DSAKey {
    fn drop(&mut self) {
        unsafe {
            umilib_crypto_dsa_dsa_verifying_key_free(self.key);
            umilib_crypto_dsa_dsa_parameters_free(self.parameters);
        }
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn dsa_wycheproof() {
    for file in [
        "dsa_2048_224_sha224_p1363_test.json",
        "dsa_2048_224_sha224_test.json",
        "dsa_2048_224_sha256_p1363_test.json",
        "dsa_2048_224_sha256_test.json",
        "dsa_2048_256_sha256_p1363_test.json",
        "dsa_2048_256_sha256_test.json",
        "dsa_3072_256_sha256_p1363_test.json",
        "dsa_3072_256_sha256_test.json",
    ] {
        let p1363 = file.contains("_p1363_");
        for (group, test) in Wycheproof::tests(&format!("crypto/dsa/{file}")) {
            let label = format!("{file} {}", test.field("tcId").as_usize());
            let key = DSAKey::new(&group);
            let hash = hash_name(group.field("sha").as_str());
            if test.field("tcId").as_usize() == 1 {
                // The getters give the values of the group, without leading zeros (g and y of the bytes of p).
                let public = group.field("publicKey");
                let significant = |bytes: Vec<u8>| bytes.into_iter().skip_while(|byte| *byte == 0).collect::<Vec<u8>>();
                let take = |function: unsafe extern "C" fn(
                    *const umilib::crypto::dsa::DSAParameters,
                    *mut Buffer,
                ) -> *const umilib::ffi::Status| {
                    let mut buffer = Buffer::default();
                    Check::ok(unsafe { function(key.parameters, &mut buffer) });
                    Bytes::take(buffer)
                };
                assert_eq!(take(umilib_crypto_dsa_dsa_parameters_p), significant(public.bytes("p")), "{label}");
                assert_eq!(take(umilib_crypto_dsa_dsa_parameters_q), significant(public.bytes("q")), "{label}");
                let g = take(umilib_crypto_dsa_dsa_parameters_g);
                assert_eq!(g.len(), take(umilib_crypto_dsa_dsa_parameters_p).len());
                assert_eq!(significant(g), significant(public.bytes("g")), "{label}");
                let mut copy = ptr::null_mut();
                Check::ok(unsafe { umilib_crypto_dsa_dsa_verifying_key_parameters(key.key, &mut copy) });
                let mut q = Buffer::default();
                Check::ok(unsafe { umilib_crypto_dsa_dsa_parameters_q(copy, &mut q) });
                assert_eq!(Bytes::take(q), significant(public.bytes("q")));
                unsafe { umilib_crypto_dsa_dsa_parameters_free(copy) };
            }
            let mut q_bytes = 0;
            Check::ok(unsafe { umilib_crypto_dsa_dsa_parameters_q_bytes(key.parameters, &mut q_bytes) });
            let signature = if p1363 {
                Some(test.bytes("sig"))
            } else {
                let der = test.bytes("sig");
                let mut buffer = Buffer::default();
                let status = unsafe {
                    umilib_crypto_dsa_dsa_signature_from_der(key.parameters, der.as_ptr(), der.len(), &mut buffer)
                };
                status.is_null().then(|| {
                    let raw = Bytes::take(buffer);
                    assert_eq!(raw.len(), 2 * q_bytes, "{label}");
                    raw
                })
            };
            let message = test.bytes("msg");
            let verified = signature.is_some_and(|signature| {
                unsafe {
                    umilib_crypto_dsa_dsa_verify(
                        key.key,
                        hash.as_ptr(),
                        hash.len(),
                        message.as_ptr(),
                        message.len(),
                        signature.as_ptr(),
                        signature.len(),
                    )
                }
                .is_null()
            });
            check_result(&test, verified, &label);
        }
    }
}

/// The public key of a Wycheproof group of RSA, released when dropped.
struct RSAPublic(*mut umilib::crypto::rsa::RSAPublicKey);

impl RSAPublic {
    fn new(key: &JSON) -> RSAPublic {
        let (n, e) = (key.bytes("modulus"), key.bytes("publicExponent"));
        let mut handle = ptr::null_mut();
        Check::ok(unsafe {
            umilib_crypto_rsa_rsa_public_key_new(n.as_ptr(), n.len(), e.as_ptr(), e.len(), &mut handle)
        });
        RSAPublic(handle)
    }
}

impl Drop for RSAPublic {
    fn drop(&mut self) {
        unsafe { umilib_crypto_rsa_rsa_public_key_free(self.0) };
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn rsa_wycheproof() {
    for file in [
        "rsa_signature_2048_sha256_test.json",
        "rsa_signature_2048_sha512_256_test.json",
        "rsa_signature_2048_sha3_256_test.json",
        "rsa_signature_3072_sha384_test.json",
        "rsa_signature_4096_sha512_test.json",
    ] {
        for (group, test) in Wycheproof::tests(&format!("crypto/rsa/{file}")) {
            let label = format!("{file} {}", test.field("tcId").as_usize());
            let key = RSAPublic::new(group.field("publicKey"));
            let hash = hash_name(group.field("sha").as_str());
            let (message, signature) = (test.bytes("msg"), test.bytes("sig"));
            let status = unsafe {
                umilib_crypto_rsa_rsa_pkcs1v15_verify(
                    key.0,
                    hash.as_ptr(),
                    hash.len(),
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                )
            };
            check_result(&test, status.is_null(), &label);
        }
    }
    for file in [
        "rsa_pss_2048_sha1_mgf1_20_test.json",
        "rsa_pss_2048_sha256_mgf1_0_test.json",
        "rsa_pss_2048_sha256_mgf1_32_test.json",
        "rsa_pss_2048_sha256_mgf1sha1_20_test.json",
    ] {
        for (group, test) in Wycheproof::tests(&format!("crypto/rsa/{file}")) {
            let label = format!("{file} {}", test.field("tcId").as_usize());
            let key = RSAPublic::new(group.field("publicKey"));
            let (hash, mgf) = (hash_name(group.field("sha").as_str()), hash_name(group.field("mgfSha").as_str()));
            let (message, signature) = (test.bytes("msg"), test.bytes("sig"));
            let status = unsafe {
                umilib_crypto_rsa_rsa_pss_verify(
                    key.0,
                    hash.as_ptr(),
                    hash.len(),
                    mgf.as_ptr(),
                    mgf.len(),
                    group.field("sLen").as_usize(),
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                )
            };
            check_result(&test, status.is_null(), &label);
        }
    }
    let generator = Generator::new(b"rsa");
    for file in ["rsa_oaep_2048_sha256_mgf1sha256_test.json", "rsa_oaep_2048_sha1_mgf1sha1_test.json"] {
        for (group, test) in Wycheproof::tests(&format!("crypto/rsa/{file}")) {
            let label = format!("{file} {}", test.field("tcId").as_usize());
            let private = group.field("privateKey");
            let (p, q, e) = (private.bytes("prime1"), private.bytes("prime2"), private.bytes("publicExponent"));
            let mut key = ptr::null_mut();
            Check::ok(unsafe {
                umilib_crypto_rsa_rsa_private_key_from_primes(
                    p.as_ptr(),
                    p.len(),
                    q.as_ptr(),
                    q.len(),
                    e.as_ptr(),
                    e.len(),
                    &mut key,
                )
            });
            let mut d = Buffer::default();
            Check::ok(unsafe { umilib_crypto_rsa_rsa_private_key_d(key, &mut d) });
            let exponent: Vec<u8> =
                private.bytes("privateExponent").into_iter().skip_while(|byte| *byte == 0).collect();
            assert_eq!(Bytes::take(d), exponent, "{label}");
            let (hash, mgf) = (hash_name(group.field("sha").as_str()), hash_name(group.field("mgfSha").as_str()));
            let (label_bytes, ciphertext) = (test.bytes("label"), test.bytes("ct"));
            let mut buffer = Buffer::default();
            let status = unsafe {
                umilib_crypto_rsa_rsa_oaep_decrypt(
                    key,
                    hash.as_ptr(),
                    hash.len(),
                    mgf.as_ptr(),
                    mgf.len(),
                    label_bytes.as_ptr(),
                    label_bytes.len(),
                    ciphertext.as_ptr(),
                    ciphertext.len(),
                    generator.handle(),
                    Generator::TYPE.as_ptr(),
                    Generator::TYPE.len(),
                    &mut buffer,
                )
            };
            let result = status.is_null().then(|| Bytes::take(buffer));
            match test.field("result").as_str() {
                "valid" => assert_eq!(result, Some(test.bytes("msg")), "{label}"),
                "invalid" => assert!(result.is_none(), "{label}"),
                _ => {}
            }
            unsafe { umilib_crypto_rsa_rsa_private_key_free(key) };
        }
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn gostr3410_and_sm2_match_the_rust_api() {
    Scheme::GOSTR3410.check_against::<GOSTR3410<GOST256A, Streebog256>>(
        b"umilib_crypto_curve_gost_GOST256A",
        b"umilib_hash_streebog_Streebog256",
    );
    Scheme::SM2DSA.check_against::<SM2DSA<SM2, SM3>>(b"umilib_crypto_curve_sm2_SM2", b"umilib_hash_sm3_SM3");
    // The DER of SM2 signatures: r = 1 and s = 2, and a signature of the scheme.
    let (curve, hash) = (b"umilib_crypto_curve_sm2_SM2", b"umilib_hash_sm3_SM3");
    let mut raw = [0u8; 64];
    raw[31] = 1;
    raw[63] = 2;
    unsafe {
        let mut der = Buffer::default();
        Check::ok(sm2dsa::der::umilib_crypto_sm2_sm2dsa_signature_to_der(
            curve.as_ptr(),
            curve.len(),
            hash.as_ptr(),
            hash.len(),
            raw.as_ptr(),
            64,
            &mut der,
        ));
        let der = Bytes::take(der);
        assert_eq!(der, [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
        let mut back = Buffer::default();
        Check::ok(sm2dsa::der::umilib_crypto_sm2_sm2dsa_signature_from_der(
            curve.as_ptr(),
            curve.len(),
            hash.as_ptr(),
            hash.len(),
            der.as_ptr(),
            der.len(),
            &mut back,
        ));
        assert_eq!(Bytes::take(back), raw);
        // BER with a long length form is not DER.
        let ber = [0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let mut refused = Buffer::default();
        Check::fails(
            sm2dsa::der::umilib_crypto_sm2_sm2dsa_signature_from_der(
                curve.as_ptr(),
                curve.len(),
                hash.as_ptr(),
                hash.len(),
                ber.as_ptr(),
                ber.len(),
                &mut refused,
            ),
            "crypto",
            "InvalidSignature",
        );
    }
}

/// The value "name := 0x ...;" of RFC 6507 appendix A, or for a hash "name
/// := hash( ... ), = 0x ...;" the value after "=", across lines.
fn rfc6507(name: &str) -> Vec<u8> {
    let text = Vectors::read("crypto/eccsi/rfc6507.txt");
    let section = &text[text.find("\nAppendix A.  Test Data").unwrap()..];
    let at = section.find(&format!("\n      {name} ")).unwrap_or_else(|| panic!("no {name}"));
    let mut value = &section[at + 1..];
    if value[..value.find('\n').unwrap()].contains("hash(") {
        value = &value[value.find("),").unwrap()..];
    }
    let from = value.find("0x").unwrap() + 2;
    let to = from + value[from..].find(';').unwrap();
    let hex: String = value[from..to].split_whitespace().collect();
    let padded = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex };
    Vectors::hex(&padded)
}

/// RFC 6507 appendix A through the C ABI, on P-256 with SHA-256.
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn eccsi_rfc6507() {
    let (curve, hash) = (b"umilib_crypto_curve_p256_P256", b"umilib_hash_sha_v2_SHA256");
    let mut sizes = [0usize; 3];
    unsafe {
        Check::ok(umilib_crypto_eccsi_eccsi_sizes(
            curve.as_ptr(),
            curve.len(),
            hash.as_ptr(),
            hash.len(),
            sizes.as_mut_ptr(),
        ));
        assert_eq!(sizes, [32, 65, 129]);
        // P-384 with SHA-256 is not a pair of section 4.1.
        let p384 = b"umilib_crypto_curve_p384_P384";
        Check::fails(
            umilib_crypto_eccsi_eccsi_sizes(p384.as_ptr(), p384.len(), hash.as_ptr(), hash.len(), sizes.as_mut_ptr()),
            "crypto",
            "InvalidParameter",
        );
        // The secrets are integers of the bytes of the order.
        let secret = |name: &str| {
            let value = rfc6507(name);
            let mut padded = vec![0u8; 32 - value.len()];
            padded.extend(value);
            padded
        };
        let (ksak, identity, v) = (secret("KSAK"), rfc6507("ID"), secret("v"));
        let mut kpak = [0u8; 65];
        Check::ok(umilib_crypto_eccsi_eccsi_kms_public_key(
            curve.as_ptr(),
            curve.len(),
            ksak.as_ptr(),
            32,
            kpak.as_mut_ptr(),
            65,
        ));
        assert_eq!(kpak.to_vec(), rfc6507("KPAK"));
        let (mut ssk, mut pvt) = ([0u8; 32], [0u8; 65]);
        Check::ok(umilib_crypto_eccsi_eccsi_kms_issue_with_ephemeral(
            curve.as_ptr(),
            curve.len(),
            hash.as_ptr(),
            hash.len(),
            ksak.as_ptr(),
            32,
            identity.as_ptr(),
            identity.len(),
            v.as_ptr(),
            v.len(),
            ssk.as_mut_ptr(),
            32,
            pvt.as_mut_ptr(),
            65,
        ));
        assert_eq!(ssk.to_vec(), rfc6507("SSK"));
        assert_eq!(pvt.to_vec(), rfc6507("PVT"));
        Check::ok(umilib_crypto_eccsi_eccsi_user_key_check(
            curve.as_ptr(),
            curve.len(),
            hash.as_ptr(),
            hash.len(),
            kpak.as_ptr(),
            65,
            identity.as_ptr(),
            identity.len(),
            ssk.as_ptr(),
            32,
            pvt.as_ptr(),
            65,
        ));
        let (message, j) = (rfc6507("M"), secret("j"));
        let mut signature = [0u8; 129];
        Check::ok(umilib_crypto_eccsi_eccsi_sign_with_ephemeral(
            curve.as_ptr(),
            curve.len(),
            hash.as_ptr(),
            hash.len(),
            kpak.as_ptr(),
            65,
            identity.as_ptr(),
            identity.len(),
            ssk.as_ptr(),
            32,
            pvt.as_ptr(),
            65,
            message.as_ptr(),
            message.len(),
            j.as_ptr(),
            j.len(),
            signature.as_mut_ptr(),
            129,
        ));
        assert_eq!(signature.to_vec(), rfc6507("Sig"));
        let verify = |message: &[u8], signature: &[u8]| {
            umilib_crypto_eccsi_eccsi_verify(
                curve.as_ptr(),
                curve.len(),
                hash.as_ptr(),
                hash.len(),
                kpak.as_ptr(),
                65,
                identity.as_ptr(),
                identity.len(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
            )
        };
        Check::ok(verify(&message, &signature));
        Check::fails(verify(b"massage\0", &signature), "crypto", "InvalidSignature");

        // A generated community: a random KMS, key and signature.
        let generator = Generator::new(b"eccsi");
        let (mut ksak, mut kpak) = ([0u8; 32], [0u8; 65]);
        Check::ok(umilib_crypto_eccsi_eccsi_kms_generate(
            curve.as_ptr(),
            curve.len(),
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            ksak.as_mut_ptr(),
            32,
            kpak.as_mut_ptr(),
            65,
        ));
        Check::ok(umilib_crypto_eccsi_eccsi_kms_issue(
            curve.as_ptr(),
            curve.len(),
            hash.as_ptr(),
            hash.len(),
            ksak.as_ptr(),
            32,
            b"alice".as_ptr(),
            5,
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            ssk.as_mut_ptr(),
            32,
            pvt.as_mut_ptr(),
            65,
        ));
        Check::ok(umilib_crypto_eccsi_eccsi_sign(
            curve.as_ptr(),
            curve.len(),
            hash.as_ptr(),
            hash.len(),
            kpak.as_ptr(),
            65,
            b"alice".as_ptr(),
            5,
            ssk.as_ptr(),
            32,
            pvt.as_ptr(),
            65,
            b"message".as_ptr(),
            7,
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            signature.as_mut_ptr(),
            129,
        ));
        Check::ok(umilib_crypto_eccsi_eccsi_verify(
            curve.as_ptr(),
            curve.len(),
            hash.as_ptr(),
            hash.len(),
            kpak.as_ptr(),
            65,
            b"alice".as_ptr(),
            5,
            b"message".as_ptr(),
            7,
            signature.as_ptr(),
            129,
        ));
    }
}

type IBSSetup = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *mut core::ffi::c_void,
    *const u8,
    usize,
    *mut *mut Box<dyn IBSMasterState>,
) -> *const Status;
type IBSMasterNew = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut *mut Box<dyn IBSMasterState>,
) -> *const Status;

type IBSVerify = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
) -> *const Status;

/// A master key of the C ABI signs through its user keys, and `S` of `umilib::crypto` verifies the
/// signatures, which the C ABI verifies too; the master key survives its secret.
fn check_ibs<S: IdentityBasedSignature>(
    curve: &[u8],
    hash: &[u8],
    setup: IBSSetup,
    master_key_new: IBSMasterNew,
    verify: IBSVerify,
) {
    let generator = Generator::new(b"ibs");
    unsafe {
        let mut master = ptr::null_mut();
        Check::ok(setup(
            curve.as_ptr(),
            curve.len(),
            hash.as_ptr(),
            hash.len(),
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            &mut master,
        ));
        let mut buffer = Buffer::default();
        Check::ok(umilib_crypto_ibs_ibs_master_key_public_key(master, &mut buffer));
        let public = Bytes::take(buffer);
        let mut user = ptr::null_mut();
        Check::ok(umilib_crypto_ibs_ibs_master_key_extract(master, b"alice".as_ptr(), 5, &mut user));
        let mut buffer = Buffer::default();
        Check::ok(umilib_crypto_ibs_ibs_user_key_identity(user, &mut buffer));
        assert_eq!(Bytes::take(buffer), b"alice");
        let mut buffer = Buffer::default();
        Check::ok(umilib_crypto_ibs_ibs_user_key_sign(
            user,
            b"message".as_ptr(),
            7,
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            &mut buffer,
        ));
        let signature = Bytes::take(buffer);

        let rust_master = S::master_public_key_from_bytes(&public).unwrap();
        let rust_signature = S::Signature::from_bytes(&signature).unwrap();
        assert_eq!(S::verify(&rust_master, b"alice", b"message", &rust_signature), Ok(()));
        let check = |identity: &[u8], message: &[u8]| {
            verify(
                curve.as_ptr(),
                curve.len(),
                hash.as_ptr(),
                hash.len(),
                public.as_ptr(),
                public.len(),
                identity.as_ptr(),
                identity.len(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
            )
        };
        Check::ok(check(b"alice", b"message"));
        Check::fails(check(b"bob", b"message"), "crypto", "InvalidSignature");
        Check::fails(check(b"alice", b"massage"), "crypto", "InvalidSignature");

        // The master key of the secret has the same public key.
        let mut buffer = Buffer::default();
        Check::ok(umilib_crypto_ibs_ibs_master_key_secret(master, &mut buffer));
        let secret = Bytes::take(buffer);
        let mut copy = ptr::null_mut();
        Check::ok(master_key_new(
            curve.as_ptr(),
            curve.len(),
            hash.as_ptr(),
            hash.len(),
            secret.as_ptr(),
            secret.len(),
            &mut copy,
        ));
        let mut buffer = Buffer::default();
        Check::ok(umilib_crypto_ibs_ibs_master_key_public_key(copy, &mut buffer));
        assert_eq!(Bytes::take(buffer), public);
        let zero = vec![0u8; secret.len()];
        let mut refused = ptr::null_mut();
        Check::fails(
            master_key_new(
                curve.as_ptr(),
                curve.len(),
                hash.as_ptr(),
                hash.len(),
                zero.as_ptr(),
                zero.len(),
                &mut refused,
            ),
            "crypto",
            "InvalidKey",
        );
        umilib_crypto_ibs_ibs_master_key_free(copy);
        umilib_crypto_ibs_ibs_user_key_free(user);
        umilib_crypto_ibs_ibs_master_key_free(master);
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn identity_based_signatures_match_the_rust_api() {
    let (bls, bn) = (&b"umilib_math_pairing_BLS12381"[..], &b"umilib_math_pairing_BN254"[..]);
    let sha256 = &b"umilib_hash_sha_v2_SHA256"[..];
    check_ibs::<Hess<BLS12381, SHA256>>(bls, sha256, hess::setup, hess::master_key_new, hess::verify);
    check_ibs::<Hess<BN254, SHA256>>(bn, sha256, hess::setup, hess::master_key_new, hess::verify);
    check_ibs::<ChaCheon<BLS12381, SHA256>>(bls, sha256, chacheon::setup, chacheon::master_key_new, chacheon::verify);
    check_ibs::<ChaCheon<BN254, SHA256>>(bn, sha256, chacheon::setup, chacheon::master_key_new, chacheon::verify);
    // SM9 as GM/T 0044 specifies it, whose master public key has its own encoding.
    let (sm9_curve, sm3) = (&b"umilib_math_pairing_SM9BN256"[..], &b"umilib_hash_sm3_SM3"[..]);
    check_ibs::<SM9<SM9BN256, SM3>>(sm9_curve, sm3, sm9::setup, sm9::master_key_new, sm9::verify);
    let mut sm9_sizes = [0usize; 3];
    unsafe {
        Check::ok(sm9::sizes(sm9_curve.as_ptr(), sm9_curve.len(), sm3.as_ptr(), sm3.len(), sm9_sizes.as_mut_ptr()));
    }
    assert_eq!(sm9_sizes, [32, 129, 97]);
    let mut sizes = [0usize; 3];
    let hash = b"umilib_hash_sha_v2_SHA256";
    unsafe {
        Check::ok(hess::sizes(bls.as_ptr(), bls.len(), hash.as_ptr(), hash.len(), sizes.as_mut_ptr()));
    }
    assert_eq!(
        sizes,
        [
            32,
            G2Affine::<BLS12381>::encoded_length(),
            <Hess<BLS12381, SHA256> as IdentityBasedSignature>::Signature::encoded_length()
        ]
    );
    assert_eq!(<BLS12381 as PairingCurve>::FAMILY, umilib::math::pairing::PairingFamily::BLS12);
}
