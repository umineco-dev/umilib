//! The C ABI of ML-KEM, ML-DSA, SLH-DSA, the hybrids of RFC 10024 and the
//! lattice transforms, through the functions C calls: known answers of the
//! ACVP vectors of NIST, and round trips with a generator.

use umilib::ffi::crypto::hybrid::hybrid_kem;
use umilib::ffi::crypto::mldsa::mldsa;
use umilib::ffi::crypto::mlkem::mlkem;
use umilib::ffi::crypto::slhdsa::slhdsa;
use umilib::ffi::math::lattice::*;
use umilib::math::lattice::{MLKEMRing, Polynomial};

use super::Generator;
use crate::Check;
use crate::vectors::Json;

/// The first test of the first group of `path` whose `parameterSet` is `name` and whose group fields
/// `filter` accepts.
fn first(path: &str, name: &str, filter: impl Fn(&Json) -> bool) -> Json {
    let vectors = Json::read(path);
    let group = vectors
        .field("testGroups")
        .items()
        .iter()
        .find(|group| group.field("parameterSet").as_str() == name && filter(group))
        .unwrap_or_else(|| panic!("no group of {name}"));
    group.field("tests").items()[0].clone()
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn mlkem_through_the_c_abi() {
    let name = b"umilib_crypto_mlkem_MLKEM768";
    let mut sizes = [0usize; 4];
    unsafe {
        Check::ok(mlkem::sizes(name.as_ptr(), name.len(), sizes.as_mut_ptr()));
        assert_eq!(sizes, [2400, 1184, 1088, 32]);
        // Key generation from the seed d || z (ACVP keyGen).
        let test = first("crypto/mlkem/acvp-keygen.json", "ML-KEM-768", |_| true);
        let seed = [test.bytes("d"), test.bytes("z")].concat();
        let mut dk = vec![0u8; 2400];
        Check::ok(mlkem::decapsulation_key_from_seed(
            name.as_ptr(),
            name.len(),
            seed.as_ptr(),
            64,
            dk.as_mut_ptr(),
            dk.len(),
        ));
        assert_eq!(dk, test.bytes("dk"));
        let mut ek = vec![0u8; 1184];
        Check::ok(mlkem::encapsulation_key(
            name.as_ptr(),
            name.len(),
            dk.as_ptr(),
            dk.len(),
            ek.as_mut_ptr(),
            ek.len(),
        ));
        assert_eq!(ek, test.bytes("ek"));
        // Encapsulation with m (ACVP encapDecap) and decapsulation.
        let test = first("crypto/mlkem/acvp-encapdecap.json", "ML-KEM-768", |group| {
            group.field("function").as_str() == "encapsulation"
        });
        let (ek, dk, m) = (test.bytes("ek"), test.bytes("dk"), test.bytes("m"));
        let (mut ciphertext, mut shared) = (vec![0u8; 1088], [0u8; 32]);
        Check::ok(mlkem::encapsulate_internal(
            name.as_ptr(),
            name.len(),
            ek.as_ptr(),
            ek.len(),
            m.as_ptr(),
            m.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            shared.as_mut_ptr(),
            32,
        ));
        assert_eq!(ciphertext, test.bytes("c"));
        assert_eq!(shared.to_vec(), test.bytes("k"));
        let mut decapsulated = [0u8; 32];
        Check::ok(mlkem::decapsulate(
            name.as_ptr(),
            name.len(),
            dk.as_ptr(),
            dk.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            decapsulated.as_mut_ptr(),
            32,
        ));
        assert_eq!(decapsulated, shared);
        // A generated key and a random encapsulation.
        let generator = Generator::new(b"mlkem");
        let mut dk = vec![0u8; 2400];
        Check::ok(mlkem::generate(
            name.as_ptr(),
            name.len(),
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            dk.as_mut_ptr(),
            dk.len(),
        ));
        Check::ok(mlkem::check_decapsulation_key(name.as_ptr(), name.len(), dk.as_ptr(), dk.len()));
        let mut ek = vec![0u8; 1184];
        Check::ok(mlkem::encapsulation_key(
            name.as_ptr(),
            name.len(),
            dk.as_ptr(),
            dk.len(),
            ek.as_mut_ptr(),
            ek.len(),
        ));
        Check::ok(mlkem::encapsulate(
            name.as_ptr(),
            name.len(),
            ek.as_ptr(),
            ek.len(),
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            shared.as_mut_ptr(),
            32,
        ));
        Check::ok(mlkem::decapsulate(
            name.as_ptr(),
            name.len(),
            dk.as_ptr(),
            dk.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            decapsulated.as_mut_ptr(),
            32,
        ));
        assert_eq!(decapsulated, shared);
        // The modulus check of FIPS 203 section 7.2.
        ek[0] = 0x01;
        ek[1] = (ek[1] & 0xF0) | 0x0D;
        Check::fails(
            mlkem::check_encapsulation_key(name.as_ptr(), name.len(), ek.as_ptr(), ek.len()),
            "crypto",
            "InvalidKey",
        );
        let unknown = b"umilib_crypto_mlkem_MLKEM999";
        Check::fails(mlkem::sizes(unknown.as_ptr(), unknown.len(), sizes.as_mut_ptr()), "ffi", "InvalidArgument");
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn mldsa_through_the_c_abi() {
    let name = b"umilib_crypto_mldsa_MLDSA44";
    let mut sizes = [0usize; 3];
    unsafe {
        Check::ok(mldsa::sizes(name.as_ptr(), name.len(), sizes.as_mut_ptr()));
        assert_eq!(sizes, [2560, 1312, 2420]);
        let test = first("crypto/mldsa/acvp-keygen.json", "ML-DSA-44", |_| true);
        let seed = test.bytes("seed");
        let mut sk = vec![0u8; 2560];
        Check::ok(mldsa::signing_key_from_seed(
            name.as_ptr(),
            name.len(),
            seed.as_ptr(),
            seed.len(),
            sk.as_mut_ptr(),
            sk.len(),
        ));
        assert_eq!(sk, test.bytes("sk"));
        // The deterministic pure signature with a context (ACVP sigGen, external interface).
        let test = first("crypto/mldsa/acvp-siggen-subset.json", "ML-DSA-44", |group| {
            matches!(group.field("deterministic"), Json::Bool(true))
                && group.field("signatureInterface").as_str() == "external"
                && group.field("preHash").as_str() == "pure"
        });
        let (sk, pk, message, context) =
            (test.bytes("sk"), test.bytes("pk"), test.bytes("message"), test.bytes("context"));
        let mut signature = vec![0u8; 2420];
        Check::ok(mldsa::sign_deterministic_with_context(
            name.as_ptr(),
            name.len(),
            sk.as_ptr(),
            sk.len(),
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            signature.as_mut_ptr(),
            signature.len(),
        ));
        assert_eq!(signature, test.bytes("signature"));
        Check::ok(mldsa::verify_with_context(
            name.as_ptr(),
            name.len(),
            pk.as_ptr(),
            pk.len(),
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            signature.as_ptr(),
            signature.len(),
        ));
        Check::fails(
            mldsa::verify(
                name.as_ptr(),
                name.len(),
                pk.as_ptr(),
                pk.len(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
            ),
            "crypto",
            "InvalidSignature",
        );
        // HashML-DSA with SHA-512, hedged.
        let generator = Generator::new(b"mldsa");
        let hash = b"umilib_hash_sha_v2_SHA512";
        Check::ok(mldsa::sign_pre_hash(
            name.as_ptr(),
            name.len(),
            hash.as_ptr(),
            hash.len(),
            sk.as_ptr(),
            sk.len(),
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            generator.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            signature.as_mut_ptr(),
            signature.len(),
        ));
        Check::ok(mldsa::verify_pre_hash(
            name.as_ptr(),
            name.len(),
            hash.as_ptr(),
            hash.len(),
            pk.as_ptr(),
            pk.len(),
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            signature.as_ptr(),
            signature.len(),
        ));
        let unknown = b"umilib_hash_md_v5_MD5";
        Check::fails(
            mldsa::verify_pre_hash(
                name.as_ptr(),
                name.len(),
                unknown.as_ptr(),
                unknown.len(),
                pk.as_ptr(),
                pk.len(),
                message.as_ptr(),
                message.len(),
                context.as_ptr(),
                context.len(),
                signature.as_ptr(),
                signature.len(),
            ),
            "ffi",
            "InvalidArgument",
        );
        let long = [0u8; 256];
        Check::fails(
            mldsa::sign_deterministic_with_context(
                name.as_ptr(),
                name.len(),
                sk.as_ptr(),
                sk.len(),
                message.as_ptr(),
                message.len(),
                long.as_ptr(),
                long.len(),
                signature.as_mut_ptr(),
                signature.len(),
            ),
            "crypto",
            "InvalidParameter",
        );
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn slhdsa_through_the_c_abi() {
    let name = b"umilib_crypto_slhdsa_SLHDSA_SHAKE_128f";
    let mut sizes = [0usize; 3];
    unsafe {
        Check::ok(slhdsa::sizes(name.as_ptr(), name.len(), sizes.as_mut_ptr()));
        assert_eq!(sizes, [64, 32, 17088]);
        let test = first("crypto/slhdsa/acvp-keygen.json", "SLH-DSA-SHAKE-128f", |_| true);
        let (sk_seed, sk_prf, pk_seed) = (test.bytes("skSeed"), test.bytes("skPrf"), test.bytes("pkSeed"));
        let mut sk = vec![0u8; 64];
        Check::ok(slhdsa::key_gen_internal(
            name.as_ptr(),
            name.len(),
            sk_seed.as_ptr(),
            sk_seed.len(),
            sk_prf.as_ptr(),
            sk_prf.len(),
            pk_seed.as_ptr(),
            pk_seed.len(),
            sk.as_mut_ptr(),
            sk.len(),
        ));
        assert_eq!(sk, test.bytes("sk"));
        let test = first("crypto/slhdsa/acvp-siggen-subset.json", "SLH-DSA-SHAKE-128f", |group| {
            matches!(group.field("deterministic"), Json::Bool(true))
                && group.field("signatureInterface").as_str() == "external"
                && group.field("preHash").as_str() == "pure"
        });
        let (sk, pk, message, context) =
            (test.bytes("sk"), test.bytes("pk"), test.bytes("message"), test.bytes("context"));
        let mut signature = vec![0u8; 17088];
        Check::ok(slhdsa::sign_deterministic_with_context(
            name.as_ptr(),
            name.len(),
            sk.as_ptr(),
            sk.len(),
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            signature.as_mut_ptr(),
            signature.len(),
        ));
        assert_eq!(signature, test.bytes("signature"));
        Check::ok(slhdsa::verify_with_context(
            name.as_ptr(),
            name.len(),
            pk.as_ptr(),
            pk.len(),
            message.as_ptr(),
            message.len(),
            context.as_ptr(),
            context.len(),
            signature.as_ptr(),
            signature.len(),
        ));
        // A private key whose PK.root is not the one of its seeds.
        let mut wrong = sk.clone();
        wrong[63] ^= 1;
        Check::fails(
            slhdsa::check_signing_key(name.as_ptr(), name.len(), wrong.as_ptr(), wrong.len()),
            "crypto",
            "InvalidKey",
        );
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn hybrid_through_the_c_abi() {
    let generator = Generator::new(b"hybrid");
    for (group, expected) in [
        (&b"umilib_crypto_hybrid_X25519MLKEM768"[..], [2432usize, 1216, 1120, 64]),
        (b"umilib_crypto_hybrid_SecP256r1MLKEM768", [2432, 1249, 1153, 64]),
        (b"umilib_crypto_hybrid_SecP384r1MLKEM1024", [3216, 1665, 1665, 80]),
    ] {
        let mut sizes = [0usize; 4];
        unsafe {
            Check::ok(hybrid_kem::sizes(group.as_ptr(), group.len(), sizes.as_mut_ptr()));
            assert_eq!(sizes, expected);
            let mut dk = vec![0u8; sizes[0]];
            Check::ok(hybrid_kem::generate(
                group.as_ptr(),
                group.len(),
                generator.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                dk.as_mut_ptr(),
                dk.len(),
            ));
            let mut ek = vec![0u8; sizes[1]];
            Check::ok(hybrid_kem::encapsulation_key(
                group.as_ptr(),
                group.len(),
                dk.as_ptr(),
                dk.len(),
                ek.as_mut_ptr(),
                ek.len(),
            ));
            let (mut ciphertext, mut shared, mut decapsulated) =
                (vec![0u8; sizes[2]], vec![0u8; sizes[3]], vec![0u8; sizes[3]]);
            Check::ok(hybrid_kem::encapsulate(
                group.as_ptr(),
                group.len(),
                ek.as_ptr(),
                ek.len(),
                generator.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                ciphertext.as_mut_ptr(),
                ciphertext.len(),
                shared.as_mut_ptr(),
                shared.len(),
            ));
            Check::ok(hybrid_kem::decapsulate(
                group.as_ptr(),
                group.len(),
                dk.as_ptr(),
                dk.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                decapsulated.as_mut_ptr(),
                decapsulated.len(),
            ));
            assert_eq!(decapsulated, shared);
        }
    }
}

#[test]
fn lattice_transforms_through_the_c_abi() {
    let ring = b"umilib_math_lattice_MLKEMRing";
    let a: Vec<u32> = (0..256u32).map(|index| index * 13 % 3329).collect();
    let b: Vec<u32> = (0..256u32).map(|index| (index * index + 7) % 3329).collect();
    let (mut a_hat, mut b_hat, mut product, mut back) = ([0u32; 256], [0u32; 256], [0u32; 256], [0u32; 256]);
    unsafe {
        Check::ok(umilib_math_lattice_polynomial_ntt(
            ring.as_ptr(),
            ring.len(),
            a.as_ptr(),
            256,
            a_hat.as_mut_ptr(),
            256,
        ));
        Check::ok(umilib_math_lattice_polynomial_ntt(
            ring.as_ptr(),
            ring.len(),
            b.as_ptr(),
            256,
            b_hat.as_mut_ptr(),
            256,
        ));
        Check::ok(umilib_math_lattice_polynomial_multiply_ntt(
            ring.as_ptr(),
            ring.len(),
            a_hat.as_ptr(),
            256,
            b_hat.as_ptr(),
            256,
            product.as_mut_ptr(),
            256,
        ));
        Check::ok(umilib_math_lattice_polynomial_inverse_ntt(
            ring.as_ptr(),
            ring.len(),
            product.as_ptr(),
            256,
            back.as_mut_ptr(),
            256,
        ));
        Check::fails(
            umilib_math_lattice_polynomial_ntt(ring.as_ptr(), ring.len(), a.as_ptr(), 255, a_hat.as_mut_ptr(), 256),
            "ffi",
            "InvalidArgument",
        );
    }
    let expected = Polynomial::<MLKEMRing>::from_values(&a)
        .unwrap()
        .ntt()
        .multiply_ntt(&Polynomial::<MLKEMRing>::from_values(&b).unwrap().ntt())
        .inverse_ntt();
    assert_eq!(back.to_vec(), (0..256).map(|index| expected.get(index)).collect::<Vec<_>>());
}
