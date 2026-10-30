//! Benchmarks of `umilib::math`: the sizes of elliptic curve fields (256 bits)
//! and of RSA and Diffie-Hellman moduli (2048 bits).

use std::hint::black_box;

use umilib::platform::bench::Bench;

pub struct Benchmarks;

impl Benchmarks {
    pub fn run(bench: &mut Bench) {
        #[cfg(umilib_feature = "math-bigint")]
        {
            use umilib::math::bigint::{BoxedUint, U256, U512};
            let wide = U512::MAX.shr(7);
            let divisor =
                U512::from_hex_vartime_or_panic("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
            bench.run("math-bigint-u256-widening-mul", None, || {
                black_box(black_box(U256::MAX).widening_mul(black_box(&U256::MAX)));
            });
            bench.run("math-bigint-u512-div-rem", None, || {
                black_box(black_box(wide).div_rem(black_box(&divisor)).unwrap());
            });
            let x = BoxedUint::from_be_bytes(&[0xA5; 256], 2048).unwrap();
            bench.run("math-bigint-boxed-2048-widening-mul", None, || {
                black_box(black_box(&x).widening_mul(black_box(&x)));
            });
        }
        #[cfg(umilib_feature = "math-modular")]
        {
            use umilib::math::bigint::{BoxedUint, U256};
            use umilib::math::modular::{BoxedModulus, Modulus};
            let p = U256::from_hex_vartime_or_panic("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
            let field = Modulus::new(p).unwrap();
            let x = field.residue(&U256::from_hex_vartime_or_panic(
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            ));
            let exponent = p.wrapping_sub(&U256::from_limb(2));
            bench.run("math-modular-p256-mul", None, || {
                black_box(field.mul(black_box(&x), black_box(&x)));
            });
            bench.run("math-modular-p256-pow", None, || {
                black_box(field.pow(black_box(&x), black_box(&exponent)));
            });
            bench.run("math-modular-p256-invert", None, || {
                black_box(field.invert(black_box(&x)).unwrap());
            });
            // The 2048-bit MODP prime of RFC 3526.
            let prime = BoxedUint::from_hex_vartime(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD\
                 EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
                 EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
                 83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
                 E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
                 15728E5A8AACAA68FFFFFFFFFFFFFFFF",
                2048,
            )
            .unwrap();
            let group = BoxedModulus::new(prime.clone()).unwrap();
            let base = group.residue(&BoxedUint::from_u64(2, 64).unwrap());
            let secret = prime.shr(1);
            let public = BoxedUint::from_u64(65537, 64).unwrap();
            bench.run("math-modular-boxed-2048-mul", None, || {
                black_box(group.mul(black_box(&base), black_box(&base)).unwrap());
            });
            bench.run("math-modular-boxed-2048-pow", None, || {
                black_box(group.pow(black_box(&base), black_box(&secret)).unwrap());
            });
            bench.run("math-modular-boxed-2048-pow-vartime-65537", None, || {
                black_box(group.pow_vartime(black_box(&base), black_box(&public)).unwrap());
            });
            bench.run("math-modular-boxed-2048-invert", None, || {
                black_box(group.invert(black_box(&base)).unwrap());
            });
        }
        #[cfg(umilib_feature = "math-lattice")]
        {
            use umilib::math::lattice::{MLDSARing, MLKEMRing, Polynomial};
            let values: Vec<u32> = (0..256u32).map(|index| index * 1009 % 3329).collect();
            let a = Polynomial::<MLKEMRing>::from_values(&values).unwrap();
            let b = a.ntt();
            let once = Some(umilib::platform::bench::Throughput::Elements(1));
            bench.run("math-lattice-mlkem-ntt", once, || {
                black_box(black_box(&a).ntt());
            });
            bench.run("math-lattice-mlkem-inverse-ntt", once, || {
                black_box(black_box(&b).inverse_ntt());
            });
            bench.run("math-lattice-mlkem-multiply-ntt", once, || {
                black_box(black_box(&b).multiply_ntt(black_box(&b)));
            });
            let c = Polynomial::<MLDSARing>::from_values(&values).unwrap();
            bench.run("math-lattice-mldsa-ntt", once, || {
                black_box(black_box(&c).ntt());
            });
        }
        #[cfg(umilib_feature = "math-pairing")]
        {
            use umilib::math::ec::AffinePoint;
            use umilib::math::pairing::{BLS12381, G2Affine, Pairing, PairingCurve};
            let p = AffinePoint::<<BLS12381 as PairingCurve>::G1>::generator();
            let q = G2Affine::<BLS12381>::generator();
            bench.run("math-pairing-bls12381-pairing", Some(umilib::platform::bench::Throughput::Elements(1)), || {
                black_box(Pairing::<BLS12381>::pairing(black_box(&p), black_box(&q)).unwrap());
            });
        }
    }
}
