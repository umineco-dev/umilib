//! Benchmarks of `umilib::hash`: the throughput of every hash function over
//! 16 KiB, and the short inputs that hash tables and checksums see.

use std::hint::black_box;

use umilib::platform::bench::{Bench, Throughput};

pub struct Benchmarks;

impl Benchmarks {
    pub const LENGTH: usize = 16 * 1024;

    pub fn run(bench: &mut Bench) {
        let data = vec![0xA5u8; Benchmarks::LENGTH];
        let data = data.as_slice();
        // Measures the hash of `LENGTH` bytes with the `Digest` `$type` as `$name`.
        #[allow(unused_macros)]
        macro_rules! digest {
            ($bench:expr, $name:literal, $type:ty) => {
                $bench.run($name, Some(Throughput::Bytes(Benchmarks::LENGTH as u64)), || {
                    black_box(<$type as umilib::hash::Digest>::digest(black_box(data)));
                });
            };
        }
        #[cfg(umilib_feature = "hash-sha-v1")]
        digest!(bench, "hash-sha-v1-sha1", umilib::hash::sha::v1::SHA1);
        #[cfg(umilib_feature = "hash-sha-v2")]
        {
            digest!(bench, "hash-sha-v2-sha256", umilib::hash::sha::v2::SHA256);
            digest!(bench, "hash-sha-v2-sha512", umilib::hash::sha::v2::SHA512);
        }
        #[cfg(umilib_feature = "hash-sha-v3")]
        {
            digest!(bench, "hash-sha-v3-sha3-256", umilib::hash::sha::v3::SHA3_256);
            bench.run("hash-sha-v3-shake128", Some(Throughput::Bytes(Benchmarks::LENGTH as u64)), || {
                let mut out = [0u8; 32];
                <umilib::hash::sha::v3::SHAKE128 as umilib::hash::ExtendableOutput>::digest_xof(
                    black_box(data),
                    &mut out,
                );
                black_box(out);
            });
        }
        #[cfg(umilib_feature = "hash-md-v5")]
        digest!(bench, "hash-md-v5-md5", umilib::hash::md::v5::MD5);
        #[cfg(umilib_feature = "hash-ripemd")]
        digest!(bench, "hash-ripemd-ripemd160", umilib::hash::ripemd::RIPEMD160);
        #[cfg(umilib_feature = "hash-sm3")]
        digest!(bench, "hash-sm3-sm3", umilib::hash::sm3::SM3);
        #[cfg(umilib_feature = "hash-streebog")]
        digest!(bench, "hash-streebog-streebog256", umilib::hash::streebog::Streebog256);
        #[cfg(umilib_feature = "hash-blake-v2")]
        {
            digest!(bench, "hash-blake-v2-blake2b512", umilib::hash::blake::v2::BLAKE2b512);
            digest!(bench, "hash-blake-v2-blake2s256", umilib::hash::blake::v2::BLAKE2s256);
        }
        #[cfg(umilib_feature = "hash-blake-v3")]
        digest!(bench, "hash-blake-v3-blake3", umilib::hash::blake::v3::BLAKE3);
        #[cfg(umilib_feature = "hash-ascon")]
        digest!(bench, "hash-ascon-ascon-hash256", umilib::hash::ascon::AsconHash256);
        #[cfg(umilib_feature = "hash-xxhash-xxh3")]
        digest!(bench, "hash-xxhash-xxh3-64", umilib::hash::xxhash::xxh3::XXH3_64);
        #[cfg(umilib_feature = "hash-xxhash-xxh64")]
        bench.run("hash-xxhash-xxh64", Some(Throughput::Bytes(Benchmarks::LENGTH as u64)), || {
            black_box(umilib::hash::xxhash::xxh64::XXH64::hash(0, black_box(data)));
        });
        #[cfg(umilib_feature = "hash-crc")]
        bench.run("hash-crc-crc32-iso-hdlc", Some(Throughput::Bytes(Benchmarks::LENGTH as u64)), || {
            use umilib::hash::crc::{CRC, CRCCatalogue};
            black_box(CRC::checksum(CRCCatalogue::CRC32_ISO_HDLC, black_box(data)));
        });
        #[cfg(umilib_feature = "hash-siphash")]
        bench.run("hash-siphash-siphash24-16-bytes", Some(Throughput::Bytes(16)), || {
            let mut state = umilib::hash::siphash::SipHash24::new(&[7; 16]);
            state.update(black_box(&data[..16]));
            black_box(state.output());
        });
    }
}
