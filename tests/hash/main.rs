//! Tests of `umilib::hash` against the test vectors of the specifications.

#[cfg(umilib_feature = "hash-adler32")]
mod adler32;
#[cfg(umilib_feature = "hash-ascon")]
mod ascon;
#[cfg(umilib_feature = "hash-blake")]
mod blake;
#[cfg(umilib_feature = "hash-crc")]
mod crc;
#[cfg(umilib_feature = "hash-md")]
mod md;
mod reset;
#[cfg(umilib_feature = "hash-ripemd")]
mod ripemd;
#[cfg(umilib_feature = "hash-sha")]
mod sha;
#[cfg(umilib_feature = "hash-siphash")]
mod siphash;
#[cfg(umilib_feature = "hash-sm3")]
mod sm3;
#[cfg(umilib_feature = "hash-streebog")]
mod streebog;
#[cfg(umilib_feature = "hash-xxhash")]
mod xxhash;

#[path = "../common/vectors.rs"]
mod vectors;

pub use vectors::{Record, Vectors};

/// The Secure Hash Algorithm Validation System of NIST CAVP.
pub struct Shavs;

impl Shavs {
    /// Checks every message of the SHAVS response files `{prefix}ShortMsg.rsp`
    /// and `{prefix}LongMsg.rsp`, hashed at once and in pieces, and the Monte
    /// Carlo test of `{prefix}Monte.rsp` (SHAVS section 6.4).
    #[cfg(umilib_feature = "hash-sha")]
    pub fn check<H: umilib::hash::Digest + Default>(prefix: &str) {
        for kind in ["ShortMsg", "LongMsg"] {
            let records = Record::all(&format!("{prefix}{kind}.rsp"));
            assert!(records.len() > 60, "{prefix}{kind}");
            for record in records {
                let message = record.message();
                let expected = record.bytes("MD");
                assert_eq!(H::digest(&message).as_ref(), expected, "{prefix}{kind} Len = {}", record.field("Len"));
                let mut hash = H::default();
                for piece in message.chunks(37) {
                    hash.update(piece);
                }
                assert_eq!(hash.finalize_reset().as_ref(), expected);
                hash.update(&message);
                assert_eq!(hash.finalize().as_ref(), expected, "after reset");
            }
        }
        let records = Record::all(&format!("{prefix}Monte.rsp"));
        let mut seed = records[0].bytes("Seed");
        for record in &records[1..] {
            let mut previous = [seed.clone(), seed.clone(), seed.clone()];
            for _ in 3..1003 {
                let mut hash = H::default();
                for digest in &previous {
                    hash.update(digest);
                }
                let digest = hash.finalize().as_ref().to_vec();
                previous = [previous[1].clone(), previous[2].clone(), digest];
            }
            seed = previous[2].clone();
            assert_eq!(seed, record.bytes("MD"), "{prefix}Monte COUNT = {}", record.field("COUNT"));
        }
    }
}
