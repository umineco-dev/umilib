use super::SLHDSAAddress;
use crate::crypto::hmac::HMAC;
use crate::hash::sha::v2::{SHA256, SHA512};
use crate::hash::sha::v3::SHAKE256;
use crate::hash::{Digest, ExtendableOutput, XOFReader};
use crate::secret::Zeroize;

/// The functions H_msg, PRF, PRF_msg, F, H and T_ℓ of an SLH-DSA family
/// (FIPS 205 section 4.1) for the security parameter n: an instance holds
/// what they precompute for PK.seed. The outputs have the lengths of their
/// `out` (n bytes, or m for H_msg).
pub trait SLHDSAHash: Clone {
    /// The functions for PK.seed.
    fn new(pk_seed: &[u8]) -> Self;

    /// PRF(PK.seed, SK.seed, ADRS).
    fn prf(&self, address: &SLHDSAAddress, sk_seed: &[u8], out: &mut [u8]);

    /// F(PK.seed, ADRS, M1).
    fn f(&self, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]);

    /// H(PK.seed, ADRS, M2), of a message of 2n bytes.
    fn h(&self, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]);

    /// T_ℓ(PK.seed, ADRS, M_ℓ), of a message of ℓ n bytes.
    fn t(&self, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]);

    /// PRF_msg(SK.prf, opt_rand, M) for M the concatenation of `message`.
    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], message: &[&[u8]], out: &mut [u8]);

    /// H_msg(R, PK.seed, PK.root, M) for M the concatenation of `message`.
    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[&[u8]], out: &mut [u8]);
}

/// The SHAKE family of FIPS 205 section 11.1: every function is SHAKE256.
#[derive(Clone)]
pub struct SLHDSASHAKE {
    seeded: SHAKE256,
}

impl SLHDSASHAKE {
    /// SHAKE256(PK.seed || ADRS || M, 8 n).
    pub fn tweak(&self, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]) {
        let mut function = self.seeded.clone();
        function.update(address.as_bytes());
        function.update(message);
        function.finalize_xof().read(out);
    }
}

impl SLHDSAHash for SLHDSASHAKE {
    fn new(pk_seed: &[u8]) -> SLHDSASHAKE {
        let mut seeded = SHAKE256::default();
        seeded.update(pk_seed);
        SLHDSASHAKE { seeded }
    }

    fn prf(&self, address: &SLHDSAAddress, sk_seed: &[u8], out: &mut [u8]) {
        self.tweak(address, sk_seed, out);
    }

    fn f(&self, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]) {
        self.tweak(address, message, out);
    }

    fn h(&self, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]) {
        self.tweak(address, message, out);
    }

    fn t(&self, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]) {
        self.tweak(address, message, out);
    }

    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], message: &[&[u8]], out: &mut [u8]) {
        let mut function = SHAKE256::default();
        function.update(sk_prf);
        function.update(opt_rand);
        message.iter().for_each(|part| function.update(part));
        function.finalize_xof().read(out);
    }

    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[&[u8]], out: &mut [u8]) {
        let mut function = SHAKE256::default();
        function.update(r);
        function.update(pk_seed);
        function.update(pk_root);
        message.iter().for_each(|part| function.update(part));
        function.finalize_xof().read(out);
    }
}

/// MGF1 of RFC 8017 appendix B.2.1 over the hash function `H`: `out` from
/// the digests of `seed` || the 32-bit counter, as H_msg of the SHA2
/// families uses it.
pub struct SLHDSAMGF1;

impl SLHDSAMGF1 {
    pub fn fill<H: Digest + Default>(seed: &[&[u8]], out: &mut [u8]) {
        for (counter, chunk) in out.chunks_mut(H::OUTPUT_SIZE).enumerate() {
            let mut hash = H::default();
            seed.iter().for_each(|part| hash.update(part));
            hash.update(&(counter as u32).to_be_bytes());
            chunk.copy_from_slice(&hash.finalize().as_ref()[..chunk.len()]);
        }
    }
}

/// The SHA2 family for security category 1 (FIPS 205 section 11.2.1, n =
/// 16): every function is built on SHA-256, F, H, T_ℓ and PRF hashing
/// PK.seed || toByte(0, 64 - n) || ADRSc || M, whose first block the
/// instance compresses once.
#[derive(Clone)]
pub struct SLHDSASHA2Category1 {
    seeded: SHA256,
}

/// The SHA2 family for security categories 3 and 5 (FIPS 205 section
/// 11.2.2, n = 24 or 32): F and PRF as in category 1; H, T_ℓ, H_msg and
/// PRF_msg built on SHA-512, with PK.seed padded to its block of 128 bytes.
#[derive(Clone)]
pub struct SLHDSASHA2Category3And5 {
    seeded: SHA256,
    seeded_wide: SHA512,
}

impl SLHDSASHA2Category1 {
    /// SHA-256(PK.seed || toByte(0, 64 - n)) state, a full block.
    pub fn seed_block(pk_seed: &[u8]) -> SHA256 {
        let mut hash = SHA256::default();
        hash.update(pk_seed);
        hash.update(&[0u8; 64][pk_seed.len()..]);
        hash
    }

    /// Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || M)) from the state of the first block.
    pub fn tweak(seeded: &SHA256, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]) {
        let mut hash = seeded.clone();
        hash.update(&address.compressed());
        hash.update(message);
        let digest = hash.finalize();
        out.copy_from_slice(&digest[..out.len()]);
    }
}

impl SLHDSAHash for SLHDSASHA2Category1 {
    fn new(pk_seed: &[u8]) -> SLHDSASHA2Category1 {
        SLHDSASHA2Category1 { seeded: SLHDSASHA2Category1::seed_block(pk_seed) }
    }

    fn prf(&self, address: &SLHDSAAddress, sk_seed: &[u8], out: &mut [u8]) {
        SLHDSASHA2Category1::tweak(&self.seeded, address, sk_seed, out);
    }

    fn f(&self, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]) {
        SLHDSASHA2Category1::tweak(&self.seeded, address, message, out);
    }

    fn h(&self, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]) {
        SLHDSASHA2Category1::tweak(&self.seeded, address, message, out);
    }

    fn t(&self, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]) {
        SLHDSASHA2Category1::tweak(&self.seeded, address, message, out);
    }

    /// Trunc_n(HMAC-SHA-256(SK.prf, opt_rand || M)).
    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], message: &[&[u8]], out: &mut [u8]) {
        let mut mac = HMAC::<SHA256>::new(sk_prf);
        crate::crypto::MAC::update(&mut mac, opt_rand);
        message.iter().for_each(|part| crate::crypto::MAC::update(&mut mac, part));
        let mut tag = crate::crypto::MAC::finalize(mac);
        out.copy_from_slice(&tag.as_ref()[..out.len()]);
        tag.as_mut().zeroize();
    }

    /// MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m).
    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[&[u8]], out: &mut [u8]) {
        let mut hash = SHA256::default();
        [r, pk_seed, pk_root].iter().chain(message).for_each(|part| hash.update(part));
        let digest = hash.finalize();
        SLHDSAMGF1::fill::<SHA256>(&[r, pk_seed, &digest], out);
    }
}

impl SLHDSAHash for SLHDSASHA2Category3And5 {
    fn new(pk_seed: &[u8]) -> SLHDSASHA2Category3And5 {
        let mut seeded_wide = SHA512::default();
        seeded_wide.update(pk_seed);
        seeded_wide.update(&[0u8; 128][pk_seed.len()..]);
        SLHDSASHA2Category3And5 { seeded: SLHDSASHA2Category1::seed_block(pk_seed), seeded_wide }
    }

    fn prf(&self, address: &SLHDSAAddress, sk_seed: &[u8], out: &mut [u8]) {
        SLHDSASHA2Category1::tweak(&self.seeded, address, sk_seed, out);
    }

    fn f(&self, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]) {
        SLHDSASHA2Category1::tweak(&self.seeded, address, message, out);
    }

    /// Trunc_n(SHA-512(PK.seed || toByte(0, 128 - n) || ADRSc || M2)).
    fn h(&self, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]) {
        self.t(address, message, out);
    }

    /// Trunc_n(SHA-512(PK.seed || toByte(0, 128 - n) || ADRSc || M_ℓ)).
    fn t(&self, address: &SLHDSAAddress, message: &[u8], out: &mut [u8]) {
        let mut hash = self.seeded_wide.clone();
        hash.update(&address.compressed());
        hash.update(message);
        let digest = hash.finalize();
        out.copy_from_slice(&digest[..out.len()]);
    }

    /// Trunc_n(HMAC-SHA-512(SK.prf, opt_rand || M)).
    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], message: &[&[u8]], out: &mut [u8]) {
        let mut mac = HMAC::<SHA512>::new(sk_prf);
        crate::crypto::MAC::update(&mut mac, opt_rand);
        message.iter().for_each(|part| crate::crypto::MAC::update(&mut mac, part));
        let mut tag = crate::crypto::MAC::finalize(mac);
        out.copy_from_slice(&tag.as_ref()[..out.len()]);
        tag.as_mut().zeroize();
    }

    /// MGF1-SHA-512(R || PK.seed || SHA-512(R || PK.seed || PK.root || M), m).
    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[&[u8]], out: &mut [u8]) {
        let mut hash = SHA512::default();
        [r, pk_seed, pk_root].iter().chain(message).for_each(|part| hash.update(part));
        let digest = hash.finalize();
        SLHDSAMGF1::fill::<SHA512>(&[r, pk_seed, &digest], out);
    }
}
