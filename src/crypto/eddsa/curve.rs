use crate::crypto::curve::curve448::Edwards448;
use crate::crypto::curve::curve25519::Edwards25519;
use crate::hash::sha::v2::SHA512;
use crate::hash::sha::v3::SHAKE256;
use crate::hash::{Digest, ExtendableOutput, XOFReader};
use crate::math::ec::EdwardsCurve;

/// A twisted Edwards curve with the parameters of EdDSA (RFC 8032 section
/// 5): the hash function H of 2b bits, the domain separation of the
/// variants, the prehash PH and the pruning of the secret scalar.
pub trait EdDSACurve: EdwardsCurve {
    /// The bytes of PH(M) of the prehash variant.
    const PREHASH_BYTES: usize;
    /// Whether the pure variant hashes dom(0, "") before its inputs (Ed448)
    /// or nothing (Ed25519).
    const PURE_DOMAIN: bool;
    /// The first octets of dom: dom2 of section 5.1 and dom4 of section 5.2
    /// are this prefix, the flag, the length of the context and the context.
    const DOMAIN_PREFIX: &'static [u8];

    /// H(dom(flag, context) || parts...) of 2 × [`EdwardsCurve::ENCODED_BYTES`]
    /// bytes into `out`, without dom when `domain` is `None`.
    fn hash(domain: Option<(u8, &[u8])>, parts: &[&[u8]], out: &mut [u8]);

    /// PH(message) of [`EdDSACurve::PREHASH_BYTES`] bytes into `out`.
    fn prehash(message: &[u8], out: &mut [u8]);

    /// Prunes the first half of H(k) into the secret scalar (the
    /// little-endian integer s of section 5.1.5 step 2 or 5.2.5 step 2).
    fn prune(half: &mut [u8]);
}

impl EdDSACurve for Edwards25519 {
    const PREHASH_BYTES: usize = 64;
    const PURE_DOMAIN: bool = false;
    const DOMAIN_PREFIX: &'static [u8] = b"SigEd25519 no Ed25519 collisions";

    /// SHA-512.
    fn hash(domain: Option<(u8, &[u8])>, parts: &[&[u8]], out: &mut [u8]) {
        let mut hash = SHA512::default();
        if let Some((flag, context)) = domain {
            hash.update(Edwards25519::DOMAIN_PREFIX);
            hash.update(&[flag, context.len() as u8]);
            hash.update(context);
        }
        for part in parts {
            hash.update(part);
        }
        out.copy_from_slice(hash.finalize().as_ref());
    }

    /// SHA-512.
    fn prehash(message: &[u8], out: &mut [u8]) {
        out.copy_from_slice(SHA512::digest(message).as_ref());
    }

    /// The lowest 3 bits and the highest bit cleared, the second highest set.
    fn prune(half: &mut [u8]) {
        half[0] &= 248;
        half[31] &= 127;
        half[31] |= 64;
    }
}

impl EdDSACurve for Edwards448 {
    const PREHASH_BYTES: usize = 64;
    const PURE_DOMAIN: bool = true;
    const DOMAIN_PREFIX: &'static [u8] = b"SigEd448";

    /// SHAKE256 with 114 bytes of output.
    fn hash(domain: Option<(u8, &[u8])>, parts: &[&[u8]], out: &mut [u8]) {
        let mut hash = SHAKE256::default();
        if let Some((flag, context)) = domain {
            hash.update(Edwards448::DOMAIN_PREFIX);
            hash.update(&[flag, context.len() as u8]);
            hash.update(context);
        }
        for part in parts {
            hash.update(part);
        }
        hash.finalize_xof().read(out);
    }

    /// SHAKE256 with 64 bytes of output.
    fn prehash(message: &[u8], out: &mut [u8]) {
        SHAKE256::digest_xof(message, out);
    }

    /// The lowest 2 bits and the last octet cleared, the highest bit of the
    /// second to last octet set.
    fn prune(half: &mut [u8]) {
        half[0] &= 252;
        half[56] = 0;
        half[55] |= 128;
    }
}
