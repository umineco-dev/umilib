use alloc::vec;
use core::marker::PhantomData;

use crate::crypto::CryptoError;
use crate::hash::CryptographicDigest;
use crate::math::bigint::BoxedUint;
use crate::math::ec::{AffinePoint, FieldElement, PrimeField, ProjectivePoint};
use crate::math::pairing::{Pairing, PairingCurve};
use crate::secret::Zeroize;

/// The functions H1 and H2 of GM/T 0044.2-2016 sections 5.4.2.2 and
/// 5.4.2.3 (and of parts 3 and 4) over the hash function `H` (Hv), modulo
/// the order N of the curve `C`.
pub struct SM9Hash<C: PairingCurve, H: CryptographicDigest + Default> {
    types: PhantomData<(C, H)>,
}

impl<C: PairingCurve, H: CryptographicDigest + Default> SM9Hash<C, H> {
    /// The prefix of H1.
    pub const H1: u8 = 0x01;
    /// The prefix of H2.
    pub const H2: u8 = 0x02;

    /// hlen = 8 × ⌈(5 × log2 N) / 32⌉ (step 2): 8 × the smallest k with 2^(32 k) ≥ N^5.
    pub fn hash_bits() -> u32 {
        let order = Pairing::<C>::order();
        let mut fifth = order.clone();
        for _ in 1..5 {
            fifth = fifth.mul_wide(&order);
        }
        // N^5 < 2^(32 k) unless N^5 is that power itself, which N > 1 odd never is.
        8 * fifth.bit_length().div_ceil(32)
    }

    /// H1 ([`SM9Hash::H1`]) or H2 ([`SM9Hash::H2`]) of the concatenation of
    /// `parts`: (Ha mod (N - 1)) + 1, Ha the leftmost hlen bits of Hv(prefix
    /// || Z || ct) for the 32-bit counters ct = 1, 2, ... The reduction
    /// takes the same time for every Ha.
    pub fn hash(prefix: u8, parts: &[&[u8]]) -> Result<FieldElement<C::Scalar>, CryptoError> {
        let length = (SM9Hash::<C, H>::hash_bits() / 8) as usize;
        let mut ha = vec![0u8; length];
        for (index, chunk) in ha.chunks_mut(H::OUTPUT_SIZE).enumerate() {
            let mut hash = H::default();
            hash.update(&[prefix]);
            for part in parts {
                hash.update(part);
            }
            hash.update(&(index as u32 + 1).to_be_bytes());
            let mut block = hash.finalize();
            chunk.copy_from_slice(&block.as_ref()[..chunk.len()]);
            block.as_mut().zeroize();
        }
        let failed = |_| CryptoError::InvalidParameter;
        let order = Pairing::<C>::order();
        let precision = (8 * length as u32).max(order.precision());
        let mut value = BoxedUint::from_be_bytes(&ha, precision).map_err(failed)?;
        ha.zeroize();
        let one = BoxedUint::one(order.precision()).map_err(failed)?;
        let quotient_and_remainder = value.div_rem(&order.wrapping_sub(&one));
        value.zeroize();
        let (mut quotient, mut remainder) = quotient_and_remainder.map_err(failed)?;
        quotient.zeroize();
        let mut h = remainder.wrapping_add(&one);
        remainder.zeroize();
        let mut bytes = vec![0u8; <C::Scalar as PrimeField>::BYTES];
        let written = h.write_be_bytes(&mut bytes).map_err(failed);
        h.zeroize();
        written?;
        let result = FieldElement::from_be_bytes(&bytes).map_err(failed);
        bytes.zeroize();
        result
    }

    /// Q = \[H1(ID || hid, N)\]P1 + Ppub-e of `identity` under the master
    /// public key `master` (GM/T 0044.3-2016 steps A1 and B1, 0044.4-2016
    /// step A1), in time that depends on the identity only.
    pub fn identity_point(
        master: &AffinePoint<C::G1>,
        identity: &[u8],
        hid: u8,
    ) -> Result<AffinePoint<C::G1>, CryptoError> {
        let h1 = SM9Hash::<C, H>::hash(SM9Hash::<C, H>::H1, &[identity, &[hid]])?;
        Ok(ProjectivePoint::<C::G1>::generator().mul_vartime(&h1).add(&master.to_projective()).to_affine())
    }
}
