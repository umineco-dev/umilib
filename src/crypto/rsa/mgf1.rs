use core::marker::PhantomData;

use crate::hash::CryptographicDigest;
use crate::secret::Zeroize;

/// The mask generation function MGF1 of RFC 8017 appendix B.2.1 over the
/// hash function `G`: the concatenation of G(seed || counter) for the
/// counters 0, 1, ... as four big-endian bytes.
pub struct MGF1<G: CryptographicDigest + Default> {
    hash: PhantomData<G>,
}

impl<G: CryptographicDigest + Default> MGF1<G> {
    /// XORs the mask of `seed`, of the length of `data`, into `data`.
    pub fn apply(seed: &[u8], data: &mut [u8]) {
        for (counter, chunk) in data.chunks_mut(G::OUTPUT_SIZE).enumerate() {
            let mut hash = G::default();
            hash.update(seed);
            hash.update(&(counter as u32).to_be_bytes());
            let mut mask = hash.finalize();
            for (byte, mask) in chunk.iter_mut().zip(mask.as_ref()) {
                *byte ^= mask;
            }
            mask.as_mut().zeroize();
        }
    }
}
