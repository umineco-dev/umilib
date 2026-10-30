use core::marker::PhantomData;

use crate::hash::CryptographicDigest;
use crate::secret::Zeroize;

/// The key derivation function of GM/T 0044.3-2016 section 5.4.3, which
/// part 4 uses as well: the concatenation of Hv(Z || ct) for the 32-bit
/// big-endian counters ct = 1, 2, ...
pub struct SM9KDF<H: CryptographicDigest + Default> {
    hash: PhantomData<H>,
}

impl<H: CryptographicDigest + Default> SM9KDF<H> {
    /// Fills `out` with the first bytes of the derivation of Z, given as the concatenation of `parts`.
    pub fn derive(parts: &[&[u8]], out: &mut [u8]) {
        for (index, chunk) in out.chunks_mut(H::OUTPUT_SIZE).enumerate() {
            let mut hash = H::default();
            for part in parts {
                hash.update(part);
            }
            hash.update(&(index as u32 + 1).to_be_bytes());
            let mut block = hash.finalize();
            chunk.copy_from_slice(&block.as_ref()[..chunk.len()]);
            block.as_mut().zeroize();
        }
    }
}
