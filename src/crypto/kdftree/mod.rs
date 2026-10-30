//! KDF_TREE (RFC 7836 section 4.4, R 50.1.113-2016): the key derivation
//! function of the GOST cipher suites, a counter-mode KDF of SP 800-108.

use core::fmt;

use crate::crypto::{CryptoError, PRF};
use crate::secret::Zeroize;

/// KDF_TREE over the pseudorandom function `P`, a MAC keyed with K_in
/// (HMAC_GOSTR3411_2012_256 in RFC 7836, HMAC over Streebog-256), with an
/// iteration counter of R = 1 to 4 bytes:
/// K(i) = PRF(K_in, \[i\]_b || label || 0x00 || seed || \[L\]_b).
///
/// KDF_GOSTR3411_2012_256 (section 4.5) is KDF_TREE with R = 1 and 32 bytes of output.
#[derive(Clone)]
pub struct KDFTree<P: PRF> {
    prf: P,
    counter_bytes: usize,
}

impl<P: PRF> KDFTree<P> {
    pub fn new(prf: P, counter_bytes: usize) -> Result<KDFTree<P>, CryptoError> {
        if !(1..=4).contains(&counter_bytes) {
            return Err(CryptoError::InvalidParameter);
        }
        Ok(KDFTree { prf, counter_bytes })
    }

    /// The keying material of `out.len()` bytes (L = 8 × out.len() bits, at most
    /// 8 × OUTPUT_SIZE × (2^(8R) - 1), and at most 2^32 - 1 since \[L\]_b has
    /// at most 4 bytes here), from `label` and `seed`.
    pub fn derive(&self, label: &[u8], seed: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let blocks = out.len().div_ceil(P::OUTPUT_SIZE) as u64;
        let bits = out.len() as u64 * 8;
        if out.is_empty() || blocks > (1u64 << (8 * self.counter_bytes)) - 1 || bits > u32::MAX as u64 {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        // [L]_b: big-endian without leading zero bytes.
        let length = (bits as u32).to_be_bytes();
        let length = &length[(bits as u32).leading_zeros() as usize / 8..];
        for (index, piece) in out.chunks_mut(P::OUTPUT_SIZE).enumerate() {
            let counter = (index as u32 + 1).to_be_bytes();
            let mut prf = self.prf.clone();
            prf.reset();
            prf.update(&counter[4 - self.counter_bytes..]);
            prf.update(label);
            prf.update(&[0x00]);
            prf.update(seed);
            prf.update(length);
            let mut block = prf.finalize();
            piece.copy_from_slice(&block.as_ref()[..piece.len()]);
            block.as_mut().zeroize();
        }
        Ok(())
    }
}

impl<P: PRF + Zeroize> Zeroize for KDFTree<P> {
    fn zeroize(&mut self) {
        self.prf.zeroize();
    }
}

impl<P: PRF> fmt::Debug for KDFTree<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "KDFTree(R = {}, ..)", self.counter_bytes)
    }
}
