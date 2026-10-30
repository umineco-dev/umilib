use core::fmt;

use super::{MLDSAFunctions, MLDSAParameters};
use crate::crypto::CryptoError;
use crate::math::lattice::{LatticeRing, MLDSARing, Polynomial, PolynomialMatrix, PolynomialVector};
use crate::secret::{ConstantTimeEq, Zeroize};

/// A public key of ML-DSA with the parameters `P`: the seed ρ of Â, t1 and
/// tr = H(pk, 64).
pub struct MLDSAVerifyingKey<P: MLDSAParameters> {
    rho: [u8; 32],
    t1: P::VectorK,
    tr: [u8; 64],
}

impl<P: MLDSAParameters> MLDSAVerifyingKey<P> {
    /// The key of ρ and t1 (coefficients below 2^10).
    pub fn new(rho: [u8; 32], t1: P::VectorK) -> MLDSAVerifyingKey<P> {
        let mut key = MLDSAVerifyingKey { rho, t1, tr: [0; 64] };
        let mut encoded = [0u8; 32 + 320 * 8];
        let encoded = &mut encoded[..P::PUBLIC_KEY_SIZE];
        key.write_bytes(encoded);
        MLDSAFunctions::<P>::h(&[encoded], &mut key.tr);
        key
    }

    /// pkDecode (algorithm 23) of a public key of the size of `P`; fails
    /// with `InvalidKey` for another length. Every encoding of that length
    /// is a key.
    pub fn from_bytes(bytes: &[u8]) -> Result<MLDSAVerifyingKey<P>, CryptoError> {
        if bytes.len() != P::PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&bytes[..32]);
        let mut t1 = P::VectorK::default();
        for (element, chunk) in t1.as_mut().iter_mut().zip(bytes[32..].as_chunks::<320>().0) {
            // 10-bit values are below q.
            *element = Polynomial::<MLDSARing>::read_bits(10, chunk).map_err(|_| CryptoError::InvalidKey)?.0;
        }
        let mut tr = [0u8; 64];
        MLDSAFunctions::<P>::h(&[bytes], &mut tr);
        Ok(MLDSAVerifyingKey { rho, t1, tr })
    }

    /// pkEncode (algorithm 22) into `out` of the size of a public key.
    pub fn write_bytes(&self, out: &mut [u8]) {
        out[..32].copy_from_slice(&self.rho);
        MLDSAFunctions::<P>::simple_bit_pack(&self.t1, 10, &mut out[32..]);
    }

    pub fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    pub fn t1(&self) -> &P::VectorK {
        &self.t1
    }

    /// tr = H(pk, 64).
    pub fn tr(&self) -> &[u8; 64] {
        &self.tr
    }
}

impl<P: MLDSAParameters> Clone for MLDSAVerifyingKey<P> {
    fn clone(&self) -> MLDSAVerifyingKey<P> {
        MLDSAVerifyingKey { rho: self.rho, t1: self.t1, tr: self.tr }
    }
}

impl<P: MLDSAParameters> PartialEq for MLDSAVerifyingKey<P> {
    fn eq(&self, other: &MLDSAVerifyingKey<P>) -> bool {
        self.rho == other.rho && self.t1.as_ref() == other.t1.as_ref()
    }
}

impl<P: MLDSAParameters> Eq for MLDSAVerifyingKey<P> {}

/// Prints the parameter set and tr.
impl<P: MLDSAParameters> fmt::Debug for MLDSAVerifyingKey<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "MLDSAVerifyingKey({}, tr = ", P::NAME)?;
        for byte in &self.tr {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

/// A private key of ML-DSA with the parameters `P`: ρ, K, tr, s1, s2 and
/// t0, its public key and, when known, the seed ξ it was generated from;
/// zeroized when dropped.
pub struct MLDSASigningKey<P: MLDSAParameters> {
    key: [u8; 32],
    s1: P::VectorL,
    s2: P::VectorK,
    t0: P::VectorK,
    verifying: MLDSAVerifyingKey<P>,
    seed: Option<[u8; 32]>,
}

impl<P: MLDSAParameters> MLDSASigningKey<P> {
    /// The key of K, s1, s2 (coefficients in \[-η, η\]) and the seed ρ'
    /// of Â: t = A s1 + s2 is computed and split into t1 and t0 by
    /// Power2Round (algorithm 6 lines 3 to 9).
    pub fn new(
        rho: [u8; 32],
        key: [u8; 32],
        s1: P::VectorL,
        s2: P::VectorK,
        seed: Option<[u8; 32]>,
    ) -> MLDSASigningKey<P> {
        let matrix = alloc::boxed::Box::new(MLDSAFunctions::<P>::expand_a(&rho));
        let mut t = matrix.multiply_ntt::<P::VectorK>(&s1.ntt()).inverse_ntt().add(&s2);
        let (mut t1, mut t0) = (P::VectorK::default(), P::VectorK::default());
        for ((value, high), low) in t.as_ref().iter().zip(t1.as_mut()).zip(t0.as_mut()) {
            for index in 0..MLDSARing::N {
                let (r1, r0) = MLDSAFunctions::<P>::power2round(value.get(index));
                high.set(index, r1);
                low.set(index, r0);
            }
        }
        t.zeroize();
        let verifying = MLDSAVerifyingKey::new(rho, t1);
        MLDSASigningKey { key, s1, s2, t0, verifying, seed }
    }

    /// skDecode (algorithm 25) of a private key of the size of `P`; fails
    /// with `InvalidKey` for another length, for coefficients of s1 or s2
    /// outside \[-η, η\] (which only a malformed key has) and for a key whose
    /// t0 and tr are not those of its s1, s2 and ρ.
    pub fn from_bytes(bytes: &[u8]) -> Result<MLDSASigningKey<P>, CryptoError> {
        if bytes.len() != P::PRIVATE_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }
        let (mut rho, mut key) = ([0u8; 32], [0u8; 32]);
        rho.copy_from_slice(&bytes[..32]);
        key.copy_from_slice(&bytes[32..64]);
        let size = 32 * P::ETA_BITS as usize;
        let (mut s1, mut s2, mut t0) = (P::VectorL::default(), P::VectorK::default(), P::VectorK::default());
        let mut valid = true;
        let mut chunks = bytes[128..].chunks_exact(size);
        for element in s1.as_mut().iter_mut().chain(s2.as_mut().iter_mut()) {
            let chunk = chunks.next().ok_or(CryptoError::InvalidKey)?;
            *element = MLDSAFunctions::<P>::bit_unpack(chunk, P::ETA, P::ETA);
            valid &= MLDSAFunctions::<P>::in_range(element, P::ETA, P::ETA);
        }
        let half = 1 << (P::D - 1);
        let t0_start = 128 + (P::K + P::L) * size;
        for (element, chunk) in t0.as_mut().iter_mut().zip(bytes[t0_start..].chunks_exact(32 * P::D as usize)) {
            *element = MLDSAFunctions::<P>::bit_unpack(chunk, half - 1, half);
        }
        let mut signing = MLDSASigningKey::<P>::new(rho, key, s1, s2, None);
        valid &= signing.t0.as_ref().ct_eq(t0.as_ref()).into_bool();
        valid &= signing.verifying.tr.as_slice().ct_eq(&bytes[64..128]).into_bool();
        key.zeroize();
        s1.zeroize();
        s2.zeroize();
        t0.zeroize();
        if !valid {
            signing.zeroize();
            return Err(CryptoError::InvalidKey);
        }
        Ok(signing)
    }

    /// skEncode (algorithm 24) into `out` of the size of a private key.
    pub fn write_bytes(&self, out: &mut [u8]) {
        out[..32].copy_from_slice(&self.verifying.rho);
        out[32..64].copy_from_slice(&self.key);
        out[64..128].copy_from_slice(&self.verifying.tr);
        let size = 32 * P::ETA_BITS as usize;
        let mut chunks = out[128..].chunks_exact_mut(size);
        for element in self.s1.as_ref().iter().chain(self.s2.as_ref()) {
            if let Some(chunk) = chunks.next() {
                MLDSAFunctions::<P>::bit_pack(element, P::ETA, P::ETA, chunk);
            }
        }
        let half = 1 << (P::D - 1);
        let t0_start = 128 + (P::K + P::L) * size;
        for (element, chunk) in self.t0.as_ref().iter().zip(out[t0_start..].chunks_exact_mut(32 * P::D as usize)) {
            MLDSAFunctions::<P>::bit_pack(element, half - 1, half, chunk);
        }
    }

    /// K, the seed of the signing randomness.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn s1(&self) -> &P::VectorL {
        &self.s1
    }

    pub fn s2(&self) -> &P::VectorK {
        &self.s2
    }

    pub fn t0(&self) -> &P::VectorK {
        &self.t0
    }

    pub fn verifying_key(&self) -> &MLDSAVerifyingKey<P> {
        &self.verifying
    }

    /// The seed ξ of the key, if it was generated or read from one.
    pub fn seed(&self) -> Option<&[u8; 32]> {
        self.seed.as_ref()
    }
}

impl<P: MLDSAParameters> Zeroize for MLDSASigningKey<P> {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.s1.zeroize();
        self.s2.zeroize();
        self.t0.zeroize();
        self.seed.zeroize();
    }
}

impl<P: MLDSAParameters> Drop for MLDSASigningKey<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the public key, not the secrets.
impl<P: MLDSAParameters> fmt::Debug for MLDSASigningKey<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "MLDSASigningKey({:?}, ..)", self.verifying)
    }
}
