use core::fmt;

use super::{MLKEMFunctions, MLKEMParameters};
use crate::crypto::CryptoError;
use crate::math::lattice::{MLKEMRing, Polynomial};
use crate::secret::{Choice, ConstantTimeEq, Zeroize};

/// An encapsulation key of ML-KEM with the parameters `P`: t̂ in T_q^k, the
/// seed ρ of Â and H(ek), the hash of its encoding.
pub struct MLKEMEncapsulationKey<P: MLKEMParameters> {
    t_hat: P::Vector,
    rho: [u8; 32],
    hash: [u8; 32],
}

impl<P: MLKEMParameters> MLKEMEncapsulationKey<P> {
    /// The key of t̂ and ρ; its hash is that of its encoding.
    pub fn new(t_hat: P::Vector, rho: [u8; 32]) -> MLKEMEncapsulationKey<P> {
        let mut key = MLKEMEncapsulationKey { t_hat, rho, hash: [0; 32] };
        let mut encoded = [0u8; 384 * 4 + 32];
        let encoded = &mut encoded[..P::ENCAPSULATION_KEY_SIZE];
        key.write_bytes(encoded);
        key.hash = MLKEMFunctions::h(encoded);
        key
    }

    /// The key of the encoding ek, checked as FIPS 203 section 7.2 requires:
    /// 384 k + 32 bytes (type check) whose integers are all below q
    /// (modulus check); fails with `InvalidKey` otherwise.
    pub fn from_bytes(bytes: &[u8]) -> Result<MLKEMEncapsulationKey<P>, CryptoError> {
        let (t_hat, rho, canonical) = MLKEMEncapsulationKey::<P>::decode(bytes)?;
        if !canonical.into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(MLKEMEncapsulationKey { t_hat, rho, hash: MLKEMFunctions::h(bytes) })
    }

    /// t̂ and ρ of 384 k + 32 bytes, each integer reduced modulo q, and
    /// whether all of them were below q (ByteDecode_12 of FIPS 203).
    pub fn decode(bytes: &[u8]) -> Result<(P::Vector, [u8; 32], Choice), CryptoError> {
        if bytes.len() != P::ENCAPSULATION_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }
        let mut t_hat = P::Vector::default();
        let mut canonical = Choice::TRUE;
        for (element, chunk) in t_hat.as_mut().iter_mut().zip(bytes.as_chunks::<384>().0) {
            let (polynomial, valid) =
                Polynomial::<MLKEMRing>::read_bits(12, chunk).map_err(|_| CryptoError::InvalidKey)?;
            *element = polynomial;
            canonical &= valid;
        }
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&bytes[384 * P::K..]);
        Ok((t_hat, rho, canonical))
    }

    /// Writes ek = ByteEncode_12(t̂) || ρ into `out` of 384 k + 32 bytes.
    pub fn write_bytes(&self, out: &mut [u8]) {
        for (element, chunk) in self.t_hat.as_ref().iter().zip(out.as_chunks_mut::<384>().0) {
            // The chunk has the 384 bytes of 256 integers of 12 bits.
            let _ = element.write_bits(12, chunk);
        }
        out[384 * P::K..].copy_from_slice(&self.rho);
    }

    pub fn t_hat(&self) -> &P::Vector {
        &self.t_hat
    }

    pub fn rho(&self) -> &[u8; 32] {
        &self.rho
    }

    /// H(ek).
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Â: the entry (i, j) is SampleNTT(ρ || j || i) (FIPS 203 algorithm 13 lines 3 to 7).
    pub fn matrix(&self) -> P::Matrix {
        let mut matrix = P::Matrix::default();
        for (i, row) in matrix.as_mut().iter_mut().enumerate() {
            for (j, entry) in row.as_mut().iter_mut().enumerate() {
                *entry = MLKEMFunctions::sample_ntt(&self.rho, j as u8, i as u8);
            }
        }
        matrix
    }
}

impl<P: MLKEMParameters> Clone for MLKEMEncapsulationKey<P> {
    fn clone(&self) -> MLKEMEncapsulationKey<P> {
        MLKEMEncapsulationKey { t_hat: self.t_hat, rho: self.rho, hash: self.hash }
    }
}

impl<P: MLKEMParameters> PartialEq for MLKEMEncapsulationKey<P> {
    fn eq(&self, other: &MLKEMEncapsulationKey<P>) -> bool {
        (self.t_hat.as_ref().ct_eq(other.t_hat.as_ref()) & self.rho.ct_eq(&other.rho)).into_bool()
    }
}

impl<P: MLKEMParameters> Eq for MLKEMEncapsulationKey<P> {}

/// Prints the parameter set and H(ek).
impl<P: MLKEMParameters> fmt::Debug for MLKEMEncapsulationKey<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "MLKEMEncapsulationKey({}, H(ek) = ", P::NAME)?;
        for byte in &self.hash {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

/// A decapsulation key of ML-KEM with the parameters `P`: ŝ, the
/// encapsulation key, the value z of implicit rejection and, when known,
/// the seed (d, z) it was generated from; zeroized when dropped.
pub struct MLKEMDecapsulationKey<P: MLKEMParameters> {
    s_hat: P::Vector,
    encapsulation: MLKEMEncapsulationKey<P>,
    z: [u8; 32],
    seed: Option<[u8; 64]>,
}

impl<P: MLKEMParameters> MLKEMDecapsulationKey<P> {
    pub fn new(
        s_hat: P::Vector,
        encapsulation: MLKEMEncapsulationKey<P>,
        z: [u8; 32],
        seed: Option<[u8; 64]>,
    ) -> MLKEMDecapsulationKey<P> {
        MLKEMDecapsulationKey { s_hat, encapsulation, z, seed }
    }

    /// The key of the encoding dk = ByteEncode_12(ŝ) || ek || H(ek) || z,
    /// checked as FIPS 203 section 7.3 requires: 768 k + 96 bytes (type
    /// check) and H(ek) the hash of the ek it holds (hash check); fails
    /// with `InvalidKey` otherwise. Integers of ŝ and t̂ not below q are
    /// reduced, as ByteDecode_12 does; the key then writes them reduced.
    pub fn from_bytes(bytes: &[u8]) -> Result<MLKEMDecapsulationKey<P>, CryptoError> {
        if bytes.len() != P::DECAPSULATION_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }
        let (secret, rest) = bytes.split_at(384 * P::K);
        let (encapsulation, rest) = rest.split_at(P::ENCAPSULATION_KEY_SIZE);
        let (hash, z) = rest.split_at(32);
        if !MLKEMFunctions::h(encapsulation).as_slice().ct_eq(hash).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let (t_hat, rho, _) = MLKEMEncapsulationKey::<P>::decode(encapsulation)?;
        let mut key_hash = [0u8; 32];
        key_hash.copy_from_slice(hash);
        let mut s_hat = P::Vector::default();
        for (element, chunk) in s_hat.as_mut().iter_mut().zip(secret.as_chunks::<384>().0) {
            let (polynomial, _) = Polynomial::<MLKEMRing>::read_bits(12, chunk).map_err(|_| CryptoError::InvalidKey)?;
            *element = polynomial;
        }
        let mut z_bytes = [0u8; 32];
        z_bytes.copy_from_slice(z);
        let encapsulation = MLKEMEncapsulationKey { t_hat, rho, hash: key_hash };
        Ok(MLKEMDecapsulationKey { s_hat, encapsulation, z: z_bytes, seed: None })
    }

    /// Writes dk into `out` of 768 k + 96 bytes.
    pub fn write_bytes(&self, out: &mut [u8]) {
        let (secret, rest) = out.split_at_mut(384 * P::K);
        for (element, chunk) in self.s_hat.as_ref().iter().zip(secret.as_chunks_mut::<384>().0) {
            // The chunk has the 384 bytes of 256 integers of 12 bits.
            let _ = element.write_bits(12, chunk);
        }
        let (encapsulation, rest) = rest.split_at_mut(P::ENCAPSULATION_KEY_SIZE);
        self.encapsulation.write_bytes(encapsulation);
        rest[..32].copy_from_slice(&self.encapsulation.hash);
        rest[32..].copy_from_slice(&self.z);
    }

    pub fn s_hat(&self) -> &P::Vector {
        &self.s_hat
    }

    pub fn encapsulation_key(&self) -> &MLKEMEncapsulationKey<P> {
        &self.encapsulation
    }

    pub fn z(&self) -> &[u8; 32] {
        &self.z
    }

    /// The seed d || z of the key, if it was generated or read from one.
    pub fn seed(&self) -> Option<&[u8; 64]> {
        self.seed.as_ref()
    }
}

impl<P: MLKEMParameters> Zeroize for MLKEMDecapsulationKey<P> {
    fn zeroize(&mut self) {
        self.s_hat.zeroize();
        self.z.zeroize();
        self.seed.zeroize();
    }
}

impl<P: MLKEMParameters> Drop for MLKEMDecapsulationKey<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the encapsulation key, not the secrets.
impl<P: MLKEMParameters> fmt::Debug for MLKEMDecapsulationKey<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "MLKEMDecapsulationKey({:?}, ..)", self.encapsulation)
    }
}
