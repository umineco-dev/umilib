use core::marker::PhantomData;

use super::{MLKEMDecapsulationKey, MLKEMEncapsulationKey, MLKEMFunctions, MLKEMParameters};
use crate::crypto::random::Random;
use crate::crypto::{CryptoError, KeyEncapsulation};
use crate::math::lattice::{MLKEMRing, Polynomial, PolynomialMatrix, PolynomialVector};
use crate::secret::{ConditionallySelectable, ConstantTimeEq, Zeroize};

/// ML-KEM with the parameters `P` (FIPS 203): `MLKEM<MLKEM768>`. The
/// functions of K-PKE (section 5) and the internal functions of ML-KEM
/// (section 6), which take their randomness as arguments for testing, are
/// associated functions too; [`KeyEncapsulation`] gives the algorithms of
/// section 7. The shared secret has 32 bytes.
pub struct MLKEM<P: MLKEMParameters> {
    parameters: PhantomData<P>,
}

impl<P: MLKEMParameters> MLKEM<P> {
    /// K-PKE.KeyGen (algorithm 13) of the seed d: ŝ and the encryption key (t̂, ρ).
    pub fn kpke_key_gen(d: &[u8; 32]) -> (P::Vector, MLKEMEncapsulationKey<P>) {
        let (rho, mut sigma) = MLKEMFunctions::g(&[d, &[P::K as u8]]);
        let mut matrix = P::Matrix::default();
        for (i, row) in matrix.as_mut().iter_mut().enumerate() {
            for (j, entry) in row.as_mut().iter_mut().enumerate() {
                *entry = MLKEMFunctions::sample_ntt(&rho, j as u8, i as u8);
            }
        }
        let (mut s, mut e) = (P::Vector::default(), P::Vector::default());
        for (counter, element) in s.as_mut().iter_mut().chain(e.as_mut().iter_mut()).enumerate() {
            *element = MLKEMFunctions::sample_cbd(P::ETA1, &sigma, counter as u8);
        }
        sigma.zeroize();
        let s_hat = s.ntt();
        let mut e_hat = e.ntt();
        let t_hat = matrix.multiply_ntt::<P::Vector>(&s_hat).add(&e_hat);
        s.zeroize();
        e.zeroize();
        e_hat.zeroize();
        (s_hat, MLKEMEncapsulationKey::new(t_hat, rho))
    }

    /// K-PKE.Encrypt (algorithm 14) of the message `message` with the
    /// randomness `randomness` into `out` of the bytes of a ciphertext.
    pub fn kpke_encrypt(key: &MLKEMEncapsulationKey<P>, message: &[u8; 32], randomness: &[u8; 32], out: &mut [u8]) {
        let matrix = key.matrix();
        let (mut y, mut e1) = (P::Vector::default(), P::Vector::default());
        for (counter, element) in y.as_mut().iter_mut().enumerate() {
            *element = MLKEMFunctions::sample_cbd(P::ETA1, randomness, counter as u8);
        }
        for (counter, element) in e1.as_mut().iter_mut().enumerate() {
            *element = MLKEMFunctions::sample_cbd(P::ETA2, randomness, (P::K + counter) as u8);
        }
        let mut e2 = MLKEMFunctions::sample_cbd(P::ETA2, randomness, (2 * P::K) as u8);
        let mut y_hat = y.ntt();
        let mut u = matrix.multiply_transposed_ntt(&y_hat).inverse_ntt().add(&e1);
        // μ = Decompress_1(ByteDecode_1(m)); the 32 bytes have the 256 bits.
        let mut mu = Polynomial::<MLKEMRing>::read_bits(1, message).map(|(mu, _)| mu).unwrap_or_default();
        mu = mu.decompress(1);
        let mut v = key.t_hat().dot_ntt(&y_hat).inverse_ntt().add(&e2).add(&mu);
        let (first, second) = out.split_at_mut(32 * P::DU as usize * P::K);
        for (element, chunk) in u.as_ref().iter().zip(first.chunks_exact_mut(32 * P::DU as usize)) {
            // Each chunk has the bytes of 256 integers of d_u bits.
            let _ = element.compress(P::DU).write_bits(P::DU, chunk);
        }
        let _ = v.compress(P::DV).write_bits(P::DV, second);
        y.zeroize();
        e1.zeroize();
        e2.zeroize();
        y_hat.zeroize();
        u.zeroize();
        mu.zeroize();
        v.zeroize();
    }

    /// K-PKE.Decrypt (algorithm 15) of the ciphertext `ciphertext` (of the
    /// bytes of a ciphertext) with ŝ.
    pub fn kpke_decrypt(s_hat: &P::Vector, ciphertext: &[u8]) -> [u8; 32] {
        let (first, second) = ciphertext.split_at(32 * P::DU as usize * P::K);
        let mut u = P::Vector::default();
        for (element, chunk) in u.as_mut().iter_mut().zip(first.chunks_exact(32 * P::DU as usize)) {
            // Each chunk has the bytes of 256 integers of d_u bits, all below 2^d_u < q.
            let polynomial =
                Polynomial::<MLKEMRing>::read_bits(P::DU, chunk).map(|(value, _)| value).unwrap_or_default();
            *element = polynomial.decompress(P::DU);
        }
        let v = Polynomial::<MLKEMRing>::read_bits(P::DV, second).map(|(value, _)| value).unwrap_or_default();
        let mut w = v.decompress(P::DV).sub(&s_hat.dot_ntt(&u.ntt()).inverse_ntt());
        let mut message = [0u8; 32];
        // 32 bytes hold the 256 bits.
        let _ = w.compress(1).write_bits(1, &mut message);
        u.zeroize();
        w.zeroize();
        message
    }

    /// ML-KEM.KeyGen_internal (algorithm 16) of the seeds d and z.
    pub fn key_gen_internal(d: &[u8; 32], z: &[u8; 32]) -> MLKEMDecapsulationKey<P> {
        let (s_hat, encapsulation) = MLKEM::<P>::kpke_key_gen(d);
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(d);
        seed[32..].copy_from_slice(z);
        MLKEMDecapsulationKey::new(s_hat, encapsulation, *z, Some(seed))
    }

    /// The decapsulation key of the seed d || z of 64 bytes (FIPS 203
    /// section 3.3); fails with `InvalidKey` for another length.
    pub fn decapsulation_key_from_seed(seed: &[u8]) -> Result<MLKEMDecapsulationKey<P>, CryptoError> {
        if seed.len() != 64 {
            return Err(CryptoError::InvalidKey);
        }
        let (mut d, mut z) = ([0u8; 32], [0u8; 32]);
        d.copy_from_slice(&seed[..32]);
        z.copy_from_slice(&seed[32..]);
        let key = MLKEM::<P>::key_gen_internal(&d, &z);
        d.zeroize();
        z.zeroize();
        Ok(key)
    }

    /// Writes the seed d || z of `key` into `out` of 64 bytes; fails with
    /// `InvalidKey` for a key read from its expanded encoding, whose seed is
    /// unknown.
    pub fn write_seed(key: &MLKEMDecapsulationKey<P>, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != 64 {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        out.copy_from_slice(key.seed().ok_or(CryptoError::InvalidKey)?);
        Ok(())
    }

    /// ML-KEM.Encaps_internal (algorithm 17) with the randomness m: the
    /// ciphertext into `ciphertext` and K into `shared` (32 bytes).
    pub fn encapsulate_internal(
        key: &MLKEMEncapsulationKey<P>,
        message: &[u8; 32],
        ciphertext: &mut [u8],
        shared: &mut [u8],
    ) -> Result<(), CryptoError> {
        if ciphertext.len() != P::CIPHERTEXT_SIZE {
            return Err(CryptoError::InputLength { length: ciphertext.len() });
        }
        if shared.len() != 32 {
            return Err(CryptoError::InputLength { length: shared.len() });
        }
        let (mut secret, mut randomness) = MLKEMFunctions::g(&[message, key.hash()]);
        MLKEM::<P>::kpke_encrypt(key, message, &randomness, ciphertext);
        shared.copy_from_slice(&secret);
        secret.zeroize();
        randomness.zeroize();
        Ok(())
    }

    /// ML-KEM.Decaps_internal (algorithm 18): K' into `shared` (32 bytes),
    /// or K̄ = J(z || c) if the ciphertext is not the one the decrypted
    /// message encrypts to, chosen in constant time (implicit rejection).
    pub fn decapsulate_internal(
        key: &MLKEMDecapsulationKey<P>,
        ciphertext: &[u8],
        shared: &mut [u8],
    ) -> Result<(), CryptoError> {
        if ciphertext.len() != P::CIPHERTEXT_SIZE {
            return Err(CryptoError::InputLength { length: ciphertext.len() });
        }
        if shared.len() != 32 {
            return Err(CryptoError::InputLength { length: shared.len() });
        }
        let encapsulation = key.encapsulation_key();
        let mut message = MLKEM::<P>::kpke_decrypt(key.s_hat(), ciphertext);
        let (mut secret, mut randomness) = MLKEMFunctions::g(&[&message, encapsulation.hash()]);
        let mut rejection = MLKEMFunctions::j(&[key.z(), ciphertext]);
        let mut again = [0u8; MLKEMFunctions::LARGEST_CIPHERTEXT];
        let again = &mut again[..P::CIPHERTEXT_SIZE];
        MLKEM::<P>::kpke_encrypt(encapsulation, &message, &randomness, again);
        let equal = again.ct_eq(ciphertext);
        for ((out, accepted), rejected) in shared.iter_mut().zip(&secret).zip(&rejection) {
            *out = u8::select(rejected, accepted, equal);
        }
        message.zeroize();
        secret.zeroize();
        randomness.zeroize();
        rejection.zeroize();
        again.zeroize();
        Ok(())
    }
}

impl<P: MLKEMParameters> KeyEncapsulation for MLKEM<P> {
    type DecapsulationKey = MLKEMDecapsulationKey<P>;
    type EncapsulationKey = MLKEMEncapsulationKey<P>;
    const DECAPSULATION_KEY_SIZE: usize = P::DECAPSULATION_KEY_SIZE;
    const ENCAPSULATION_KEY_SIZE: usize = P::ENCAPSULATION_KEY_SIZE;
    const CIPHERTEXT_SIZE: usize = P::CIPHERTEXT_SIZE;
    const SHARED_SECRET_SIZE: usize = 32;

    /// ML-KEM.KeyGen (algorithm 19): d and z from `random`.
    fn generate<R: Random>(random: &mut R) -> Result<MLKEMDecapsulationKey<P>, CryptoError> {
        let mut seed = [0u8; 64];
        let result = random.fill(&mut seed).map_err(|_| CryptoError::RandomFailed);
        let key = result.and_then(|_| MLKEM::<P>::decapsulation_key_from_seed(&seed));
        seed.zeroize();
        key
    }

    fn decapsulation_key_from_bytes(bytes: &[u8]) -> Result<MLKEMDecapsulationKey<P>, CryptoError> {
        MLKEMDecapsulationKey::from_bytes(bytes)
    }

    fn write_decapsulation_key(key: &MLKEMDecapsulationKey<P>, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != P::DECAPSULATION_KEY_SIZE {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        key.write_bytes(out);
        Ok(())
    }

    fn encapsulation_key(key: &MLKEMDecapsulationKey<P>) -> MLKEMEncapsulationKey<P> {
        key.encapsulation_key().clone()
    }

    fn encapsulation_key_from_bytes(bytes: &[u8]) -> Result<MLKEMEncapsulationKey<P>, CryptoError> {
        MLKEMEncapsulationKey::from_bytes(bytes)
    }

    fn write_encapsulation_key(key: &MLKEMEncapsulationKey<P>, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != P::ENCAPSULATION_KEY_SIZE {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        key.write_bytes(out);
        Ok(())
    }

    /// ML-KEM.Encaps (algorithm 20): m from `random`.
    fn encapsulate<R: Random>(
        key: &MLKEMEncapsulationKey<P>,
        random: &mut R,
        ciphertext: &mut [u8],
        shared: &mut [u8],
    ) -> Result<(), CryptoError> {
        let mut message = [0u8; 32];
        let result = random.fill(&mut message).map_err(|_| CryptoError::RandomFailed);
        let result = result.and_then(|_| MLKEM::<P>::encapsulate_internal(key, &message, ciphertext, shared));
        message.zeroize();
        result
    }

    /// ML-KEM.Decaps (algorithm 21).
    fn decapsulate(key: &MLKEMDecapsulationKey<P>, ciphertext: &[u8], shared: &mut [u8]) -> Result<(), CryptoError> {
        MLKEM::<P>::decapsulate_internal(key, ciphertext, shared)
    }
}
