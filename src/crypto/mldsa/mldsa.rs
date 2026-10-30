use alloc::boxed::Box;
use core::marker::PhantomData;

use super::{MLDSAFunctions, MLDSAParameters, MLDSASigningKey, MLDSAVerifyingKey};
use crate::crypto::random::Random;
use crate::crypto::{CryptoError, PreHash, SignatureScheme};
use crate::hash::sha::v3::SHAKE256;
use crate::hash::{ExtendableOutput, XOFReader};
use crate::math::lattice::{MLDSARing, Polynomial, PolynomialMatrix, PolynomialVector};
use crate::secret::{ConstantTimeEq, Zeroize};

/// ML-DSA with the parameters `P` (FIPS 204): `MLDSA<MLDSA65>`.
///
/// The signing functions take a context of at most 255 bytes and come in
/// the hedged variant (`sign_with_context`, rnd from a generator) and the deterministic
/// one (`sign_deterministic_with_context`, rnd = 0^32); `_pre_hash` gives HashML-DSA
/// with a [`PreHash`] function, `_mu` the internal functions on the message
/// representative μ, and `_internal` those of section 6 on M'.
/// [`SignatureScheme`] signs deterministically with the empty context.
pub struct MLDSA<P: MLDSAParameters> {
    parameters: PhantomData<P>,
}

impl<P: MLDSAParameters> MLDSA<P> {
    /// ML-DSA.KeyGen_internal (algorithm 6) of the seed ξ.
    pub fn key_gen_internal(xi: &[u8; 32]) -> MLDSASigningKey<P> {
        let mut expanded = [0u8; 128];
        MLDSAFunctions::<P>::h(&[xi, &[P::K as u8, P::L as u8]], &mut expanded);
        let (mut rho, mut rho_prime, mut key) = ([0u8; 32], [0u8; 64], [0u8; 32]);
        rho.copy_from_slice(&expanded[..32]);
        rho_prime.copy_from_slice(&expanded[32..96]);
        key.copy_from_slice(&expanded[96..]);
        let (s1, s2) = MLDSAFunctions::<P>::expand_s(&rho_prime);
        let signing = MLDSASigningKey::new(rho, key, s1, s2, Some(*xi));
        expanded.zeroize();
        rho_prime.zeroize();
        key.zeroize();
        signing
    }

    /// The private key of the seed ξ of 32 bytes; fails with `InvalidKey` for another length.
    pub fn signing_key_from_seed(seed: &[u8]) -> Result<MLDSASigningKey<P>, CryptoError> {
        let mut xi: [u8; 32] = seed.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let key = MLDSA::<P>::key_gen_internal(&xi);
        xi.zeroize();
        Ok(key)
    }

    /// Writes the seed ξ of `key` into `out` of 32 bytes; fails with
    /// `InvalidKey` for a key read from its expanded encoding.
    pub fn write_seed(key: &MLDSASigningKey<P>, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != 32 {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        out.copy_from_slice(key.seed().ok_or(CryptoError::InvalidKey)?);
        Ok(())
    }

    /// μ = H(tr || M', 64) of M' = the concatenation of `parts`.
    pub fn message_representative(key: &MLDSAVerifyingKey<P>, parts: &[&[u8]]) -> [u8; 64] {
        let mut function = SHAKE256::default();
        function.update(key.tr());
        for part in parts {
            function.update(part);
        }
        let mut mu = [0u8; 64];
        function.finalize_xof().read(&mut mu);
        mu
    }

    /// The first bytes of M' for the domain separator (0 for ML-DSA, 1 for
    /// HashML-DSA) and the context; fails with `InvalidParameter` for a
    /// context of more than 255 bytes.
    pub fn prefix(domain: u8, context: &[u8]) -> Result<[u8; 2], CryptoError> {
        let length = u8::try_from(context.len()).map_err(|_| CryptoError::InvalidParameter)?;
        Ok([domain, length])
    }

    /// ĉ ∘ v̂: the product in T_q of ĉ with each entry of `vector`, all NTT representations.
    pub fn multiply_each_ntt<V: PolynomialVector<MLDSARing>>(c_hat: &Polynomial<MLDSARing>, vector: &V) -> V {
        let mut out = *vector;
        out.as_mut().iter_mut().for_each(|element| *element = c_hat.multiply_ntt(element));
        out
    }

    /// ML-DSA.Sign_internal (algorithm 7) from line 7, on the message
    /// representative μ and rnd: the signature into `out` of the size of a
    /// signature.
    pub fn sign_mu(key: &MLDSASigningKey<P>, mu: &[u8; 64], rnd: &[u8; 32], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != P::SIGNATURE_SIZE {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        let verifying = key.verifying_key();
        let matrix = Box::new(MLDSAFunctions::<P>::expand_a(verifying.rho()));
        let (mut s1_hat, mut s2_hat, mut t0_hat) = (key.s1().ntt(), key.s2().ntt(), key.t0().ntt());
        let mut rho_double_prime = [0u8; 64];
        MLDSAFunctions::<P>::h(&[key.key(), rnd, mu], &mut rho_double_prime);
        let mut kappa = 0u16;
        let mut w1_bytes = [0u8; 32 * 6 * 8];
        let w1_bytes = &mut w1_bytes[..32 * P::W1_BITS as usize * P::K];
        let mut challenge = [0u8; 64];
        let challenge = &mut challenge[..P::CHALLENGE_SIZE];
        loop {
            let mut y = MLDSAFunctions::<P>::expand_mask(&rho_double_prime, kappa);
            kappa = kappa.wrapping_add(P::L as u16);
            let mut w = matrix.multiply_ntt::<P::VectorK>(&y.ntt()).inverse_ntt();
            let mut w1 = w;
            for polynomial in w1.as_mut() {
                *polynomial = polynomial.map(|_, value| MLDSAFunctions::<P>::high_bits(value));
            }
            MLDSAFunctions::<P>::simple_bit_pack(&w1, P::W1_BITS, w1_bytes);
            MLDSAFunctions::<P>::h(&[mu, w1_bytes], challenge);
            let c_hat = MLDSAFunctions::<P>::sample_in_ball(challenge).ntt();
            let mut z = y.add(&MLDSA::<P>::multiply_each_ntt(&c_hat, &s1_hat).inverse_ntt());
            let mut w_minus = w.sub(&MLDSA::<P>::multiply_each_ntt(&c_hat, &s2_hat).inverse_ntt());
            let mut r0 = w_minus;
            for polynomial in r0.as_mut() {
                *polynomial = polynomial.map(|_, value| MLDSAFunctions::<P>::low_bits(value));
            }
            let mut accepted = MLDSAFunctions::<P>::norm_below(&z, P::GAMMA1 - P::BETA)
                & MLDSAFunctions::<P>::norm_below(&r0, P::GAMMA2 - P::BETA);
            let mut hint = P::VectorK::default();
            if accepted {
                let mut ct0 = MLDSA::<P>::multiply_each_ntt(&c_hat, &t0_hat).inverse_ntt();
                let sum = w_minus.add(&ct0);
                for ((target, low), high) in hint.as_mut().iter_mut().zip(ct0.as_ref()).zip(sum.as_ref()) {
                    *target = low.neg().combine(high, MLDSAFunctions::<P>::make_hint);
                }
                let ones: usize = hint
                    .as_ref()
                    .iter()
                    .map(|polynomial| polynomial.coefficients().iter().filter(|value| **value != 0).count())
                    .sum();
                accepted = MLDSAFunctions::<P>::norm_below(&ct0, P::GAMMA2) & (ones <= P::OMEGA);
                ct0.zeroize();
            }
            if accepted {
                out[..P::CHALLENGE_SIZE].copy_from_slice(challenge);
                let z_size = 32 * P::GAMMA1_BITS as usize;
                for (element, chunk) in z.as_ref().iter().zip(out[P::CHALLENGE_SIZE..].chunks_exact_mut(z_size)) {
                    MLDSAFunctions::<P>::bit_pack(element, P::GAMMA1 - 1, P::GAMMA1, chunk);
                }
                MLDSAFunctions::<P>::hint_bit_pack(&hint, &mut out[P::CHALLENGE_SIZE + P::L * z_size..]);
            }
            y.zeroize();
            w.zeroize();
            w1.zeroize();
            z.zeroize();
            w_minus.zeroize();
            r0.zeroize();
            if accepted {
                break;
            }
        }
        s1_hat.zeroize();
        s2_hat.zeroize();
        t0_hat.zeroize();
        rho_double_prime.zeroize();
        Ok(())
    }

    /// ML-DSA.Verify_internal (algorithm 8) from line 8, on μ; fails with
    /// `InvalidSignature` for a signature that is not one of μ.
    pub fn verify_mu(key: &MLDSAVerifyingKey<P>, mu: &[u8; 64], signature: &[u8]) -> Result<(), CryptoError> {
        if signature.len() != P::SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let (challenge, rest) = signature.split_at(P::CHALLENGE_SIZE);
        let z_size = 32 * P::GAMMA1_BITS as usize;
        let (z_bytes, hint_bytes) = rest.split_at(P::L * z_size);
        let hint = MLDSAFunctions::<P>::hint_bit_unpack(hint_bytes).ok_or(CryptoError::InvalidSignature)?;
        let mut z = P::VectorL::default();
        for (element, chunk) in z.as_mut().iter_mut().zip(z_bytes.chunks_exact(z_size)) {
            *element = MLDSAFunctions::<P>::bit_unpack(chunk, P::GAMMA1 - 1, P::GAMMA1);
        }
        if !MLDSAFunctions::<P>::norm_below(&z, P::GAMMA1 - P::BETA) {
            return Err(CryptoError::InvalidSignature);
        }
        let matrix = Box::new(MLDSAFunctions::<P>::expand_a(key.rho()));
        let c_hat = MLDSAFunctions::<P>::sample_in_ball(challenge).ntt();
        let mut shifted = *key.t1();
        for polynomial in shifted.as_mut() {
            *polynomial = polynomial.scale(1 << P::D);
        }
        let w_approx = matrix
            .multiply_ntt::<P::VectorK>(&z.ntt())
            .sub(&MLDSA::<P>::multiply_each_ntt(&c_hat, &shifted.ntt()))
            .inverse_ntt();
        let mut w1 = P::VectorK::default();
        for ((target, approximation), bits) in w1.as_mut().iter_mut().zip(w_approx.as_ref()).zip(hint.as_ref()) {
            *target = approximation.combine(bits, |value, hint| MLDSAFunctions::<P>::use_hint(hint, value));
        }
        let mut w1_bytes = [0u8; 32 * 6 * 8];
        let w1_bytes = &mut w1_bytes[..32 * P::W1_BITS as usize * P::K];
        MLDSAFunctions::<P>::simple_bit_pack(&w1, P::W1_BITS, w1_bytes);
        let mut expected = [0u8; 64];
        let expected = &mut expected[..P::CHALLENGE_SIZE];
        MLDSAFunctions::<P>::h(&[mu, w1_bytes], expected);
        if !expected.ct_eq(challenge).into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }

    /// ML-DSA.Sign_internal (algorithm 7) of M' = the concatenation of `parts`.
    pub fn sign_internal(
        key: &MLDSASigningKey<P>,
        parts: &[&[u8]],
        rnd: &[u8; 32],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let mu = MLDSA::<P>::message_representative(key.verifying_key(), parts);
        MLDSA::<P>::sign_mu(key, &mu, rnd, out)
    }

    /// ML-DSA.Verify_internal (algorithm 8) of M' = the concatenation of `parts`.
    pub fn verify_internal(key: &MLDSAVerifyingKey<P>, parts: &[&[u8]], signature: &[u8]) -> Result<(), CryptoError> {
        let mu = MLDSA::<P>::message_representative(key, parts);
        MLDSA::<P>::verify_mu(key, &mu, signature)
    }

    /// ML-DSA.Sign (algorithm 2) of `message` with `context` and rnd from `random`.
    pub fn sign_with_context<R: Random>(
        key: &MLDSASigningKey<P>,
        message: &[u8],
        context: &[u8],
        random: &mut R,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let prefix = MLDSA::<P>::prefix(0, context)?;
        let mut rnd = [0u8; 32];
        random.fill(&mut rnd).map_err(|_| CryptoError::RandomFailed)?;
        let result = MLDSA::<P>::sign_internal(key, &[&prefix, context, message], &rnd, out);
        rnd.zeroize();
        result
    }

    /// The deterministic variant of ML-DSA.Sign: rnd = 0^32.
    pub fn sign_deterministic_with_context(
        key: &MLDSASigningKey<P>,
        message: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let prefix = MLDSA::<P>::prefix(0, context)?;
        MLDSA::<P>::sign_internal(key, &[&prefix, context, message], &[0; 32], out)
    }

    /// ML-DSA.Verify (algorithm 3); fails with `InvalidParameter` for a
    /// context of more than 255 bytes and `InvalidSignature` for a
    /// signature that is not one of `message` with `context`.
    pub fn verify_with_context(
        key: &MLDSAVerifyingKey<P>,
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let prefix = MLDSA::<P>::prefix(0, context)?;
        MLDSA::<P>::verify_internal(key, &[&prefix, context, message], signature)
    }

    /// M' of HashML-DSA (algorithm 4 line 23) for `H`: its parts after the
    /// prefix are the context, the OID and PH(M), written into `digest`.
    pub fn pre_hash<H: PreHash>(message: &[u8], digest: &mut [u8; 64]) -> usize {
        H::pre_hash(message, &mut digest[..H::OUTPUT_SIZE]);
        H::OUTPUT_SIZE
    }

    /// HashML-DSA.Sign (algorithm 4) with the pre-hash `H` and rnd from `random`.
    pub fn sign_pre_hash<H: PreHash, R: Random>(
        key: &MLDSASigningKey<P>,
        message: &[u8],
        context: &[u8],
        random: &mut R,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let mut rnd = [0u8; 32];
        random.fill(&mut rnd).map_err(|_| CryptoError::RandomFailed)?;
        let result = MLDSA::<P>::sign_pre_hash_with_rnd::<H>(key, message, context, &rnd, out);
        rnd.zeroize();
        result
    }

    /// The deterministic variant of HashML-DSA.Sign: rnd = 0^32.
    pub fn sign_pre_hash_deterministic<H: PreHash>(
        key: &MLDSASigningKey<P>,
        message: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        MLDSA::<P>::sign_pre_hash_with_rnd::<H>(key, message, context, &[0; 32], out)
    }

    /// HashML-DSA.Sign with the given rnd.
    pub fn sign_pre_hash_with_rnd<H: PreHash>(
        key: &MLDSASigningKey<P>,
        message: &[u8],
        context: &[u8],
        rnd: &[u8; 32],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let prefix = MLDSA::<P>::prefix(1, context)?;
        let mut digest = [0u8; 64];
        let length = MLDSA::<P>::pre_hash::<H>(message, &mut digest);
        MLDSA::<P>::sign_internal(key, &[&prefix, context, H::OID, &digest[..length]], rnd, out)
    }

    /// HashML-DSA.Verify (algorithm 5) with the pre-hash `H`.
    pub fn verify_pre_hash<H: PreHash>(
        key: &MLDSAVerifyingKey<P>,
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let prefix = MLDSA::<P>::prefix(1, context)?;
        let mut digest = [0u8; 64];
        let length = MLDSA::<P>::pre_hash::<H>(message, &mut digest);
        MLDSA::<P>::verify_internal(key, &[&prefix, context, H::OID, &digest[..length]], signature)
    }
}

impl<P: MLDSAParameters> SignatureScheme for MLDSA<P> {
    type SigningKey = MLDSASigningKey<P>;
    type VerifyingKey = MLDSAVerifyingKey<P>;
    const SIGNING_KEY_SIZE: usize = P::PRIVATE_KEY_SIZE;
    const VERIFYING_KEY_SIZE: usize = P::PUBLIC_KEY_SIZE;
    const SIGNATURE_SIZE: usize = P::SIGNATURE_SIZE;

    /// ML-DSA.KeyGen (algorithm 1): ξ from `random`.
    fn generate<R: Random>(random: &mut R) -> Result<MLDSASigningKey<P>, CryptoError> {
        let mut xi = [0u8; 32];
        random.fill(&mut xi).map_err(|_| CryptoError::RandomFailed)?;
        let key = MLDSA::<P>::key_gen_internal(&xi);
        xi.zeroize();
        Ok(key)
    }

    fn signing_key_from_bytes(bytes: &[u8]) -> Result<MLDSASigningKey<P>, CryptoError> {
        MLDSASigningKey::from_bytes(bytes)
    }

    fn write_signing_key(key: &MLDSASigningKey<P>, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != P::PRIVATE_KEY_SIZE {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        key.write_bytes(out);
        Ok(())
    }

    fn verifying_key(key: &MLDSASigningKey<P>) -> MLDSAVerifyingKey<P> {
        key.verifying_key().clone()
    }

    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<MLDSAVerifyingKey<P>, CryptoError> {
        MLDSAVerifyingKey::from_bytes(bytes)
    }

    fn write_verifying_key(key: &MLDSAVerifyingKey<P>, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != P::PUBLIC_KEY_SIZE {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        key.write_bytes(out);
        Ok(())
    }

    /// The deterministic ML-DSA.Sign with the empty context.
    fn sign(key: &MLDSASigningKey<P>, message: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        MLDSA::<P>::sign_deterministic_with_context(key, message, &[], out)
    }

    /// ML-DSA.Verify with the empty context.
    fn verify(key: &MLDSAVerifyingKey<P>, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        MLDSA::<P>::verify_with_context(key, message, &[], signature)
    }
}
