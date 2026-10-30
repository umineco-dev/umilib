use alloc::vec;
use core::fmt;
use core::marker::PhantomData;

use super::{DSAParameters, DSASignature};
use crate::crypto::CryptoError;
use crate::crypto::random::{DRBGConfig, HMACDRBG, Random};
use crate::hash::CryptographicDigest;
use crate::math::bigint::BoxedUint;
use crate::secret::Zeroize;

/// DSA with the hash function `H`.
pub struct DSA<H: CryptographicDigest + Default> {
    hash: PhantomData<H>,
}

/// A signing key of [`DSA`]: the parameters, the private key x with
/// 1 ≤ x < q and its public key; zeroized when dropped.
#[derive(Clone)]
pub struct DSASigningKey {
    x: BoxedUint,
    verifying: DSAVerifyingKey,
}

impl DSASigningKey {
    /// The key x under `parameters`; fails with `InvalidKey` unless 1 ≤ x < q.
    pub fn new(parameters: DSAParameters, x: &BoxedUint) -> Result<DSASigningKey, CryptoError> {
        let q = parameters.q().value();
        if (x.is_zero() | !x.ct_lt(q)).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let x = x.resize(q.precision()).map_err(|_| CryptoError::InvalidKey)?;
        let p = parameters.p();
        let failed = |_| CryptoError::InvalidKey;
        let y = p.retrieve(&p.pow(&p.residue(parameters.g()), &x).map_err(failed)?).map_err(failed)?;
        Ok(DSASigningKey { x, verifying: DSAVerifyingKey { parameters, y } })
    }

    /// A key with x uniformly random in 1..q (FIPS 186-4 appendix B.1.2, by
    /// rejection sampling).
    pub fn generate<R: Random>(parameters: DSAParameters, random: &mut R) -> Result<DSASigningKey, CryptoError> {
        let q = parameters.q().value().clone();
        let bits = q.bit_length();
        let mut bytes = vec![0u8; bits.div_ceil(8) as usize];
        loop {
            random.fill(&mut bytes).map_err(|_| CryptoError::RandomFailed)?;
            let value = BoxedUint::from_be_bytes(&bytes, q.precision()).map_err(|_| CryptoError::InvalidParameter)?;
            let mut x = value.shr(8 * bytes.len() as u32 - bits);
            if (!x.is_zero() & x.ct_lt(&q)).into_bool() {
                let key = DSASigningKey::new(parameters, &x);
                x.zeroize();
                bytes.zeroize();
                return key;
            }
            x.zeroize();
        }
    }

    pub fn x(&self) -> &BoxedUint {
        &self.x
    }

    pub fn verifying_key(&self) -> &DSAVerifyingKey {
        &self.verifying
    }

    pub fn parameters(&self) -> &DSAParameters {
        &self.verifying.parameters
    }
}

impl Zeroize for DSASigningKey {
    fn zeroize(&mut self) {
        self.x.zeroize();
    }
}

impl Drop for DSASigningKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the parameters, not the key.
impl fmt::Debug for DSASigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "DSASigningKey({:?}, ..)", self.verifying.parameters)
    }
}

/// A verifying key of [`DSA`]: the parameters and y = g^x mod p.
#[derive(Clone, PartialEq, Eq)]
pub struct DSAVerifyingKey {
    parameters: DSAParameters,
    y: BoxedUint,
}

impl DSAVerifyingKey {
    /// The key y under `parameters`, validated as SP 800-89 section 5.3.2
    /// does: 2 ≤ y ≤ p - 2 and y^q = 1 mod p. Fails with `InvalidKey` otherwise.
    pub fn new(parameters: DSAParameters, y: &BoxedUint) -> Result<DSAVerifyingKey, CryptoError> {
        let invalid = |_| CryptoError::InvalidKey;
        let p = parameters.p();
        let two = BoxedUint::from_u64(2, 64).map_err(invalid)?;
        let p_minus_1 = p.value().wrapping_sub(&BoxedUint::one(64).map_err(invalid)?);
        if (y.ct_lt(&two) | !y.ct_lt(&p_minus_1)).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        if p.pow_vartime(&p.residue(y), parameters.q().value()).map_err(invalid)? != p.one() {
            return Err(CryptoError::InvalidKey);
        }
        let y = y.resize(p.precision()).map_err(invalid)?;
        Ok(DSAVerifyingKey { parameters, y })
    }

    pub fn y(&self) -> &BoxedUint {
        &self.y
    }

    pub fn parameters(&self) -> &DSAParameters {
        &self.parameters
    }
}

impl fmt::Debug for DSAVerifyingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "DSAVerifyingKey({:?}, y: {:?})", self.parameters, self.y)
    }
}

impl<H: CryptographicDigest + Default> DSA<H> {
    /// bits2int of a digest (RFC 6979 section 2.3.2): its leftmost bits, as
    /// many as q has; the z of FIPS 186-4 section 4.6, not reduced.
    pub fn digest_integer(parameters: &DSAParameters, digest: &[u8]) -> Result<BoxedUint, CryptoError> {
        let q = parameters.q().value();
        let bits = q.bit_length();
        let taken = &digest[..digest.len().min(parameters.q_bytes())];
        let value = BoxedUint::from_be_bytes(taken, q.precision()).map_err(|_| CryptoError::InvalidParameter)?;
        Ok(value.shr((8 * taken.len() as u32).saturating_sub(bits)))
    }

    /// The signature of `message` under `key` with the nonce of RFC 6979.
    pub fn sign(key: &DSASigningKey, message: &[u8]) -> Result<DSASignature, CryptoError> {
        DSA::<H>::sign_digest(key, H::digest(message).as_ref())
    }

    /// The signature of the digest `digest` (FIPS 186-4 section 4.6) with
    /// the nonce k of RFC 6979 section 3.2, HMAC_DRBG over `H` seeded with
    /// int2octets(x) and bits2octets(digest).
    pub fn sign_digest(key: &DSASigningKey, digest: &[u8]) -> Result<DSASignature, CryptoError> {
        let parameters = key.parameters();
        let (p, q) = (parameters.p(), parameters.q());
        let bytes = parameters.q_bytes();
        let bits = q.value().bit_length();
        let failed = |_| CryptoError::InvalidKey;
        let z = DSA::<H>::digest_integer(parameters, digest)?;
        let z_reduced = q.residue(&z);
        let mut seed = vec![0u8; 2 * bytes];
        key.x.write_be_bytes(&mut seed[..bytes]).map_err(failed)?;
        q.retrieve(&z_reduced).map_err(failed)?.write_be_bytes(&mut seed[bytes..]).map_err(failed)?;
        let mut generator = HMACDRBG::<H>::with_seed(DRBGConfig::default(), &[&seed]);
        seed.zeroize();
        let mut candidate = vec![0u8; bytes];
        let x = q.residue(&key.x);
        let result = loop {
            if generator.fill(&mut candidate).is_err() {
                break Err(CryptoError::RandomFailed);
            }
            let value = BoxedUint::from_be_bytes(&candidate, q.precision()).map_err(failed)?;
            let mut k = value.shr(8 * bytes as u32 - bits);
            if (k.is_zero() | !k.ct_lt(q.value())).into_bool() {
                k.zeroize();
                continue;
            }
            // r = (g^k mod p) mod q; s = k^-1 (z + x r) mod q.
            let power = p.retrieve(&p.pow(&p.residue(parameters.g()), &k).map_err(failed)?).map_err(failed)?;
            let r = q.residue(&power);
            let k_residue = q.residue(&k);
            k.zeroize();
            let inverse = q.invert(&k_residue).map_err(failed)?;
            let sum = q.add(&z_reduced, &q.mul(&x, &r).map_err(failed)?).map_err(failed)?;
            let s = q.mul(&inverse, &sum).map_err(failed)?;
            let (r, s) = (q.retrieve(&r).map_err(failed)?, q.retrieve(&s).map_err(failed)?);
            if let Ok(signature) = DSASignature::new(parameters, &r, &s) {
                break Ok(signature);
            }
        };
        candidate.zeroize();
        result
    }

    /// Succeeds if `signature` is a signature of `message` under `key`;
    /// fails with `InvalidSignature` otherwise.
    pub fn verify(key: &DSAVerifyingKey, message: &[u8], signature: &DSASignature) -> Result<(), CryptoError> {
        DSA::<H>::verify_digest(key, H::digest(message).as_ref(), signature)
    }

    /// The verification of FIPS 186-4 section 4.7 for the digest `digest`.
    pub fn verify_digest(key: &DSAVerifyingKey, digest: &[u8], signature: &DSASignature) -> Result<(), CryptoError> {
        let parameters = key.parameters();
        let (p, q) = (parameters.p(), parameters.q());
        let invalid = |_| CryptoError::InvalidSignature;
        // r and s are in 1..q by construction of the signature.
        let z = q.residue(&DSA::<H>::digest_integer(parameters, digest)?);
        let w = q.invert(&q.residue(signature.s())).map_err(invalid)?;
        let u1 = q.retrieve(&q.mul(&z, &w).map_err(invalid)?).map_err(invalid)?;
        let u2 = q.retrieve(&q.mul(&q.residue(signature.r()), &w).map_err(invalid)?).map_err(invalid)?;
        let first = p.pow_vartime(&p.residue(parameters.g()), &u1).map_err(invalid)?;
        let second = p.pow_vartime(&p.residue(&key.y), &u2).map_err(invalid)?;
        let v = p.retrieve(&p.mul(&first, &second).map_err(invalid)?).map_err(invalid)?;
        let v = q.retrieve(&q.residue(&v)).map_err(invalid)?;
        if !v.compare_vartime(signature.r()).is_eq() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }
}
