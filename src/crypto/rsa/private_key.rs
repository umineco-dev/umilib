#[cfg(umilib_feature = "codec-asn1-der")]
use alloc::vec::Vec;
use core::fmt;

use super::RSAPublicKey;
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::math::bigint::{BoxedUint, Limb};
use crate::math::modular::BoxedModulus;
use crate::secret::{ConstantTimeEq, Zeroize};

/// The primes of a two-prime RSA key with the values of the Chinese
/// remainder theorem (RFC 8017 section 3.2, second representation).
#[derive(Clone)]
pub struct RSAPrimes {
    p: BoxedModulus,
    q: BoxedModulus,
    /// d mod (p - 1).
    dp: BoxedUint,
    /// d mod (q - 1).
    dq: BoxedUint,
    /// q^-1 mod p.
    q_inverse: BoxedUint,
}

impl RSAPrimes {
    pub fn p(&self) -> &BoxedUint {
        self.p.value()
    }

    pub fn q(&self) -> &BoxedUint {
        self.q.value()
    }

    pub fn dp(&self) -> &BoxedUint {
        &self.dp
    }

    pub fn dq(&self) -> &BoxedUint {
        &self.dq
    }

    pub fn q_inverse(&self) -> &BoxedUint {
        &self.q_inverse
    }
}

impl Zeroize for RSAPrimes {
    /// The moduli zeroize themselves when dropped.
    fn zeroize(&mut self) {
        self.dp.zeroize();
        self.dq.zeroize();
        self.q_inverse.zeroize();
    }
}

impl Drop for RSAPrimes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// An RSA private key: the public key, the private exponent d and, when
/// known, the primes (RFC 8017 section 3.2). Zeroized when dropped.
#[derive(Clone)]
pub struct RSAPrivateKey {
    public: RSAPublicKey,
    d: BoxedUint,
    primes: Option<RSAPrimes>,
}

impl RSAPrivateKey {
    /// The smallest modulus [`RSAPrivateKey::generate`] makes, in bits (FIPS
    /// 186-5 appendix A.1.1).
    pub const MINIMUM_GENERATED_BITS: u32 = 2048;
    /// The primes the candidates of [`RSAPrivateKey::generate`] are sieved by.
    pub const SIEVE: &'static [u16] = &[
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
        109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
        233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359,
        367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491,
        499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
        643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
        797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
        947, 953, 967, 971, 977, 983, 991, 997,
    ];

    /// The key of the private exponent `d` alone (the first representation
    /// of section 3.2), whose operations do not use the Chinese remainder
    /// theorem. Fails with `InvalidKey` unless 0 < d < n and d inverts e
    /// (checked on a test value).
    pub fn new(public: RSAPublicKey, d: &BoxedUint) -> Result<RSAPrivateKey, CryptoError> {
        let d = d.resize(public.modulus().precision()).map_err(|_| CryptoError::InvalidKey)?;
        if (d.is_zero() | !d.ct_lt(public.n())).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let key = RSAPrivateKey { public, d, primes: None };
        key.check_pair()?;
        Ok(key)
    }

    /// The key of every component of section 3.2 (n, e, d, p, q, dP, dQ,
    /// qInv), as PKCS #1 stores it; fails with `InvalidKey` unless n = pq,
    /// both primes are odd, dP = d mod (p - 1), dQ = d mod (q - 1),
    /// q × qInv = 1 mod p and d inverts e (checked on a test value).
    #[allow(clippy::too_many_arguments)]
    pub fn from_components(
        public: RSAPublicKey,
        d: &BoxedUint,
        p: &BoxedUint,
        q: &BoxedUint,
        dp: &BoxedUint,
        dq: &BoxedUint,
        q_inverse: &BoxedUint,
    ) -> Result<RSAPrivateKey, CryptoError> {
        let invalid = |_| CryptoError::InvalidKey;
        let mut key = RSAPrivateKey::new(public, d)?;
        let p = BoxedModulus::new(p.resize(p.bit_length()).map_err(invalid)?).map_err(invalid)?;
        let q = BoxedModulus::new(q.resize(q.bit_length()).map_err(invalid)?).map_err(invalid)?;
        if !p.value().mul_wide(q.value()).ct_eq(key.public.n()).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let one = BoxedUint::one(64).map_err(invalid)?;
        let expected_dp = key.d.rem(&p.value().wrapping_sub(&one)).map_err(invalid)?;
        let expected_dq = key.d.rem(&q.value().wrapping_sub(&one)).map_err(invalid)?;
        let dp = dp.resize(p.precision()).map_err(invalid)?;
        let dq = dq.resize(q.precision()).map_err(invalid)?;
        let q_inverse = q_inverse.resize(p.precision()).map_err(invalid)?;
        let inverse_checks = p
            .retrieve(&p.mul(&p.residue(q.value()), &p.residue(&q_inverse)).map_err(invalid)?)
            .map_err(invalid)?
            .ct_eq(&one)
            .into_bool()
            && q_inverse.ct_lt(p.value()).into_bool();
        if !(expected_dp.ct_eq(&dp).into_bool() && expected_dq.ct_eq(&dq).into_bool() && inverse_checks) {
            return Err(CryptoError::InvalidKey);
        }
        key.primes = Some(RSAPrimes { p, q, dp, dq, q_inverse });
        key.check_pair()?;
        Ok(key)
    }

    /// The key of the primes `p` and `q` and the public exponent `e`, with
    /// d = e^-1 mod lcm(p - 1, q - 1) (FIPS 186-5 appendix A.1.1); fails
    /// with `InvalidKey` if e is not invertible or the primes are not odd.
    /// The time depends on the primes (key generation and import only).
    pub fn from_primes(p: &BoxedUint, q: &BoxedUint, e: &BoxedUint) -> Result<RSAPrivateKey, CryptoError> {
        let invalid = |_| CryptoError::InvalidKey;
        let n = p.mul_wide(q);
        let public = RSAPublicKey::new(&n, e)?;
        let one = BoxedUint::one(64).map_err(invalid)?;
        let (p_minus_1, q_minus_1) = (p.wrapping_sub(&one), q.wrapping_sub(&one));
        let gcd = p_minus_1.gcd_vartime(&q_minus_1);
        let (lambda, _) = p_minus_1.mul_wide(&q_minus_1).div_rem(&gcd).map_err(invalid)?;
        let d = RSAPrivateKey::inverse(public.e(), &lambda)?;
        let primes = RSAPrimes::from_primes(p, q, &d)?;
        let mut key = RSAPrivateKey::new(public, &d)?;
        key.primes = Some(primes);
        key.check_pair()?;
        Ok(key)
    }

    /// A key of a modulus of `bits` bits, at least
    /// [`RSAPrivateKey::MINIMUM_GENERATED_BITS`] and even, with the public
    /// exponent `e`, odd with 2^16 < e < 2^256 (FIPS 186-5 appendix A.1.1
    /// and A.1.3): random primes of bits / 2 bits whose two top bits are set,
    /// sieved by small primes, coprime to e and passing the rounds of
    /// Miller–Rabin of table B.1; |p - q| > 2^(bits/2 - 100) and
    /// d > 2^(bits/2). Fails with `InvalidParameter` for other sizes.
    pub fn generate<R: Random>(bits: u32, e: &BoxedUint, random: &mut R) -> Result<RSAPrivateKey, CryptoError> {
        let large = e.bit_length() > 16 && e.bit_length() <= 256 && e.is_odd().into_bool();
        if bits < RSAPrivateKey::MINIMUM_GENERATED_BITS || !bits.is_multiple_of(2) || !large {
            return Err(CryptoError::InvalidParameter);
        }
        let half = bits / 2;
        loop {
            let p = RSAPrivateKey::generate_prime(half, e, random)?;
            let q = RSAPrivateKey::generate_prime(half, e, random)?;
            let difference = if p.ct_gt(&q).into_bool() { p.wrapping_sub(&q) } else { q.wrapping_sub(&p) };
            if difference.bit_length() <= half - 100 {
                continue;
            }
            let key = RSAPrivateKey::from_primes(&p, &q, e)?;
            if key.d.bit_length() > half {
                return Ok(key);
            }
        }
    }

    /// A probable prime of `bits` bits whose two top bits are set, with
    /// gcd(prime - 1, e) = 1 (FIPS 186-5 appendix A.1.3).
    pub fn generate_prime<R: Random>(bits: u32, e: &BoxedUint, random: &mut R) -> Result<BoxedUint, CryptoError> {
        let rounds = if bits <= 1024 { 5 } else { 4 };
        let bytes = bits.div_ceil(8) as usize;
        let mut buffer = alloc::vec![0u8; bytes];
        let failed = |_| CryptoError::InvalidParameter;
        let one = BoxedUint::one(64).map_err(failed)?;
        loop {
            random.fill(&mut buffer).map_err(|_| CryptoError::RandomFailed)?;
            let mut candidate = BoxedUint::from_be_bytes(&buffer, bits).map_err(failed)?;
            // Keep `bits` bits, set the two top bits and the lowest.
            candidate = candidate.shl(candidate.precision() - bits).shr(candidate.precision() - bits);
            let top = BoxedUint::from_u64(3, candidate.precision()).map_err(failed)?.shl(bits - 2);
            candidate = BoxedUint::combine(&candidate, &top, |a, b| a | b);
            candidate = BoxedUint::combine(&candidate, &one, |a, b| a | b);
            let divisible =
                RSAPrivateKey::SIEVE.iter().any(|prime| candidate.rem_limb_vartime(*prime as Limb) == Some(0));
            if divisible {
                continue;
            }
            if !candidate.wrapping_sub(&one).gcd_vartime(e).ct_eq(&one).into_bool() {
                continue;
            }
            let modulus = BoxedModulus::new(candidate.clone()).map_err(failed)?;
            let mut prime = true;
            for _ in 0..rounds {
                // A base in 2..candidate - 2, by rejection.
                let base = loop {
                    random.fill(&mut buffer).map_err(|_| CryptoError::RandomFailed)?;
                    let base = BoxedUint::from_be_bytes(&buffer, bits).map_err(failed)?;
                    let base = base.shl(base.precision() - bits).shr(base.precision() - bits);
                    let two = BoxedUint::from_u64(2, 64).map_err(failed)?;
                    if !base.ct_lt(&two).into_bool() && base.ct_lt(&candidate.wrapping_sub(&one)).into_bool() {
                        break base;
                    }
                };
                if !modulus.miller_rabin(&base).map_err(failed)?.into_bool() {
                    prime = false;
                    break;
                }
            }
            if prime {
                buffer.zeroize();
                return Ok(candidate);
            }
        }
    }

    /// e^-1 mod m for an odd e: with t = -m^-1 mod e, (1 + m t) / e, exactly.
    /// Fails with `InvalidKey` if e and m are not coprime.
    pub fn inverse(e: &BoxedUint, m: &BoxedUint) -> Result<BoxedUint, CryptoError> {
        let invalid = |_| CryptoError::InvalidKey;
        let modulus = BoxedModulus::new(e.clone()).map_err(invalid)?;
        let m_inverse = modulus.invert(&modulus.residue(m)).map_err(invalid)?;
        let t = modulus.retrieve(&modulus.neg(&m_inverse).map_err(invalid)?).map_err(invalid)?;
        let product = m.mul_wide(&t);
        let one = BoxedUint::one(product.precision()).map_err(invalid)?;
        let (sum, _) = product.overflowing_add(&one);
        let (quotient, remainder) = sum.div_rem(e).map_err(invalid)?;
        if !remainder.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        quotient.resize(m.precision()).map_err(invalid)
    }

    pub fn public_key(&self) -> &RSAPublicKey {
        &self.public
    }

    /// The private exponent d.
    pub fn d(&self) -> &BoxedUint {
        &self.d
    }

    pub fn primes(&self) -> Option<&RSAPrimes> {
        self.primes.as_ref()
    }

    /// RSADP and RSASP1 (sections 5.1.2 and 5.2.1): x^d mod n for x < n,
    /// blinded by r^e with r of the bytes of `random`, with the Chinese
    /// remainder theorem when the primes are known, and checked against
    /// the public operation. Fails with `InvalidParameter` for x ≥ n,
    /// `RandomFailed` if `random` fails and `InvalidKey` if the check fails.
    pub fn apply<R: Random>(&self, x: &BoxedUint, random: &mut R) -> Result<BoxedUint, CryptoError> {
        if !self.public.contains(x) {
            return Err(CryptoError::InvalidParameter);
        }
        let failed = |_| CryptoError::InvalidKey;
        let n = self.public.modulus();
        let (blinding, unblinding) = self.blinding(random)?;
        let blinded = n.mul(&n.residue(x), &blinding).map_err(failed)?;
        let blinded = n.retrieve(&blinded).map_err(failed)?;
        let mut result = match &self.primes {
            None => n.retrieve(&n.pow(&n.residue(&blinded), &self.d).map_err(failed)?).map_err(failed)?,
            Some(primes) => {
                let (p, q) = (&primes.p, &primes.q);
                let m1 = p.pow(&p.residue(&blinded), &primes.dp).map_err(failed)?;
                let m2 = q.pow(&q.residue(&blinded), &primes.dq).map_err(failed)?;
                let mut m2 = q.retrieve(&m2).map_err(failed)?;
                // h = qInv (m1 - m2) mod p; m = m2 + q h.
                let h = p.mul(&p.residue(&primes.q_inverse), &p.sub(&m1, &p.residue(&m2)).map_err(failed)?);
                let mut h = p.retrieve(&h.map_err(failed)?).map_err(failed)?;
                let sum = n.add(&n.residue(&m2), &n.mul(&n.residue(&h), &n.residue(q.value())).map_err(failed)?);
                h.zeroize();
                m2.zeroize();
                n.retrieve(&sum.map_err(failed)?).map_err(failed)?
            }
        };
        // The result must invert the public operation on the blinded value.
        let check = self.public.apply(&result)?;
        if !check.ct_eq(&blinded).into_bool() {
            result.zeroize();
            return Err(CryptoError::InvalidKey);
        }
        let unblinded = n.mul(&n.residue(&result), &unblinding).map_err(failed)?;
        result.zeroize();
        n.retrieve(&unblinded).map_err(failed)
    }

    /// r^e and r^-1 mod n for a random r in 1..n that is invertible.
    pub fn blinding<R: Random>(
        &self,
        random: &mut R,
    ) -> Result<(crate::math::modular::BoxedResidue, crate::math::modular::BoxedResidue), CryptoError> {
        let n = self.public.modulus();
        let bits = self.public.bits();
        let mut buffer = alloc::vec![0u8; self.public.size()];
        loop {
            random.fill(&mut buffer).map_err(|_| CryptoError::RandomFailed)?;
            let r = BoxedUint::from_be_bytes(&buffer, n.precision()).map_err(|_| CryptoError::InvalidKey)?;
            let mut r = r.shl(r.precision() - bits).shr(r.precision() - bits);
            if (r.is_zero() | !r.ct_lt(n.value())).into_bool() {
                continue;
            }
            let residue = n.residue(&r);
            r.zeroize();
            let Ok(inverse) = n.invert(&residue) else { continue };
            let power = n.pow_vartime(&residue, self.public.e()).map_err(|_| CryptoError::InvalidKey)?;
            buffer.zeroize();
            return Ok((power, inverse));
        }
    }

    /// Whether (2^e)^d = 2 mod n, without blinding (the value is public).
    pub fn check_pair(&self) -> Result<(), CryptoError> {
        let n = self.public.modulus();
        let failed = |_| CryptoError::InvalidKey;
        let two = BoxedUint::from_u64(2, 64).map_err(failed)?;
        let encrypted = self.public.apply(&two.resize(n.precision()).map_err(failed)?)?;
        let decrypted = n.retrieve(&n.pow(&n.residue(&encrypted), &self.d).map_err(failed)?).map_err(failed)?;
        if !decrypted.ct_eq(&two).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(())
    }

    /// The PKCS #1 `RSAPrivateKey` of RFC 8017 appendix A.1.2 in DER, of
    /// version 0 (two primes); fails with `InvalidKey` otherwise or for
    /// inconsistent components.
    #[cfg(umilib_feature = "codec-asn1-der")]
    pub fn from_pkcs1_der(bytes: &[u8]) -> Result<RSAPrivateKey, CryptoError> {
        let invalid = |_| CryptoError::InvalidKey;
        let mut reader = crate::codec::asn1::der::DERReader::new(bytes);
        let mut sequence = reader.read_sequence().map_err(invalid)?;
        reader.finish().map_err(invalid)?;
        let version = RSAPublicKey::read_integer(&mut sequence)?;
        if !version.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let mut values = Vec::new();
        for _ in 0..8 {
            values.push(RSAPublicKey::read_integer(&mut sequence)?);
        }
        sequence.finish().map_err(invalid)?;
        let public = RSAPublicKey::new(&values[0], &values[1])?;
        let key = RSAPrivateKey::from_components(
            public, &values[2], &values[3], &values[4], &values[5], &values[6], &values[7],
        );
        values.iter_mut().for_each(|value| value.zeroize());
        key
    }

    /// The PKCS #1 `RSAPrivateKey` in DER; fails with `InvalidKey` for a key
    /// without its primes.
    #[cfg(umilib_feature = "codec-asn1-der")]
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, CryptoError> {
        let primes = self.primes.as_ref().ok_or(CryptoError::InvalidKey)?;
        let mut writer = crate::codec::asn1::der::DERWriter::new();
        let mut values = [
            self.public.n().to_be_bytes(),
            self.public.e().to_be_bytes(),
            self.d.to_be_bytes(),
            primes.p().to_be_bytes(),
            primes.q().to_be_bytes(),
            primes.dp.to_be_bytes(),
            primes.dq.to_be_bytes(),
            primes.q_inverse.to_be_bytes(),
        ];
        // Writing into a sequence cannot fail.
        let _ = writer.write_sequence(|sequence| {
            sequence.write_integer_i128(0);
            for value in &values {
                sequence.write_integer_unsigned(value);
            }
            Ok(())
        });
        values.iter_mut().for_each(|value| value.zeroize());
        Ok(writer.into_bytes())
    }
}

impl RSAPrimes {
    /// The values of the Chinese remainder theorem for `p`, `q` and `d`.
    pub fn from_primes(p: &BoxedUint, q: &BoxedUint, d: &BoxedUint) -> Result<RSAPrimes, CryptoError> {
        let invalid = |_| CryptoError::InvalidKey;
        let p = BoxedModulus::new(p.resize(p.bit_length()).map_err(invalid)?).map_err(invalid)?;
        let q = BoxedModulus::new(q.resize(q.bit_length()).map_err(invalid)?).map_err(invalid)?;
        let one = BoxedUint::one(64).map_err(invalid)?;
        let dp = d.rem(&p.value().wrapping_sub(&one)).map_err(invalid)?;
        let dq = d.rem(&q.value().wrapping_sub(&one)).map_err(invalid)?;
        let q_inverse = p.retrieve(&p.invert(&p.residue(q.value())).map_err(invalid)?).map_err(invalid)?;
        Ok(RSAPrimes { p, q, dp, dq, q_inverse })
    }
}

impl Zeroize for RSAPrivateKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
        if let Some(primes) = &mut self.primes {
            primes.zeroize();
        }
    }
}

impl Drop for RSAPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the public key, not the private one.
impl fmt::Debug for RSAPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RSAPrivateKey({:?}, ..)", self.public)
    }
}
