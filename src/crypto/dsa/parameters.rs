use core::fmt;

use crate::crypto::CryptoError;
use crate::math::bigint::BoxedUint;
use crate::math::modular::BoxedModulus;

/// The domain parameters (p, q, g) of DSA (FIPS 186-4 section 4.3): primes
/// p and q of the sizes (L, N) of section 4.2 with q dividing p - 1, and a
/// generator g of the subgroup of order q.
#[derive(Clone)]
pub struct DSAParameters {
    p: BoxedModulus,
    q: BoxedModulus,
    g: BoxedUint,
}

impl DSAParameters {
    /// The pairs (L, N) of the bits of p and q that FIPS 186-4 section 4.2 allows.
    pub const SIZES: &'static [(u32, u32)] = &[(1024, 160), (2048, 224), (2048, 256), (3072, 256)];

    /// The parameters (p, q, g); fails with `InvalidParameter` unless their
    /// sizes are a pair of [`DSAParameters::SIZES`], p and q are odd, q
    /// divides p - 1, 1 < g < p and g^q = 1 mod p. The primality of p and q
    /// is not tested: parameters come from a trusted source or with the
    /// seeds of their generation.
    pub fn new(p: &BoxedUint, q: &BoxedUint, g: &BoxedUint) -> Result<DSAParameters, CryptoError> {
        let invalid = |_| CryptoError::InvalidParameter;
        let sizes = (p.bit_length(), q.bit_length());
        if !DSAParameters::SIZES.contains(&sizes) {
            return Err(CryptoError::InvalidParameter);
        }
        let p = BoxedModulus::new(p.resize(sizes.0).map_err(invalid)?).map_err(invalid)?;
        let q = BoxedModulus::new(q.resize(sizes.1).map_err(invalid)?).map_err(invalid)?;
        let g = g.resize(sizes.0).map_err(invalid)?;
        let one = BoxedUint::one(64).map_err(invalid)?;
        let divides = p.value().wrapping_sub(&one).rem(q.value()).map_err(invalid)?.is_zero();
        let in_range = one.ct_lt(&g) & g.ct_lt(p.value());
        if !(divides & in_range).into_bool() {
            return Err(CryptoError::InvalidParameter);
        }
        let power = p.pow_vartime(&p.residue(&g), q.value()).map_err(invalid)?;
        if power != p.one() {
            return Err(CryptoError::InvalidParameter);
        }
        Ok(DSAParameters { p, q, g })
    }

    pub fn p(&self) -> &BoxedModulus {
        &self.p
    }

    pub fn q(&self) -> &BoxedModulus {
        &self.q
    }

    pub fn g(&self) -> &BoxedUint {
        &self.g
    }

    /// The bytes of q: those of each half of a fixed signature.
    pub fn q_bytes(&self) -> usize {
        self.q.value().bit_length().div_ceil(8) as usize
    }

    /// The bytes of p: those of an encoded public key.
    pub fn p_bytes(&self) -> usize {
        self.p.value().bit_length().div_ceil(8) as usize
    }
}

impl PartialEq for DSAParameters {
    fn eq(&self, other: &DSAParameters) -> bool {
        self.p.value().compare_vartime(other.p.value()).is_eq()
            && self.q.value().compare_vartime(other.q.value()).is_eq()
            && self.g.compare_vartime(&other.g).is_eq()
    }
}

impl Eq for DSAParameters {}

impl fmt::Debug for DSAParameters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (l, n) = (self.p.value().bit_length(), self.q.value().bit_length());
        write!(formatter, "DSAParameters(L: {l}, N: {n})")
    }
}
