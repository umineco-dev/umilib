use core::fmt;

use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::math::ec::{AffinePoint, FieldElement, PrimeField, ProjectivePoint, WeierstrassCurve};
use crate::secret::Zeroize;

/// A signing key of GOST R 34.10-2012: d with 0 < d < q and its verifying
/// key; zeroized when dropped.
pub struct GOSTR3410SigningKey<C: WeierstrassCurve> {
    scalar: FieldElement<C::Scalar>,
    verifying: GOSTR3410VerifyingKey<C>,
}

impl<C: WeierstrassCurve> GOSTR3410SigningKey<C> {
    /// The key of `scalar`; fails with `InvalidKey` for zero.
    pub fn new(scalar: FieldElement<C::Scalar>) -> Result<GOSTR3410SigningKey<C>, CryptoError> {
        if scalar.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let point = ProjectivePoint::generator().mul(&scalar).to_affine();
        Ok(GOSTR3410SigningKey { scalar, verifying: GOSTR3410VerifyingKey { point } })
    }

    /// A key of a scalar uniformly random in 1..q.
    pub fn generate<R: Random>(random: &mut R) -> Result<GOSTR3410SigningKey<C>, CryptoError> {
        let scalar = FieldElement::random_nonzero(|bytes| random.fill(bytes)).map_err(|_| CryptoError::RandomFailed)?;
        GOSTR3410SigningKey::new(scalar)
    }

    /// The key of d little-endian in the bytes of q.
    pub fn from_bytes(bytes: &[u8]) -> Result<GOSTR3410SigningKey<C>, CryptoError> {
        GOSTR3410SigningKey::new(FieldElement::from_le_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?)
    }

    /// Writes d little-endian into `out` of the bytes of q.
    pub fn write_bytes(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != <C::Scalar as PrimeField>::BYTES {
            return Err(CryptoError::InputLength { length });
        }
        self.scalar.write_le_bytes(out).map_err(|_| CryptoError::InputLength { length })
    }

    pub fn scalar(&self) -> &FieldElement<C::Scalar> {
        &self.scalar
    }

    pub fn verifying_key(&self) -> &GOSTR3410VerifyingKey<C> {
        &self.verifying
    }
}

impl<C: WeierstrassCurve> Clone for GOSTR3410SigningKey<C> {
    fn clone(&self) -> GOSTR3410SigningKey<C> {
        GOSTR3410SigningKey { scalar: self.scalar, verifying: self.verifying }
    }
}

impl<C: WeierstrassCurve> Zeroize for GOSTR3410SigningKey<C> {
    fn zeroize(&mut self) {
        self.scalar.zeroize();
    }
}

impl<C: WeierstrassCurve> Drop for GOSTR3410SigningKey<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the verifying key, not the signing one.
impl<C: WeierstrassCurve> fmt::Debug for GOSTR3410SigningKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GOSTR3410SigningKey({:?}, ..)", self.verifying)
    }
}

/// A verifying key of GOST R 34.10-2012: Q = d P, a point of the subgroup
/// of order q other than the identity.
pub struct GOSTR3410VerifyingKey<C: WeierstrassCurve> {
    point: AffinePoint<C>,
}

impl<C: WeierstrassCurve> GOSTR3410VerifyingKey<C> {
    /// The key of `point`; fails with `InvalidKey` for the identity or a
    /// point outside the subgroup of order q.
    pub fn new(point: AffinePoint<C>) -> Result<GOSTR3410VerifyingKey<C>, CryptoError> {
        if (point.is_identity() | !point.is_in_subgroup()).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(GOSTR3410VerifyingKey { point })
    }

    /// The key of the encoding of RFC 9215 section 3: x then y, each
    /// little-endian of the bytes of p.
    pub fn from_bytes(bytes: &[u8]) -> Result<GOSTR3410VerifyingKey<C>, CryptoError> {
        let size = <C::Field as PrimeField>::BYTES;
        if bytes.len() != 2 * size {
            return Err(CryptoError::InvalidKey);
        }
        let read = |bytes: &[u8]| FieldElement::from_le_bytes(bytes).map_err(|_| CryptoError::InvalidKey);
        let point =
            AffinePoint::new(read(&bytes[..size])?, read(&bytes[size..])?).map_err(|_| CryptoError::InvalidKey)?;
        GOSTR3410VerifyingKey::new(point)
    }

    /// Writes the encoding of RFC 9215 section 3 into `out` of twice the bytes of p.
    pub fn write_bytes(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        let size = <C::Field as PrimeField>::BYTES;
        let length = out.len();
        if length != 2 * size {
            return Err(CryptoError::InputLength { length });
        }
        let failed = |_| CryptoError::InputLength { length };
        let (x, y) = out.split_at_mut(size);
        self.point.x().write_le_bytes(x).map_err(failed)?;
        self.point.y().write_le_bytes(y).map_err(failed)
    }

    pub fn point(&self) -> &AffinePoint<C> {
        &self.point
    }
}

impl<C: WeierstrassCurve> Clone for GOSTR3410VerifyingKey<C> {
    fn clone(&self) -> GOSTR3410VerifyingKey<C> {
        *self
    }
}

impl<C: WeierstrassCurve> Copy for GOSTR3410VerifyingKey<C> {}

impl<C: WeierstrassCurve> PartialEq for GOSTR3410VerifyingKey<C> {
    fn eq(&self, other: &GOSTR3410VerifyingKey<C>) -> bool {
        self.point == other.point
    }
}

impl<C: WeierstrassCurve> Eq for GOSTR3410VerifyingKey<C> {}

impl<C: WeierstrassCurve> fmt::Debug for GOSTR3410VerifyingKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GOSTR3410VerifyingKey({:?})", self.point)
    }
}
