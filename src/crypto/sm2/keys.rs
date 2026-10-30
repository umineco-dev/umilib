use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::math::ec::{AffinePoint, FieldElement, PrimeField, ProjectivePoint, WeierstrassCurve};
use crate::secret::{ConstantTimeEq, Zeroize};

/// A private key of SM2: a scalar d with 1 ≤ d ≤ n - 2 (GB/T 32918.1
/// section 6.1, so that 1 + d is invertible) and its public key; zeroized
/// when dropped.
pub struct SM2PrivateKey<C: WeierstrassCurve> {
    scalar: FieldElement<C::Scalar>,
    public: SM2PublicKey<C>,
}

impl<C: WeierstrassCurve> SM2PrivateKey<C> {
    /// The key of `scalar`; fails with `InvalidKey` for 0 and n - 1.
    pub fn new(scalar: FieldElement<C::Scalar>) -> Result<SM2PrivateKey<C>, CryptoError> {
        let last = FieldElement::<C::Scalar>::one().neg();
        if (scalar.is_zero() | scalar.ct_eq(&last)).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let public = SM2PublicKey { point: ProjectivePoint::generator().mul(&scalar).to_affine() };
        Ok(SM2PrivateKey { scalar, public })
    }

    /// The key of the big-endian bytes of the order's length.
    pub fn from_bytes(bytes: &[u8]) -> Result<SM2PrivateKey<C>, CryptoError> {
        SM2PrivateKey::new(FieldElement::from_be_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?)
    }

    /// Writes the scalar into `out` big-endian, of the bytes of the order.
    pub fn write_bytes(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != <C::Scalar as PrimeField>::BYTES {
            return Err(CryptoError::InputLength { length });
        }
        self.scalar.write_be_bytes(out).map_err(|_| CryptoError::InputLength { length })
    }

    /// A key of a scalar uniformly random in 1..n - 1.
    pub fn generate<R: Random>(random: &mut R) -> Result<SM2PrivateKey<C>, CryptoError> {
        loop {
            let scalar =
                FieldElement::random_nonzero(|bytes| random.fill(bytes)).map_err(|_| CryptoError::RandomFailed)?;
            if let Ok(key) = SM2PrivateKey::new(scalar) {
                return Ok(key);
            }
        }
    }

    pub fn scalar(&self) -> &FieldElement<C::Scalar> {
        &self.scalar
    }

    pub fn public_key(&self) -> &SM2PublicKey<C> {
        &self.public
    }
}

impl<C: WeierstrassCurve> Clone for SM2PrivateKey<C> {
    fn clone(&self) -> SM2PrivateKey<C> {
        SM2PrivateKey { scalar: self.scalar, public: self.public }
    }
}

impl<C: WeierstrassCurve> Zeroize for SM2PrivateKey<C> {
    fn zeroize(&mut self) {
        self.scalar.zeroize();
    }
}

impl<C: WeierstrassCurve> Drop for SM2PrivateKey<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the public key, not the private one.
impl<C: WeierstrassCurve> fmt::Debug for SM2PrivateKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SM2PrivateKey({:?}, ..)", self.public)
    }
}

/// A public key of SM2: a point of the curve other than the identity, in
/// the subgroup of the generator (GB/T 32918.1 section 6.2).
pub struct SM2PublicKey<C: WeierstrassCurve> {
    point: AffinePoint<C>,
}

impl<C: WeierstrassCurve> SM2PublicKey<C> {
    /// The key of `point`; fails with `InvalidKey` for the identity or a
    /// point outside the subgroup.
    pub fn new(point: AffinePoint<C>) -> Result<SM2PublicKey<C>, CryptoError> {
        if (point.is_identity() | !point.is_in_subgroup()).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(SM2PublicKey { point })
    }

    /// The key of an encoded point (GB/T 32918.1 section 4.2.9, compressed
    /// or not); fails with `InvalidKey` otherwise.
    pub fn from_encoded(bytes: &[u8]) -> Result<SM2PublicKey<C>, CryptoError> {
        SM2PublicKey::new(AffinePoint::from_encoded(bytes).map_err(|_| CryptoError::InvalidKey)?)
    }

    /// The uncompressed encoding 04 || x || y.
    pub fn to_encoded(&self) -> Vec<u8> {
        let mut out = vec![0u8; AffinePoint::<C>::encoded_length(false)];
        // The buffer has the length of the encoding.
        let _ = self.point.write_encoded(&mut out, false);
        out
    }

    pub fn point(&self) -> &AffinePoint<C> {
        &self.point
    }

    /// Z = H(ENTL || ID || a || b || xG || yG || xA || yA) of the identity
    /// `identity` (GB/T 32918.2 section 5.5), ENTL its length in bits as two
    /// bytes; fails with `InvalidParameter` for an identity of 8192 bytes or more.
    pub fn identity_hash<H: CryptographicDigest + Default>(&self, identity: &[u8]) -> Result<H::Output, CryptoError> {
        let bits = u16::try_from(identity.len() * 8).map_err(|_| CryptoError::InvalidParameter)?;
        let mut hash = H::default();
        hash.update(&bits.to_be_bytes());
        hash.update(identity);
        let size = <C::Field as PrimeField>::BYTES;
        let mut buffer = vec![0u8; size];
        for element in [&C::A, &C::B, &C::GENERATOR_X, &C::GENERATOR_Y, self.point.x(), self.point.y()] {
            element.write_be_bytes(&mut buffer).map_err(|_| CryptoError::InvalidParameter)?;
            hash.update(&buffer);
        }
        Ok(hash.finalize())
    }
}

impl<C: WeierstrassCurve> Clone for SM2PublicKey<C> {
    fn clone(&self) -> SM2PublicKey<C> {
        *self
    }
}

impl<C: WeierstrassCurve> Copy for SM2PublicKey<C> {}

impl<C: WeierstrassCurve> PartialEq for SM2PublicKey<C> {
    fn eq(&self, other: &SM2PublicKey<C>) -> bool {
        self.point == other.point
    }
}

impl<C: WeierstrassCurve> Eq for SM2PublicKey<C> {}

impl<C: WeierstrassCurve> fmt::Debug for SM2PublicKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SM2PublicKey({:?})", self.point)
    }
}
