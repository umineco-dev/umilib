use core::fmt;
use core::marker::PhantomData;

use crate::crypto::random::Random;
use crate::crypto::{CryptoError, KeyAgreement};
use crate::math::ec::{AffinePoint, FieldElement, PrimeField, ProjectivePoint, WeierstrassCurve};
use crate::secret::Zeroize;

/// The key agreement of SEC 1 section 3.3.1 on the curve `C`.
pub struct ECDH<C: WeierstrassCurve> {
    curve: PhantomData<C>,
}

/// A private key of [`ECDH`]: a scalar d with 1 ≤ d < n, zeroized when dropped.
pub struct ECDHPrivateKey<C: WeierstrassCurve> {
    scalar: FieldElement<C::Scalar>,
}

impl<C: WeierstrassCurve> ECDHPrivateKey<C> {
    /// The key of the scalar `scalar`; fails with `InvalidKey` for zero.
    pub fn new(scalar: FieldElement<C::Scalar>) -> Result<ECDHPrivateKey<C>, CryptoError> {
        if scalar.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(ECDHPrivateKey { scalar })
    }

    pub fn scalar(&self) -> &FieldElement<C::Scalar> {
        &self.scalar
    }
}

impl<C: WeierstrassCurve> Clone for ECDHPrivateKey<C> {
    fn clone(&self) -> ECDHPrivateKey<C> {
        ECDHPrivateKey { scalar: self.scalar }
    }
}

impl<C: WeierstrassCurve> Zeroize for ECDHPrivateKey<C> {
    fn zeroize(&mut self) {
        self.scalar.zeroize();
    }
}

impl<C: WeierstrassCurve> Drop for ECDHPrivateKey<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the curve, not the key.
impl<C: WeierstrassCurve> fmt::Debug for ECDHPrivateKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = core::any::type_name::<C>();
        write!(formatter, "ECDHPrivateKey<{}>(..)", name.rsplit("::").next().unwrap_or(name))
    }
}

/// A public key of [`ECDH`]: a point of the subgroup of `C` other than the identity.
pub struct ECDHPublicKey<C: WeierstrassCurve> {
    point: AffinePoint<C>,
}

impl<C: WeierstrassCurve> Clone for ECDHPublicKey<C> {
    fn clone(&self) -> ECDHPublicKey<C> {
        *self
    }
}

impl<C: WeierstrassCurve> Copy for ECDHPublicKey<C> {}

impl<C: WeierstrassCurve> PartialEq for ECDHPublicKey<C> {
    fn eq(&self, other: &ECDHPublicKey<C>) -> bool {
        self.point == other.point
    }
}

impl<C: WeierstrassCurve> Eq for ECDHPublicKey<C> {}

impl<C: WeierstrassCurve> fmt::Debug for ECDHPublicKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ECDHPublicKey({:?})", self.point)
    }
}

impl<C: WeierstrassCurve> ECDHPublicKey<C> {
    /// The key of `point`, validated as SEC 1 section 3.2.2.1 requires: not
    /// the identity, on the curve (as every `AffinePoint` is) and in the
    /// subgroup of the generator. Fails with `InvalidKey` otherwise.
    pub fn new(point: AffinePoint<C>) -> Result<ECDHPublicKey<C>, CryptoError> {
        if (point.is_identity() | !point.is_in_subgroup()).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(ECDHPublicKey { point })
    }

    pub fn point(&self) -> &AffinePoint<C> {
        &self.point
    }

    /// The key of the SEC 1 encoding `bytes`, compressed or not (SEC 1
    /// section 2.3.4); fails with `InvalidKey` for anything else.
    pub fn from_encoded(bytes: &[u8]) -> Result<ECDHPublicKey<C>, CryptoError> {
        ECDHPublicKey::new(AffinePoint::from_encoded(bytes).map_err(|_| CryptoError::InvalidKey)?)
    }

    /// Writes the SEC 1 encoding into `out` of its length,
    /// `AffinePoint::<C>::encoded_length(compressed)`.
    pub fn write_encoded(&self, out: &mut [u8], compressed: bool) -> Result<(), CryptoError> {
        let length = out.len();
        self.point.write_encoded(out, compressed).map_err(|_| CryptoError::InputLength { length })
    }
}

impl<C: WeierstrassCurve> KeyAgreement for ECDH<C> {
    type PrivateKey = ECDHPrivateKey<C>;
    type PublicKey = ECDHPublicKey<C>;
    const PRIVATE_KEY_SIZE: usize = <C::Scalar as PrimeField>::BYTES;
    /// The uncompressed SEC 1 encoding.
    const PUBLIC_KEY_SIZE: usize = AffinePoint::<C>::encoded_length(false);
    const SHARED_SECRET_SIZE: usize = <C::Field as PrimeField>::BYTES;

    /// A scalar of FIPS 186-5 appendix A.2.2, by rejection sampling.
    fn generate<R: Random>(random: &mut R) -> Result<ECDHPrivateKey<C>, CryptoError> {
        let scalar = FieldElement::random_nonzero(|bytes| random.fill(bytes)).map_err(|_| CryptoError::RandomFailed)?;
        Ok(ECDHPrivateKey { scalar })
    }

    /// The scalar of [`ECDH::PRIVATE_KEY_SIZE`] big-endian bytes, in 1..n
    /// (SEC 1 section 2.3.6).
    fn private_key_from_bytes(bytes: &[u8]) -> Result<ECDHPrivateKey<C>, CryptoError> {
        let scalar = FieldElement::from_be_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
        ECDHPrivateKey::new(scalar)
    }

    fn write_private_key(key: &ECDHPrivateKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != <ECDH<C> as KeyAgreement>::PRIVATE_KEY_SIZE {
            return Err(CryptoError::InputLength { length });
        }
        key.scalar.write_be_bytes(out).map_err(|_| CryptoError::InputLength { length })
    }

    fn public_key(key: &ECDHPrivateKey<C>) -> ECDHPublicKey<C> {
        ECDHPublicKey { point: ProjectivePoint::generator().mul(&key.scalar).to_affine() }
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<ECDHPublicKey<C>, CryptoError> {
        ECDHPublicKey::from_encoded(bytes)
    }

    fn write_public_key(key: &ECDHPublicKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        key.write_encoded(out, false)
    }

    /// The primitive ECSVDP-DH of SEC 1 section 3.3.1: the x-coordinate of
    /// d × Q; fails with `InvalidKey` if that is the identity, which a
    /// validated key of a curve of cofactor 1 never gives.
    fn agree(private: &ECDHPrivateKey<C>, public: &ECDHPublicKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != <ECDH<C> as KeyAgreement>::SHARED_SECRET_SIZE {
            return Err(CryptoError::InputLength { length });
        }
        let mut shared = public.point.to_projective().mul(&private.scalar).to_affine();
        let result = if shared.is_identity().into_bool() {
            Err(CryptoError::InvalidKey)
        } else {
            shared.x().write_be_bytes(out).map_err(|_| CryptoError::InputLength { length })
        };
        shared.zeroize();
        result
    }
}
