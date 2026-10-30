use core::fmt;
use core::marker::PhantomData;

use crate::crypto::random::Random;
use crate::crypto::{CryptoError, KeyAgreement};
use crate::math::bigint::UnsignedInteger;
use crate::math::ec::{FieldValue, MontgomeryCurve, MontgomeryPoint, PrimeField};
use crate::secret::Zeroize;

/// The key agreement of RFC 7748 on the Montgomery curve `C`.
pub struct XDH<C: MontgomeryCurve> {
    curve: PhantomData<C>,
}

/// X25519 of RFC 7748 section 5, on curve25519.
#[cfg(umilib_feature = "crypto-curve-curve25519")]
pub type X25519 = XDH<crate::crypto::curve::curve25519::Curve25519>;

/// X448 of RFC 7748 section 5, on curve448.
#[cfg(umilib_feature = "crypto-curve-curve448")]
pub type X448 = XDH<crate::crypto::curve::curve448::Curve448>;

impl<C: MontgomeryCurve> XDH<C> {
    /// decodeScalar25519 and decodeScalar448 of RFC 7748 section 5 for the
    /// curve: the bits below the cofactor and above
    /// [`MontgomeryCurve::SCALAR_BITS`] - 1 cleared, that bit set.
    pub fn decode_scalar(value: &FieldValue<C::Field>) -> FieldValue<C::Field> {
        let bits = <FieldValue<C::Field> as UnsignedInteger>::BITS;
        let low = C::COFACTOR.trailing_zeros();
        let top = C::SCALAR_BITS - 1;
        let cleared = value.shr(low).shl(low).shl(bits - top).shr(bits - top);
        cleared.wrapping_add(&FieldValue::<C::Field>::ONE.shl(top))
    }
}

/// A private key of [`XDH`]: the integer of its little-endian bytes, as
/// given; the function decodes it at each use. Zeroized when dropped.
pub struct XDHPrivateKey<C: MontgomeryCurve> {
    value: FieldValue<C::Field>,
}

impl<C: MontgomeryCurve> XDHPrivateKey<C> {
    pub fn value(&self) -> &FieldValue<C::Field> {
        &self.value
    }
}

impl<C: MontgomeryCurve> Clone for XDHPrivateKey<C> {
    fn clone(&self) -> XDHPrivateKey<C> {
        XDHPrivateKey { value: self.value }
    }
}

impl<C: MontgomeryCurve> Zeroize for XDHPrivateKey<C> {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl<C: MontgomeryCurve> Drop for XDHPrivateKey<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the curve, not the key.
impl<C: MontgomeryCurve> fmt::Debug for XDHPrivateKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = core::any::type_name::<C>();
        write!(formatter, "XDHPrivateKey<{}>(..)", name.rsplit("::").next().unwrap_or(name))
    }
}

/// A public key of [`XDH`]: the coordinate u of a point.
pub struct XDHPublicKey<C: MontgomeryCurve> {
    point: MontgomeryPoint<C>,
}

impl<C: MontgomeryCurve> Clone for XDHPublicKey<C> {
    fn clone(&self) -> XDHPublicKey<C> {
        *self
    }
}

impl<C: MontgomeryCurve> Copy for XDHPublicKey<C> {}

impl<C: MontgomeryCurve> PartialEq for XDHPublicKey<C> {
    fn eq(&self, other: &XDHPublicKey<C>) -> bool {
        self.point == other.point
    }
}

impl<C: MontgomeryCurve> Eq for XDHPublicKey<C> {}

impl<C: MontgomeryCurve> fmt::Debug for XDHPublicKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "XDHPublicKey({:?})", self.point)
    }
}

impl<C: MontgomeryCurve> XDHPublicKey<C> {
    pub fn new(point: MontgomeryPoint<C>) -> XDHPublicKey<C> {
        XDHPublicKey { point }
    }

    pub fn point(&self) -> &MontgomeryPoint<C> {
        &self.point
    }
}

impl<C: MontgomeryCurve> KeyAgreement for XDH<C> {
    type PrivateKey = XDHPrivateKey<C>;
    type PublicKey = XDHPublicKey<C>;
    const PRIVATE_KEY_SIZE: usize = <C::Field as PrimeField>::BYTES;
    const PUBLIC_KEY_SIZE: usize = <C::Field as PrimeField>::BYTES;
    const SHARED_SECRET_SIZE: usize = <C::Field as PrimeField>::BYTES;

    /// [`XDH::PRIVATE_KEY_SIZE`] random bytes (RFC 7748 section 6).
    fn generate<R: Random>(random: &mut R) -> Result<XDHPrivateKey<C>, CryptoError> {
        let bits = <FieldValue<C::Field> as UnsignedInteger>::BITS;
        let unused = bits - 8 * <C::Field as PrimeField>::BYTES as u32;
        let value = FieldValue::<C::Field>::from_byte_source(|bytes| random.fill(bytes))
            .map_err(|_| CryptoError::RandomFailed)?
            .shl(unused)
            .shr(unused);
        Ok(XDHPrivateKey { value })
    }

    /// The key of [`XDH::PRIVATE_KEY_SIZE`] bytes, any of which are accepted.
    fn private_key_from_bytes(bytes: &[u8]) -> Result<XDHPrivateKey<C>, CryptoError> {
        if bytes.len() != <XDH<C> as KeyAgreement>::PRIVATE_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }
        let value = FieldValue::<C::Field>::from_le_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(XDHPrivateKey { value })
    }

    fn write_private_key(key: &XDHPrivateKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != <XDH<C> as KeyAgreement>::PRIVATE_KEY_SIZE {
            return Err(CryptoError::InputLength { length });
        }
        key.value.write_le_bytes(out).map_err(|_| CryptoError::InputLength { length })
    }

    /// The function applied to the base point (RFC 7748 section 6).
    fn public_key(key: &XDHPrivateKey<C>) -> XDHPublicKey<C> {
        let mut scalar = XDH::<C>::decode_scalar(&key.value);
        let point = MontgomeryPoint::base().mul_value(&scalar);
        scalar.zeroize();
        XDHPublicKey { point }
    }

    /// The coordinate of [`XDH::PUBLIC_KEY_SIZE`] little-endian bytes,
    /// decoded as decodeUCoordinate of RFC 7748 section 5 (the unused bits
    /// ignored, values not below p reduced).
    fn public_key_from_bytes(bytes: &[u8]) -> Result<XDHPublicKey<C>, CryptoError> {
        let point = MontgomeryPoint::from_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(XDHPublicKey { point })
    }

    fn write_public_key(key: &XDHPublicKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        key.point.write_bytes(out).map_err(|_| CryptoError::InputLength { length })
    }

    /// The function of RFC 7748 section 5 on `public`; fails with
    /// `InvalidKey` for a shared secret of zero, checked in constant time.
    fn agree(private: &XDHPrivateKey<C>, public: &XDHPublicKey<C>, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != <XDH<C> as KeyAgreement>::SHARED_SECRET_SIZE {
            return Err(CryptoError::InputLength { length });
        }
        let mut scalar = XDH::<C>::decode_scalar(&private.value);
        let mut shared = public.point.mul_value(&scalar);
        scalar.zeroize();
        let result = if shared.u().is_zero().into_bool() {
            Err(CryptoError::InvalidKey)
        } else {
            shared.write_bytes(out).map_err(|_| CryptoError::InputLength { length })
        };
        shared.zeroize();
        result
    }
}
