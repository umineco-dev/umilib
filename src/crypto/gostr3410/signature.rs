use core::fmt;

use crate::crypto::CryptoError;
use crate::math::ec::{FieldElement, PrimeField, WeierstrassCurve};
use crate::secret::ConstantTimeEq;

/// A signature of [`GOSTR3410`](super::GOSTR3410): the integers r and s,
/// each in 1..q.
pub struct GOSTR3410Signature<C: WeierstrassCurve> {
    r: FieldElement<C::Scalar>,
    s: FieldElement<C::Scalar>,
}

impl<C: WeierstrassCurve> GOSTR3410Signature<C> {
    /// The bytes of the encoding: s then r, each of the bytes of q.
    pub const BYTES: usize = 2 * <C::Scalar as PrimeField>::BYTES;

    /// The signature (r, s); fails with `InvalidSignature` if either is zero.
    pub fn new(r: FieldElement<C::Scalar>, s: FieldElement<C::Scalar>) -> Result<GOSTR3410Signature<C>, CryptoError> {
        if (r.is_zero() | s.is_zero()).into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(GOSTR3410Signature { r, s })
    }

    pub fn r(&self) -> &FieldElement<C::Scalar> {
        &self.r
    }

    pub fn s(&self) -> &FieldElement<C::Scalar> {
        &self.s
    }

    /// The signature of the encoding of RFC 9215 section 2: s then r, each
    /// big-endian of the bytes of q (step 1 of algorithm II: 0 < r, s < q).
    /// Fails with `InvalidSignature` otherwise.
    pub fn from_bytes(bytes: &[u8]) -> Result<GOSTR3410Signature<C>, CryptoError> {
        if bytes.len() != GOSTR3410Signature::<C>::BYTES {
            return Err(CryptoError::InvalidSignature);
        }
        let (s, r) = bytes.split_at(<C::Scalar as PrimeField>::BYTES);
        let read = |bytes: &[u8]| FieldElement::from_be_bytes(bytes).map_err(|_| CryptoError::InvalidSignature);
        GOSTR3410Signature::new(read(r)?, read(s)?)
    }

    /// Writes the encoding of RFC 9215 section 2 into `out` of
    /// [`GOSTR3410Signature::BYTES`] bytes.
    pub fn write_bytes(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != GOSTR3410Signature::<C>::BYTES {
            return Err(CryptoError::InputLength { length });
        }
        let (s, r) = out.split_at_mut(<C::Scalar as PrimeField>::BYTES);
        let failed = |_| CryptoError::InputLength { length };
        self.s.write_be_bytes(s).map_err(failed)?;
        self.r.write_be_bytes(r).map_err(failed)
    }
}

impl<C: WeierstrassCurve> Clone for GOSTR3410Signature<C> {
    fn clone(&self) -> GOSTR3410Signature<C> {
        *self
    }
}

impl<C: WeierstrassCurve> Copy for GOSTR3410Signature<C> {}

impl<C: WeierstrassCurve> PartialEq for GOSTR3410Signature<C> {
    fn eq(&self, other: &GOSTR3410Signature<C>) -> bool {
        (self.r.ct_eq(&other.r) & self.s.ct_eq(&other.s)).into_bool()
    }
}

impl<C: WeierstrassCurve> Eq for GOSTR3410Signature<C> {}

impl<C: WeierstrassCurve> fmt::Debug for GOSTR3410Signature<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GOSTR3410Signature(r: {:?}, s: {:?})", self.r, self.s)
    }
}
