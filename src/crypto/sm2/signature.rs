use core::fmt;

use crate::crypto::CryptoError;
use crate::math::ec::{FieldElement, PrimeField, WeierstrassCurve};
use crate::secret::{ConditionallySelectable, ConstantTimeEq};

/// A signature of [`SM2DSA`](super::SM2DSA): the integers r and s, each in 1..n.
pub struct SM2Signature<C: WeierstrassCurve> {
    r: FieldElement<C::Scalar>,
    s: FieldElement<C::Scalar>,
}

impl<C: WeierstrassCurve> SM2Signature<C> {
    /// The bytes of the fixed encoding: r then s, each of the bytes of the order.
    pub const BYTES: usize = 2 * <C::Scalar as PrimeField>::BYTES;

    /// The signature (r, s); fails with `InvalidSignature` if either is zero.
    pub fn new(r: FieldElement<C::Scalar>, s: FieldElement<C::Scalar>) -> Result<SM2Signature<C>, CryptoError> {
        if (r.is_zero() | s.is_zero()).into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(SM2Signature { r, s })
    }

    pub fn r(&self) -> &FieldElement<C::Scalar> {
        &self.r
    }

    pub fn s(&self) -> &FieldElement<C::Scalar> {
        &self.s
    }

    /// The signature of the fixed encoding of [`SM2Signature::BYTES`]
    /// bytes; fails with `InvalidSignature` for another length or an integer
    /// outside 1..n.
    pub fn from_bytes(bytes: &[u8]) -> Result<SM2Signature<C>, CryptoError> {
        if bytes.len() != SM2Signature::<C>::BYTES {
            return Err(CryptoError::InvalidSignature);
        }
        let (r, s) = bytes.split_at(<C::Scalar as PrimeField>::BYTES);
        let read = |bytes: &[u8]| FieldElement::from_be_bytes(bytes).map_err(|_| CryptoError::InvalidSignature);
        SM2Signature::new(read(r)?, read(s)?)
    }

    /// Writes the fixed encoding into `out` of [`SM2Signature::BYTES`] bytes.
    pub fn write_bytes(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != SM2Signature::<C>::BYTES {
            return Err(CryptoError::InputLength { length });
        }
        let (r, s) = out.split_at_mut(<C::Scalar as PrimeField>::BYTES);
        let failed = |_| CryptoError::InputLength { length };
        self.r.write_be_bytes(r).map_err(failed)?;
        self.s.write_be_bytes(s).map_err(failed)
    }

    /// The signature of the DER encoding of `SM2Signature` (GM/T 0009-2012
    /// section 7.3): a SEQUENCE of the INTEGERs r and s and nothing else, in
    /// the one encoding DER allows. Fails with `InvalidSignature` otherwise or
    /// for an integer outside 1..n.
    #[cfg(umilib_feature = "codec-asn1-der")]
    pub fn from_der(bytes: &[u8]) -> Result<SM2Signature<C>, CryptoError> {
        use crate::codec::asn1::Tag;
        use crate::codec::asn1::der::DERReader;
        use crate::math::bigint::UnsignedInteger;
        use crate::math::ec::FieldValue;
        let invalid = |_| CryptoError::InvalidSignature;
        let mut reader = DERReader::new(bytes);
        let mut sequence = reader.read_sequence().map_err(invalid)?;
        reader.finish().map_err(invalid)?;
        let mut integer = || -> Result<FieldElement<C::Scalar>, CryptoError> {
            let element = sequence.read_expected(Tag::INTEGER).map_err(invalid)?;
            let value = element.as_integer().map_err(invalid)?;
            let magnitude = value.magnitude().ok_or(CryptoError::InvalidSignature)?;
            let value = FieldValue::<C::Scalar>::from_be_bytes(magnitude).map_err(|_| CryptoError::InvalidSignature)?;
            FieldElement::from_value(&value).map_err(|_| CryptoError::InvalidSignature)
        };
        let (r, s) = (integer()?, integer()?);
        sequence.finish().map_err(invalid)?;
        SM2Signature::new(r, s)
    }

    /// The DER encoding of `SM2Signature` (GM/T 0009-2012 section 7.3).
    #[cfg(umilib_feature = "codec-asn1-der")]
    pub fn to_der(&self) -> alloc::vec::Vec<u8> {
        use crate::codec::asn1::der::DERWriter;
        let mut writer = DERWriter::new();
        let mut bytes = alloc::vec![0u8; <C::Scalar as PrimeField>::BYTES];
        // Writing into a sequence cannot fail.
        let _ = writer.write_sequence(|sequence| {
            for value in [&self.r, &self.s] {
                // The buffer has the length of every element.
                let _ = value.write_be_bytes(&mut bytes);
                sequence.write_integer_unsigned(&bytes);
            }
            Ok(())
        });
        writer.into_bytes()
    }
}

impl<C: WeierstrassCurve> Clone for SM2Signature<C> {
    fn clone(&self) -> SM2Signature<C> {
        *self
    }
}

impl<C: WeierstrassCurve> Copy for SM2Signature<C> {}

impl<C: WeierstrassCurve> PartialEq for SM2Signature<C> {
    fn eq(&self, other: &SM2Signature<C>) -> bool {
        (self.r.ct_eq(&other.r) & self.s.ct_eq(&other.s)).into_bool()
    }
}

impl<C: WeierstrassCurve> Eq for SM2Signature<C> {}

impl<C: WeierstrassCurve> ConditionallySelectable for SM2Signature<C> {
    fn select(a: &SM2Signature<C>, b: &SM2Signature<C>, choice: crate::secret::Choice) -> SM2Signature<C> {
        SM2Signature { r: FieldElement::select(&a.r, &b.r, choice), s: FieldElement::select(&a.s, &b.s, choice) }
    }
}

impl<C: WeierstrassCurve> fmt::Debug for SM2Signature<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SM2Signature(r: {:?}, s: {:?})", self.r, self.s)
    }
}
