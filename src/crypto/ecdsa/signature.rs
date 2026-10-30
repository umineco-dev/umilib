use core::fmt;

use crate::crypto::CryptoError;
use crate::math::ec::{FieldElement, PrimeField, WeierstrassCurve};
use crate::secret::{ConditionallySelectable, ConstantTimeEq};

/// A signature of [`ECDSA`](super::ECDSA): the integers r and s, each in 1..n.
pub struct ECDSASignature<C: WeierstrassCurve> {
    r: FieldElement<C::Scalar>,
    s: FieldElement<C::Scalar>,
}

impl<C: WeierstrassCurve> ECDSASignature<C> {
    /// The bytes of the fixed encoding: r then s, each of the bytes of the order.
    pub const BYTES: usize = 2 * <C::Scalar as PrimeField>::BYTES;

    /// The signature (r, s); fails with `InvalidSignature` if either is zero.
    pub fn new(r: FieldElement<C::Scalar>, s: FieldElement<C::Scalar>) -> Result<ECDSASignature<C>, CryptoError> {
        if (r.is_zero() | s.is_zero()).into_bool() {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(ECDSASignature { r, s })
    }

    pub fn r(&self) -> &FieldElement<C::Scalar> {
        &self.r
    }

    pub fn s(&self) -> &FieldElement<C::Scalar> {
        &self.s
    }

    /// The signature of the fixed encoding of [`ECDSASignature::BYTES`]
    /// bytes; fails with `InvalidSignature` for another length or an integer
    /// outside 1..n.
    pub fn from_bytes(bytes: &[u8]) -> Result<ECDSASignature<C>, CryptoError> {
        if bytes.len() != ECDSASignature::<C>::BYTES {
            return Err(CryptoError::InvalidSignature);
        }
        let (r, s) = bytes.split_at(<C::Scalar as PrimeField>::BYTES);
        let read = |bytes: &[u8]| FieldElement::from_be_bytes(bytes).map_err(|_| CryptoError::InvalidSignature);
        ECDSASignature::new(read(r)?, read(s)?)
    }

    /// Writes the fixed encoding into `out` of [`ECDSASignature::BYTES`] bytes.
    pub fn write_bytes(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != ECDSASignature::<C>::BYTES {
            return Err(CryptoError::InputLength { length });
        }
        let (r, s) = out.split_at_mut(<C::Scalar as PrimeField>::BYTES);
        let failed = |_| CryptoError::InputLength { length };
        self.r.write_be_bytes(r).map_err(failed)?;
        self.s.write_be_bytes(s).map_err(failed)
    }

    /// The signature of the DER encoding of `Ecdsa-Sig-Value` (SEC 1
    /// section C.5): a SEQUENCE of the INTEGERs r and s and nothing else, in
    /// the one encoding DER allows. Fails with `InvalidSignature` otherwise or
    /// for an integer outside 1..n.
    #[cfg(umilib_feature = "codec-asn1-der")]
    pub fn from_der(bytes: &[u8]) -> Result<ECDSASignature<C>, CryptoError> {
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
        ECDSASignature::new(r, s)
    }

    /// The DER encoding of `Ecdsa-Sig-Value` (SEC 1 section C.5).
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

impl<C: WeierstrassCurve> Clone for ECDSASignature<C> {
    fn clone(&self) -> ECDSASignature<C> {
        *self
    }
}

impl<C: WeierstrassCurve> Copy for ECDSASignature<C> {}

impl<C: WeierstrassCurve> PartialEq for ECDSASignature<C> {
    fn eq(&self, other: &ECDSASignature<C>) -> bool {
        (self.r.ct_eq(&other.r) & self.s.ct_eq(&other.s)).into_bool()
    }
}

impl<C: WeierstrassCurve> Eq for ECDSASignature<C> {}

impl<C: WeierstrassCurve> ConditionallySelectable for ECDSASignature<C> {
    fn select(a: &ECDSASignature<C>, b: &ECDSASignature<C>, choice: crate::secret::Choice) -> ECDSASignature<C> {
        ECDSASignature { r: FieldElement::select(&a.r, &b.r, choice), s: FieldElement::select(&a.s, &b.s, choice) }
    }
}

impl<C: WeierstrassCurve> fmt::Debug for ECDSASignature<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ECDSASignature(r: {:?}, s: {:?})", self.r, self.s)
    }
}
