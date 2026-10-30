use core::fmt;

use super::DSAParameters;
use crate::crypto::CryptoError;
use crate::math::bigint::BoxedUint;

/// A signature of [`DSA`](super::DSA): the integers r and s, each in 1..q.
#[derive(Clone, PartialEq, Eq)]
pub struct DSASignature {
    r: BoxedUint,
    s: BoxedUint,
}

impl DSASignature {
    /// The signature (r, s) under `parameters`; fails with `InvalidSignature`
    /// unless both are in 1..q.
    pub fn new(parameters: &DSAParameters, r: &BoxedUint, s: &BoxedUint) -> Result<DSASignature, CryptoError> {
        let q = parameters.q().value();
        let valid = |value: &BoxedUint| (!value.is_zero() & value.ct_lt(q)).into_bool();
        if !valid(r) || !valid(s) {
            return Err(CryptoError::InvalidSignature);
        }
        let invalid = |_| CryptoError::InvalidSignature;
        Ok(DSASignature { r: r.resize(q.precision()).map_err(invalid)?, s: s.resize(q.precision()).map_err(invalid)? })
    }

    pub fn r(&self) -> &BoxedUint {
        &self.r
    }

    pub fn s(&self) -> &BoxedUint {
        &self.s
    }

    /// The signature of the fixed encoding of r and s, each of the bytes of
    /// q; fails with `InvalidSignature` for another length or an integer
    /// outside 1..q.
    pub fn from_bytes(parameters: &DSAParameters, bytes: &[u8]) -> Result<DSASignature, CryptoError> {
        let size = parameters.q_bytes();
        if bytes.len() != 2 * size {
            return Err(CryptoError::InvalidSignature);
        }
        let precision = parameters.q().value().precision();
        let read = |bytes: &[u8]| BoxedUint::from_be_bytes(bytes, precision).map_err(|_| CryptoError::InvalidSignature);
        DSASignature::new(parameters, &read(&bytes[..size])?, &read(&bytes[size..])?)
    }

    /// Writes the fixed encoding into `out` of twice the bytes of q.
    pub fn write_bytes(&self, parameters: &DSAParameters, out: &mut [u8]) -> Result<(), CryptoError> {
        let size = parameters.q_bytes();
        let length = out.len();
        if length != 2 * size {
            return Err(CryptoError::InputLength { length });
        }
        let failed = |_| CryptoError::InputLength { length };
        let (r, s) = out.split_at_mut(size);
        self.r.write_be_bytes(r).map_err(failed)?;
        self.s.write_be_bytes(s).map_err(failed)
    }

    /// The signature of the DER encoding of `Dss-Sig-Value` (RFC 3279
    /// section 2.2.2): a SEQUENCE of the INTEGERs r and s and nothing else;
    /// fails with `InvalidSignature` otherwise.
    #[cfg(umilib_feature = "codec-asn1-der")]
    pub fn from_der(parameters: &DSAParameters, bytes: &[u8]) -> Result<DSASignature, CryptoError> {
        use crate::codec::asn1::Tag;
        use crate::codec::asn1::der::DERReader;
        let invalid = |_| CryptoError::InvalidSignature;
        let mut reader = DERReader::new(bytes);
        let mut sequence = reader.read_sequence().map_err(invalid)?;
        reader.finish().map_err(invalid)?;
        let precision = parameters.q().value().precision();
        let mut integer = || -> Result<BoxedUint, CryptoError> {
            let element = sequence.read_expected(Tag::INTEGER).map_err(invalid)?;
            let value = element.as_integer().map_err(invalid)?;
            let magnitude = value.magnitude().ok_or(CryptoError::InvalidSignature)?;
            BoxedUint::from_be_bytes(magnitude, precision).map_err(|_| CryptoError::InvalidSignature)
        };
        let (r, s) = (integer()?, integer()?);
        sequence.finish().map_err(invalid)?;
        DSASignature::new(parameters, &r, &s)
    }

    /// The DER encoding of `Dss-Sig-Value`.
    #[cfg(umilib_feature = "codec-asn1-der")]
    pub fn to_der(&self) -> alloc::vec::Vec<u8> {
        let mut writer = crate::codec::asn1::der::DERWriter::new();
        // Writing into a sequence cannot fail.
        let _ = writer.write_sequence(|sequence| {
            sequence.write_integer_unsigned(&self.r.to_be_bytes());
            sequence.write_integer_unsigned(&self.s.to_be_bytes());
            Ok(())
        });
        writer.into_bytes()
    }
}

impl fmt::Debug for DSASignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "DSASignature(r: {:?}, s: {:?})", self.r, self.s)
    }
}
