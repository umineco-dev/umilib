use core::fmt;

use crate::crypto::CryptoError;
use crate::math::bigint::BoxedUint;
use crate::math::modular::BoxedModulus;

/// An RSA public key (n, e) of RFC 8017 section 3.1: n odd, e odd with
/// 3 ≤ e < n. The modulus keeps the precision of its bit length.
#[derive(Clone)]
pub struct RSAPublicKey {
    modulus: BoxedModulus,
    exponent: BoxedUint,
}

impl RSAPublicKey {
    /// The key (n, e); fails with `InvalidKey` unless n is odd and above 3
    /// and e is odd with 3 ≤ e < n.
    pub fn new(n: &BoxedUint, e: &BoxedUint) -> Result<RSAPublicKey, CryptoError> {
        let invalid = |_| CryptoError::InvalidKey;
        let n = n.resize(n.bit_length()).map_err(invalid)?;
        let modulus = BoxedModulus::new(n).map_err(invalid)?;
        let exponent = e.resize(e.bit_length()).map_err(invalid)?;
        let three = BoxedUint::from_u64(3, 64).map_err(invalid)?;
        let valid = exponent.is_odd() & !exponent.ct_lt(&three) & exponent.ct_lt(modulus.value());
        if !valid.into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(RSAPublicKey { modulus, exponent })
    }

    /// The modulus n.
    pub fn n(&self) -> &BoxedUint {
        self.modulus.value()
    }

    /// The public exponent e.
    pub fn e(&self) -> &BoxedUint {
        &self.exponent
    }

    pub fn modulus(&self) -> &BoxedModulus {
        &self.modulus
    }

    /// The bits of n.
    pub fn bits(&self) -> u32 {
        self.n().bit_length()
    }

    /// The bytes of n: k of RFC 8017, the length of signatures and ciphertexts.
    pub fn size(&self) -> usize {
        self.bits().div_ceil(8) as usize
    }

    /// RSAEP and RSAVP1 (sections 5.1.1 and 5.2.2): x^e mod n for x < n;
    /// fails with `InvalidParameter` for x ≥ n. The time depends on e, which
    /// is public.
    pub fn apply(&self, x: &BoxedUint) -> Result<BoxedUint, CryptoError> {
        if !self.contains(x) {
            return Err(CryptoError::InvalidParameter);
        }
        let failed = |_| CryptoError::InvalidParameter;
        let power = self.modulus.pow_vartime(&self.modulus.residue(x), &self.exponent).map_err(failed)?;
        self.modulus.retrieve(&power).map_err(failed)
    }

    /// Whether x < n.
    pub fn contains(&self, x: &BoxedUint) -> bool {
        x.ct_lt(self.n()).into_bool()
    }

    /// OS2IP of `bytes` (section 4.2) in the precision of n; fails with
    /// `InvalidParameter` for more than [`RSAPublicKey::size`] bytes or a
    /// value not below n.
    pub fn integer(&self, bytes: &[u8]) -> Result<BoxedUint, CryptoError> {
        if bytes.len() > self.size() {
            return Err(CryptoError::InvalidParameter);
        }
        let x = BoxedUint::from_be_bytes(bytes, self.modulus.precision()).map_err(|_| CryptoError::InvalidParameter)?;
        if !self.contains(&x) {
            return Err(CryptoError::InvalidParameter);
        }
        Ok(x)
    }

    /// The PKCS #1 `RSAPublicKey` of RFC 8017 appendix A.1.1 in DER: a
    /// SEQUENCE of the INTEGERs n and e and nothing else. Fails with
    /// `InvalidKey` otherwise.
    #[cfg(umilib_feature = "codec-asn1-der")]
    pub fn from_pkcs1_der(bytes: &[u8]) -> Result<RSAPublicKey, CryptoError> {
        let mut reader = crate::codec::asn1::der::DERReader::new(bytes);
        let mut sequence = reader.read_sequence().map_err(|_| CryptoError::InvalidKey)?;
        reader.finish().map_err(|_| CryptoError::InvalidKey)?;
        let n = RSAPublicKey::read_integer(&mut sequence)?;
        let e = RSAPublicKey::read_integer(&mut sequence)?;
        sequence.finish().map_err(|_| CryptoError::InvalidKey)?;
        RSAPublicKey::new(&n, &e)
    }

    /// The PKCS #1 `RSAPublicKey` in DER.
    #[cfg(umilib_feature = "codec-asn1-der")]
    pub fn to_pkcs1_der(&self) -> alloc::vec::Vec<u8> {
        let mut writer = crate::codec::asn1::der::DERWriter::new();
        // Writing into a sequence cannot fail.
        let _ = writer.write_sequence(|sequence| {
            sequence.write_integer_unsigned(&self.n().to_be_bytes());
            sequence.write_integer_unsigned(&self.e().to_be_bytes());
            Ok(())
        });
        writer.into_bytes()
    }

    /// A non-negative INTEGER of a DER sequence; fails with `InvalidKey`.
    #[cfg(umilib_feature = "codec-asn1-der")]
    pub fn read_integer(sequence: &mut crate::codec::asn1::der::DERReader<'_>) -> Result<BoxedUint, CryptoError> {
        let element = sequence.read_expected(crate::codec::asn1::Tag::INTEGER).map_err(|_| CryptoError::InvalidKey)?;
        let integer = element.as_integer().map_err(|_| CryptoError::InvalidKey)?;
        let magnitude = integer.magnitude().ok_or(CryptoError::InvalidKey)?;
        let precision = u32::try_from(magnitude.len().max(1) * 8).map_err(|_| CryptoError::InvalidKey)?;
        BoxedUint::from_be_bytes(magnitude, precision).map_err(|_| CryptoError::InvalidKey)
    }
}

impl PartialEq for RSAPublicKey {
    fn eq(&self, other: &RSAPublicKey) -> bool {
        self.n().compare_vartime(other.n()).is_eq() && self.e().compare_vartime(other.e()).is_eq()
    }
}

impl Eq for RSAPublicKey {}

impl fmt::Debug for RSAPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RSAPublicKey(bits: {}, e: {:?})", self.bits(), self.exponent)
    }
}
