use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::X509Error;
use crate::auth::cert::key::KeyError;
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ASN1Integer, Tag};
use crate::crypto::CryptoError;
use crate::crypto::random::Random;

/// A `CertificateSerialNumber` (RFC 5280 §4.1.2.2): an INTEGER, kept as
/// its contents octets (big-endian two's complement, in the fewest octets).
///
/// Reading accepts any integer, as RFC 5280 asks users to handle
/// non-positive and long serial numbers gracefully; [`SerialNumber::check`]
/// tests the requirement on CAs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SerialNumber<'a> {
    bytes: Cow<'a, [u8]>,
}

impl<'a> SerialNumber<'a> {
    /// The most octets a CA may use (RFC 5280 §4.1.2.2).
    pub const MAXIMUM_LENGTH: usize = 20;

    /// The serial number of the contents octets `bytes`, which must be a
    /// minimal INTEGER encoding.
    pub fn new(bytes: Cow<'a, [u8]>) -> Result<SerialNumber<'a>, X509Error> {
        ASN1Integer::new(&bytes)?;
        Ok(SerialNumber { bytes })
    }

    /// The non-negative serial number with the big-endian `magnitude`.
    pub fn from_magnitude(magnitude: &[u8]) -> SerialNumber<'static> {
        let mut bytes = Vec::with_capacity(magnitude.len() + 1);
        ASN1Integer::encode_unsigned(magnitude, &mut bytes);
        SerialNumber { bytes: Cow::Owned(bytes) }
    }

    pub fn from_u64(value: u64) -> SerialNumber<'static> {
        SerialNumber::from_magnitude(&value.to_be_bytes())
    }

    /// A positive serial number of 159 random bits, the most RFC 5280
    /// allows, which meets the 64 bits of entropy the CA/Browser Forum
    /// requires with room to spare.
    pub fn random<R: Random>(random: &mut R) -> Result<SerialNumber<'static>, X509Error> {
        let mut magnitude = [0u8; SerialNumber::MAXIMUM_LENGTH];
        random.fill(&mut magnitude).map_err(|_| X509Error::Key(KeyError::Crypto(CryptoError::RandomFailed)))?;
        magnitude[0] &= 0x7F;
        // Zero is not positive; it comes once in 2^159.
        if magnitude.iter().all(|&byte| byte == 0) {
            magnitude[SerialNumber::MAXIMUM_LENGTH - 1] = 1;
        }
        Ok(SerialNumber::from_magnitude(&magnitude))
    }

    /// The contents octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn is_negative(&self) -> bool {
        self.bytes.first().is_some_and(|&first| first & 0x80 != 0)
    }

    /// Whether the serial number is positive and at most
    /// [`SerialNumber::MAXIMUM_LENGTH`] octets, as RFC 5280 §4.1.2.2 requires of CAs.
    pub fn is_conforming(&self) -> bool {
        let positive = !self.is_negative() && self.bytes.iter().any(|&byte| byte != 0);
        positive && self.bytes.len() <= SerialNumber::MAXIMUM_LENGTH
    }

    /// Fails with [`X509Error::InvalidSerialNumber`] unless [`SerialNumber::is_conforming`].
    pub fn check(&self) -> Result<(), X509Error> {
        if self.is_conforming() { Ok(()) } else { Err(X509Error::InvalidSerialNumber) }
    }

    /// Reads the next INTEGER of `reader`.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<SerialNumber<'a>, X509Error> {
        let integer = reader.read_integer()?;
        Ok(SerialNumber { bytes: Cow::Borrowed(integer.as_bytes()) })
    }

    pub fn encode(&self, writer: &mut DERWriter) {
        writer.write_element(Tag::INTEGER, &self.bytes);
    }

    pub fn into_owned(self) -> SerialNumber<'static> {
        SerialNumber { bytes: Cow::Owned(self.bytes.into_owned()) }
    }
}
