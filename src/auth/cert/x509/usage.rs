use alloc::vec::Vec;
use core::ops::BitOr;

use super::{ExtensionValue, X509Error};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ASN1Time, BitString, ObjectIdentifier, Tag};

/// The `KeyUsage` extension (RFC 5280 §4.2.1.3): the purposes of the key,
/// bit `n` of the named bit list being `1 << n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyUsage {
    pub bits: u16,
}

impl KeyUsage {
    pub const DIGITAL_SIGNATURE: KeyUsage = KeyUsage { bits: 1 << 0 };
    /// `nonRepudiation`, renamed `contentCommitment` by recent editions of X.509.
    pub const CONTENT_COMMITMENT: KeyUsage = KeyUsage { bits: 1 << 1 };
    pub const KEY_ENCIPHERMENT: KeyUsage = KeyUsage { bits: 1 << 2 };
    pub const DATA_ENCIPHERMENT: KeyUsage = KeyUsage { bits: 1 << 3 };
    pub const KEY_AGREEMENT: KeyUsage = KeyUsage { bits: 1 << 4 };
    pub const KEY_CERT_SIGN: KeyUsage = KeyUsage { bits: 1 << 5 };
    pub const CRL_SIGN: KeyUsage = KeyUsage { bits: 1 << 6 };
    pub const ENCIPHER_ONLY: KeyUsage = KeyUsage { bits: 1 << 7 };
    pub const DECIPHER_ONLY: KeyUsage = KeyUsage { bits: 1 << 8 };
    /// The bits RFC 5280 names.
    pub const ALL: KeyUsage = KeyUsage { bits: 0x1FF };

    /// Whether every bit of `usage` is set.
    pub const fn contains(self, usage: KeyUsage) -> bool {
        self.bits & usage.bits == usage.bits
    }

    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Fails unless at least one bit is set (RFC 5280 §4.2.1.3) and every
    /// bit is one RFC 5280 names.
    pub fn check(&self) -> Result<(), X509Error> {
        if self.is_empty() || !KeyUsage::ALL.contains(*self) {
            return Err(X509Error::InvalidExtension);
        }
        Ok(())
    }
}

impl BitOr for KeyUsage {
    type Output = KeyUsage;

    fn bitor(self, other: KeyUsage) -> KeyUsage {
        KeyUsage { bits: self.bits | other.bits }
    }
}

impl ExtensionValue<'_> for KeyUsage {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 15]);

    /// Reads the bits; trailing zero bits, which DER omits, are accepted,
    /// and bits RFC 5280 does not name are refused (see [`KeyUsage::check`]).
    fn decode(reader: &mut DERReader<'_>) -> Result<KeyUsage, X509Error> {
        let bits = reader.read_bit_string()?.named_bits().map_err(|_| X509Error::InvalidExtension)?;
        let usage = KeyUsage { bits: u16::try_from(bits).map_err(|_| X509Error::InvalidExtension)? };
        usage.check()?;
        Ok(usage)
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        self.check()?;
        writer.write_bit_string(&BitString::from_named_bits(self.bits as u64))?;
        Ok(())
    }
}

/// The `ExtendedKeyUsage` extension (RFC 5280 §4.2.1.12): the purposes of
/// the key, at least one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExtendedKeyUsage<'a> {
    pub purposes: Vec<ObjectIdentifier<'a>>,
}

impl ExtendedKeyUsage<'_> {
    /// `anyExtendedKeyUsage`.
    pub const ANY: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 37, 0]);
    pub const SERVER_AUTH: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]);
    pub const CLIENT_AUTH: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]);
    pub const CODE_SIGNING: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03]);
    pub const EMAIL_PROTECTION: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04]);
    pub const TIME_STAMPING: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08]);
    pub const OCSP_SIGNING: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09]);

    /// Whether `purpose` is listed.
    pub fn contains(&self, purpose: &ObjectIdentifier<'_>) -> bool {
        self.purposes.iter().any(|listed| listed == purpose)
    }

    pub fn into_owned(self) -> ExtendedKeyUsage<'static> {
        ExtendedKeyUsage { purposes: self.purposes.into_iter().map(ObjectIdentifier::into_owned).collect() }
    }
}

impl<'a> ExtensionValue<'a> for ExtendedKeyUsage<'a> {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 37]);

    fn decode(reader: &mut DERReader<'a>) -> Result<ExtendedKeyUsage<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let mut purposes = Vec::new();
        while !sequence.is_empty() {
            purposes.push(sequence.read_object_identifier()?);
        }
        if purposes.is_empty() {
            return Err(X509Error::InvalidExtension);
        }
        Ok(ExtendedKeyUsage { purposes })
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        if self.purposes.is_empty() {
            return Err(X509Error::InvalidExtension);
        }
        writer.write_sequence(|sequence| {
            self.purposes.iter().for_each(|purpose| sequence.write_object_identifier(purpose));
            Ok(())
        })?;
        Ok(())
    }
}

/// The `PrivateKeyUsagePeriod` extension (X.509 §9.2.2.5; RFC 5280
/// appendix A.2): the period in which the private key may be used, at
/// least one end present.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PrivateKeyUsagePeriod {
    pub not_before: Option<ASN1Time>,
    pub not_after: Option<ASN1Time>,
}

impl ExtensionValue<'_> for PrivateKeyUsagePeriod {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 16]);

    fn decode(reader: &mut DERReader<'_>) -> Result<PrivateKeyUsagePeriod, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let mut time = |number| -> Result<Option<ASN1Time>, X509Error> {
            Ok(match sequence.read_optional(Tag::context(number, false))? {
                Some(element) => Some(element.as_generalized_time()?),
                None => None,
            })
        };
        let not_before = time(0)?;
        let not_after = time(1)?;
        sequence.finish()?;
        if not_before.is_none() && not_after.is_none() {
            return Err(X509Error::InvalidExtension);
        }
        Ok(PrivateKeyUsagePeriod { not_before, not_after })
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        if self.not_before.is_none() && self.not_after.is_none() {
            return Err(X509Error::InvalidExtension);
        }
        let mut inner = DERWriter::new();
        for (number, time) in [(0, &self.not_before), (1, &self.not_after)] {
            if let Some(time) = time {
                let mut content = Vec::new();
                time.encode_generalized_time(&mut content)?;
                inner.write_element(Tag::context(number, false), &content);
            }
        }
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }
}
