use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::{ExtensionValue, GeneralName, SerialNumber, X509Error};
use crate::auth::cert::key::PublicKey;
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ObjectIdentifier, Tag};
use crate::hash::Digest;
use crate::hash::sha::v1::SHA1;

/// The `AuthorityKeyIdentifier` extension (RFC 5280 §4.2.1.1): which key of
/// the issuer signed the certificate or CRL.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AuthorityKeyIdentifier<'a> {
    pub key_identifier: Option<Cow<'a, [u8]>>,
    /// The issuer and serial number of the issuer's certificate, both
    /// present or both absent.
    pub authority_cert_issuer: Option<Vec<GeneralName<'a>>>,
    pub authority_cert_serial_number: Option<SerialNumber<'a>>,
}

impl AuthorityKeyIdentifier<'_> {
    pub fn into_owned(self) -> AuthorityKeyIdentifier<'static> {
        AuthorityKeyIdentifier {
            key_identifier: self.key_identifier.map(|identifier| Cow::Owned(identifier.into_owned())),
            authority_cert_issuer: self.authority_cert_issuer.map(GeneralName::into_owned_names),
            authority_cert_serial_number: self.authority_cert_serial_number.map(SerialNumber::into_owned),
        }
    }
}

impl<'a> ExtensionValue<'a> for AuthorityKeyIdentifier<'a> {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 35]);

    fn decode(reader: &mut DERReader<'a>) -> Result<AuthorityKeyIdentifier<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let key_identifier =
            sequence.read_optional(Tag::context(0, false))?.map(|element| Cow::Borrowed(element.content));
        let authority_cert_issuer = match sequence.read_optional(Tag::context(1, true))? {
            Some(element) => Some(GeneralName::decode_names_in(&mut sequence.nested(&element)?)?),
            None => None,
        };
        let authority_cert_serial_number = match sequence.read_optional(Tag::context(2, false))? {
            Some(element) => Some(SerialNumber::new(Cow::Borrowed(element.as_integer()?.as_bytes()))?),
            None => None,
        };
        sequence.finish()?;
        if authority_cert_issuer.is_some() != authority_cert_serial_number.is_some() {
            return Err(X509Error::InvalidExtension);
        }
        Ok(AuthorityKeyIdentifier { key_identifier, authority_cert_issuer, authority_cert_serial_number })
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        if self.authority_cert_issuer.is_some() != self.authority_cert_serial_number.is_some() {
            return Err(X509Error::InvalidExtension);
        }
        let mut inner = DERWriter::new();
        if let Some(identifier) = &self.key_identifier {
            inner.write_element(Tag::context(0, false), identifier);
        }
        if let Some(names) = &self.authority_cert_issuer {
            let mut contents = DERWriter::new();
            GeneralName::encode_names_in(names, &mut contents)?;
            inner.write_element(Tag::context(1, true), contents.as_bytes());
        }
        if let Some(serial_number) = &self.authority_cert_serial_number {
            inner.write_element(Tag::context(2, false), serial_number.as_bytes());
        }
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }
}

/// The `SubjectKeyIdentifier` extension (RFC 5280 §4.2.1.2): an identifier
/// of the subject's public key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SubjectKeyIdentifier<'a> {
    pub key_identifier: Cow<'a, [u8]>,
}

impl SubjectKeyIdentifier<'_> {
    /// The identifier of `key` by the first method of RFC 5280 §4.2.1.2:
    /// the SHA-1 hash of the `subjectPublicKey` bits, as OpenSSL computes it.
    pub fn from_public_key(key: &PublicKey) -> SubjectKeyIdentifier<'static> {
        SubjectKeyIdentifier { key_identifier: Cow::Owned(SHA1::digest(key.key()).as_ref().to_vec()) }
    }

    pub fn into_owned(self) -> SubjectKeyIdentifier<'static> {
        SubjectKeyIdentifier { key_identifier: Cow::Owned(self.key_identifier.into_owned()) }
    }
}

impl<'a> ExtensionValue<'a> for SubjectKeyIdentifier<'a> {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 14]);

    fn decode(reader: &mut DERReader<'a>) -> Result<SubjectKeyIdentifier<'a>, X509Error> {
        Ok(SubjectKeyIdentifier { key_identifier: Cow::Borrowed(reader.read_octet_string()?) })
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        writer.write_octet_string(&self.key_identifier);
        Ok(())
    }
}
