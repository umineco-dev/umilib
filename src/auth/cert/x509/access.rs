use alloc::vec::Vec;

use super::{ExtensionValue, GeneralName, X509Error};
use crate::codec::asn1::ObjectIdentifier;
use crate::codec::asn1::der::{DERReader, DERWriter};

/// An `AccessDescription` (RFC 5280 §4.2.2.1): how and where to reach a service.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AccessDescription<'a> {
    pub method: ObjectIdentifier<'a>,
    pub location: GeneralName<'a>,
}

impl<'a> AccessDescription<'a> {
    /// `id-ad-ocsp`: an OCSP responder (RFC 6960).
    pub const OCSP: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]);
    /// `id-ad-caIssuers`: certificates of the issuer.
    pub const CA_ISSUERS: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02]);
    /// `id-ad-timeStamping`: a time-stamping service (RFC 3161).
    pub const TIME_STAMPING: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x03]);
    /// `id-ad-caRepository`: certificates and CRLs the subject CA issued.
    pub const CA_REPOSITORY: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x05]);

    pub fn decode(reader: &mut DERReader<'a>) -> Result<AccessDescription<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let method = sequence.read_object_identifier()?;
        let location = GeneralName::decode(&mut sequence)?;
        sequence.finish()?;
        Ok(AccessDescription { method, location })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        let mut inner = DERWriter::new();
        inner.write_object_identifier(&self.method);
        self.location.encode(&mut inner)?;
        writer.write_element(crate::codec::asn1::Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn into_owned(self) -> AccessDescription<'static> {
        AccessDescription { method: self.method.into_owned(), location: self.location.into_owned() }
    }
}

/// Defines an extension whose value is a sequence of at least one `AccessDescription`.
macro_rules! access_extension {
    ($(#[$meta:meta])* $name:ident, $oid:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name<'a> {
            pub descriptions: Vec<AccessDescription<'a>>,
        }

        impl $name<'_> {
            pub fn into_owned(self) -> $name<'static> {
                $name { descriptions: self.descriptions.into_iter().map(AccessDescription::into_owned).collect() }
            }
        }

        impl<'a> ExtensionValue<'a> for $name<'a> {
            const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static($oid);

            fn decode(reader: &mut DERReader<'a>) -> Result<$name<'a>, X509Error> {
                let mut sequence = reader.read_sequence()?;
                let mut descriptions = Vec::new();
                while !sequence.is_empty() {
                    descriptions.push(AccessDescription::decode(&mut sequence)?);
                }
                if descriptions.is_empty() {
                    return Err(X509Error::InvalidExtension);
                }
                Ok($name { descriptions })
            }

            fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
                if self.descriptions.is_empty() {
                    return Err(X509Error::InvalidExtension);
                }
                let mut inner = DERWriter::new();
                self.descriptions.iter().try_for_each(|description| description.encode(&mut inner))?;
                writer.write_element(crate::codec::asn1::Tag::SEQUENCE, inner.as_bytes());
                Ok(())
            }
        }
    };
}

access_extension!(
    /// The `AuthorityInfoAccess` extension (RFC 5280 §4.2.2.1): services of the issuer.
    AuthorityInformationAccess,
    &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]
);

access_extension!(
    /// The `SubjectInfoAccess` extension (RFC 5280 §4.2.2.2): services of the subject.
    SubjectInformationAccess,
    &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0B]
);
