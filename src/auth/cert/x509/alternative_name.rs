use alloc::vec::Vec;

use super::{ExtensionValue, GeneralName, X509Error};
use crate::codec::asn1::ObjectIdentifier;
use crate::codec::asn1::der::{DERReader, DERWriter};

/// Defines an extension whose value is a `GeneralNames` that names
/// entities, in which an `iPAddress` is an address of 4 or 16 octets (RFC
/// 5280 §4.2.1.6).
macro_rules! general_names_extension {
    ($(#[$meta:meta])* $name:ident, $oid:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name<'a> {
            pub names: Vec<GeneralName<'a>>,
        }

        impl $name<'_> {
            pub fn into_owned(self) -> $name<'static> {
                $name { names: GeneralName::into_owned_names(self.names) }
            }
        }

        impl<'a> ExtensionValue<'a> for $name<'a> {
            const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static($oid);

            fn decode(reader: &mut DERReader<'a>) -> Result<$name<'a>, X509Error> {
                let names = GeneralName::decode_names(reader)?;
                SubjectAlternativeName::check_addresses(&names)?;
                Ok($name { names })
            }

            fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
                SubjectAlternativeName::check_addresses(&self.names)?;
                GeneralName::encode_names(&self.names, writer)
            }
        }
    };
}

general_names_extension!(
    /// The `SubjectAltName` extension (RFC 5280 §4.2.1.6): the names of the subject.
    SubjectAlternativeName,
    &[0x55, 0x1D, 17]
);

general_names_extension!(
    /// The `IssuerAltName` extension (RFC 5280 §4.2.1.7, §5.2.2): the names of the issuer.
    IssuerAlternativeName,
    &[0x55, 0x1D, 18]
);

general_names_extension!(
    /// The `CertificateIssuer` CRL entry extension (RFC 5280 §5.3.3): the
    /// issuer of the certificate of the entry and those after it, in an indirect CRL.
    CertificateIssuer,
    &[0x55, 0x1D, 29]
);

impl SubjectAlternativeName<'_> {
    /// Fails with [`X509Error::InvalidName`] if an `iPAddress` of `names`
    /// is not an address of 4 or 16 octets.
    pub fn check_addresses(names: &[GeneralName<'_>]) -> Result<(), X509Error> {
        let invalid = |name: &GeneralName<'_>| matches!(name, GeneralName::IPAddress(address) if address.len() != 4 && address.len() != 16);
        if names.iter().any(invalid) {
            return Err(X509Error::InvalidName);
        }
        Ok(())
    }
}
