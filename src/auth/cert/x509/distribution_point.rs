use alloc::vec::Vec;

use super::{ExtensionValue, GeneralName, RelativeDistinguishedName, X509Error};
use crate::codec::asn1::der::{DERElement, DERReader, DERWriter};
use crate::codec::asn1::{ASN1Error, BitString, ObjectIdentifier, Tag};

/// The `ReasonFlags` (RFC 5280 §4.2.1.13): reasons for revocation, bit `n`
/// of the named bit list being `1 << n`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ReasonFlags {
    pub bits: u16,
}

impl ReasonFlags {
    pub const UNUSED: ReasonFlags = ReasonFlags { bits: 1 << 0 };
    pub const KEY_COMPROMISE: ReasonFlags = ReasonFlags { bits: 1 << 1 };
    pub const CA_COMPROMISE: ReasonFlags = ReasonFlags { bits: 1 << 2 };
    pub const AFFILIATION_CHANGED: ReasonFlags = ReasonFlags { bits: 1 << 3 };
    pub const SUPERSEDED: ReasonFlags = ReasonFlags { bits: 1 << 4 };
    pub const CESSATION_OF_OPERATION: ReasonFlags = ReasonFlags { bits: 1 << 5 };
    pub const CERTIFICATE_HOLD: ReasonFlags = ReasonFlags { bits: 1 << 6 };
    pub const PRIVILEGE_WITHDRAWN: ReasonFlags = ReasonFlags { bits: 1 << 7 };
    pub const AA_COMPROMISE: ReasonFlags = ReasonFlags { bits: 1 << 8 };
    /// The bits RFC 5280 names.
    pub const ALL: ReasonFlags = ReasonFlags { bits: 0x1FF };

    pub const fn contains(self, reasons: ReasonFlags) -> bool {
        self.bits & reasons.bits == reasons.bits
    }

    /// Reads the bits of `element`, a BIT STRING of any tag; trailing zero
    /// bits are accepted and bits RFC 5280 does not name refused.
    pub fn decode(element: &DERElement<'_>) -> Result<ReasonFlags, X509Error> {
        let bits = element.as_bit_string()?.named_bits().map_err(|_| X509Error::InvalidExtension)?;
        if bits & !(ReasonFlags::ALL.bits as u64) != 0 {
            return Err(X509Error::InvalidExtension);
        }
        Ok(ReasonFlags { bits: bits as u16 })
    }

    /// Writes the bits as a BIT STRING of `tag`.
    pub fn encode(&self, tag: Tag, writer: &mut DERWriter) -> Result<(), X509Error> {
        if !ReasonFlags::ALL.contains(*self) {
            return Err(X509Error::InvalidExtension);
        }
        let mut content = Vec::new();
        BitString::from_named_bits(self.bits as u64).encode_content(&mut content);
        writer.write_element(tag, &content);
        Ok(())
    }
}

/// A `DistributionPointName` (RFC 5280 §4.2.1.13): where a CRL is found.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DistributionPointName<'a> {
    FullName(Vec<GeneralName<'a>>),
    /// A name relative to the issuer of the CRL.
    NameRelativeToCRLIssuer(RelativeDistinguishedName<'a>),
}

impl<'a> DistributionPointName<'a> {
    /// Reads the name inside the explicit tag `[0]` that holds it.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<DistributionPointName<'a>, X509Error> {
        let element = reader.read_element()?;
        match element.tag {
            tag if tag == Tag::context(0, true) => {
                Ok(DistributionPointName::FullName(GeneralName::decode_names_in(&mut reader.nested(&element)?)?))
            }
            tag if tag == Tag::context(1, true) => {
                // `[1] IMPLICIT RelativeDistinguishedName`: the contents of a SET OF.
                let mut set = DERWriter::new();
                set.write_element(Tag::SET, element.content);
                let rdn = RelativeDistinguishedName::decode(&mut DERReader::new(set.as_bytes()))?;
                Ok(DistributionPointName::NameRelativeToCRLIssuer(rdn.into_owned()))
            }
            _ => Err(X509Error::Encoding(ASN1Error::UnexpectedTag { position: element.position })),
        }
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        match self {
            DistributionPointName::FullName(names) => {
                let mut contents = DERWriter::new();
                GeneralName::encode_names_in(names, &mut contents)?;
                writer.write_element(Tag::context(0, true), contents.as_bytes());
            }
            DistributionPointName::NameRelativeToCRLIssuer(rdn) => {
                let set = DERReader::new(rdn.as_der()).read_element()?;
                writer.write_element(Tag::context(1, true), set.content);
            }
        }
        Ok(())
    }

    pub fn into_owned(self) -> DistributionPointName<'static> {
        match self {
            DistributionPointName::FullName(names) => {
                DistributionPointName::FullName(GeneralName::into_owned_names(names))
            }
            DistributionPointName::NameRelativeToCRLIssuer(rdn) => {
                DistributionPointName::NameRelativeToCRLIssuer(rdn.into_owned())
            }
        }
    }
}

/// A `DistributionPoint` (RFC 5280 §4.2.1.13): where to find a CRL, for
/// which reasons, and who issues it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DistributionPoint<'a> {
    pub name: Option<DistributionPointName<'a>>,
    pub reasons: Option<ReasonFlags>,
    pub crl_issuer: Option<Vec<GeneralName<'a>>>,
}

impl<'a> DistributionPoint<'a> {
    /// Fails unless the point has a name or a CRL issuer: RFC 5280
    /// §4.2.1.13 forbids a point of only reasons.
    pub fn check(&self) -> Result<(), X509Error> {
        if self.name.is_none() && self.crl_issuer.is_none() {
            return Err(X509Error::InvalidExtension);
        }
        Ok(())
    }

    pub fn decode(reader: &mut DERReader<'a>) -> Result<DistributionPoint<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let name = match sequence.read_optional(Tag::context(0, true))? {
            Some(element) => {
                let mut explicit = sequence.nested(&element)?;
                let name = DistributionPointName::decode(&mut explicit)?;
                explicit.finish()?;
                Some(name)
            }
            None => None,
        };
        let reasons =
            sequence.read_optional(Tag::context(1, false))?.map(|element| ReasonFlags::decode(&element)).transpose()?;
        let crl_issuer = match sequence.read_optional(Tag::context(2, true))? {
            Some(element) => Some(GeneralName::decode_names_in(&mut sequence.nested(&element)?)?),
            None => None,
        };
        sequence.finish()?;
        let point = DistributionPoint { name, reasons, crl_issuer };
        point.check()?;
        Ok(point)
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        self.check()?;
        let mut inner = DERWriter::new();
        if let Some(name) = &self.name {
            let mut explicit = DERWriter::new();
            name.encode(&mut explicit)?;
            inner.write_element(Tag::context(0, true), explicit.as_bytes());
        }
        if let Some(reasons) = &self.reasons {
            reasons.encode(Tag::context(1, false), &mut inner)?;
        }
        if let Some(names) = &self.crl_issuer {
            let mut contents = DERWriter::new();
            GeneralName::encode_names_in(names, &mut contents)?;
            inner.write_element(Tag::context(2, true), contents.as_bytes());
        }
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn into_owned(self) -> DistributionPoint<'static> {
        DistributionPoint {
            name: self.name.map(DistributionPointName::into_owned),
            reasons: self.reasons,
            crl_issuer: self.crl_issuer.map(GeneralName::into_owned_names),
        }
    }
}

/// Defines an extension whose value is a sequence of at least one `DistributionPoint`.
macro_rules! distribution_points_extension {
    ($(#[$meta:meta])* $name:ident, $oid:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name<'a> {
            pub points: Vec<DistributionPoint<'a>>,
        }

        impl $name<'_> {
            pub fn into_owned(self) -> $name<'static> {
                $name { points: self.points.into_iter().map(DistributionPoint::into_owned).collect() }
            }
        }

        impl<'a> ExtensionValue<'a> for $name<'a> {
            const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static($oid);

            fn decode(reader: &mut DERReader<'a>) -> Result<$name<'a>, X509Error> {
                let mut sequence = reader.read_sequence()?;
                let mut points = Vec::new();
                while !sequence.is_empty() {
                    points.push(DistributionPoint::decode(&mut sequence)?);
                }
                if points.is_empty() {
                    return Err(X509Error::InvalidExtension);
                }
                Ok($name { points })
            }

            fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
                if self.points.is_empty() {
                    return Err(X509Error::InvalidExtension);
                }
                let mut inner = DERWriter::new();
                self.points.iter().try_for_each(|point| point.encode(&mut inner))?;
                writer.write_element(Tag::SEQUENCE, inner.as_bytes());
                Ok(())
            }
        }
    };
}

distribution_points_extension!(
    /// The `CRLDistributionPoints` extension (RFC 5280 §4.2.1.13): where the CRLs are.
    CRLDistributionPoints,
    &[0x55, 0x1D, 31]
);

distribution_points_extension!(
    /// The `FreshestCRL` extension (RFC 5280 §4.2.1.15, §5.2.6): where the delta CRLs are.
    FreshestCRL,
    &[0x55, 0x1D, 46]
);

/// The `IssuingDistributionPoint` CRL extension (RFC 5280 §5.2.5): the
/// distribution point of the CRL and the certificates and reasons it covers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IssuingDistributionPoint<'a> {
    pub name: Option<DistributionPointName<'a>>,
    pub only_contains_user_certs: bool,
    pub only_contains_ca_certs: bool,
    pub only_some_reasons: Option<ReasonFlags>,
    pub indirect_crl: bool,
    pub only_contains_attribute_certs: bool,
}

impl IssuingDistributionPoint<'_> {
    /// Fails unless at most one of the `onlyContains` flags is set and the
    /// point is not the empty sequence (RFC 5280 §5.2.5).
    pub fn check(&self) -> Result<(), X509Error> {
        let only = [self.only_contains_user_certs, self.only_contains_ca_certs, self.only_contains_attribute_certs];
        if only.iter().filter(|&&flag| flag).count() > 1 {
            return Err(X509Error::InvalidExtension);
        }
        let flags = only.iter().any(|&flag| flag) || self.indirect_crl;
        if !flags && self.name.is_none() && self.only_some_reasons.is_none() {
            return Err(X509Error::InvalidExtension);
        }
        Ok(())
    }

    /// Reads `[number] IMPLICIT BOOLEAN DEFAULT FALSE`; a FALSE written out,
    /// which DER omits, is accepted.
    pub fn decode_flag(reader: &mut DERReader<'_>, number: u32) -> Result<bool, X509Error> {
        match reader.read_optional(Tag::context(number, false))? {
            Some(element) => Ok(element.as_boolean()?),
            None => Ok(false),
        }
    }

    /// Writes `[number] IMPLICIT BOOLEAN DEFAULT FALSE`, omitted when false.
    pub fn encode_flag(writer: &mut DERWriter, number: u32, flag: bool) {
        if flag {
            writer.write_element(Tag::context(number, false), &[0xFF]);
        }
    }

    pub fn into_owned(self) -> IssuingDistributionPoint<'static> {
        IssuingDistributionPoint { name: self.name.map(DistributionPointName::into_owned), ..self }
    }
}

impl<'a> ExtensionValue<'a> for IssuingDistributionPoint<'a> {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 28]);

    /// Reads the point; flags written as FALSE, which DER omits, are accepted.
    fn decode(reader: &mut DERReader<'a>) -> Result<IssuingDistributionPoint<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let name = match sequence.read_optional(Tag::context(0, true))? {
            Some(element) => {
                let mut explicit = sequence.nested(&element)?;
                let name = DistributionPointName::decode(&mut explicit)?;
                explicit.finish()?;
                Some(name)
            }
            None => None,
        };
        let only_contains_user_certs = IssuingDistributionPoint::decode_flag(&mut sequence, 1)?;
        let only_contains_ca_certs = IssuingDistributionPoint::decode_flag(&mut sequence, 2)?;
        let only_some_reasons =
            sequence.read_optional(Tag::context(3, false))?.map(|element| ReasonFlags::decode(&element)).transpose()?;
        let indirect_crl = IssuingDistributionPoint::decode_flag(&mut sequence, 4)?;
        let only_contains_attribute_certs = IssuingDistributionPoint::decode_flag(&mut sequence, 5)?;
        sequence.finish()?;
        let point = IssuingDistributionPoint {
            name,
            only_contains_user_certs,
            only_contains_ca_certs,
            only_some_reasons,
            indirect_crl,
            only_contains_attribute_certs,
        };
        point.check()?;
        Ok(point)
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        self.check()?;
        let mut inner = DERWriter::new();
        if let Some(name) = &self.name {
            let mut explicit = DERWriter::new();
            name.encode(&mut explicit)?;
            inner.write_element(Tag::context(0, true), explicit.as_bytes());
        }
        IssuingDistributionPoint::encode_flag(&mut inner, 1, self.only_contains_user_certs);
        IssuingDistributionPoint::encode_flag(&mut inner, 2, self.only_contains_ca_certs);
        if let Some(reasons) = &self.only_some_reasons {
            reasons.encode(Tag::context(3, false), &mut inner)?;
        }
        IssuingDistributionPoint::encode_flag(&mut inner, 4, self.indirect_crl);
        IssuingDistributionPoint::encode_flag(&mut inner, 5, self.only_contains_attribute_certs);
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }
}
