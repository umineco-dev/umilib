use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::{ExtensionValue, X509Error};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ObjectIdentifier, Tag};

/// A `DisplayText` (RFC 5280 §4.2.1.4): a text of one of four string types.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DisplayText<'a> {
    IA5String(Cow<'a, str>),
    VisibleString(Cow<'a, str>),
    BMPString(Cow<'a, str>),
    UTF8String(Cow<'a, str>),
}

impl<'a> DisplayText<'a> {
    pub fn text(&self) -> &str {
        match self {
            DisplayText::IA5String(text)
            | DisplayText::VisibleString(text)
            | DisplayText::BMPString(text)
            | DisplayText::UTF8String(text) => text,
        }
    }

    /// Reads the next `DisplayText` of `reader`. The limit of 200
    /// characters, which RFC 5280 asks users to tolerate exceeding, is not checked.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<DisplayText<'a>, X509Error> {
        let element = reader.read_element()?;
        Ok(match element.tag {
            Tag::IA5_STRING => DisplayText::IA5String(Cow::Borrowed(element.as_ia5_string()?)),
            Tag::VISIBLE_STRING => DisplayText::VisibleString(Cow::Borrowed(element.as_visible_string()?)),
            Tag::BMP_STRING => DisplayText::BMPString(Cow::Owned(element.as_bmp_string()?)),
            Tag::UTF8_STRING => DisplayText::UTF8String(Cow::Borrowed(element.as_utf8_string()?)),
            _ => return Err(X509Error::InvalidExtension),
        })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        match self {
            DisplayText::IA5String(text) => writer.write_ia5_string(text)?,
            DisplayText::VisibleString(text) => writer.write_visible_string(text)?,
            DisplayText::BMPString(text) => writer.write_bmp_string(text)?,
            DisplayText::UTF8String(text) => writer.write_utf8_string(text),
        }
        Ok(())
    }

    pub fn into_owned(self) -> DisplayText<'static> {
        match self {
            DisplayText::IA5String(text) => DisplayText::IA5String(Cow::Owned(text.into_owned())),
            DisplayText::VisibleString(text) => DisplayText::VisibleString(Cow::Owned(text.into_owned())),
            DisplayText::BMPString(text) => DisplayText::BMPString(Cow::Owned(text.into_owned())),
            DisplayText::UTF8String(text) => DisplayText::UTF8String(Cow::Owned(text.into_owned())),
        }
    }
}

/// A `NoticeReference` (RFC 5280 §4.2.1.4): numbered statements of an organization.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NoticeReference<'a> {
    pub organization: DisplayText<'a>,
    /// The numbers; numbers beyond `i64` are refused.
    pub notice_numbers: Vec<i64>,
}

/// A `UserNotice` (RFC 5280 §4.2.1.4): a statement for the relying party.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct UserNotice<'a> {
    pub notice_reference: Option<NoticeReference<'a>>,
    pub explicit_text: Option<DisplayText<'a>>,
}

impl<'a> UserNotice<'a> {
    pub fn decode(reader: &mut DERReader<'a>) -> Result<UserNotice<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let notice_reference = match sequence.read_optional(Tag::SEQUENCE)? {
            Some(element) => {
                let mut reference = sequence.nested(&element)?;
                let organization = DisplayText::decode(&mut reference)?;
                let mut numbers = reference.read_sequence()?;
                let mut notice_numbers = Vec::new();
                while !numbers.is_empty() {
                    notice_numbers.push(numbers.read_integer()?.as_i64()?);
                }
                reference.finish()?;
                Some(NoticeReference { organization, notice_numbers })
            }
            None => None,
        };
        let explicit_text = if sequence.is_empty() { None } else { Some(DisplayText::decode(&mut sequence)?) };
        sequence.finish()?;
        Ok(UserNotice { notice_reference, explicit_text })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        let mut inner = DERWriter::new();
        if let Some(reference) = &self.notice_reference {
            let mut contents = DERWriter::new();
            reference.organization.encode(&mut contents)?;
            contents.write_sequence(|numbers| {
                reference.notice_numbers.iter().for_each(|&number| numbers.write_integer_i128(number as i128));
                Ok(())
            })?;
            inner.write_element(Tag::SEQUENCE, contents.as_bytes());
        }
        if let Some(text) = &self.explicit_text {
            text.encode(&mut inner)?;
        }
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }
}

/// A `PolicyQualifierInfo` (RFC 5280 §4.2.1.4): a qualifier of a policy,
/// kept as its DER encoding (one element) and decoded on request, so that
/// a qualifier of an unexpected form does not hide the policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyQualifierInfo<'a> {
    pub oid: ObjectIdentifier<'a>,
    pub qualifier: Cow<'a, [u8]>,
}

impl<'a> PolicyQualifierInfo<'a> {
    /// `id-qt-cps`: the URI of a certification practice statement.
    pub const CPS: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01]);
    /// `id-qt-unotice`: a [`UserNotice`].
    pub const USER_NOTICE: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02]);

    /// The qualifier of a CPS URI.
    pub fn cps(uri: &str) -> Result<PolicyQualifierInfo<'static>, X509Error> {
        let mut writer = DERWriter::new();
        writer.write_ia5_string(uri)?;
        Ok(PolicyQualifierInfo { oid: PolicyQualifierInfo::CPS, qualifier: Cow::Owned(writer.into_bytes()) })
    }

    /// The qualifier of a user notice.
    pub fn user_notice(notice: &UserNotice<'_>) -> Result<PolicyQualifierInfo<'static>, X509Error> {
        let mut writer = DERWriter::new();
        notice.encode(&mut writer)?;
        Ok(PolicyQualifierInfo { oid: PolicyQualifierInfo::USER_NOTICE, qualifier: Cow::Owned(writer.into_bytes()) })
    }

    /// The URI of a CPS qualifier; fails with [`X509Error::InvalidExtension`]
    /// for a qualifier of another type or form.
    pub fn cps_uri(&self) -> Result<&str, X509Error> {
        if self.oid != PolicyQualifierInfo::CPS {
            return Err(X509Error::InvalidExtension);
        }
        let mut reader = DERReader::new(&self.qualifier);
        let uri = reader.read_ia5_string().map_err(|_| X509Error::InvalidExtension)?;
        reader.finish().map_err(|_| X509Error::InvalidExtension)?;
        Ok(uri)
    }

    /// The notice of a user notice qualifier; fails with
    /// [`X509Error::InvalidExtension`] for a qualifier of another type or form.
    pub fn notice(&self) -> Result<UserNotice<'_>, X509Error> {
        if self.oid != PolicyQualifierInfo::USER_NOTICE {
            return Err(X509Error::InvalidExtension);
        }
        let mut reader = DERReader::new(&self.qualifier);
        let notice = UserNotice::decode(&mut reader).map_err(|_| X509Error::InvalidExtension)?;
        reader.finish().map_err(|_| X509Error::InvalidExtension)?;
        Ok(notice)
    }

    pub fn decode(reader: &mut DERReader<'a>) -> Result<PolicyQualifierInfo<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let oid = sequence.read_object_identifier()?;
        let qualifier = sequence.read_element()?.encoding;
        sequence.finish()?;
        Ok(PolicyQualifierInfo { oid, qualifier: Cow::Borrowed(qualifier) })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        super::AttributeTypeAndValue::check_value(&self.qualifier)?;
        writer.write_sequence(|sequence| {
            sequence.write_object_identifier(&self.oid);
            sequence.write_raw(&self.qualifier);
            Ok(())
        })?;
        Ok(())
    }

    pub fn into_owned(self) -> PolicyQualifierInfo<'static> {
        PolicyQualifierInfo { oid: self.oid.into_owned(), qualifier: Cow::Owned(self.qualifier.into_owned()) }
    }
}

/// A `PolicyInformation` (RFC 5280 §4.2.1.4): a policy and its qualifiers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyInformation<'a> {
    pub identifier: ObjectIdentifier<'a>,
    /// The qualifiers; an empty list stands for the absent field.
    pub qualifiers: Vec<PolicyQualifierInfo<'a>>,
}

impl<'a> PolicyInformation<'a> {
    pub fn decode(reader: &mut DERReader<'a>) -> Result<PolicyInformation<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let identifier = sequence.read_object_identifier()?;
        let mut qualifiers = Vec::new();
        if !sequence.is_empty() {
            let mut list = sequence.read_sequence()?;
            while !list.is_empty() {
                qualifiers.push(PolicyQualifierInfo::decode(&mut list)?);
            }
            if qualifiers.is_empty() {
                return Err(X509Error::InvalidExtension);
            }
        }
        sequence.finish()?;
        Ok(PolicyInformation { identifier, qualifiers })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        let mut inner = DERWriter::new();
        inner.write_object_identifier(&self.identifier);
        if !self.qualifiers.is_empty() {
            let mut list = DERWriter::new();
            self.qualifiers.iter().try_for_each(|qualifier| qualifier.encode(&mut list))?;
            inner.write_element(Tag::SEQUENCE, list.as_bytes());
        }
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn into_owned(self) -> PolicyInformation<'static> {
        PolicyInformation {
            identifier: self.identifier.into_owned(),
            qualifiers: self.qualifiers.into_iter().map(PolicyQualifierInfo::into_owned).collect(),
        }
    }
}

/// The `CertificatePolicies` extension (RFC 5280 §4.2.1.4): at least one
/// policy, each at most once.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertificatePolicies<'a> {
    pub policies: Vec<PolicyInformation<'a>>,
}

impl CertificatePolicies<'_> {
    /// `anyPolicy`.
    pub const ANY_POLICY: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 32, 0]);

    /// Fails unless there is at least one policy and no policy is listed twice.
    pub fn check(policies: &[PolicyInformation<'_>]) -> Result<(), X509Error> {
        let mut identifiers: Vec<&ObjectIdentifier<'_>> = policies.iter().map(|policy| &policy.identifier).collect();
        identifiers.sort_unstable();
        if identifiers.is_empty() || identifiers.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(X509Error::InvalidExtension);
        }
        Ok(())
    }

    pub fn into_owned(self) -> CertificatePolicies<'static> {
        CertificatePolicies { policies: self.policies.into_iter().map(PolicyInformation::into_owned).collect() }
    }
}

impl<'a> ExtensionValue<'a> for CertificatePolicies<'a> {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 32]);

    fn decode(reader: &mut DERReader<'a>) -> Result<CertificatePolicies<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let mut policies = Vec::new();
        while !sequence.is_empty() {
            policies.push(PolicyInformation::decode(&mut sequence)?);
        }
        CertificatePolicies::check(&policies)?;
        Ok(CertificatePolicies { policies })
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        CertificatePolicies::check(&self.policies)?;
        let mut inner = DERWriter::new();
        self.policies.iter().try_for_each(|policy| policy.encode(&mut inner))?;
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }
}

/// A mapping of `PolicyMappings` (RFC 5280 §4.2.1.5): a policy of the
/// issuer's domain considered equivalent to one of the subject's.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyMapping<'a> {
    pub issuer_domain_policy: ObjectIdentifier<'a>,
    pub subject_domain_policy: ObjectIdentifier<'a>,
}

/// The `PolicyMappings` extension (RFC 5280 §4.2.1.5): at least one mapping.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyMappings<'a> {
    pub mappings: Vec<PolicyMapping<'a>>,
}

impl PolicyMappings<'_> {
    pub fn into_owned(self) -> PolicyMappings<'static> {
        let owned = |mapping: PolicyMapping<'_>| PolicyMapping {
            issuer_domain_policy: mapping.issuer_domain_policy.into_owned(),
            subject_domain_policy: mapping.subject_domain_policy.into_owned(),
        };
        PolicyMappings { mappings: self.mappings.into_iter().map(owned).collect() }
    }
}

impl<'a> ExtensionValue<'a> for PolicyMappings<'a> {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 33]);

    fn decode(reader: &mut DERReader<'a>) -> Result<PolicyMappings<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let mut mappings = Vec::new();
        while !sequence.is_empty() {
            let mut pair = sequence.read_sequence()?;
            let issuer_domain_policy = pair.read_object_identifier()?;
            let subject_domain_policy = pair.read_object_identifier()?;
            pair.finish()?;
            mappings.push(PolicyMapping { issuer_domain_policy, subject_domain_policy });
        }
        if mappings.is_empty() {
            return Err(X509Error::InvalidExtension);
        }
        Ok(PolicyMappings { mappings })
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        if self.mappings.is_empty() {
            return Err(X509Error::InvalidExtension);
        }
        writer.write_sequence(|sequence| {
            for mapping in &self.mappings {
                sequence.write_sequence(|pair| {
                    pair.write_object_identifier(&mapping.issuer_domain_policy);
                    pair.write_object_identifier(&mapping.subject_domain_policy);
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        Ok(())
    }
}
