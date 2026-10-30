use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::ops::RangeInclusive;

use super::X509Error;
use crate::codec::asn1::der::{DERElement, DERReader, DERWriter};
use crate::codec::asn1::{ASN1Error, ObjectIdentifier, Tag};
use crate::codec::stringprep::{LDAPMatching, LDAPPrep, LDAPString};

/// The syntax of the value of a [`NameAttribute`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttributeSyntax {
    /// `DirectoryString` (RFC 5280 §4.1.2.4), written as UTF8String.
    DirectoryString,
    PrintableString,
    IA5String,
}

/// The attribute types of names that RFC 5280 §4.1.2.4 requires or
/// recommends implementations to know, and others common in certificates
/// (X.520, RFC 4519, PKCS #9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NameAttribute {
    CommonName,
    Surname,
    SerialNumber,
    Country,
    Locality,
    StateOrProvince,
    Street,
    Organization,
    OrganizationalUnit,
    Title,
    BusinessCategory,
    PostalCode,
    Name,
    GivenName,
    Initials,
    GenerationQualifier,
    DNQualifier,
    Pseudonym,
    OrganizationIdentifier,
    DomainComponent,
    UserID,
    EmailAddress,
}

impl NameAttribute {
    pub const ALL: [NameAttribute; 22] = [
        NameAttribute::CommonName,
        NameAttribute::Surname,
        NameAttribute::SerialNumber,
        NameAttribute::Country,
        NameAttribute::Locality,
        NameAttribute::StateOrProvince,
        NameAttribute::Street,
        NameAttribute::Organization,
        NameAttribute::OrganizationalUnit,
        NameAttribute::Title,
        NameAttribute::BusinessCategory,
        NameAttribute::PostalCode,
        NameAttribute::Name,
        NameAttribute::GivenName,
        NameAttribute::Initials,
        NameAttribute::GenerationQualifier,
        NameAttribute::DNQualifier,
        NameAttribute::Pseudonym,
        NameAttribute::OrganizationIdentifier,
        NameAttribute::DomainComponent,
        NameAttribute::UserID,
        NameAttribute::EmailAddress,
    ];

    /// The object identifier: `id-at` (2.5.4) attributes of X.520,
    /// `domainComponent` and `uid` of RFC 4519, `emailAddress` of PKCS #9.
    pub const fn oid(self) -> ObjectIdentifier<'static> {
        const DOMAIN_COMPONENT: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19];
        const USER_ID: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01];
        const EMAIL_ADDRESS: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01];
        ObjectIdentifier::from_static(match self {
            NameAttribute::CommonName => &[0x55, 0x04, 3],
            NameAttribute::Surname => &[0x55, 0x04, 4],
            NameAttribute::SerialNumber => &[0x55, 0x04, 5],
            NameAttribute::Country => &[0x55, 0x04, 6],
            NameAttribute::Locality => &[0x55, 0x04, 7],
            NameAttribute::StateOrProvince => &[0x55, 0x04, 8],
            NameAttribute::Street => &[0x55, 0x04, 9],
            NameAttribute::Organization => &[0x55, 0x04, 10],
            NameAttribute::OrganizationalUnit => &[0x55, 0x04, 11],
            NameAttribute::Title => &[0x55, 0x04, 12],
            NameAttribute::BusinessCategory => &[0x55, 0x04, 15],
            NameAttribute::PostalCode => &[0x55, 0x04, 17],
            NameAttribute::Name => &[0x55, 0x04, 41],
            NameAttribute::GivenName => &[0x55, 0x04, 42],
            NameAttribute::Initials => &[0x55, 0x04, 43],
            NameAttribute::GenerationQualifier => &[0x55, 0x04, 44],
            NameAttribute::DNQualifier => &[0x55, 0x04, 46],
            NameAttribute::Pseudonym => &[0x55, 0x04, 65],
            NameAttribute::OrganizationIdentifier => &[0x55, 0x04, 97],
            NameAttribute::DomainComponent => DOMAIN_COMPONENT,
            NameAttribute::UserID => USER_ID,
            NameAttribute::EmailAddress => EMAIL_ADDRESS,
        })
    }

    pub fn from_oid(oid: &ObjectIdentifier<'_>) -> Option<NameAttribute> {
        NameAttribute::ALL.into_iter().find(|attribute| attribute.oid() == *oid)
    }

    /// The syntax of the values (RFC 5280 appendix A, RFC 4519 §2).
    pub const fn syntax(self) -> AttributeSyntax {
        match self {
            NameAttribute::SerialNumber | NameAttribute::Country | NameAttribute::DNQualifier => {
                AttributeSyntax::PrintableString
            }
            NameAttribute::DomainComponent | NameAttribute::EmailAddress => AttributeSyntax::IA5String,
            _ => AttributeSyntax::DirectoryString,
        }
    }

    /// The number of characters a value may have: the `SIZE` constraints of
    /// RFC 5280 appendix A (the `ub-*` bounds), `1..` for the other
    /// directory strings and `0..` for the other strings.
    pub const fn size(self) -> RangeInclusive<usize> {
        match self {
            NameAttribute::Name
            | NameAttribute::Surname
            | NameAttribute::GivenName
            | NameAttribute::Initials
            | NameAttribute::GenerationQualifier => 1..=32768,
            NameAttribute::CommonName
            | NameAttribute::Organization
            | NameAttribute::OrganizationalUnit
            | NameAttribute::Title
            | NameAttribute::SerialNumber => 1..=64,
            NameAttribute::Locality | NameAttribute::StateOrProvince | NameAttribute::Pseudonym => 1..=128,
            NameAttribute::Country => 2..=2,
            NameAttribute::EmailAddress => 1..=255,
            NameAttribute::DNQualifier | NameAttribute::DomainComponent => 0..=usize::MAX,
            _ => 1..=usize::MAX,
        }
    }

    /// The short name of RFC 4514 §3, for the types that have one.
    pub const fn short_name(self) -> Option<&'static str> {
        match self {
            NameAttribute::CommonName => Some("CN"),
            NameAttribute::Locality => Some("L"),
            NameAttribute::StateOrProvince => Some("ST"),
            NameAttribute::Organization => Some("O"),
            NameAttribute::OrganizationalUnit => Some("OU"),
            NameAttribute::Country => Some("C"),
            NameAttribute::Street => Some("STREET"),
            NameAttribute::DomainComponent => Some("DC"),
            NameAttribute::UserID => Some("UID"),
            _ => None,
        }
    }
}

/// An `AttributeTypeAndValue` (RFC 5280 §4.1.2.4): an attribute type and
/// its value, kept as its DER encoding (one element).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AttributeTypeAndValue<'a> {
    pub oid: ObjectIdentifier<'a>,
    pub value: Cow<'a, [u8]>,
}

impl<'a> AttributeTypeAndValue<'a> {
    /// An attribute of `oid` with the DER encoding `value`, which must be one element.
    pub fn new(oid: ObjectIdentifier<'a>, value: Cow<'a, [u8]>) -> Result<AttributeTypeAndValue<'a>, X509Error> {
        AttributeTypeAndValue::check_value(&value)?;
        Ok(AttributeTypeAndValue { oid, value })
    }

    /// An attribute of `attribute` with the text `text`, in the syntax of the
    /// type ([`NameAttribute::syntax`], directory strings as UTF8String, as
    /// RFC 5280 §4.1.2.4 allows) and within its [`NameAttribute::size`].
    pub fn from_text(attribute: NameAttribute, text: &str) -> Result<AttributeTypeAndValue<'static>, X509Error> {
        if !attribute.size().contains(&text.chars().count()) {
            return Err(X509Error::InvalidName);
        }
        let mut writer = DERWriter::new();
        match attribute.syntax() {
            AttributeSyntax::DirectoryString => writer.write_utf8_string(text),
            AttributeSyntax::PrintableString => {
                writer.write_printable_string(text).map_err(|_| X509Error::InvalidName)?
            }
            AttributeSyntax::IA5String => writer.write_ia5_string(text).map_err(|_| X509Error::InvalidName)?,
        }
        Ok(AttributeTypeAndValue { oid: attribute.oid(), value: Cow::Owned(writer.into_bytes()) })
    }

    /// Fails unless `value` is exactly one DER element (its contents are not checked).
    pub fn check_value(value: &[u8]) -> Result<(), X509Error> {
        let mut reader = DERReader::new(value);
        reader.read_element()?;
        reader.finish()?;
        Ok(())
    }

    /// Reads the next `AttributeTypeAndValue` of `reader`.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<AttributeTypeAndValue<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let oid = sequence.read_object_identifier()?;
        let value = sequence.read_element()?.encoding;
        sequence.finish()?;
        Ok(AttributeTypeAndValue { oid, value: Cow::Borrowed(value) })
    }

    /// Writes the attribute; fails unless the value is one element.
    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        AttributeTypeAndValue::check_value(&self.value)?;
        Ok(self.write(writer)?)
    }

    /// Writes the attribute without checking the value.
    pub fn write(&self, writer: &mut DERWriter) -> Result<(), ASN1Error> {
        writer.write_sequence(|sequence| {
            sequence.write_object_identifier(&self.oid);
            sequence.write_raw(&self.value);
            Ok(())
        })
    }

    /// The type, if it is one of [`NameAttribute::ALL`].
    pub fn attribute(&self) -> Option<NameAttribute> {
        NameAttribute::from_oid(&self.oid)
    }

    /// The element of the value.
    pub fn element(&self) -> Result<DERElement<'_>, X509Error> {
        Ok(DERReader::new(&self.value).read_element()?)
    }

    /// The text of a value of a string type: UTF8String, PrintableString,
    /// IA5String, VisibleString, NumericString, BMPString, UniversalString,
    /// and TeletexString read as ISO 8859-1 (as most implementations do; its
    /// T.61 repertoire is not otherwise usable). Fails with
    /// [`X509Error::InvalidName`] for other types and with
    /// [`X509Error::Encoding`] for contents invalid for the type.
    pub fn text(&self) -> Result<Cow<'_, str>, X509Error> {
        let element = self.element()?;
        let text = match element.tag {
            Tag::UTF8_STRING => Cow::Borrowed(element.as_utf8_string()?),
            Tag::PRINTABLE_STRING => Cow::Borrowed(element.as_printable_string()?),
            Tag::IA5_STRING => Cow::Borrowed(element.as_ia5_string()?),
            Tag::VISIBLE_STRING => Cow::Borrowed(element.as_visible_string()?),
            Tag::NUMERIC_STRING => Cow::Borrowed(element.as_numeric_string()?),
            Tag::BMP_STRING => Cow::Owned(element.as_bmp_string()?),
            Tag::UNIVERSAL_STRING => Cow::Owned(element.as_universal_string()?),
            Tag::TELETEX_STRING => Cow::Owned(element.as_teletex_string()?.iter().map(|&byte| byte as char).collect()),
            _ => return Err(X509Error::InvalidName),
        };
        Ok(text)
    }

    /// The value prepared for comparison (RFC 5280 §7.1): a directory string
    /// (UTF8String, PrintableString, BMPString, UniversalString,
    /// TeletexString) by the string preparation of LDAP for
    /// caseIgnoreMatch (RFC 4518); an IA5String (domainComponent,
    /// emailAddress) folded to ASCII lower case (§7.3). `None` for another
    /// type, or a string the preparation refuses.
    pub fn comparable(&self) -> Option<String> {
        let tag = self.element().ok()?.tag;
        let text = self.text().ok()?;
        match tag {
            Tag::IA5_STRING => Some(text.to_ascii_lowercase()),
            Tag::UTF8_STRING
            | Tag::PRINTABLE_STRING
            | Tag::BMP_STRING
            | Tag::UNIVERSAL_STRING
            | Tag::TELETEX_STRING => LDAPPrep::prepare(&text, LDAPMatching::CaseIgnore, LDAPString::Value).ok(),
            _ => None,
        }
    }

    /// The value in the form it is compared in (RFC 5280 §7.1): prepared
    /// ([`AttributeTypeAndValue::comparable`]), or its encoding when it has
    /// no prepared form.
    pub fn comparable_value(&self) -> ComparableValue<'_> {
        match self.comparable() {
            Some(prepared) => ComparableValue::Prepared(prepared),
            None => ComparableValue::Encoded(&self.value),
        }
    }

    /// Whether the attributes match (RFC 5280 §7.1): the same type, and
    /// the same encoding or the same prepared value ([`AttributeTypeAndValue::comparable`]).
    pub fn matches(&self, other: &AttributeTypeAndValue<'_>) -> bool {
        self.oid == other.oid && (self.value == other.value || self.comparable_value() == other.comparable_value())
    }

    pub fn into_owned(self) -> AttributeTypeAndValue<'static> {
        AttributeTypeAndValue { oid: self.oid.into_owned(), value: Cow::Owned(self.value.into_owned()) }
    }

    /// Writes the attribute as RFC 4514 §2.3 and §2.4 do: the short name
    /// and the escaped text, or, for a type without a short name or a value
    /// that is not text, the dotted object identifier or short name, `#`
    /// and the hexadecimal encoding of the value.
    pub fn write_rfc4514(&self, output: &mut impl fmt::Write) -> fmt::Result {
        let short_name = self.attribute().and_then(NameAttribute::short_name);
        match short_name {
            Some(name) => output.write_str(name)?,
            None => write!(output, "{}", self.oid)?,
        }
        output.write_char('=')?;
        let text = match short_name {
            Some(_) => self.text().ok(),
            None => None,
        };
        let Some(text) = text else {
            output.write_char('#')?;
            return self.value.iter().try_for_each(|byte| write!(output, "{byte:02x}"));
        };
        let last = text.chars().count().saturating_sub(1);
        for (index, character) in text.chars().enumerate() {
            match character {
                '\0' => output.write_str("\\00")?,
                '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                    output.write_char('\\')?;
                    output.write_char(character)?;
                }
                ' ' | '#' if index == 0 => {
                    output.write_char('\\')?;
                    output.write_char(character)?;
                }
                ' ' if index == last => output.write_str("\\ ")?,
                _ => output.write_char(character)?,
            }
        }
        Ok(())
    }
}

/// A `RelativeDistinguishedName` (RFC 5280 §4.1.2.4): a non-empty set of
/// attributes, kept as its DER encoding (the SET OF element).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelativeDistinguishedName<'a> {
    encoding: Cow<'a, [u8]>,
}

impl<'a> RelativeDistinguishedName<'a> {
    /// The set of `attributes`, at least one, in the order DER requires.
    pub fn new(attributes: &[AttributeTypeAndValue<'_>]) -> Result<RelativeDistinguishedName<'static>, X509Error> {
        if attributes.is_empty() {
            return Err(X509Error::InvalidName);
        }
        attributes.iter().try_for_each(|attribute| AttributeTypeAndValue::check_value(&attribute.value))?;
        let mut writer = DERWriter::new();
        writer.write_set_of(|set| attributes.iter().try_for_each(|attribute| attribute.write(set)))?;
        Ok(RelativeDistinguishedName { encoding: Cow::Owned(writer.into_bytes()) })
    }

    /// Reads the next `RelativeDistinguishedName` of `reader`.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<RelativeDistinguishedName<'a>, X509Error> {
        let encoding = reader.peek()?.encoding;
        let mut set = reader.read_set_of()?;
        if set.is_empty() {
            return Err(X509Error::InvalidName);
        }
        while !set.is_empty() {
            AttributeTypeAndValue::decode(&mut set)?;
        }
        Ok(RelativeDistinguishedName { encoding: Cow::Borrowed(encoding) })
    }

    pub fn encode(&self, writer: &mut DERWriter) {
        writer.write_raw(&self.encoding);
    }

    /// The DER encoding.
    pub fn as_der(&self) -> &[u8] {
        &self.encoding
    }

    /// The attributes, in the order of their encodings.
    pub fn attributes(&self) -> impl Iterator<Item = AttributeTypeAndValue<'_>> + '_ {
        // The encoding was checked when the set was made or read.
        let mut set = DERReader::new(&self.encoding).read_set_of().unwrap_or(DERReader::new(&[]));
        core::iter::from_fn(move || if set.is_empty() { None } else { AttributeTypeAndValue::decode(&mut set).ok() })
    }

    /// Whether the relative names match (RFC 5280 §7.1): the same set of
    /// attributes, each compared by its type and [`AttributeTypeAndValue::comparable_value`].
    /// Each attribute is prepared once, and the sets are compared sorted, so
    /// the work grows as `n log n` with the attributes.
    pub fn matches(&self, other: &RelativeDistinguishedName<'_>) -> bool {
        if self.encoding == other.encoding {
            return true;
        }
        let mine: Vec<AttributeTypeAndValue<'_>> = self.attributes().collect();
        let theirs: Vec<AttributeTypeAndValue<'_>> = other.attributes().collect();
        if mine.len() != theirs.len() {
            return false;
        }
        RelativeDistinguishedName::sorted_values(&mine) == RelativeDistinguishedName::sorted_values(&theirs)
    }

    /// The types and [`AttributeTypeAndValue::comparable_value`]s of
    /// `attributes`, sorted: two sets match when these are equal.
    pub fn sorted_values<'v>(
        attributes: &'v [AttributeTypeAndValue<'_>],
    ) -> Vec<(&'v ObjectIdentifier<'v>, ComparableValue<'v>)> {
        let mut values: Vec<(&'v ObjectIdentifier<'v>, ComparableValue<'v>)> =
            attributes.iter().map(|attribute| (&attribute.oid, attribute.comparable_value())).collect();
        values.sort_unstable();
        values
    }

    pub fn into_owned(self) -> RelativeDistinguishedName<'static> {
        RelativeDistinguishedName { encoding: Cow::Owned(self.encoding.into_owned()) }
    }
}

/// The form in which an attribute value is compared (RFC 5280 §7.1): its
/// prepared text, or its encoding when it has no prepared form. Values of
/// one attribute type match when their forms are equal.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ComparableValue<'a> {
    Prepared(String),
    Encoded(&'a [u8]),
}

/// A `Name` (RFC 5280 §4.1.2.4): a sequence of relative distinguished
/// names, the most significant first, kept as its DER encoding.
///
/// Names are equal ([`PartialEq`]) when their encodings are;
/// [`Name::matches`] compares them as RFC 5280 §7.1 requires, ignoring case
/// and insignificant spaces.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name<'a> {
    encoding: Cow<'a, [u8]>,
}

impl<'a> Name<'a> {
    /// The DER encoding of the empty name.
    pub const EMPTY: &'static [u8] = &[0x30, 0x00];

    /// The empty name.
    pub const fn empty() -> Name<'static> {
        Name { encoding: Cow::Borrowed(Name::EMPTY) }
    }

    /// The name made of `rdns`, the most significant first.
    pub fn new(rdns: &[RelativeDistinguishedName<'_>]) -> Result<Name<'static>, X509Error> {
        let mut writer = DERWriter::new();
        writer.write_sequence(|sequence| {
            rdns.iter().for_each(|rdn| rdn.encode(sequence));
            Ok(())
        })?;
        Ok(Name { encoding: Cow::Owned(writer.into_bytes()) })
    }

    /// The name with one relative distinguished name of one attribute for
    /// each of `attributes` (see [`AttributeTypeAndValue::from_text`]), the
    /// most significant first: `[(Country, "JP"), (CommonName, "Example")]`.
    pub fn from_attributes(attributes: &[(NameAttribute, &str)]) -> Result<Name<'static>, X509Error> {
        let mut rdns = Vec::with_capacity(attributes.len());
        for &(attribute, text) in attributes {
            rdns.push(RelativeDistinguishedName::new(&[AttributeTypeAndValue::from_text(attribute, text)?])?);
        }
        Name::new(&rdns)
    }

    /// Reads the next `Name` of `reader`.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<Name<'a>, X509Error> {
        let encoding = reader.peek()?.encoding;
        let mut sequence = reader.read_sequence()?;
        while !sequence.is_empty() {
            RelativeDistinguishedName::decode(&mut sequence)?;
        }
        Ok(Name { encoding: Cow::Borrowed(encoding) })
    }

    /// The name of the DER encoding `bytes`.
    pub fn from_der(bytes: &'a [u8]) -> Result<Name<'a>, X509Error> {
        let mut reader = DERReader::new(bytes);
        let name = Name::decode(&mut reader)?;
        reader.finish()?;
        Ok(name)
    }

    pub fn encode(&self, writer: &mut DERWriter) {
        writer.write_raw(&self.encoding);
    }

    /// The DER encoding.
    pub fn as_der(&self) -> &[u8] {
        &self.encoding
    }

    pub fn is_empty(&self) -> bool {
        *self.encoding == *Name::EMPTY
    }

    /// The relative distinguished names, the most significant first.
    pub fn rdns(&self) -> impl Iterator<Item = RelativeDistinguishedName<'_>> + '_ {
        // The encoding was checked when the name was made or read.
        let mut sequence = DERReader::new(&self.encoding).read_sequence().unwrap_or(DERReader::new(&[]));
        core::iter::from_fn(move || {
            if sequence.is_empty() { None } else { RelativeDistinguishedName::decode(&mut sequence).ok() }
        })
    }

    /// The attributes of every relative distinguished name, the most significant first.
    pub fn attributes(&self) -> impl Iterator<Item = AttributeTypeAndValue<'_>> + '_ {
        // The encoding was checked when the name was made or read.
        let mut sequence = DERReader::new(&self.encoding).read_sequence().unwrap_or(DERReader::new(&[]));
        let mut set = DERReader::new(&[]);
        core::iter::from_fn(move || {
            while set.is_empty() {
                set = sequence.read_set_of().ok()?;
            }
            AttributeTypeAndValue::decode(&mut set).ok()
        })
    }

    /// Whether the names match (RFC 5280 §7.1): as many relative names,
    /// matching in the same order. [`PartialEq`] compares encodings instead.
    pub fn matches(&self, other: &Name<'_>) -> bool {
        if self.encoding == other.encoding {
            return true;
        }
        let mine: Vec<RelativeDistinguishedName<'_>> = self.rdns().collect();
        let theirs: Vec<RelativeDistinguishedName<'_>> = other.rdns().collect();
        mine.len() == theirs.len() && mine.iter().zip(&theirs).all(|(rdn, other)| rdn.matches(other))
    }

    /// Whether the name is within the subtree of `base` (RFC 5280 §7.1): it
    /// has at least as many relative names, and the first ones match `base`.
    pub fn is_within(&self, base: &Name<'_>) -> bool {
        let mine: Vec<RelativeDistinguishedName<'_>> = self.rdns().collect();
        let theirs: Vec<RelativeDistinguishedName<'_>> = base.rdns().collect();
        mine.len() >= theirs.len() && mine.iter().zip(&theirs).all(|(rdn, base)| rdn.matches(base))
    }

    pub fn into_owned(self) -> Name<'static> {
        Name { encoding: Cow::Owned(self.encoding.into_owned()) }
    }

    /// The string representation of RFC 4514: the relative distinguished
    /// names from the least significant, separated by `,`, and the
    /// attributes of each separated by `+`.
    pub fn to_rfc4514(&self) -> String {
        let mut output = String::new();
        let _ = self.write_rfc4514(&mut output);
        output
    }

    pub fn write_rfc4514(&self, output: &mut impl fmt::Write) -> fmt::Result {
        let rdns: Vec<RelativeDistinguishedName<'_>> = self.rdns().collect();
        for (index, rdn) in rdns.iter().rev().enumerate() {
            if index > 0 {
                output.write_char(',')?;
            }
            for (position, attribute) in rdn.attributes().enumerate() {
                if position > 0 {
                    output.write_char('+')?;
                }
                attribute.write_rfc4514(output)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for Name<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_rfc4514(formatter)
    }
}
