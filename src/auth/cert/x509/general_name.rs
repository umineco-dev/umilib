use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::{AttributeTypeAndValue, Name, X509Error};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ASN1Error, ASN1String, ObjectIdentifier, Tag, TagClass};

/// An `AnotherName` (RFC 5280 §4.2.1.6): a name of a type identified by an
/// object identifier, with its value kept as its DER encoding (one element).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OtherName<'a> {
    pub type_id: ObjectIdentifier<'a>,
    pub value: Cow<'a, [u8]>,
}

/// A `GeneralName` (RFC 5280 §4.2.1.6).
///
/// The forms whose syntax this module does not interpret (`x400Address`,
/// `ediPartyName`) keep the contents of their element; every form is read
/// and written as the implicitly tagged module of RFC 5280 appendix A.2
/// defines (`directoryName` is explicitly tagged, `Name` being a CHOICE).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum GeneralName<'a> {
    OtherName(OtherName<'a>),
    /// An email address (`rfc822Name`, RFC 5280 §4.2.1.6).
    RFC822Name(Cow<'a, str>),
    DNSName(Cow<'a, str>),
    /// The contents of an `ORAddress`.
    X400Address(Cow<'a, [u8]>),
    DirectoryName(Name<'a>),
    /// The contents of an `EDIPartyName`.
    EDIPartyName(Cow<'a, [u8]>),
    /// A `uniformResourceIdentifier`.
    URI(Cow<'a, str>),
    /// An address of 4 or 16 octets, or in name constraints an address and
    /// a mask of 8 or 32 octets (RFC 5280 §4.2.1.10).
    IPAddress(Cow<'a, [u8]>),
    RegisteredID(ObjectIdentifier<'a>),
}

impl<'a> GeneralName<'a> {
    /// The context tag number of the form.
    pub const fn tag_number(&self) -> u32 {
        match self {
            GeneralName::OtherName(_) => 0,
            GeneralName::RFC822Name(_) => 1,
            GeneralName::DNSName(_) => 2,
            GeneralName::X400Address(_) => 3,
            GeneralName::DirectoryName(_) => 4,
            GeneralName::EDIPartyName(_) => 5,
            GeneralName::URI(_) => 6,
            GeneralName::IPAddress(_) => 7,
            GeneralName::RegisteredID(_) => 8,
        }
    }

    /// Fails unless `content` is a series of complete DER elements.
    pub fn check_elements(content: &[u8]) -> Result<(), X509Error> {
        let mut reader = DERReader::new(content);
        while !reader.is_empty() {
            reader.read_element()?;
        }
        Ok(())
    }

    /// Reads the next `GeneralName` of `reader`.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<GeneralName<'a>, X509Error> {
        let element = reader.read_element()?;
        let tag = element.tag;
        let unexpected = ASN1Error::UnexpectedTag { position: element.position };
        let constructed = matches!(tag.number, 0 | 3 | 4 | 5);
        if tag.class != TagClass::ContextSpecific || tag.constructed != constructed {
            return Err(X509Error::Encoding(unexpected));
        }
        Ok(match tag.number {
            0 => {
                let mut sequence = reader.nested(&element)?;
                let type_id = sequence.read_object_identifier()?;
                let mut explicit = sequence.read_explicit(0)?;
                let value = explicit.read_element()?.encoding;
                explicit.finish()?;
                sequence.finish()?;
                GeneralName::OtherName(OtherName { type_id, value: Cow::Borrowed(value) })
            }
            1 => GeneralName::RFC822Name(Cow::Borrowed(element.as_ia5_string()?)),
            2 => GeneralName::DNSName(Cow::Borrowed(element.as_ia5_string()?)),
            3 => {
                GeneralName::check_elements(element.content)?;
                GeneralName::X400Address(Cow::Borrowed(element.content))
            }
            4 => {
                let mut explicit = reader.nested(&element)?;
                let name = Name::decode(&mut explicit)?;
                explicit.finish()?;
                GeneralName::DirectoryName(name)
            }
            5 => {
                GeneralName::check_elements(element.content)?;
                GeneralName::EDIPartyName(Cow::Borrowed(element.content))
            }
            6 => GeneralName::URI(Cow::Borrowed(element.as_ia5_string()?)),
            7 => GeneralName::IPAddress(Cow::Borrowed(element.as_octet_string()?)),
            8 => GeneralName::RegisteredID(element.as_object_identifier()?),
            _ => return Err(X509Error::Encoding(unexpected)),
        })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        let primitive = Tag::context(self.tag_number(), false);
        let constructed = Tag::context(self.tag_number(), true);
        let ia5 = |text: &str| {
            if !ASN1String::is_ia5(text.as_bytes()) {
                return Err(X509Error::InvalidName);
            }
            Ok(())
        };
        match self {
            GeneralName::OtherName(other) => {
                AttributeTypeAndValue::check_value(&other.value)?;
                writer.write_constructed(constructed, |sequence| {
                    sequence.write_object_identifier(&other.type_id);
                    sequence.write_explicit(0, |explicit| {
                        explicit.write_raw(&other.value);
                        Ok(())
                    })
                })?;
            }
            GeneralName::RFC822Name(text) | GeneralName::DNSName(text) | GeneralName::URI(text) => {
                ia5(text)?;
                writer.write_element(primitive, text.as_bytes());
            }
            GeneralName::X400Address(content) | GeneralName::EDIPartyName(content) => {
                GeneralName::check_elements(content)?;
                writer.write_element(constructed, content);
            }
            GeneralName::DirectoryName(name) => writer.write_element(constructed, name.as_der()),
            GeneralName::IPAddress(address) => writer.write_element(primitive, address),
            GeneralName::RegisteredID(oid) => writer.write_element(primitive, oid.as_bytes()),
        }
        Ok(())
    }

    /// Reads a `GeneralNames`: a sequence of at least one name.
    pub fn decode_names(reader: &mut DERReader<'a>) -> Result<Vec<GeneralName<'a>>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        GeneralName::decode_names_in(&mut sequence)
    }

    /// Reads the contents of a `GeneralNames`, which `reader` reads to its end.
    pub fn decode_names_in(reader: &mut DERReader<'a>) -> Result<Vec<GeneralName<'a>>, X509Error> {
        let mut names = Vec::new();
        while !reader.is_empty() {
            names.push(GeneralName::decode(reader)?);
        }
        if names.is_empty() {
            return Err(X509Error::InvalidName);
        }
        Ok(names)
    }

    /// Writes a `GeneralNames`; fails if `names` is empty.
    pub fn encode_names(names: &[GeneralName<'_>], writer: &mut DERWriter) -> Result<(), X509Error> {
        let mut inner = DERWriter::new();
        GeneralName::encode_names_in(names, &mut inner)?;
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    /// Writes the contents of a `GeneralNames`; fails if `names` is empty.
    pub fn encode_names_in(names: &[GeneralName<'_>], writer: &mut DERWriter) -> Result<(), X509Error> {
        if names.is_empty() {
            return Err(X509Error::InvalidName);
        }
        names.iter().try_for_each(|name| name.encode(writer))
    }

    pub fn into_owned(self) -> GeneralName<'static> {
        let owned = |bytes: Cow<'a, [u8]>| Cow::Owned(bytes.into_owned());
        let text = |text: Cow<'a, str>| Cow::Owned(text.into_owned());
        match self {
            GeneralName::OtherName(other) => {
                GeneralName::OtherName(OtherName { type_id: other.type_id.into_owned(), value: owned(other.value) })
            }
            GeneralName::RFC822Name(name) => GeneralName::RFC822Name(text(name)),
            GeneralName::DNSName(name) => GeneralName::DNSName(text(name)),
            GeneralName::X400Address(content) => GeneralName::X400Address(owned(content)),
            GeneralName::DirectoryName(name) => GeneralName::DirectoryName(name.into_owned()),
            GeneralName::EDIPartyName(content) => GeneralName::EDIPartyName(owned(content)),
            GeneralName::URI(uri) => GeneralName::URI(text(uri)),
            GeneralName::IPAddress(address) => GeneralName::IPAddress(owned(address)),
            GeneralName::RegisteredID(oid) => GeneralName::RegisteredID(oid.into_owned()),
        }
    }

    /// Copies of `names` that own their contents.
    pub fn into_owned_names(names: Vec<GeneralName<'a>>) -> Vec<GeneralName<'static>> {
        names.into_iter().map(GeneralName::into_owned).collect()
    }
}
