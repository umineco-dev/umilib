use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::{AttributeTypeAndValue, ExtensionValue, X509Error};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ObjectIdentifier, Tag};

/// An `Attribute` (RFC 5280 appendix A.1, RFC 2986 §4.1): a type and a set
/// of at least one value, each kept as its DER encoding (one element).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Attribute<'a> {
    pub oid: ObjectIdentifier<'a>,
    pub values: Vec<Cow<'a, [u8]>>,
}

impl<'a> Attribute<'a> {
    pub fn decode(reader: &mut DERReader<'a>) -> Result<Attribute<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let oid = sequence.read_object_identifier()?;
        let mut set = sequence.read_set_of()?;
        let mut values = Vec::new();
        while !set.is_empty() {
            values.push(Cow::Borrowed(set.read_element()?.encoding));
        }
        sequence.finish()?;
        if values.is_empty() {
            return Err(X509Error::InvalidAttribute);
        }
        Ok(Attribute { oid, values })
    }

    /// Writes the attribute, its values in the order DER requires; fails
    /// unless there is at least one value and each is one element.
    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        if self.values.is_empty() {
            return Err(X509Error::InvalidAttribute);
        }
        self.values.iter().try_for_each(|value| AttributeTypeAndValue::check_value(value))?;
        writer.write_sequence(|sequence| {
            sequence.write_object_identifier(&self.oid);
            sequence.write_set_of(|set| {
                self.values.iter().for_each(|value| set.write_raw(value));
                Ok(())
            })
        })?;
        Ok(())
    }

    pub fn into_owned(self) -> Attribute<'static> {
        Attribute {
            oid: self.oid.into_owned(),
            values: self.values.into_iter().map(|value| Cow::Owned(value.into_owned())).collect(),
        }
    }

    /// Reads the contents of a `SET OF Attribute`, which `reader` reads to its end.
    pub fn decode_set(reader: &mut DERReader<'a>) -> Result<Vec<Attribute<'a>>, X509Error> {
        let mut attributes = Vec::new();
        while !reader.is_empty() {
            attributes.push(Attribute::decode(reader)?);
        }
        Ok(attributes)
    }

    /// Writes `attributes` as a SET OF with `tag`, in the order DER requires.
    pub fn encode_set(attributes: &[Attribute<'_>], tag: Tag, writer: &mut DERWriter) -> Result<(), X509Error> {
        let mut encodings = Vec::with_capacity(attributes.len());
        for attribute in attributes {
            let mut encoding = DERWriter::new();
            attribute.encode(&mut encoding)?;
            encodings.push(encoding.into_bytes());
        }
        encodings.sort_by(|a, b| DERReader::compare_encodings(a, b));
        writer.write_element(tag, &encodings.concat());
        Ok(())
    }
}

/// The `SubjectDirectoryAttributes` extension (RFC 5280 §4.2.1.8):
/// attributes of the subject, at least one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SubjectDirectoryAttributes<'a> {
    pub attributes: Vec<Attribute<'a>>,
}

impl SubjectDirectoryAttributes<'_> {
    pub fn into_owned(self) -> SubjectDirectoryAttributes<'static> {
        SubjectDirectoryAttributes { attributes: self.attributes.into_iter().map(Attribute::into_owned).collect() }
    }
}

impl<'a> ExtensionValue<'a> for SubjectDirectoryAttributes<'a> {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 9]);

    fn decode(reader: &mut DERReader<'a>) -> Result<SubjectDirectoryAttributes<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let attributes = Attribute::decode_set(&mut sequence)?;
        if attributes.is_empty() {
            return Err(X509Error::InvalidExtension);
        }
        Ok(SubjectDirectoryAttributes { attributes })
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        if self.attributes.is_empty() {
            return Err(X509Error::InvalidExtension);
        }
        let mut inner = DERWriter::new();
        self.attributes.iter().try_for_each(|attribute| attribute.encode(&mut inner))?;
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }
}
