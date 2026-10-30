use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::X509Error;
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ASN1Integer, ObjectIdentifier, Tag};

/// The value of an extension of a known type: its object identifier and
/// the syntax of the DER encoding that `extnValue` holds.
pub trait ExtensionValue<'a>: Sized {
    const OID: ObjectIdentifier<'static>;

    /// Reads the value from `reader`, which holds the contents of `extnValue`.
    fn decode(reader: &mut DERReader<'a>) -> Result<Self, X509Error>;

    /// Writes the value, which becomes the contents of `extnValue`.
    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error>;

    /// The value of the contents of `extnValue`; fails with
    /// [`X509Error::InvalidExtension`] if they are not one value of the type.
    fn from_der(value: &'a [u8]) -> Result<Self, X509Error> {
        let mut reader = DERReader::new(value);
        let decoded = Self::decode(&mut reader).map_err(|_| X509Error::InvalidExtension)?;
        reader.finish().map_err(|_| X509Error::InvalidExtension)?;
        Ok(decoded)
    }

    fn to_der(&self) -> Result<Vec<u8>, X509Error> {
        let mut writer = DERWriter::new();
        self.encode(&mut writer)?;
        Ok(writer.into_bytes())
    }
}

/// An `Extension` (RFC 5280 §4.1, §4.2): an object identifier, whether it
/// is critical, and the DER encoding of its value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Extension<'a> {
    pub oid: ObjectIdentifier<'a>,
    pub critical: bool,
    pub value: Cow<'a, [u8]>,
}

impl<'a> Extension<'a> {
    /// The extension holding `value`.
    pub fn new<'b, T: ExtensionValue<'b>>(value: &T, critical: bool) -> Result<Extension<'static>, X509Error> {
        Ok(Extension { oid: T::OID, critical, value: Cow::Owned(value.to_der()?) })
    }

    /// The value as `T`; fails with [`X509Error::InvalidExtension`] if the
    /// extension is of another type or its value does not decode.
    pub fn typed<'b, T: ExtensionValue<'b>>(&'b self) -> Result<T, X509Error> {
        if self.oid != T::OID {
            return Err(X509Error::InvalidExtension);
        }
        T::from_der(&self.value)
    }

    /// A count of the extensions' syntaxes, an `INTEGER (0..MAX)`
    /// (`pathLenConstraint`, `SkipCerts`, `BaseDistance`); counts beyond
    /// `u32::MAX`, longer than any path, are refused.
    pub fn decode_count(integer: ASN1Integer<'_>) -> Result<u32, X509Error> {
        let count = integer.as_u64().map_err(|_| X509Error::InvalidExtension)?;
        u32::try_from(count).map_err(|_| X509Error::InvalidExtension)
    }

    /// Reads the next `Extension` of `reader`. A `critical` written as
    /// FALSE, which DER omits, is accepted, as most implementations do.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<Extension<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let oid = sequence.read_object_identifier()?;
        let critical = if sequence.peek_tag() == Some(Tag::BOOLEAN) { sequence.read_boolean()? } else { false };
        let value = sequence.read_octet_string()?;
        sequence.finish()?;
        Ok(Extension { oid, critical, value: Cow::Borrowed(value) })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        writer.write_sequence(|sequence| {
            sequence.write_object_identifier(&self.oid);
            if self.critical {
                sequence.write_boolean(true);
            }
            sequence.write_octet_string(&self.value);
            Ok(())
        })?;
        Ok(())
    }

    pub fn into_owned(self) -> Extension<'static> {
        Extension { oid: self.oid.into_owned(), critical: self.critical, value: Cow::Owned(self.value.into_owned()) }
    }
}

/// The `Extensions` of a certificate, a CRL or one of its entries: at
/// least one extension when written, each of a different type (RFC 5280
/// §4.2). An empty list stands for the absent field.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Extensions<'a> {
    pub entries: Vec<Extension<'a>>,
}

impl<'a> Extensions<'a> {
    pub const fn new() -> Extensions<'a> {
        Extensions { entries: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The extension of type `oid`.
    pub fn get(&self, oid: &ObjectIdentifier<'_>) -> Option<&Extension<'a>> {
        self.entries.iter().find(|extension| extension.oid == *oid)
    }

    /// The extension of type `T`, decoded, if there is one.
    pub fn typed<'b, T: ExtensionValue<'b>>(&'b self) -> Result<Option<T>, X509Error> {
        self.get(&T::OID).map(Extension::typed).transpose()
    }

    /// Appends `extension`; fails with [`X509Error::DuplicateExtension`] if
    /// one of its type is already there.
    pub fn push(&mut self, extension: Extension<'a>) -> Result<(), X509Error> {
        if self.get(&extension.oid).is_some() {
            return Err(X509Error::DuplicateExtension);
        }
        self.entries.push(extension);
        Ok(())
    }

    /// Fails with [`X509Error::DuplicateExtension`] if two extensions have the same type.
    pub fn check(&self) -> Result<(), X509Error> {
        let mut oids: Vec<&ObjectIdentifier<'a>> = self.entries.iter().map(|extension| &extension.oid).collect();
        oids.sort_unstable();
        if oids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(X509Error::DuplicateExtension);
        }
        Ok(())
    }

    /// Reads a `SEQUENCE SIZE (1..MAX) OF Extension` from `reader`.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<Extensions<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let mut entries = Vec::new();
        while !sequence.is_empty() {
            entries.push(Extension::decode(&mut sequence)?);
        }
        if entries.is_empty() {
            return Err(X509Error::InvalidExtension);
        }
        let extensions = Extensions { entries };
        extensions.check()?;
        Ok(extensions)
    }

    /// Writes the list; fails if it is empty or has two extensions of the same type.
    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        if self.entries.is_empty() {
            return Err(X509Error::InvalidExtension);
        }
        self.check()?;
        let mut inner = DERWriter::new();
        self.entries.iter().try_for_each(|extension| extension.encode(&mut inner))?;
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    pub fn into_owned(self) -> Extensions<'static> {
        Extensions { entries: self.entries.into_iter().map(Extension::into_owned).collect() }
    }
}
