use alloc::vec::Vec;

use super::{Extension, ExtensionValue, GeneralName, X509Error};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ObjectIdentifier, Tag};

/// The `BasicConstraints` extension (RFC 5280 §4.2.1.9): whether the
/// subject is a CA, and how many intermediate CAs may follow it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_length: Option<u32>,
}

impl ExtensionValue<'_> for BasicConstraints {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 19]);

    /// Reads the constraints; a `cA` written as FALSE, which DER omits, is accepted.
    fn decode(reader: &mut DERReader<'_>) -> Result<BasicConstraints, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let ca = if sequence.peek_tag() == Some(Tag::BOOLEAN) { sequence.read_boolean()? } else { false };
        let path_length = match sequence.peek_tag() {
            Some(Tag::INTEGER) => Some(Extension::decode_count(sequence.read_integer()?)?),
            _ => None,
        };
        sequence.finish()?;
        Ok(BasicConstraints { ca, path_length })
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        writer.write_sequence(|sequence| {
            if self.ca {
                sequence.write_boolean(true);
            }
            if let Some(length) = self.path_length {
                sequence.write_integer_i128(length as i128);
            }
            Ok(())
        })?;
        Ok(())
    }
}

/// A `GeneralSubtree` (RFC 5280 §4.2.1.10): the names under `base`.
///
/// RFC 5280 requires `minimum` to be 0 and `maximum` to be absent; they
/// are kept as written so that path validation can refuse other values.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GeneralSubtree<'a> {
    pub base: GeneralName<'a>,
    pub minimum: u32,
    pub maximum: Option<u32>,
}

impl<'a> GeneralSubtree<'a> {
    pub fn decode(reader: &mut DERReader<'a>) -> Result<GeneralSubtree<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let base = GeneralName::decode(&mut sequence)?;
        let minimum = match sequence.read_optional(Tag::context(0, false))? {
            Some(element) => Extension::decode_count(element.as_integer()?)?,
            None => 0,
        };
        let maximum = match sequence.read_optional(Tag::context(1, false))? {
            Some(element) => Some(Extension::decode_count(element.as_integer()?)?),
            None => None,
        };
        sequence.finish()?;
        Ok(GeneralSubtree { base, minimum, maximum })
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        let mut inner = DERWriter::new();
        self.base.encode(&mut inner)?;
        let mut integer = |number, value: u32| {
            let mut content = Vec::new();
            crate::codec::asn1::ASN1Integer::encode_i128(value as i128, &mut content);
            inner.write_element(Tag::context(number, false), &content);
        };
        if self.minimum != 0 {
            integer(0, self.minimum);
        }
        if let Some(maximum) = self.maximum {
            integer(1, maximum);
        }
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }

    /// Reads the contents of a `GeneralSubtrees`, at least one subtree.
    pub fn decode_subtrees(reader: &mut DERReader<'a>) -> Result<Vec<GeneralSubtree<'a>>, X509Error> {
        let mut subtrees = Vec::new();
        while !reader.is_empty() {
            subtrees.push(GeneralSubtree::decode(reader)?);
        }
        if subtrees.is_empty() {
            return Err(X509Error::InvalidExtension);
        }
        Ok(subtrees)
    }

    pub fn into_owned(self) -> GeneralSubtree<'static> {
        GeneralSubtree { base: self.base.into_owned(), minimum: self.minimum, maximum: self.maximum }
    }
}

/// The `NameConstraints` extension (RFC 5280 §4.2.1.10): the names that
/// the certificates below a CA may and may not have. An empty list stands
/// for the absent field; at least one list has subtrees.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct NameConstraints<'a> {
    pub permitted_subtrees: Vec<GeneralSubtree<'a>>,
    pub excluded_subtrees: Vec<GeneralSubtree<'a>>,
}

impl NameConstraints<'_> {
    /// Fails unless there are permitted or excluded subtrees: RFC 5280
    /// §4.2.1.10 forbids the empty sequence.
    pub fn check(&self) -> Result<(), X509Error> {
        if self.permitted_subtrees.is_empty() && self.excluded_subtrees.is_empty() {
            return Err(X509Error::InvalidExtension);
        }
        Ok(())
    }

    pub fn into_owned(self) -> NameConstraints<'static> {
        NameConstraints {
            permitted_subtrees: self.permitted_subtrees.into_iter().map(GeneralSubtree::into_owned).collect(),
            excluded_subtrees: self.excluded_subtrees.into_iter().map(GeneralSubtree::into_owned).collect(),
        }
    }
}

impl<'a> ExtensionValue<'a> for NameConstraints<'a> {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 30]);

    fn decode(reader: &mut DERReader<'a>) -> Result<NameConstraints<'a>, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let mut subtrees = |number| -> Result<Vec<GeneralSubtree<'a>>, X509Error> {
            match sequence.read_optional(Tag::context(number, true))? {
                Some(element) => GeneralSubtree::decode_subtrees(&mut sequence.nested(&element)?),
                None => Ok(Vec::new()),
            }
        };
        let permitted_subtrees = subtrees(0)?;
        let excluded_subtrees = subtrees(1)?;
        sequence.finish()?;
        let constraints = NameConstraints { permitted_subtrees, excluded_subtrees };
        constraints.check()?;
        Ok(constraints)
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        self.check()?;
        let mut inner = DERWriter::new();
        for (number, subtrees) in [(0, &self.permitted_subtrees), (1, &self.excluded_subtrees)] {
            if !subtrees.is_empty() {
                let mut contents = DERWriter::new();
                subtrees.iter().try_for_each(|subtree| subtree.encode(&mut contents))?;
                inner.write_element(Tag::context(number, true), contents.as_bytes());
            }
        }
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }
}

/// The `PolicyConstraints` extension (RFC 5280 §4.2.1.11): after how many
/// certificates explicit policies are required and policy mapping is
/// inhibited. RFC 5280 requires at least one to be present.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PolicyConstraints {
    pub require_explicit_policy: Option<u32>,
    pub inhibit_policy_mapping: Option<u32>,
}

impl PolicyConstraints {
    /// Fails unless one of the fields is present: RFC 5280 §4.2.1.11
    /// forbids the empty sequence.
    pub fn check(&self) -> Result<(), X509Error> {
        if self.require_explicit_policy.is_none() && self.inhibit_policy_mapping.is_none() {
            return Err(X509Error::InvalidExtension);
        }
        Ok(())
    }
}

impl ExtensionValue<'_> for PolicyConstraints {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 36]);

    fn decode(reader: &mut DERReader<'_>) -> Result<PolicyConstraints, X509Error> {
        let mut sequence = reader.read_sequence()?;
        let mut count = |number| -> Result<Option<u32>, X509Error> {
            match sequence.read_optional(Tag::context(number, false))? {
                Some(element) => Ok(Some(Extension::decode_count(element.as_integer()?)?)),
                None => Ok(None),
            }
        };
        let require_explicit_policy = count(0)?;
        let inhibit_policy_mapping = count(1)?;
        sequence.finish()?;
        let constraints = PolicyConstraints { require_explicit_policy, inhibit_policy_mapping };
        constraints.check()?;
        Ok(constraints)
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        self.check()?;
        let mut inner = DERWriter::new();
        for (number, count) in [(0, self.require_explicit_policy), (1, self.inhibit_policy_mapping)] {
            if let Some(count) = count {
                let mut content = Vec::new();
                crate::codec::asn1::ASN1Integer::encode_i128(count as i128, &mut content);
                inner.write_element(Tag::context(number, false), &content);
            }
        }
        writer.write_element(Tag::SEQUENCE, inner.as_bytes());
        Ok(())
    }
}

/// The `InhibitAnyPolicy` extension (RFC 5280 §4.2.1.14): after how many
/// certificates `anyPolicy` no longer matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InhibitAnyPolicy {
    pub skip_certs: u32,
}

impl ExtensionValue<'_> for InhibitAnyPolicy {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 54]);

    fn decode(reader: &mut DERReader<'_>) -> Result<InhibitAnyPolicy, X509Error> {
        Ok(InhibitAnyPolicy { skip_certs: Extension::decode_count(reader.read_integer()?)? })
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        writer.write_integer_i128(self.skip_certs as i128);
        Ok(())
    }
}
