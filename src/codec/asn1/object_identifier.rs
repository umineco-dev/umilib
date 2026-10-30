use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt;

use super::ASN1Error;

/// An OBJECT IDENTIFIER, kept as its contents octets (X.690 section 8.19).
///
/// Arcs are at most 128 bits, which covers UUID-based identifiers (`2.25.n`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectIdentifier<'a> {
    content: Cow<'a, [u8]>,
}

impl<'a> ObjectIdentifier<'a> {
    /// Wraps contents octets known to be valid, for constants such as
    /// `ObjectIdentifier::from_static(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D])`.
    /// Invalid contents give wrong arcs but never undefined behaviour.
    pub const fn from_static(content: &'a [u8]) -> ObjectIdentifier<'a> {
        ObjectIdentifier { content: Cow::Borrowed(content) }
    }

    /// Validates contents octets: every subidentifier is minimal base-128 and
    /// fits 128 bits (X.690 section 8.19.2).
    pub fn new(content: &'a [u8]) -> Result<ObjectIdentifier<'a>, ASN1Error> {
        ObjectIdentifier::validate_subidentifiers(content)?;
        Ok(ObjectIdentifier { content: Cow::Borrowed(content) })
    }

    /// Checks a list of subidentifiers, the contents of an OBJECT IDENTIFIER
    /// or a RELATIVE-OID: at least one, each in the fewest base-128 octets
    /// (X.690 sections 8.19.2 and 8.20.2) and within 128 bits.
    pub fn validate_subidentifiers(content: &[u8]) -> Result<(), ASN1Error> {
        let invalid = ASN1Error::InvalidContent { position: 0 };
        if content.is_empty() || content[content.len() - 1] & 0x80 != 0 {
            return Err(invalid);
        }
        // A subidentifier starts at the beginning or after an octet without
        // the continuation bit, and must not start with the padding octet 0x80.
        let mut starts = true;
        for &byte in content {
            if starts && byte == 0x80 {
                return Err(invalid);
            }
            starts = byte & 0x80 == 0;
        }
        ObjectIdentifier::subidentifiers(content).try_for_each(|value| value.map(|_| ()))
    }

    /// The subidentifiers of contents octets, as 128-bit values.
    pub fn subidentifiers(content: &[u8]) -> impl Iterator<Item = Result<u128, ASN1Error>> + '_ {
        let mut position = 0;
        core::iter::from_fn(move || {
            if position >= content.len() {
                return None;
            }
            let mut value: u128 = 0;
            loop {
                let byte = content[position];
                position += 1;
                if value > (u128::MAX >> 7) {
                    return Some(Err(ASN1Error::OutOfRange));
                }
                value = (value << 7) | (byte & 0x7F) as u128;
                if byte & 0x80 == 0 || position >= content.len() {
                    return Some(Ok(value));
                }
            }
        })
    }

    /// Creates an identifier from its arcs: at least two, the first 0, 1 or 2,
    /// and the second below 40 unless the first is 2 (X.690 section 8.19.4).
    pub fn from_arcs(arcs: &[u128]) -> Result<ObjectIdentifier<'static>, ASN1Error> {
        let invalid = ASN1Error::InvalidContent { position: 0 };
        let [first, second, rest @ ..] = arcs else {
            return Err(invalid);
        };
        if *first > 2 || (*first < 2 && *second >= 40) {
            return Err(invalid);
        }
        let leading =
            first.checked_mul(40).and_then(|value| value.checked_add(*second)).ok_or(ASN1Error::OutOfRange)?;
        let mut content = Vec::new();
        for value in core::iter::once(leading).chain(rest.iter().copied()) {
            let mut groups = [0u8; 19];
            let mut count = 0;
            let mut remaining = value;
            loop {
                groups[count] = (remaining & 0x7F) as u8;
                count += 1;
                remaining >>= 7;
                if remaining == 0 {
                    break;
                }
            }
            for index in (0..count).rev() {
                content.push(groups[index] | if index > 0 { 0x80 } else { 0 });
            }
        }
        Ok(ObjectIdentifier { content: Cow::Owned(content) })
    }

    /// Parses dotted decimal text such as `1.2.840.113549`.
    pub fn parse(text: &str) -> Result<ObjectIdentifier<'static>, ASN1Error> {
        let mut arcs = Vec::new();
        for part in text.split('.') {
            // Decimal digits only, without leading zeros.
            if part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                return Err(ASN1Error::InvalidContent { position: 0 });
            }
            arcs.push(part.parse::<u128>().map_err(|_| ASN1Error::OutOfRange)?);
        }
        ObjectIdentifier::from_arcs(&arcs)
    }

    /// The contents octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.content
    }

    /// The arcs, the first two recovered from the first subidentifier.
    pub fn arcs(&self) -> Vec<u128> {
        let mut arcs = Vec::new();
        for (index, value) in ObjectIdentifier::subidentifiers(&self.content).enumerate() {
            let value = value.unwrap_or(0);
            if index == 0 {
                let first = (value / 40).min(2);
                arcs.push(first);
                arcs.push(value - first * 40);
            } else {
                arcs.push(value);
            }
        }
        arcs
    }

    /// A copy that owns its contents.
    pub fn into_owned(self) -> ObjectIdentifier<'static> {
        ObjectIdentifier { content: Cow::Owned(self.content.into_owned()) }
    }
}

impl fmt::Display for ObjectIdentifier<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, arc) in self.arcs().iter().enumerate() {
            if index > 0 {
                formatter.write_str(".")?;
            }
            write!(formatter, "{arc}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ObjectIdentifier<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ObjectIdentifier({self})")
    }
}
