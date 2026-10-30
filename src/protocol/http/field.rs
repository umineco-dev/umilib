use alloc::vec::Vec;

use super::{HTTPError, HTTPSyntax};

/// A field line (RFC 9110 §5): a name, a token kept in lowercase since
/// names are case-insensitive and HTTP/2 and HTTP/3 send them so, and a
/// value; sensitive fields stay out of compression tables (RFC 7541 §7.1.3,
/// RFC 9204 §7.1.3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HTTPField {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub sensitive: bool,
}

impl HTTPField {
    /// The field of `name` (lowercased) and `value`; fails for a name that
    /// is not a token or a value that is not a field value.
    pub fn new(name: &[u8], value: &[u8]) -> Result<HTTPField, HTTPError> {
        if !HTTPSyntax::is_token(name) {
            return Err(HTTPError::Malformed("a field name that is not a token"));
        }
        if !HTTPSyntax::is_field_value(value) {
            return Err(HTTPError::Malformed("an invalid field value"));
        }
        Ok(HTTPField { name: name.to_ascii_lowercase(), value: value.to_vec(), sensitive: false })
    }

    /// The size the field counts for in limits of field sections: its name,
    /// value and 32 bytes (RFC 9113 §6.5.2, RFC 9114 §4.2.2).
    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }
}

/// The fields of a message's header or trailer section, in order (RFC 9110 §5.3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HTTPFields {
    pub fields: Vec<HTTPField>,
}

impl HTTPFields {
    pub fn new() -> HTTPFields {
        HTTPFields::default()
    }

    /// Adds a field line after the others.
    pub fn append(&mut self, name: &[u8], value: &[u8]) -> Result<(), HTTPError> {
        self.fields.push(HTTPField::new(name, value)?);
        Ok(())
    }

    /// These fields with one more line, for building.
    pub fn with(mut self, name: &[u8], value: &[u8]) -> Result<HTTPFields, HTTPError> {
        self.append(name, value)?;
        Ok(self)
    }

    /// Replaces the lines of `name` with one of `value`.
    pub fn set(&mut self, name: &[u8], value: &[u8]) -> Result<(), HTTPError> {
        let field = HTTPField::new(name, value)?;
        self.remove(name);
        self.fields.push(field);
        Ok(())
    }

    /// Removes the lines of `name`; returns whether there were any.
    pub fn remove(&mut self, name: &[u8]) -> bool {
        let before = self.fields.len();
        self.fields.retain(|field| !field.name.eq_ignore_ascii_case(name));
        self.fields.len() != before
    }

    /// The value of the first line of `name`.
    pub fn get(&self, name: &[u8]) -> Option<&[u8]> {
        self.fields.iter().find(|field| field.name.eq_ignore_ascii_case(name)).map(|field| field.value.as_slice())
    }

    /// The values of every line of `name`, in order.
    pub fn get_all<'a>(&'a self, name: &'a [u8]) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.fields
            .iter()
            .filter(move |field| field.name.eq_ignore_ascii_case(name))
            .map(|field| field.value.as_slice())
    }

    /// The lines of `name` as one value, joined by ", " (RFC 9110 §5.3);
    /// not meaningful for Set-Cookie, which is not a list.
    pub fn combined(&self, name: &[u8]) -> Option<Vec<u8>> {
        let mut values = self.get_all(name);
        let mut combined = values.next()?.to_vec();
        for value in values {
            combined.extend_from_slice(b", ");
            combined.extend_from_slice(value);
        }
        Some(combined)
    }

    /// Whether the list fields of `name` have `token` (RFC 9110 §5.6.1).
    pub fn contains_token(&self, name: &[u8], token: &[u8]) -> bool {
        self.get_all(name).any(|value| HTTPSyntax::list_contains(value, token))
    }

    pub fn contains(&self, name: &[u8]) -> bool {
        self.get(name).is_some()
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn iter(&self) -> core::slice::Iter<'_, HTTPField> {
        self.fields.iter()
    }

    /// The size of the section in limits of field sections (RFC 9113 §6.5.2).
    pub fn size(&self) -> usize {
        self.fields.iter().map(HTTPField::size).sum()
    }

    /// The value of Content-Length, if there is one valid: one or more
    /// lines of the same digits (RFC 9110 §8.6); fails for any other.
    pub fn content_length(&self) -> Result<Option<u64>, HTTPError> {
        let invalid = HTTPError::Malformed("an invalid Content-Length");
        let mut length = None;
        for value in self.get_all(b"content-length") {
            // A list of the same values is allowed: "42, 42".
            let elements = HTTPSyntax::list(value);
            if elements.is_empty() {
                return Err(invalid);
            }
            for element in elements {
                if element.is_empty() || element.len() > 19 || !element.iter().all(u8::is_ascii_digit) {
                    return Err(invalid);
                }
                let parsed = element.iter().fold(0u64, |value, digit| value * 10 + u64::from(digit - b'0'));
                if length.is_some_and(|length| length != parsed) {
                    return Err(invalid);
                }
                length = Some(parsed);
            }
        }
        Ok(length)
    }
}

impl<'a> IntoIterator for &'a HTTPFields {
    type Item = &'a HTTPField;
    type IntoIter = core::slice::Iter<'a, HTTPField>;

    fn into_iter(self) -> Self::IntoIter {
        self.fields.iter()
    }
}
