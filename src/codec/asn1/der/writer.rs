use alloc::vec::Vec;

use crate::codec::asn1::{ASN1Error, ASN1Integer, ASN1String, ASN1Time, BitString, ObjectIdentifier, Tag};
use crate::secret::Zeroize;

use super::DERReader;

/// Writes DER elements into a vector.
///
/// Constructed elements are written with closures that fill a nested writer;
/// [`DERWriter::write_set`] and [`DERWriter::write_set_of`] sort the
/// components as DER requires.
///
/// The writer leaves no copy of what it wrote in freed memory, so that it
/// may write private keys: it grows its vector itself, zeroizing the
/// buffer it leaves, and zeroizes its nested writers and its own vector when
/// they are dropped ([`DERWriter::into_bytes`] hands the vector over).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DERWriter {
    output: Vec<u8>,
}

impl DERWriter {
    pub const fn new() -> DERWriter {
        DERWriter { output: Vec::new() }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.output
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.output)
    }

    /// Makes room for `additional` more bytes: in a larger buffer if needed,
    /// zeroizing the one it leaves (which `Vec`'s own growth would not).
    pub fn reserve(&mut self, additional: usize) {
        let needed = self.output.len().saturating_add(additional);
        if needed <= self.output.capacity() {
            return;
        }
        let mut larger = Vec::with_capacity(needed.max(self.output.capacity().saturating_mul(2)));
        larger.extend_from_slice(&self.output);
        self.output.zeroize();
        self.output = larger;
    }

    /// Appends length octets in the fewest octets (X.690 section 10.1).
    pub fn encode_length(length: usize, output: &mut Vec<u8>) {
        if length < 0x80 {
            output.push(length as u8);
            return;
        }
        let bytes = length.to_be_bytes();
        let start = bytes.iter().position(|&byte| byte != 0).unwrap_or(bytes.len() - 1);
        output.push(0x80 | (bytes.len() - start) as u8);
        output.extend_from_slice(&bytes[start..]);
    }

    /// Appends an element with `tag` and `content`.
    pub fn write_element(&mut self, tag: Tag, content: &[u8]) {
        // The identifier takes at most 6 octets and the length at most 9.
        self.reserve(content.len().saturating_add(16));
        tag.encode(&mut self.output);
        DERWriter::encode_length(content.len(), &mut self.output);
        self.output.extend_from_slice(content);
    }

    /// Appends an encoding produced elsewhere, which must be a valid DER element.
    pub fn write_raw(&mut self, encoding: &[u8]) {
        self.reserve(encoding.len());
        self.output.extend_from_slice(encoding);
    }

    /// Appends a constructed element with `tag` whose contents `build` writes.
    pub fn write_constructed(
        &mut self,
        tag: Tag,
        build: impl FnOnce(&mut DERWriter) -> Result<(), ASN1Error>,
    ) -> Result<(), ASN1Error> {
        let mut inner = DERWriter::new();
        build(&mut inner)?;
        self.write_element(tag.with_constructed(true), &inner.output);
        Ok(())
    }

    pub fn write_sequence(
        &mut self,
        build: impl FnOnce(&mut DERWriter) -> Result<(), ASN1Error>,
    ) -> Result<(), ASN1Error> {
        self.write_constructed(Tag::SEQUENCE, build)
    }

    /// Appends a SET whose components `build` writes in any order; they are
    /// sorted by their tags (X.690 section 10.3, see [`Tag::compare_order`]).
    /// Fails if two components have the same tag, which a SET does not allow.
    pub fn write_set(&mut self, build: impl FnOnce(&mut DERWriter) -> Result<(), ASN1Error>) -> Result<(), ASN1Error> {
        let mut inner = DERWriter::new();
        build(&mut inner)?;
        let mut components = Vec::new();
        let mut reader = DERReader::new(&inner.output).with_maximum_depth(usize::MAX);
        while !reader.is_empty() {
            components.push(reader.read_element()?);
        }
        components.sort_by(|a, b| a.tag.compare_order(&b.tag));
        if let Some(pair) = components.windows(2).find(|pair| pair[0].tag.compare_order(&pair[1].tag).is_eq()) {
            return Err(ASN1Error::InvalidContent { position: pair[1].position });
        }
        let mut content = Vec::with_capacity(inner.output.len());
        components.iter().for_each(|component| content.extend_from_slice(component.encoding));
        self.write_element(Tag::SET, &content);
        content.zeroize();
        Ok(())
    }

    /// Appends a SET OF whose components `build` writes in any order; they are
    /// sorted by their encodings (X.690 section 11.6).
    pub fn write_set_of(
        &mut self,
        build: impl FnOnce(&mut DERWriter) -> Result<(), ASN1Error>,
    ) -> Result<(), ASN1Error> {
        let mut inner = DERWriter::new();
        build(&mut inner)?;
        let mut components = Vec::new();
        let mut reader = DERReader::new(&inner.output).with_maximum_depth(usize::MAX);
        while !reader.is_empty() {
            components.push(reader.read_element()?.encoding);
        }
        components.sort_by(|a, b| DERReader::compare_encodings(a, b));
        let mut content = Vec::with_capacity(inner.output.len());
        components.iter().for_each(|component| content.extend_from_slice(component));
        self.write_element(Tag::SET, &content);
        content.zeroize();
        Ok(())
    }

    /// Appends `[number] EXPLICIT` around the element `build` writes.
    pub fn write_explicit(
        &mut self,
        number: u32,
        build: impl FnOnce(&mut DERWriter) -> Result<(), ASN1Error>,
    ) -> Result<(), ASN1Error> {
        self.write_constructed(Tag::context(number, true), build)
    }

    pub fn write_boolean(&mut self, value: bool) {
        self.write_element(Tag::BOOLEAN, &[if value { 0xFF } else { 0x00 }]);
    }

    pub fn write_integer_i128(&mut self, value: i128) {
        let mut content = Vec::new();
        ASN1Integer::encode_i128(value, &mut content);
        self.write_element(Tag::INTEGER, &content);
    }

    /// Appends the non-negative INTEGER with the big-endian `magnitude`.
    pub fn write_integer_unsigned(&mut self, magnitude: &[u8]) {
        let mut content = Vec::new();
        ASN1Integer::encode_unsigned(magnitude, &mut content);
        self.write_element(Tag::INTEGER, &content);
    }

    pub fn write_integer(&mut self, value: &ASN1Integer<'_>) {
        self.write_element(Tag::INTEGER, value.as_bytes());
    }

    pub fn write_enumerated(&mut self, value: i128) {
        let mut content = Vec::new();
        ASN1Integer::encode_i128(value, &mut content);
        self.write_element(Tag::ENUMERATED, &content);
    }

    /// Appends a BIT STRING; fails if its unused bits are not zero.
    pub fn write_bit_string(&mut self, value: &BitString<'_>) -> Result<(), ASN1Error> {
        if !value.has_zero_padding() {
            return Err(ASN1Error::NonCanonical { position: 0 });
        }
        let mut content = Vec::new();
        value.encode_content(&mut content);
        self.write_element(Tag::BIT_STRING, &content);
        Ok(())
    }

    pub fn write_octet_string(&mut self, value: &[u8]) {
        self.write_element(Tag::OCTET_STRING, value);
    }

    pub fn write_null(&mut self) {
        self.write_element(Tag::NULL, &[]);
    }

    pub fn write_object_identifier(&mut self, value: &ObjectIdentifier<'_>) {
        self.write_element(Tag::OBJECT_IDENTIFIER, value.as_bytes());
    }

    pub fn write_utf8_string(&mut self, value: &str) {
        self.write_element(Tag::UTF8_STRING, value.as_bytes());
    }

    /// Appends a string with `tag` whose characters must satisfy `valid`.
    pub fn write_restricted_string(
        &mut self,
        tag: Tag,
        value: &str,
        valid: fn(&[u8]) -> bool,
    ) -> Result<(), ASN1Error> {
        if !valid(value.as_bytes()) {
            return Err(ASN1Error::InvalidContent { position: 0 });
        }
        self.write_element(tag, value.as_bytes());
        Ok(())
    }

    pub fn write_printable_string(&mut self, value: &str) -> Result<(), ASN1Error> {
        self.write_restricted_string(Tag::PRINTABLE_STRING, value, ASN1String::is_printable)
    }

    pub fn write_ia5_string(&mut self, value: &str) -> Result<(), ASN1Error> {
        self.write_restricted_string(Tag::IA5_STRING, value, ASN1String::is_ia5)
    }

    pub fn write_visible_string(&mut self, value: &str) -> Result<(), ASN1Error> {
        self.write_restricted_string(Tag::VISIBLE_STRING, value, ASN1String::is_visible)
    }

    pub fn write_numeric_string(&mut self, value: &str) -> Result<(), ASN1Error> {
        self.write_restricted_string(Tag::NUMERIC_STRING, value, ASN1String::is_numeric)
    }

    pub fn write_bmp_string(&mut self, value: &str) -> Result<(), ASN1Error> {
        let content = ASN1String::encode_bmp(value)?;
        self.write_element(Tag::BMP_STRING, &content);
        Ok(())
    }

    pub fn write_universal_string(&mut self, value: &str) {
        self.write_element(Tag::UNIVERSAL_STRING, &ASN1String::encode_universal(value));
    }

    pub fn write_utc_time(&mut self, value: &ASN1Time) -> Result<(), ASN1Error> {
        let mut content = Vec::new();
        value.encode_utc_time(&mut content)?;
        self.write_element(Tag::UTC_TIME, &content);
        Ok(())
    }

    pub fn write_generalized_time(&mut self, value: &ASN1Time) -> Result<(), ASN1Error> {
        let mut content = Vec::new();
        value.encode_generalized_time(&mut content)?;
        self.write_element(Tag::GENERALIZED_TIME, &content);
        Ok(())
    }
}

impl Drop for DERWriter {
    fn drop(&mut self) {
        self.output.zeroize();
    }
}
