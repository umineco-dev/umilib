use alloc::string::String;

use crate::codec::asn1::{ASN1Error, ASN1Integer, ASN1String, ASN1Time, BitString, ObjectIdentifier, Tag};

/// One DER element, borrowed from the input.
///
/// The `as_*` methods check the contents against the DER rules of a type
/// without checking the tag, so they also read implicitly tagged values
/// (`[0] IMPLICIT INTEGER`); use [`DERReader`](super::DERReader) to check tags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DERElement<'a> {
    pub tag: Tag,
    /// The contents octets.
    pub content: &'a [u8],
    /// The whole encoding: identifier, length and contents octets.
    pub encoding: &'a [u8],
    /// The offset of the identifier octets in the input of the outermost reader.
    pub position: usize,
}

impl<'a> DERElement<'a> {
    /// The offset of the contents octets in the input of the outermost
    /// reader. For an element whose fields were changed so that the contents
    /// are longer than the encoding, it is `position`.
    pub fn content_position(&self) -> usize {
        self.position.saturating_add(self.encoding.len().saturating_sub(self.content.len()))
    }

    /// Fails unless the element is primitive, as DER requires for every string type.
    pub fn primitive(&self) -> Result<&'a [u8], ASN1Error> {
        if self.tag.constructed {
            return Err(ASN1Error::NonCanonical { position: self.position });
        }
        Ok(self.content)
    }

    /// The error for invalid contents of this element.
    pub fn invalid(&self) -> ASN1Error {
        ASN1Error::InvalidContent { position: self.content_position() }
    }

    /// A BOOLEAN: one octet, `0x00` for false and `0xFF` for true (X.690 section 11.1).
    pub fn as_boolean(&self) -> Result<bool, ASN1Error> {
        match self.primitive()? {
            [0x00] => Ok(false),
            [0xFF] => Ok(true),
            [_] => Err(ASN1Error::NonCanonical { position: self.position }),
            _ => Err(self.invalid()),
        }
    }

    /// An INTEGER or ENUMERATED in the fewest octets.
    pub fn as_integer(&self) -> Result<ASN1Integer<'a>, ASN1Error> {
        ASN1Integer::new(self.primitive()?).map_err(|_| self.invalid())
    }

    /// A BIT STRING whose unused bits are zero (X.690 section 11.2.1).
    pub fn as_bit_string(&self) -> Result<BitString<'a>, ASN1Error> {
        let bits = BitString::decode_content(self.primitive()?).map_err(|_| self.invalid())?;
        if !bits.has_zero_padding() {
            return Err(ASN1Error::NonCanonical { position: self.position });
        }
        Ok(bits)
    }

    /// An OCTET STRING.
    pub fn as_octet_string(&self) -> Result<&'a [u8], ASN1Error> {
        self.primitive()
    }

    /// A NULL: no contents.
    pub fn as_null(&self) -> Result<(), ASN1Error> {
        if !self.primitive()?.is_empty() {
            return Err(self.invalid());
        }
        Ok(())
    }

    pub fn as_object_identifier(&self) -> Result<ObjectIdentifier<'a>, ASN1Error> {
        ObjectIdentifier::new(self.primitive()?).map_err(|_| self.invalid())
    }

    pub fn as_utf8_string(&self) -> Result<&'a str, ASN1Error> {
        ASN1String::decode_utf8(self.primitive()?).map_err(|_| self.invalid())
    }

    /// A string whose characters satisfy `valid`; the characters are ASCII.
    pub fn as_ascii_string(&self, valid: fn(&[u8]) -> bool) -> Result<&'a str, ASN1Error> {
        let bytes = self.primitive()?;
        if !valid(bytes) {
            return Err(self.invalid());
        }
        core::str::from_utf8(bytes).map_err(|_| self.invalid())
    }

    pub fn as_printable_string(&self) -> Result<&'a str, ASN1Error> {
        self.as_ascii_string(ASN1String::is_printable)
    }

    pub fn as_ia5_string(&self) -> Result<&'a str, ASN1Error> {
        self.as_ascii_string(ASN1String::is_ia5)
    }

    pub fn as_visible_string(&self) -> Result<&'a str, ASN1Error> {
        self.as_ascii_string(ASN1String::is_visible)
    }

    pub fn as_numeric_string(&self) -> Result<&'a str, ASN1Error> {
        self.as_ascii_string(ASN1String::is_numeric)
    }

    pub fn as_bmp_string(&self) -> Result<String, ASN1Error> {
        ASN1String::decode_bmp(self.primitive()?).map_err(|_| self.invalid())
    }

    pub fn as_universal_string(&self) -> Result<String, ASN1Error> {
        ASN1String::decode_universal(self.primitive()?).map_err(|_| self.invalid())
    }

    /// The octets of a TeletexString (T.61), which are not interpreted.
    pub fn as_teletex_string(&self) -> Result<&'a [u8], ASN1Error> {
        self.primitive()
    }

    pub fn as_utc_time(&self) -> Result<ASN1Time, ASN1Error> {
        ASN1Time::decode_utc_time(self.primitive()?).map_err(|_| self.invalid())
    }

    pub fn as_generalized_time(&self) -> Result<ASN1Time, ASN1Error> {
        ASN1Time::decode_generalized_time(self.primitive()?).map_err(|error| match error {
            ASN1Error::OutOfRange => ASN1Error::OutOfRange,
            _ => self.invalid(),
        })
    }
}
