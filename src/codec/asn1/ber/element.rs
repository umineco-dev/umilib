use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use super::BERReader;
use crate::codec::asn1::{ASN1Error, ASN1Integer, ASN1String, ASN1Time, BitString, ObjectIdentifier, Tag};

/// One BER element, borrowed from the input.
///
/// For the indefinite form, `content` excludes the end-of-contents octets.
/// The `as_*` methods accept every BER encoding of a type, including strings
/// made of constructed segments, which are joined into an owned copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BERElement<'a> {
    pub tag: Tag,
    pub content: &'a [u8],
    pub encoding: &'a [u8],
    pub position: usize,
    /// The offset of the contents octets in the input of the outermost reader.
    pub content_position: usize,
    /// Whether the length uses the indefinite form.
    pub indefinite: bool,
    /// The nesting depth of the reader the element was read from.
    pub depth: usize,
    pub maximum_depth: usize,
}

impl<'a> BERElement<'a> {
    pub fn invalid(&self) -> ASN1Error {
        ASN1Error::InvalidContent { position: self.content_position }
    }

    /// A reader over the contents of a constructed element.
    pub fn children(&self) -> Result<BERReader<'a>, ASN1Error> {
        if !self.tag.constructed {
            return Err(ASN1Error::UnexpectedTag { position: self.position });
        }
        BERReader::nested(self)
    }

    /// The contents of a string type, joining constructed segments (X.690
    /// section 8.21.6), which may themselves be segmented; every segment must
    /// have the universal tag `segment`. Nested segments are walked with an
    /// explicit stack, limited by the maximum depth.
    pub fn string_content(&self, segment: Tag) -> Result<Cow<'a, [u8]>, ASN1Error> {
        if !self.tag.constructed {
            return Ok(Cow::Borrowed(self.content));
        }
        let mut joined = Vec::new();
        let mut stack = Vec::from([self.children()?]);
        while let Some(reader) = stack.last_mut() {
            if reader.is_empty() {
                stack.pop();
                continue;
            }
            let child = reader.read_element()?;
            if child.tag.with_constructed(false) != segment {
                return Err(ASN1Error::UnexpectedTag { position: child.position });
            }
            if child.tag.constructed {
                stack.try_reserve(1).map_err(|_| ASN1Error::AllocationFailed)?;
                stack.push(child.children()?);
            } else {
                joined.try_reserve(child.content.len()).map_err(|_| ASN1Error::AllocationFailed)?;
                joined.extend_from_slice(child.content);
            }
        }
        Ok(Cow::Owned(joined))
    }

    /// A BOOLEAN: one octet, any non-zero value being true (X.690 section 8.2).
    pub fn as_boolean(&self) -> Result<bool, ASN1Error> {
        match self.content {
            [value] if !self.tag.constructed => Ok(*value != 0),
            _ => Err(self.invalid()),
        }
    }

    /// An INTEGER or ENUMERATED; BER also requires the fewest octets.
    pub fn as_integer(&self) -> Result<ASN1Integer<'a>, ASN1Error> {
        if self.tag.constructed {
            return Err(self.invalid());
        }
        ASN1Integer::new(self.content).map_err(|_| self.invalid())
    }

    /// A BIT STRING, joining segments, which may themselves be segmented:
    /// only the last primitive segment may have unused bits (X.690 section
    /// 8.6.4). Unused bits may be set in BER.
    pub fn as_bit_string(&self) -> Result<BitString<'a>, ASN1Error> {
        if !self.tag.constructed {
            return BitString::decode_content(self.content).map_err(|_| self.invalid());
        }
        let mut joined = Vec::new();
        let mut unused = 0;
        let mut stack = Vec::from([self.children()?]);
        while let Some(reader) = stack.last_mut() {
            if reader.is_empty() {
                stack.pop();
                continue;
            }
            let child = reader.read_element()?;
            if child.tag.with_constructed(false) != Tag::BIT_STRING {
                return Err(ASN1Error::UnexpectedTag { position: child.position });
            }
            if child.tag.constructed {
                stack.try_reserve(1).map_err(|_| ASN1Error::AllocationFailed)?;
                stack.push(child.children()?);
                continue;
            }
            if unused != 0 {
                return Err(child.invalid());
            }
            let bits = BitString::decode_content(child.content).map_err(|_| child.invalid())?;
            unused = bits.unused_bits();
            joined.try_reserve(bits.bytes().len()).map_err(|_| ASN1Error::AllocationFailed)?;
            joined.extend_from_slice(bits.bytes());
        }
        BitString::new(unused, joined).map_err(|_| self.invalid())
    }

    pub fn as_octet_string(&self) -> Result<Cow<'a, [u8]>, ASN1Error> {
        self.string_content(Tag::OCTET_STRING)
    }

    pub fn as_null(&self) -> Result<(), ASN1Error> {
        if self.tag.constructed || !self.content.is_empty() {
            return Err(self.invalid());
        }
        Ok(())
    }

    pub fn as_object_identifier(&self) -> Result<ObjectIdentifier<'a>, ASN1Error> {
        if self.tag.constructed {
            return Err(self.invalid());
        }
        ObjectIdentifier::new(self.content).map_err(|_| self.invalid())
    }

    pub fn as_utf8_string(&self) -> Result<String, ASN1Error> {
        let bytes = self.string_content(Tag::UTF8_STRING)?;
        ASN1String::decode_utf8(&bytes).map(String::from).map_err(|_| self.invalid())
    }

    /// A string of the universal type `tag` whose characters satisfy `valid`.
    pub fn as_ascii_string(&self, tag: Tag, valid: fn(&[u8]) -> bool) -> Result<String, ASN1Error> {
        let bytes = self.string_content(tag)?;
        if !valid(&bytes) {
            return Err(self.invalid());
        }
        String::from_utf8(bytes.into_owned()).map_err(|_| self.invalid())
    }

    pub fn as_printable_string(&self) -> Result<String, ASN1Error> {
        self.as_ascii_string(Tag::PRINTABLE_STRING, ASN1String::is_printable)
    }

    pub fn as_ia5_string(&self) -> Result<String, ASN1Error> {
        self.as_ascii_string(Tag::IA5_STRING, ASN1String::is_ia5)
    }

    pub fn as_visible_string(&self) -> Result<String, ASN1Error> {
        self.as_ascii_string(Tag::VISIBLE_STRING, ASN1String::is_visible)
    }

    pub fn as_numeric_string(&self) -> Result<String, ASN1Error> {
        self.as_ascii_string(Tag::NUMERIC_STRING, ASN1String::is_numeric)
    }

    pub fn as_bmp_string(&self) -> Result<String, ASN1Error> {
        ASN1String::decode_bmp(&self.string_content(Tag::BMP_STRING)?).map_err(|_| self.invalid())
    }

    pub fn as_universal_string(&self) -> Result<String, ASN1Error> {
        ASN1String::decode_universal(&self.string_content(Tag::UNIVERSAL_STRING)?).map_err(|_| self.invalid())
    }

    /// A UTCTime in any BER form with a zone, converted to UTC.
    pub fn as_utc_time(&self) -> Result<ASN1Time, ASN1Error> {
        ASN1Time::decode_utc_time_ber(&self.string_content(Tag::UTC_TIME)?).map_err(|_| self.invalid())
    }

    /// A GeneralizedTime in any BER form with a zone, converted to UTC.
    pub fn as_generalized_time(&self) -> Result<ASN1Time, ASN1Error> {
        ASN1Time::decode_generalized_time_ber(&self.string_content(Tag::GENERALIZED_TIME)?).map_err(|error| match error
        {
            ASN1Error::OutOfRange => ASN1Error::OutOfRange,
            _ => self.invalid(),
        })
    }
}
