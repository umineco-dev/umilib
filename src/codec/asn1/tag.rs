use alloc::vec::Vec;

use super::ASN1Error;

/// The class of a tag (X.680 section 8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TagClass {
    Universal = 0,
    Application = 1,
    ContextSpecific = 2,
    Private = 3,
}

/// The identifier of an element: class, form and number (X.690 section 8.1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag {
    pub class: TagClass,
    pub constructed: bool,
    pub number: u32,
}

impl Tag {
    pub const BOOLEAN: Tag = Tag::universal(1, false);
    pub const INTEGER: Tag = Tag::universal(2, false);
    pub const BIT_STRING: Tag = Tag::universal(3, false);
    pub const OCTET_STRING: Tag = Tag::universal(4, false);
    pub const NULL: Tag = Tag::universal(5, false);
    pub const OBJECT_IDENTIFIER: Tag = Tag::universal(6, false);
    pub const OBJECT_DESCRIPTOR: Tag = Tag::universal(7, false);
    pub const EXTERNAL: Tag = Tag::universal(8, true);
    pub const REAL: Tag = Tag::universal(9, false);
    pub const ENUMERATED: Tag = Tag::universal(10, false);
    pub const EMBEDDED_PDV: Tag = Tag::universal(11, true);
    pub const UTF8_STRING: Tag = Tag::universal(12, false);
    pub const RELATIVE_OID: Tag = Tag::universal(13, false);
    pub const TIME: Tag = Tag::universal(14, false);
    pub const SEQUENCE: Tag = Tag::universal(16, true);
    pub const SET: Tag = Tag::universal(17, true);
    pub const NUMERIC_STRING: Tag = Tag::universal(18, false);
    pub const PRINTABLE_STRING: Tag = Tag::universal(19, false);
    pub const TELETEX_STRING: Tag = Tag::universal(20, false);
    pub const VIDEOTEX_STRING: Tag = Tag::universal(21, false);
    pub const IA5_STRING: Tag = Tag::universal(22, false);
    pub const UTC_TIME: Tag = Tag::universal(23, false);
    pub const GENERALIZED_TIME: Tag = Tag::universal(24, false);
    pub const GRAPHIC_STRING: Tag = Tag::universal(25, false);
    pub const VISIBLE_STRING: Tag = Tag::universal(26, false);
    pub const GENERAL_STRING: Tag = Tag::universal(27, false);
    pub const UNIVERSAL_STRING: Tag = Tag::universal(28, false);
    pub const CHARACTER_STRING: Tag = Tag::universal(29, true);
    pub const BMP_STRING: Tag = Tag::universal(30, false);
    pub const DATE: Tag = Tag::universal(31, false);
    pub const TIME_OF_DAY: Tag = Tag::universal(32, false);
    pub const DATE_TIME: Tag = Tag::universal(33, false);
    pub const DURATION: Tag = Tag::universal(34, false);

    pub const fn universal(number: u32, constructed: bool) -> Tag {
        Tag { class: TagClass::Universal, constructed, number }
    }

    /// A context-specific tag, as used by `[number]` in modules with explicit or implicit tagging.
    pub const fn context(number: u32, constructed: bool) -> Tag {
        Tag { class: TagClass::ContextSpecific, constructed, number }
    }

    pub const fn application(number: u32, constructed: bool) -> Tag {
        Tag { class: TagClass::Application, constructed, number }
    }

    pub const fn private(number: u32, constructed: bool) -> Tag {
        Tag { class: TagClass::Private, constructed, number }
    }

    /// Compares tags in the canonical order of X.680 section 8.6, which DER
    /// uses for the components of a SET (X.690 section 10.3): universal,
    /// application, context-specific, then private, and by number within a
    /// class. The form (primitive or constructed) is not part of the order,
    /// so this differs from comparing identifier octets.
    pub fn compare_order(&self, other: &Tag) -> core::cmp::Ordering {
        (self.class, self.number).cmp(&(other.class, other.number))
    }

    /// The same tag with the other form.
    pub const fn with_constructed(self, constructed: bool) -> Tag {
        Tag { class: self.class, constructed, number: self.number }
    }

    /// Reads the identifier octets at `position` and returns the tag and the
    /// position after them. Tag numbers up to 30 must use the short form and
    /// longer forms must be minimal (X.690 section 8.1.2.4), in BER as in DER.
    pub fn decode(input: &[u8], position: usize) -> Result<(Tag, usize), ASN1Error> {
        let invalid = ASN1Error::InvalidTag { position };
        let first = *input.get(position).ok_or(ASN1Error::UnexpectedEnd { position })?;
        let class = match first >> 6 {
            0 => TagClass::Universal,
            1 => TagClass::Application,
            2 => TagClass::ContextSpecific,
            _ => TagClass::Private,
        };
        let constructed = first & 0x20 != 0;
        if first & 0x1F != 0x1F {
            return Ok((Tag { class, constructed, number: (first & 0x1F) as u32 }, position + 1));
        }
        let mut number: u32 = 0;
        let mut index = position + 1;
        loop {
            let byte = *input.get(index).ok_or(ASN1Error::UnexpectedEnd { position })?;
            if index == position + 1 && byte == 0x80 {
                return Err(invalid);
            }
            if number > (u32::MAX >> 7) {
                return Err(invalid);
            }
            number = (number << 7) | (byte & 0x7F) as u32;
            index += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        if number < 31 {
            return Err(invalid);
        }
        Ok((Tag { class, constructed, number }, index))
    }

    /// Appends the identifier octets of the tag.
    pub fn encode(&self, output: &mut Vec<u8>) {
        let leading = ((self.class as u8) << 6) | if self.constructed { 0x20 } else { 0 };
        if self.number < 31 {
            output.push(leading | self.number as u8);
            return;
        }
        output.push(leading | 0x1F);
        let mut groups = [0u8; 5];
        let mut count = 0;
        let mut number = self.number;
        while number > 0 {
            groups[count] = (number & 0x7F) as u8;
            number >>= 7;
            count += 1;
        }
        for index in (0..count).rev() {
            output.push(groups[index] | if index > 0 { 0x80 } else { 0 });
        }
    }
}
