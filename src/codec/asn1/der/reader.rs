use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use super::{DERElement, DERSetOrder};
use crate::codec::asn1::{ASN1Error, ASN1Integer, ASN1Real, ASN1Time, BitString, ObjectIdentifier, Tag, TagClass};

/// A cursor over DER elements, borrowed from the input.
///
/// Every read either returns a complete, valid element or fails without
/// moving. Constructed elements are read with a nested reader over their
/// contents, which counts nesting against `maximum_depth`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DERReader<'a> {
    input: &'a [u8],
    position: usize,
    /// The offset of `input` in the input of the outermost reader.
    base: usize,
    depth: usize,
    maximum_depth: usize,
}

impl<'a> DERReader<'a> {
    /// The default limit of nesting; certificates nest about ten levels deep.
    pub const DEFAULT_MAXIMUM_DEPTH: usize = 64;

    pub const fn new(input: &'a [u8]) -> DERReader<'a> {
        DERReader { input, position: 0, base: 0, depth: 0, maximum_depth: DERReader::DEFAULT_MAXIMUM_DEPTH }
    }

    pub const fn with_maximum_depth(self, maximum_depth: usize) -> DERReader<'a> {
        DERReader { maximum_depth, ..self }
    }

    /// The offset of the next element in the input of the outermost reader.
    pub fn position(&self) -> usize {
        self.base + self.position
    }

    /// The nesting depth: 0 for the outermost reader.
    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn is_empty(&self) -> bool {
        self.position == self.input.len()
    }

    /// Fails if any element is left.
    pub fn finish(&self) -> Result<(), ASN1Error> {
        if !self.is_empty() {
            return Err(ASN1Error::TrailingData { position: self.position() });
        }
        Ok(())
    }

    /// Reads definite length octets at `position` in `input` (X.690 section
    /// 8.1.3); the indefinite form (`0x80`) is reported as `None`. `strict`
    /// requires the fewest octets, as DER does (section 10.1); otherwise the
    /// long form may have any number of leading zero octets (section 8.1.3.5).
    pub fn decode_length(input: &[u8], position: usize, strict: bool) -> Result<(Option<usize>, usize), ASN1Error> {
        let invalid = ASN1Error::InvalidLength { position };
        let first = *input.get(position).ok_or(ASN1Error::UnexpectedEnd { position })?;
        if first < 0x80 {
            return Ok((Some(first as usize), position + 1));
        }
        if first == 0x80 {
            return Ok((None, position + 1));
        }
        if first == 0xFF {
            return Err(invalid);
        }
        let count = (first & 0x7F) as usize;
        let bytes = input.get(position + 1..position + 1 + count).ok_or(ASN1Error::UnexpectedEnd { position })?;
        if strict && bytes[0] == 0 {
            return Err(ASN1Error::NonCanonical { position });
        }
        let significant = &bytes[bytes.iter().take_while(|&&byte| byte == 0).count()..];
        if significant.len() > core::mem::size_of::<usize>() {
            return Err(invalid);
        }
        let length = significant.iter().fold(0usize, |length, &byte| (length << 8) | byte as usize);
        if strict && length < 0x80 {
            return Err(ASN1Error::NonCanonical { position });
        }
        Ok((Some(length), position + 1 + count))
    }

    /// Reads the element at the cursor without moving.
    pub fn peek(&self) -> Result<DERElement<'a>, ASN1Error> {
        let start = self.position;
        let position = self.position();
        let (tag, after_tag) = Tag::decode(self.input, start).map_err(|error| match error {
            ASN1Error::InvalidTag { .. } => ASN1Error::InvalidTag { position },
            _ => ASN1Error::UnexpectedEnd { position },
        })?;
        let (length, after_length) =
            DERReader::decode_length(self.input, after_tag, true).map_err(|error| match error {
                ASN1Error::NonCanonical { .. } => ASN1Error::NonCanonical { position: self.base + after_tag },
                ASN1Error::UnexpectedEnd { .. } => ASN1Error::UnexpectedEnd { position },
                _ => ASN1Error::InvalidLength { position: self.base + after_tag },
            })?;
        // DER always uses the definite form (X.690 section 10.1).
        let length = length.ok_or(ASN1Error::NonCanonical { position: self.base + after_tag })?;
        let end = after_length
            .checked_add(length)
            .filter(|&end| end <= self.input.len())
            .ok_or(ASN1Error::UnexpectedEnd { position })?;
        Ok(DERElement { tag, content: &self.input[after_length..end], encoding: &self.input[start..end], position })
    }

    /// The tag of the next element, if any element is left.
    pub fn peek_tag(&self) -> Option<Tag> {
        Tag::decode(self.input, self.position).ok().map(|(tag, _)| tag)
    }

    /// Reads the next element of any type.
    pub fn read_element(&mut self) -> Result<DERElement<'a>, ASN1Error> {
        let element = self.peek()?;
        self.position += element.encoding.len();
        Ok(element)
    }

    /// Reads the next element, which must have `tag`.
    pub fn read_expected(&mut self, tag: Tag) -> Result<DERElement<'a>, ASN1Error> {
        let element = self.peek()?;
        if element.tag != tag {
            return Err(ASN1Error::UnexpectedTag { position: element.position });
        }
        self.position += element.encoding.len();
        Ok(element)
    }

    /// Reads the next element if it has `tag`, for OPTIONAL and DEFAULT components.
    pub fn read_optional(&mut self, tag: Tag) -> Result<Option<DERElement<'a>>, ASN1Error> {
        if self.peek_tag() != Some(tag) {
            return Ok(None);
        }
        self.read_expected(tag).map(Some)
    }

    /// A reader over the contents of `element`, one level deeper.
    pub fn nested(&self, element: &DERElement<'a>) -> Result<DERReader<'a>, ASN1Error> {
        if self.depth >= self.maximum_depth {
            return Err(ASN1Error::TooDeep { position: element.position, maximum: self.maximum_depth });
        }
        Ok(DERReader {
            input: element.content,
            position: 0,
            base: element.content_position(),
            depth: self.depth + 1,
            maximum_depth: self.maximum_depth,
        })
    }

    /// Reads a constructed element with `tag` and returns a reader over its contents.
    pub fn read_constructed(&mut self, tag: Tag) -> Result<DERReader<'a>, ASN1Error> {
        let element = self.peek()?;
        if element.tag != tag || !tag.constructed {
            return Err(ASN1Error::UnexpectedTag { position: element.position });
        }
        let nested = self.nested(&element)?;
        self.position += element.encoding.len();
        Ok(nested)
    }

    pub fn read_sequence(&mut self) -> Result<DERReader<'a>, ASN1Error> {
        self.read_constructed(Tag::SEQUENCE)
    }

    /// Reads a SET, whose components must have distinct tags in ascending
    /// canonical order (X.690 section 10.3; see [`Tag::compare_order`]). Use
    /// [`DERReader::read_set_of`] for SET OF.
    pub fn read_set(&mut self) -> Result<DERReader<'a>, ASN1Error> {
        let element = self.peek()?;
        if element.tag != Tag::SET {
            return Err(ASN1Error::UnexpectedTag { position: element.position });
        }
        let nested = self.nested(&element)?;
        let mut components = nested;
        let mut previous: Option<Tag> = None;
        while !components.is_empty() {
            let component = components.read_element()?;
            if previous.is_some_and(|previous| previous.compare_order(&component.tag) != Ordering::Less) {
                return Err(ASN1Error::NonCanonical { position: component.position });
            }
            previous = Some(component.tag);
        }
        self.position += element.encoding.len();
        Ok(nested)
    }

    /// Compares two encodings as X.690 section 11.6 orders SET OF components:
    /// as octet strings, the shorter padded with zeros at its end.
    pub fn compare_encodings(a: &[u8], b: &[u8]) -> Ordering {
        let length = a.len().max(b.len());
        (0..length)
            .map(|index| a.get(index).copied().unwrap_or(0).cmp(&b.get(index).copied().unwrap_or(0)))
            .find(|order| order.is_ne())
            .unwrap_or(Ordering::Equal)
    }

    /// Reads a SET OF, whose components must be in ascending order of their encodings.
    pub fn read_set_of(&mut self) -> Result<DERReader<'a>, ASN1Error> {
        self.read_set_of_tagged(Tag::SET)
    }

    /// Reads a SET OF with `tag`, which may be an implicit tag (`[0] IMPLICIT
    /// SET OF`); its components must be in ascending order of their encodings.
    pub fn read_set_of_tagged(&mut self, tag: Tag) -> Result<DERReader<'a>, ASN1Error> {
        let element = self.peek()?;
        if element.tag != tag || !tag.constructed {
            return Err(ASN1Error::UnexpectedTag { position: element.position });
        }
        let nested = self.nested(&element)?;
        let mut components = nested;
        let mut previous: Option<&[u8]> = None;
        while !components.is_empty() {
            let component = components.read_element()?;
            if previous
                .is_some_and(|previous| DERReader::compare_encodings(previous, component.encoding) == Ordering::Greater)
            {
                return Err(ASN1Error::NonCanonical { position: component.position });
            }
            previous = Some(component.encoding);
        }
        self.position += element.encoding.len();
        Ok(nested)
    }

    /// Reads `[number] EXPLICIT` and returns a reader over the tagged contents.
    pub fn read_explicit(&mut self, number: u32) -> Result<DERReader<'a>, ASN1Error> {
        self.read_constructed(Tag::context(number, true))
    }

    /// Reads `[number] EXPLICIT` if it is the next element.
    pub fn read_optional_explicit(&mut self, number: u32) -> Result<Option<DERReader<'a>>, ASN1Error> {
        if self.peek_tag() != Some(Tag::context(number, true)) {
            return Ok(None);
        }
        self.read_explicit(number).map(Some)
    }

    /// Reads an element with `tag` and decodes it with `decode`, without moving on failure.
    pub fn read_with<T>(
        &mut self,
        tag: Tag,
        decode: impl FnOnce(&DERElement<'a>) -> Result<T, ASN1Error>,
    ) -> Result<T, ASN1Error> {
        let element = self.peek()?;
        if element.tag != tag {
            return Err(ASN1Error::UnexpectedTag { position: element.position });
        }
        let value = decode(&element)?;
        self.position += element.encoding.len();
        Ok(value)
    }

    pub fn read_boolean(&mut self) -> Result<bool, ASN1Error> {
        self.read_with(Tag::BOOLEAN, DERElement::as_boolean)
    }

    pub fn read_integer(&mut self) -> Result<ASN1Integer<'a>, ASN1Error> {
        self.read_with(Tag::INTEGER, DERElement::as_integer)
    }

    pub fn read_enumerated(&mut self) -> Result<ASN1Integer<'a>, ASN1Error> {
        self.read_with(Tag::ENUMERATED, DERElement::as_integer)
    }

    pub fn read_bit_string(&mut self) -> Result<BitString<'a>, ASN1Error> {
        self.read_with(Tag::BIT_STRING, DERElement::as_bit_string)
    }

    pub fn read_octet_string(&mut self) -> Result<&'a [u8], ASN1Error> {
        self.read_with(Tag::OCTET_STRING, DERElement::as_octet_string)
    }

    pub fn read_null(&mut self) -> Result<(), ASN1Error> {
        self.read_with(Tag::NULL, DERElement::as_null)
    }

    pub fn read_object_identifier(&mut self) -> Result<ObjectIdentifier<'a>, ASN1Error> {
        self.read_with(Tag::OBJECT_IDENTIFIER, DERElement::as_object_identifier)
    }

    pub fn read_utf8_string(&mut self) -> Result<&'a str, ASN1Error> {
        self.read_with(Tag::UTF8_STRING, DERElement::as_utf8_string)
    }

    pub fn read_printable_string(&mut self) -> Result<&'a str, ASN1Error> {
        self.read_with(Tag::PRINTABLE_STRING, DERElement::as_printable_string)
    }

    pub fn read_ia5_string(&mut self) -> Result<&'a str, ASN1Error> {
        self.read_with(Tag::IA5_STRING, DERElement::as_ia5_string)
    }

    pub fn read_visible_string(&mut self) -> Result<&'a str, ASN1Error> {
        self.read_with(Tag::VISIBLE_STRING, DERElement::as_visible_string)
    }

    pub fn read_numeric_string(&mut self) -> Result<&'a str, ASN1Error> {
        self.read_with(Tag::NUMERIC_STRING, DERElement::as_numeric_string)
    }

    pub fn read_bmp_string(&mut self) -> Result<String, ASN1Error> {
        self.read_with(Tag::BMP_STRING, DERElement::as_bmp_string)
    }

    pub fn read_universal_string(&mut self) -> Result<String, ASN1Error> {
        self.read_with(Tag::UNIVERSAL_STRING, DERElement::as_universal_string)
    }

    pub fn read_utc_time(&mut self) -> Result<ASN1Time, ASN1Error> {
        self.read_with(Tag::UTC_TIME, DERElement::as_utc_time)
    }

    pub fn read_generalized_time(&mut self) -> Result<ASN1Time, ASN1Error> {
        self.read_with(Tag::GENERALIZED_TIME, DERElement::as_generalized_time)
    }

    /// Validates the whole of `input` as DER: one element, everything nested
    /// in it, and the contents of the universal primitives whose rules this
    /// module knows (see [`DERReader::validate_shallow`]).
    pub fn validate(input: &'a [u8], maximum_depth: usize) -> Result<(), ASN1Error> {
        let mut reader = DERReader::new(input).with_maximum_depth(maximum_depth);
        let element = reader.read_element()?;
        reader.finish()?;
        reader.validate_element(&element)
    }

    /// Checks `element`, read by this reader, and everything nested in it.
    /// The walk uses an explicit stack, so the depth is limited only by
    /// `maximum_depth`, never by the call stack.
    pub fn validate_element(&self, element: &DERElement<'a>) -> Result<(), ASN1Error> {
        let mut stack: Vec<(DERReader<'a>, Option<DERSetOrder<'a>>)> = Vec::new();
        let mut next = Some((*self, *element));
        loop {
            if let Some((reader, element)) = next.take() {
                DERReader::validate_shallow(&element)?;
                if element.tag.constructed {
                    let nested = reader.nested(&element)?;
                    stack.try_reserve(1).map_err(|_| ASN1Error::AllocationFailed)?;
                    stack.push((nested, (element.tag == Tag::SET).then(DERSetOrder::new)));
                }
            }
            let Some((reader, order)) = stack.last_mut() else {
                return Ok(());
            };
            if reader.is_empty() {
                stack.pop();
                continue;
            }
            let child = reader.read_element()?;
            if let Some(order) = order {
                order.push(&child)?;
            }
            next = Some((*reader, child));
        }
    }

    /// Checks the form of `element` and, for a universal primitive, its
    /// contents, without looking inside constructed elements.
    ///
    /// SEQUENCE, SET, EXTERNAL, EMBEDDED PDV and CHARACTER STRING must be
    /// constructed and every other universal type primitive (X.690 sections
    /// 8.9 to 8.18 and 10.2). The contents of BOOLEAN, INTEGER, ENUMERATED,
    /// BIT STRING, NULL, OBJECT IDENTIFIER, RELATIVE-OID, REAL, the times and
    /// the strings with a known character set are checked; those of other
    /// universal types (ObjectDescriptor, TIME, the ISO 2022 strings, DATE,
    /// TIME-OF-DAY, DATE-TIME, DURATION, the IRIs and unassigned numbers) are not.
    pub fn validate_shallow(element: &DERElement<'a>) -> Result<(), ASN1Error> {
        if element.tag.class != TagClass::Universal {
            return Ok(());
        }
        let constructed_type = matches!(element.tag.number, 8 | 11 | 16 | 17 | 29);
        if element.tag.constructed != constructed_type {
            return Err(ASN1Error::NonCanonical { position: element.position });
        }
        let invalid = |error: ASN1Error| match error {
            ASN1Error::NonCanonical { .. } => ASN1Error::NonCanonical { position: element.content_position() },
            ASN1Error::OutOfRange => ASN1Error::OutOfRange,
            _ => element.invalid(),
        };
        match element.tag.number {
            0 => Err(ASN1Error::InvalidTag { position: element.position }),
            1 => element.as_boolean().map(drop),
            2 | 10 => element.as_integer().map(drop),
            3 => element.as_bit_string().map(drop),
            5 => element.as_null(),
            6 => element.as_object_identifier().map(drop),
            9 => ASN1Real::validate_der(element.content).map_err(invalid),
            12 => element.as_utf8_string().map(drop),
            13 => ObjectIdentifier::validate_subidentifiers(element.content).map_err(invalid),
            18 => element.as_numeric_string().map(drop),
            19 => element.as_printable_string().map(drop),
            22 => element.as_ia5_string().map(drop),
            23 => element.as_utc_time().map(drop),
            24 => ASN1Time::check_generalized_time(element.content).map(drop).map_err(invalid),
            26 => element.as_visible_string().map(drop),
            28 => element.as_universal_string().map(drop),
            30 => element.as_bmp_string().map(drop),
            _ => Ok(()),
        }
    }
}
