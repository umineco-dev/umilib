use alloc::vec::Vec;

use super::BERElement;
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ASN1Error, ASN1Real, ASN1Time, Tag, TagClass};

/// A cursor over BER elements, borrowed from the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BERReader<'a> {
    input: &'a [u8],
    position: usize,
    base: usize,
    depth: usize,
    maximum_depth: usize,
}

impl<'a> BERReader<'a> {
    pub const DEFAULT_MAXIMUM_DEPTH: usize = 64;
    /// The end-of-contents octets of the indefinite form.
    pub const END_OF_CONTENTS: [u8; 2] = [0, 0];

    pub const fn new(input: &'a [u8]) -> BERReader<'a> {
        BERReader { input, position: 0, base: 0, depth: 0, maximum_depth: BERReader::DEFAULT_MAXIMUM_DEPTH }
    }

    pub const fn with_maximum_depth(self, maximum_depth: usize) -> BERReader<'a> {
        BERReader { maximum_depth, ..self }
    }

    pub fn position(&self) -> usize {
        self.base + self.position
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn is_empty(&self) -> bool {
        self.position == self.input.len()
    }

    pub fn finish(&self) -> Result<(), ASN1Error> {
        if !self.is_empty() {
            return Err(ASN1Error::TrailingData { position: self.position() });
        }
        Ok(())
    }

    /// Reads the header at `start` of `input`: tag, definite length or
    /// `None` for the indefinite form, and the start of the contents.
    pub fn decode_header(input: &[u8], start: usize, base: usize) -> Result<(Tag, Option<usize>, usize), ASN1Error> {
        let position = base + start;
        let (tag, after_tag) = Tag::decode(input, start).map_err(|error| match error {
            ASN1Error::InvalidTag { .. } => ASN1Error::InvalidTag { position },
            _ => ASN1Error::UnexpectedEnd { position },
        })?;
        if tag.class == TagClass::Universal && tag.number == 0 {
            // Tag 0 is reserved for the end-of-contents octets (X.690 section 8.1.5).
            return Err(ASN1Error::InvalidTag { position });
        }
        let (length, after_length) =
            DERReader::decode_length(input, after_tag, false).map_err(|error| match error {
                ASN1Error::UnexpectedEnd { .. } => ASN1Error::UnexpectedEnd { position },
                _ => ASN1Error::InvalidLength { position: base + after_tag },
            })?;
        if length.is_none() && !tag.constructed {
            // Only constructed elements may use the indefinite form (X.690 section 8.1.3.2).
            return Err(ASN1Error::InvalidLength { position: base + after_tag });
        }
        Ok((tag, length, after_length))
    }

    /// The position of the end-of-contents octets closing the indefinite
    /// element whose contents start at `start`, walking nested elements
    /// iteratively; `depth` levels are already open.
    pub fn find_end_of_contents(&self, start: usize, depth: usize) -> Result<usize, ASN1Error> {
        let mut open = 1usize;
        let mut position = start;
        loop {
            if self.input[position..].starts_with(&BERReader::END_OF_CONTENTS) {
                open -= 1;
                if open == 0 {
                    return Ok(position);
                }
                position += 2;
                continue;
            }
            if position >= self.input.len() {
                return Err(ASN1Error::UnexpectedEnd { position: self.base + start });
            }
            let (_, length, content) = BERReader::decode_header(self.input, position, self.base)?;
            match length {
                Some(length) => {
                    position = content
                        .checked_add(length)
                        .filter(|&end| end <= self.input.len())
                        .ok_or(ASN1Error::UnexpectedEnd { position: self.base + position })?;
                }
                None => {
                    if depth + open >= self.maximum_depth {
                        return Err(ASN1Error::TooDeep { position: self.base + position, maximum: self.maximum_depth });
                    }
                    open += 1;
                    position = content;
                }
            }
        }
    }

    /// Reads the element at the cursor without moving.
    pub fn peek(&self) -> Result<BERElement<'a>, ASN1Error> {
        let start = self.position;
        let position = self.position();
        if self.input[start..].starts_with(&BERReader::END_OF_CONTENTS) {
            // End-of-contents octets are only allowed where an indefinite element ends.
            return Err(ASN1Error::InvalidTag { position });
        }
        let (tag, length, content_start) = BERReader::decode_header(self.input, start, self.base)?;
        let (content_end, end) = match length {
            Some(length) => {
                let end = content_start
                    .checked_add(length)
                    .filter(|&end| end <= self.input.len())
                    .ok_or(ASN1Error::UnexpectedEnd { position })?;
                (end, end)
            }
            None => {
                let end = self.find_end_of_contents(content_start, self.depth + 1)?;
                (end, end + 2)
            }
        };
        Ok(BERElement {
            tag,
            content: &self.input[content_start..content_end],
            encoding: &self.input[start..end],
            position,
            content_position: self.base + content_start,
            indefinite: length.is_none(),
            depth: self.depth,
            maximum_depth: self.maximum_depth,
        })
    }

    pub fn peek_tag(&self) -> Option<Tag> {
        Tag::decode(self.input, self.position).ok().map(|(tag, _)| tag)
    }

    pub fn read_element(&mut self) -> Result<BERElement<'a>, ASN1Error> {
        let element = self.peek()?;
        self.position += element.encoding.len();
        Ok(element)
    }

    pub fn read_expected(&mut self, tag: Tag) -> Result<BERElement<'a>, ASN1Error> {
        let element = self.peek()?;
        if element.tag != tag {
            return Err(ASN1Error::UnexpectedTag { position: element.position });
        }
        self.position += element.encoding.len();
        Ok(element)
    }

    pub fn read_optional(&mut self, tag: Tag) -> Result<Option<BERElement<'a>>, ASN1Error> {
        if self.peek_tag() != Some(tag) {
            return Ok(None);
        }
        self.read_expected(tag).map(Some)
    }

    /// A reader over the contents of a constructed `element`, one level deeper.
    pub fn nested(element: &BERElement<'a>) -> Result<BERReader<'a>, ASN1Error> {
        if element.depth >= element.maximum_depth {
            return Err(ASN1Error::TooDeep { position: element.position, maximum: element.maximum_depth });
        }
        Ok(BERReader {
            input: element.content,
            position: 0,
            base: element.content_position,
            depth: element.depth + 1,
            maximum_depth: element.maximum_depth,
        })
    }

    pub fn read_constructed(&mut self, tag: Tag) -> Result<BERReader<'a>, ASN1Error> {
        let element = self.peek()?;
        if element.tag != tag || !tag.constructed {
            return Err(ASN1Error::UnexpectedTag { position: element.position });
        }
        let nested = BERReader::nested(&element)?;
        self.position += element.encoding.len();
        Ok(nested)
    }

    pub fn read_sequence(&mut self) -> Result<BERReader<'a>, ASN1Error> {
        self.read_constructed(Tag::SEQUENCE)
    }

    pub fn read_set(&mut self) -> Result<BERReader<'a>, ASN1Error> {
        self.read_constructed(Tag::SET)
    }

    pub fn read_explicit(&mut self, number: u32) -> Result<BERReader<'a>, ASN1Error> {
        self.read_constructed(Tag::context(number, true))
    }

    /// Whether elements of the universal type `number` are strings, which BER
    /// may split into constructed segments and DER writes as primitives.
    pub fn is_string_type(number: u32) -> bool {
        matches!(number, 3 | 4 | 7 | 12 | 18..=28 | 30)
    }

    /// Whether elements of the universal type `number` may be constructed in
    /// BER: SEQUENCE, SET, EXTERNAL, EMBEDDED PDV, CHARACTER STRING and the strings.
    pub fn may_be_constructed(number: u32) -> bool {
        BERReader::must_be_constructed(number) || BERReader::is_string_type(number)
    }

    /// Whether elements of the universal type `number` must be constructed:
    /// SEQUENCE, SET, EXTERNAL, EMBEDDED PDV and CHARACTER STRING (X.690
    /// sections 8.9.1, 8.11.1 and 8.18 to 8.20).
    pub fn must_be_constructed(number: u32) -> bool {
        matches!(number, 8 | 11 | 16 | 17 | 29)
    }

    /// Converts the single element of `input` to its DER encoding.
    ///
    /// Lengths become minimal and definite, segmented strings are joined, true
    /// becomes `0xFF`, unused bits are cleared, times are written in their DER
    /// form in UTC with every digit of their fraction, reals in their DER form
    /// (see [`ASN1Real`]), and the components of every SET are sorted: by tag
    /// if their tags are distinct, as a SET requires, and by encoding
    /// otherwise, as a SET OF requires. Without the schema three conversions
    /// cannot be done: components equal to their DEFAULT value are kept,
    /// implicitly tagged strings split into segments stay constructed, and a
    /// SET OF whose components have distinct tags (a SET OF CHOICE) is sorted
    /// by tag.
    pub fn to_der(input: &'a [u8], maximum_depth: usize) -> Result<Vec<u8>, ASN1Error> {
        let mut reader = BERReader::new(input).with_maximum_depth(maximum_depth);
        let element = reader.read_element()?;
        reader.finish()?;
        let mut writer = DERWriter::new();
        BERReader::convert(&element, &mut writer)?;
        Ok(writer.into_bytes())
    }

    /// Appends the DER encoding of `element` to `writer` (see
    /// [`BERReader::to_der`]). Universal primitive values are checked against
    /// their type, as DER requires, so the result always passes
    /// [`DERReader::validate`]. Nested elements are converted with an
    /// explicit stack, limited by the maximum depth.
    pub fn convert(element: &BERElement<'a>, writer: &mut DERWriter) -> Result<(), ASN1Error> {
        // Each open constructed element: its tag, the reader over its
        // contents, and the DER encodings of the components converted so far.
        let mut stack: Vec<(Tag, BERReader<'a>, Vec<Vec<u8>>)> = Vec::new();
        let mut next = Some(*element);
        loop {
            let mut finished = None;
            if let Some(element) = next.take() {
                match BERReader::convert_shallow(&element)? {
                    Some(encoding) => finished = Some(encoding),
                    None => {
                        stack.try_reserve(1).map_err(|_| ASN1Error::AllocationFailed)?;
                        stack.push((element.tag, element.children()?, Vec::new()));
                    }
                }
            }
            if finished.is_none()
                && stack.last().is_some_and(|(_, children, _)| children.is_empty())
                && let Some((tag, _, components)) = stack.pop()
            {
                finished = Some(BERReader::assemble(tag, components)?);
            }
            if let Some(encoding) = finished {
                match stack.last_mut() {
                    None => {
                        writer.write_raw(&encoding);
                        return Ok(());
                    }
                    Some((_, _, components)) => {
                        components.try_reserve(1).map_err(|_| ASN1Error::AllocationFailed)?;
                        components.push(encoding);
                        continue;
                    }
                }
            }
            if let Some((_, children, _)) = stack.last_mut() {
                next = Some(children.read_element()?);
            }
        }
    }

    /// The DER encoding of a constructed element with `tag` whose components
    /// are the DER `components`, sorted if it is a SET (see [`BERReader::to_der`]).
    pub fn assemble(tag: Tag, mut components: Vec<Vec<u8>>) -> Result<Vec<u8>, ASN1Error> {
        if tag == Tag::SET {
            let mut tags = Vec::new();
            tags.try_reserve(components.len()).map_err(|_| ASN1Error::AllocationFailed)?;
            for component in &components {
                tags.push(Tag::decode(component, 0)?.0);
            }
            tags.sort_by(|a, b| a.compare_order(b));
            if tags.windows(2).all(|pair| pair[0].compare_order(&pair[1]).is_lt()) {
                components.sort_by_cached_key(|component| {
                    Tag::decode(component, 0).map(|(tag, _)| (tag.class, tag.number)).ok()
                });
            } else {
                components.sort_by(|a, b| DERReader::compare_encodings(a, b));
            }
        }
        let mut writer = DERWriter::new();
        writer.write_element(tag, &components.concat());
        Ok(writer.into_bytes())
    }

    /// The DER encoding of `element` if it is primitive or a segmented string,
    /// or `None` for a constructed element whose components are to be
    /// converted one by one.
    pub fn convert_shallow(element: &BERElement<'a>) -> Result<Option<Vec<u8>>, ASN1Error> {
        let universal = element.tag.class == TagClass::Universal;
        let primitive = element.tag.with_constructed(false);
        if universal && element.tag.constructed && !BERReader::may_be_constructed(element.tag.number) {
            // Booleans, integers, identifiers, reals and times are primitive in BER too.
            return Err(element.invalid());
        }
        if universal && !element.tag.constructed && BERReader::must_be_constructed(element.tag.number) {
            return Err(element.invalid());
        }
        if element.tag.constructed && !(universal && BERReader::is_string_type(element.tag.number)) {
            return Ok(None);
        }
        let mut content = Vec::new();
        match (universal, element.tag.number) {
            (true, 1) => content.push(if element.as_boolean()? { 0xFF } else { 0x00 }),
            (true, 3) => element.as_bit_string()?.with_zero_padding().encode_content(&mut content),
            (true, 9) => {
                content = ASN1Real::to_der(element.content).map_err(|error| match error {
                    ASN1Error::OutOfRange => ASN1Error::OutOfRange,
                    _ => element.invalid(),
                })?
            }
            (true, 23) => element.as_utc_time()?.encode_utc_time(&mut content)?,
            (true, 24) => {
                content =
                    ASN1Time::generalized_time_ber_to_der(&element.string_content(primitive)?).map_err(|error| {
                        match error {
                            ASN1Error::OutOfRange => ASN1Error::OutOfRange,
                            _ => element.invalid(),
                        }
                    })?
            }
            (true, number) if BERReader::is_string_type(number) => {
                content.extend_from_slice(&element.string_content(primitive)?)
            }
            _ => content.extend_from_slice(element.content),
        }
        let mut encoded = DERWriter::new();
        encoded.write_element(primitive, &content);
        if universal {
            // Rules on the contents (minimal integers, valid identifiers and
            // character sets) are the same in BER and DER.
            DERReader::validate(encoded.as_bytes(), 0).map_err(|_| element.invalid())?;
        }
        Ok(Some(encoded.into_bytes()))
    }
}
