use alloc::string::String;
use alloc::vec::Vec;

use super::{PEMConfig, PEMError, PEMLabel, PEMLineEnding, PEMStrictness};
use crate::codec::base::base64::Base64;
use crate::codec::base::{Alphabet, Encoding, Padding};
use crate::secret::Zeroize;

/// One PEM document: a label and the data encoded under it.
///
/// The data is zeroized when the document is dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct PEMDocument {
    label: String,
    data: Vec<u8>,
}

impl core::fmt::Debug for PEMDocument {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("PEMDocument").field("label", &self.label).field("length", &self.data.len()).finish()
    }
}

impl Drop for PEMDocument {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl PEMDocument {
    /// The start of a pre-encapsulation boundary.
    pub const BEGIN: &'static [u8] = b"-----BEGIN ";
    /// The start of a post-encapsulation boundary.
    pub const END: &'static [u8] = b"-----END ";
    /// The end of both boundaries.
    pub const DASHES: &'static [u8] = b"-----";
    /// Characters per line of the strict format.
    pub const LINE_LENGTH: usize = 64;

    /// Creates a document; fails if `label` is not valid (RFC 7468 section 3).
    pub fn new(label: &str, data: Vec<u8>) -> Result<PEMDocument, PEMError> {
        if !PEMLabel::is_valid(label) {
            return Err(PEMError::InvalidLabel { position: 0 });
        }
        Ok(PEMDocument { label: String::from(label), data })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Takes the data out of the document; the caller becomes responsible for zeroizing it.
    pub fn into_data(mut self) -> Vec<u8> {
        core::mem::take(&mut self.data)
    }

    /// Whether `byte` is WSP (space or tab).
    pub fn is_space(byte: u8) -> bool {
        byte == b' ' || byte == b'\t'
    }

    /// Whether `byte` is white space of the lax grammar (WSP, CR, LF, VT, FF).
    pub fn is_lax_space(byte: u8) -> bool {
        matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | 0x0B | 0x0C)
    }

    /// Whether `byte` is a base64 character of the standard alphabet, by
    /// mask arithmetic, so that the class of a character (which depends on
    /// the encoded secret) does not select a branch.
    pub fn is_base64(byte: u8) -> bool {
        let mask = Alphabet::mask_in(byte, b'A', 26)
            | Alphabet::mask_in(byte, b'a', 26)
            | Alphabet::mask_in(byte, b'0', 10)
            | Alphabet::mask_in(byte, b'+', 1)
            | Alphabet::mask_in(byte, b'/', 1);
        mask != 0
    }

    /// The end of the line starting at `start` (before CRLF, CR or LF) and the
    /// start of the next line; `None` as the second value at the end of the text.
    pub fn line(text: &[u8], start: usize) -> (usize, Option<usize>) {
        let mut end = start;
        while end < text.len() && text[end] != b'\r' && text[end] != b'\n' {
            end += 1;
        }
        match text.get(end) {
            None => (end, None),
            Some(b'\r') if text.get(end + 1) == Some(&b'\n') => (end, Some(end + 2)),
            Some(_) => (end, Some(end + 1)),
        }
    }

    /// Reads the label that follows a boundary start at `start` and returns it
    /// with the position after its closing dashes.
    pub fn boundary_label(text: &[u8], start: usize) -> Result<(&str, usize), PEMError> {
        let (line_end, _) = PEMDocument::line(text, start);
        let line = &text[start..line_end];
        let close = line
            .windows(5)
            .position(|window| window == PEMDocument::DASHES)
            .ok_or(PEMError::InvalidLabel { position: start })?;
        let label = core::str::from_utf8(&line[..close]).map_err(|_| PEMError::InvalidLabel { position: start })?;
        if !PEMLabel::is_valid(label) {
            return Err(PEMError::InvalidLabel { position: start });
        }
        Ok((label, start + close + 5))
    }

    /// Finds the next BEGIN line at or after `start`. In the lax grammar it may follow white space.
    pub fn find_begin(text: &[u8], start: usize, strictness: PEMStrictness) -> Option<usize> {
        let mut line_start = (start <= text.len()).then_some(start);
        while let Some(position) = line_start {
            let mut first = position;
            if strictness == PEMStrictness::Lax {
                while first < text.len() && PEMDocument::is_space(text[first]) {
                    first += 1;
                }
            }
            if text[first..].starts_with(PEMDocument::BEGIN) {
                return Some(first);
            }
            line_start = PEMDocument::line(text, position).1;
        }
        None
    }

    /// Parses the next document at or after `start`, and returns it with the
    /// position after it; `None` if there is no BEGIN line.
    pub fn decode_next(text: &[u8], start: usize, config: PEMConfig) -> Result<Option<(PEMDocument, usize)>, PEMError> {
        if text.len() > config.maximum_length {
            return Err(PEMError::TooLong { length: text.len(), maximum: config.maximum_length });
        }
        let Some(begin) = PEMDocument::find_begin(text, start, config.strictness) else {
            return Ok(None);
        };
        let (label, after_label) = PEMDocument::boundary_label(text, begin + PEMDocument::BEGIN.len())?;
        // The END line: at the start of a line, except in the lax grammar.
        let mut end = None;
        let mut search = after_label;
        while let Some(offset) =
            text[search..].windows(PEMDocument::END.len()).position(|window| window == PEMDocument::END)
        {
            let candidate = search + offset;
            let at_line_start = candidate == 0 || matches!(text[candidate - 1], b'\r' | b'\n');
            // The lax grammar allows anything but `-` before it; base64 text has no `-`.
            if at_line_start || config.strictness == PEMStrictness::Lax {
                end = Some(candidate);
                break;
            }
            search = candidate + 1;
        }
        let end = end.ok_or(PEMError::MissingEnd { position: begin })?;
        let mut base64 = Vec::new();
        let result = PEMDocument::collect(text, after_label, end, config.strictness, &mut base64)
            .and_then(|()| PEMDocument::finish(text, label, end, config, &base64));
        base64.zeroize();
        result.map(Some)
    }

    /// Checks the text between the BEGIN label and the END line against the
    /// grammar and appends its base64 characters to `base64`.
    pub fn collect(
        text: &[u8],
        after_label: usize,
        end: usize,
        strictness: PEMStrictness,
        base64: &mut Vec<u8>,
    ) -> Result<(), PEMError> {
        if after_label > end || end > text.len() {
            return Err(PEMError::InvalidLine { position: after_label });
        }
        base64.try_reserve(end - after_label).map_err(|_| PEMError::AllocationFailed)?;
        if strictness == PEMStrictness::Lax {
            let mut padding = false;
            for (offset, &byte) in text[after_label..end].iter().enumerate() {
                let position = after_label + offset;
                if PEMDocument::is_lax_space(byte) {
                    continue;
                }
                if byte == b'=' {
                    padding = true;
                } else if padding || !PEMDocument::is_base64(byte) {
                    return Err(PEMError::InvalidLine { position });
                }
                base64.push(byte);
            }
            return Ok(());
        }
        // The rest of the BEGIN line: an end of line, after spaces in the standard grammar.
        let (line_end, next) = PEMDocument::line(text, after_label);
        let rest = &text[after_label..line_end];
        if (strictness == PEMStrictness::Strict && !rest.is_empty())
            || !rest.iter().all(|&byte| PEMDocument::is_space(byte))
        {
            return Err(PEMError::InvalidLine { position: after_label });
        }
        let mut line_start = next.ok_or(PEMError::MissingEnd { position: after_label })?;
        // Standard: blank lines may precede the data; a padded line ends it,
        // except that the second padding character may be on the next line.
        let mut leading = true;
        let mut finished = false;
        let mut split_padding = false;
        let mut previous_length = PEMDocument::LINE_LENGTH;
        while line_start < end {
            let (line_end, next) = PEMDocument::line(text, line_start);
            let line = &text[line_start..line_end];
            let invalid = PEMError::InvalidLine { position: line_start };
            if next.is_none() || line_end > end {
                return Err(invalid);
            }
            match strictness {
                PEMStrictness::Strict => {
                    // Only the last line may be shorter than 64 characters, and
                    // every line holds whole groups of four.
                    if previous_length != PEMDocument::LINE_LENGTH
                        || line.is_empty()
                        || line.len() > PEMDocument::LINE_LENGTH
                        || !line.len().is_multiple_of(4)
                    {
                        return Err(invalid);
                    }
                    let data = line.iter().take_while(|&&byte| PEMDocument::is_base64(byte)).count();
                    let padding = &line[data..];
                    if padding.len() > 2 || padding.iter().any(|&byte| byte != b'=') {
                        return Err(invalid);
                    }
                    if !padding.is_empty() {
                        previous_length = 0;
                    } else {
                        previous_length = line.len();
                    }
                    base64.extend_from_slice(line);
                }
                _ => {
                    let trimmed =
                        line.len() - line.iter().rev().take_while(|&&byte| PEMDocument::is_space(byte)).count();
                    let content = &line[..trimmed];
                    if leading && content.is_empty() {
                        line_start = next.unwrap_or(end);
                        continue;
                    }
                    leading = false;
                    if finished {
                        // The final line (an empty one, or one with padding)
                        // is followed by the END line, except for the second
                        // padding character (RFC 7468 figure 1, base64finl).
                        if split_padding && content == b"=" {
                            base64.push(b'=');
                            split_padding = false;
                            line_start = next.unwrap_or(end);
                            continue;
                        }
                        return Err(invalid);
                    }
                    let data = content.iter().take_while(|&&byte| PEMDocument::is_base64(byte)).count();
                    let padding = &content[data..];
                    if padding.len() > 2 || padding.iter().any(|&byte| byte != b'=') {
                        return Err(invalid);
                    }
                    if content.is_empty() || !padding.is_empty() {
                        finished = true;
                        split_padding = padding.len() == 1;
                    }
                    base64.extend_from_slice(content);
                }
            }
            line_start = next.unwrap_or(end);
        }
        Ok(())
    }

    /// Checks the END line and decodes the collected base64 text.
    pub fn finish(
        text: &[u8],
        label: &str,
        end: usize,
        config: PEMConfig,
        base64: &[u8],
    ) -> Result<(PEMDocument, usize), PEMError> {
        let (end_label, after) = PEMDocument::boundary_label(text, end + PEMDocument::END.len())?;
        if config.require_matching_label && end_label != label {
            return Err(PEMError::LabelMismatch { position: end });
        }
        let (line_end, next) = PEMDocument::line(text, after);
        let rest = &text[after..line_end];
        let allowed = match config.strictness {
            PEMStrictness::Strict => rest.is_empty() && next.is_some(),
            PEMStrictness::Standard => rest.iter().all(|&byte| PEMDocument::is_space(byte)),
            PEMStrictness::Lax => rest.iter().all(|&byte| PEMDocument::is_lax_space(byte)),
        };
        if !allowed {
            return Err(PEMError::InvalidLine { position: after });
        }
        let padding = if config.strictness == PEMStrictness::Strict { Padding::Required } else { Padding::Indifferent };
        let encoding = Base64::new(Base64::STANDARD_ALPHABET, padding);
        let length = encoding.maximum_decoded_length(base64.len());
        let mut data = Vec::new();
        data.try_reserve_exact(length).map_err(|_| PEMError::AllocationFailed)?;
        data.resize(length, 0);
        match encoding.decode_to_slice(base64, &mut data) {
            Ok(written) => data.truncate(written),
            Err(error) => {
                // Bytes decoded before the error may be secret.
                data.zeroize();
                return Err(error.into());
            }
        }
        Ok((PEMDocument { label: String::from(label), data }, next.unwrap_or(text.len())))
    }

    /// Parses the first document in `text`; text before and after it is ignored.
    pub fn decode(text: &[u8], config: PEMConfig) -> Result<PEMDocument, PEMError> {
        PEMDocument::decode_next(text, 0, config)?.map(|(document, _)| document).ok_or(PEMError::NotFound)
    }

    /// Parses every document in `text`, in order; text between them is ignored.
    pub fn decode_all(text: &[u8], config: PEMConfig) -> Result<Vec<PEMDocument>, PEMError> {
        let mut documents = Vec::new();
        let mut position = 0;
        while let Some((document, next)) = PEMDocument::decode_next(text, position, config)? {
            documents.try_reserve(1).map_err(|_| PEMError::AllocationFailed)?;
            documents.push(document);
            position = next;
        }
        Ok(documents)
    }

    /// The document in the strict format (RFC 7468 figure 3) with LF line endings.
    pub fn encode(&self) -> String {
        self.encode_with(PEMLineEnding::LF)
    }

    /// The document in the strict format with `line_ending`.
    pub fn encode_with(&self, line_ending: PEMLineEnding) -> String {
        let eol = line_ending.as_str();
        let mut base64 = Base64::STANDARD.encode(&self.data);
        // The exact length, so that the text is never reallocated, which
        // would leave copies of the encoded data in freed memory.
        let lines = base64.len().div_ceil(PEMDocument::LINE_LENGTH);
        let boundaries = "-----BEGIN ".len() + "-----END ".len() + 2 * (self.label.len() + "-----".len() + eol.len());
        let mut text = String::with_capacity(boundaries + base64.len() + lines * eol.len());
        text.push_str("-----BEGIN ");
        text.push_str(&self.label);
        text.push_str("-----");
        text.push_str(eol);
        for chunk in base64.as_bytes().chunks(PEMDocument::LINE_LENGTH) {
            // Base64 text is ASCII, so every chunk is valid UTF-8.
            text.push_str(core::str::from_utf8(chunk).unwrap_or_default());
            text.push_str(eol);
        }
        text.push_str("-----END ");
        text.push_str(&self.label);
        text.push_str("-----");
        text.push_str(eol);
        base64.zeroize();
        text
    }
}
