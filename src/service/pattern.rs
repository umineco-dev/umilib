use alloc::vec::Vec;

use super::Rule;

/// How a [`Pattern`] matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PatternKind {
    /// Every input.
    Any,
    /// The bytes of the pattern.
    Exact,
    /// The inputs that start with the bytes of the pattern.
    Prefix,
    /// The inputs that end with the bytes of the pattern.
    Suffix,
}

/// Why the text of a pattern is not one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternError {
    /// A `*` that is neither the first nor the last byte, or a `*` at both
    /// ends (reserved for patterns this version does not know).
    MisplacedWildcard,
    /// A `\` at the end, escaping nothing.
    UnfinishedEscape,
}

impl core::fmt::Display for PatternError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            PatternError::MisplacedWildcard => "a `*` is only allowed as the first or the last byte",
            PatternError::UnfinishedEscape => "a `\\` at the end escapes nothing",
        })
    }
}

impl core::error::Error for PatternError {}

/// A pattern of bytes: any input, exactly some bytes, the inputs starting
/// with them, or those ending with them; optionally ignoring ASCII case.
/// As a [`Rule`], it matches the bytes of a request (`AsRef<[u8]>`).
///
/// Its text ([`Pattern::parse`], [`Pattern::format`]) is `*` for any
/// input, `bytes*` for a prefix, `*bytes` for a suffix and `bytes` for the
/// exact bytes; `\*` and `\\` stand for a `*` and a `\` of the bytes.
/// Whether case is ignored is not part of the text. A prefix or suffix of
/// nothing is [`PatternKind::Any`], so that a pattern and its text convert
/// both ways.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Pattern {
    kind: PatternKind,
    bytes: Vec<u8>,
    ignore_ascii_case: bool,
}

impl Pattern {
    pub const WILDCARD: u8 = b'*';
    pub const ESCAPE: u8 = b'\\';

    /// The pattern of `kind` and `bytes` (a prefix or suffix of nothing is any input).
    pub fn new(kind: PatternKind, bytes: &[u8]) -> Pattern {
        let kind = match kind {
            PatternKind::Prefix | PatternKind::Suffix if bytes.is_empty() => PatternKind::Any,
            kind => kind,
        };
        let bytes = if kind == PatternKind::Any { Vec::new() } else { bytes.to_vec() };
        Pattern { kind, bytes, ignore_ascii_case: false }
    }

    pub fn any() -> Pattern {
        Pattern::new(PatternKind::Any, &[])
    }

    pub fn exact(bytes: &[u8]) -> Pattern {
        Pattern::new(PatternKind::Exact, bytes)
    }

    pub fn prefix(bytes: &[u8]) -> Pattern {
        Pattern::new(PatternKind::Prefix, bytes)
    }

    pub fn suffix(bytes: &[u8]) -> Pattern {
        Pattern::new(PatternKind::Suffix, bytes)
    }

    /// The same pattern, ignoring the case of ASCII letters (as host names do) if `ignore` is true.
    pub fn ignoring_ascii_case(mut self, ignore: bool) -> Pattern {
        self.ignore_ascii_case = ignore;
        self
    }

    pub fn kind(&self) -> PatternKind {
        self.kind
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn ignores_ascii_case(&self) -> bool {
        self.ignore_ascii_case
    }

    /// Whether `input` matches.
    pub fn matches_bytes(&self, input: &[u8]) -> bool {
        let equal = |part: &[u8]| {
            if self.ignore_ascii_case { part.eq_ignore_ascii_case(&self.bytes) } else { part == self.bytes.as_slice() }
        };
        let length = self.bytes.len();
        match self.kind {
            PatternKind::Any => true,
            PatternKind::Exact => equal(input),
            PatternKind::Prefix => input.len() >= length && equal(&input[..length]),
            PatternKind::Suffix => input.len() >= length && equal(&input[input.len() - length..]),
        }
    }

    /// The pattern of `text` (case not ignored).
    pub fn parse(text: &[u8]) -> Result<Pattern, PatternError> {
        if text == [Pattern::WILDCARD] {
            return Ok(Pattern::any());
        }
        let mut bytes = Vec::with_capacity(text.len());
        let (mut leading, mut trailing) = (false, false);
        let mut index = 0;
        while index < text.len() {
            match text[index] {
                Pattern::ESCAPE => {
                    let escaped = *text.get(index + 1).ok_or(PatternError::UnfinishedEscape)?;
                    bytes.push(escaped);
                    index += 2;
                }
                Pattern::WILDCARD => {
                    if index == 0 {
                        leading = true;
                    } else if index == text.len() - 1 {
                        trailing = true;
                    } else {
                        return Err(PatternError::MisplacedWildcard);
                    }
                    index += 1;
                }
                byte => {
                    bytes.push(byte);
                    index += 1;
                }
            }
        }
        match (leading, trailing) {
            (true, true) => Err(PatternError::MisplacedWildcard),
            (true, false) => Ok(Pattern::suffix(&bytes)),
            (false, true) => Ok(Pattern::prefix(&bytes)),
            (false, false) => Ok(Pattern::exact(&bytes)),
        }
    }

    /// The text of the pattern (see [`Pattern::parse`]).
    pub fn format(&self) -> Vec<u8> {
        let mut text = Vec::with_capacity(self.bytes.len() + 2);
        if self.kind == PatternKind::Any {
            text.push(Pattern::WILDCARD);
            return text;
        }
        if self.kind == PatternKind::Suffix {
            text.push(Pattern::WILDCARD);
        }
        for &byte in &self.bytes {
            if byte == Pattern::WILDCARD || byte == Pattern::ESCAPE {
                text.push(Pattern::ESCAPE);
            }
            text.push(byte);
        }
        if self.kind == PatternKind::Prefix {
            text.push(Pattern::WILDCARD);
        }
        text
    }
}

impl<Request: AsRef<[u8]>> Rule<Request> for Pattern {
    fn matches(&self, request: &Request) -> bool {
        self.matches_bytes(request.as_ref())
    }
}
