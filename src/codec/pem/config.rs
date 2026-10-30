/// The grammar used to parse the base64 text of a document (RFC 7468 section 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PEMStrictness {
    /// Figure 3: lines of exactly 64 characters, the last one shorter, no white space.
    Strict,
    /// Figure 1: lines of any length, white space at the end of lines, blank
    /// lines before the data, and the final padding character on its own line.
    Standard,
    /// Figure 2: white space anywhere in the base64 text.
    Lax,
}

/// The line ending written by [`PEMDocument::encode_with`](super::PEMDocument::encode_with).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PEMLineEnding {
    LF,
    CRLF,
}

impl PEMLineEnding {
    pub const fn as_str(&self) -> &'static str {
        match self {
            PEMLineEnding::LF => "\n",
            PEMLineEnding::CRLF => "\r\n",
        }
    }
}

/// Options of PEM parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PEMConfig {
    pub strictness: PEMStrictness,
    /// Whether the label of the END line must equal that of the BEGIN line
    /// (RFC 7468 section 2 lets parsers disregard it).
    pub require_matching_label: bool,
    /// The longest text accepted, in bytes.
    pub maximum_length: usize,
}

impl Default for PEMConfig {
    fn default() -> PEMConfig {
        PEMConfig {
            strictness: PEMStrictness::Standard,
            require_matching_label: true,
            maximum_length: 16 * 1024 * 1024,
        }
    }
}
