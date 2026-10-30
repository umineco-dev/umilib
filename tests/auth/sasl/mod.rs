//! Tests of `umilib::auth::sasl` against RFC 4422, RFC 4505, RFC 4616,
//! RFC 5801, RFC 5802, RFC 7628 and RFC 7677.

mod anonymous;
mod external;
mod gs2;
mod oauthbearer;
mod plain;
mod scram;

use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;

use crate::RFC;

/// The generator of the tests (the same bytes on every call).
pub fn random() -> HMACDRBG<SHA256> {
    HMACDRBG::<SHA256>::new(&[3; 32], &[5; 16], b"umilib sasl tests").unwrap()
}

/// The messages of an example exchange of an RFC: the lines beginning
/// with `C:` or `S:` after the line containing `marker` (not a line of the
/// table of contents, which has dot leaders), each with its wrapped lines
/// (indented further) joined. Blank lines and annotations in brackets are
/// skipped; the exchange ends at the first other line. A message is the
/// side (`'C'` or `'S'`) and its text.
pub fn exchange(text: &str, marker: &str) -> Vec<(char, String)> {
    let mut messages: Vec<(char, String)> = Vec::new();
    let mut indentation = 0;
    let lines = text.lines().skip_while(|line| !line.contains(marker) || line.contains(". .")).skip(1);
    for line in lines.filter(|line| !RFC::is_page_break(line)) {
        let trimmed = line.trim();
        let indent = line.len() - line.trim_start().len();
        if let Some(side) = ["C:", "S:"].iter().find(|side| trimmed.starts_with(**side)) {
            messages.push((side.chars().next().unwrap(), trimmed[2..].trim().to_string()));
            indentation = indent;
        } else if trimmed.is_empty() || trimmed.starts_with('[') {
            continue;
        } else if let Some(last) = messages.last_mut() {
            if indent <= indentation {
                break;
            }
            last.1.push_str(trimmed);
        }
    }
    assert!(!messages.is_empty(), "no exchange after {marker}");
    messages
}
