use alloc::vec::Vec;

use crate::protocol::http::{HTTPError, HTTPFields, HTTPMethod, HTTPStatus, HTTPSyntax, HTTPVersion};

/// The start line of a message (RFC 9112 §3, §4).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum H1StartLine {
    Request { method: HTTPMethod, target: Vec<u8>, version: HTTPVersion },
    Response { version: HTTPVersion, status: HTTPStatus },
}

/// The head of a message: its start line and header fields.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct H1Head {
    pub start: H1StartLine,
    pub fields: HTTPFields,
}

/// The reading of HTTP/1.1's lines: message heads (RFC 9112 §2.2, §3, §4,
/// §5) and the lines of chunks (§7.1). Lines end with CRLF, or a bare LF
/// (§2.2 allows it); a bare CR elsewhere is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct H1Parser;

impl H1Parser {
    /// The end of the first line of `bytes`: the index of its LF, and of the line's end before CR LF or LF.
    pub fn line(bytes: &[u8]) -> Option<(usize, usize)> {
        let newline = bytes.iter().position(|byte| *byte == b'\n')?;
        let end = if newline > 0 && bytes[newline - 1] == b'\r' { newline - 1 } else { newline };
        Some((newline, end))
    }

    /// The length of the head at the start of `bytes`, to the empty line
    /// that ends it, its lines included. `from` is the start of a line
    /// after which to look, the lines before it known not to be empty;
    /// while the head is not whole, `Err` gives where to look from next,
    /// so that a head arriving in pieces is scanned once.
    pub fn head_length(bytes: &[u8], from: usize) -> Result<usize, usize> {
        let mut start = from;
        loop {
            let Some((newline, end)) = H1Parser::line(&bytes[start..]) else { return Err(start) };
            if end == 0 {
                return Ok(start + newline + 1);
            }
            start += newline + 1;
        }
    }

    /// The head of `bytes`, a whole head ([`H1Parser::head_length`]). A
    /// server's (`request`) obs-fold is invalid; a client replaces a
    /// response's with a space (RFC 9112 §5.2).
    pub fn parse_head(bytes: &[u8], request: bool) -> Result<H1Head, HTTPError> {
        let (newline, end) = H1Parser::line(bytes).ok_or(HTTPError::Malformed("a head without lines"))?;
        let start =
            if request { H1Parser::request_line(&bytes[..end])? } else { H1Parser::status_line(&bytes[..end])? };
        let rest = &bytes[newline + 1..];
        // §2.2: no whitespace between the start line and the first field.
        if rest.first().is_some_and(|byte| HTTPSyntax::is_whitespace(*byte)) {
            return Err(HTTPError::Malformed("whitespace after the start line"));
        }
        let fields = H1Parser::parse_fields(rest, !request)?;
        Ok(H1Head { start, fields })
    }

    /// The field lines of `bytes` to the empty line that ends them: a header
    /// or trailer section (RFC 9112 §5, §7.1.2). Obs-fold is replaced with a
    /// space if `folding`, invalid otherwise (§5.2).
    pub fn parse_fields(mut rest: &[u8], folding: bool) -> Result<HTTPFields, HTTPError> {
        let mut fields = HTTPFields::new();
        loop {
            let (newline, end) = H1Parser::line(rest).ok_or(HTTPError::Malformed("a field section cut short"))?;
            let line = &rest[..end];
            rest = &rest[newline + 1..];
            if line.is_empty() {
                return Ok(fields);
            }
            if line.contains(&b'\r') {
                return Err(HTTPError::Malformed("a bare CR"));
            }
            if HTTPSyntax::is_whitespace(line[0]) {
                // obs-fold: a continuation of the previous line.
                let previous = fields.fields.last_mut().filter(|_| folding);
                let previous = previous.ok_or(HTTPError::Malformed("an obsolete line folding"))?;
                let continued = HTTPSyntax::trim(line);
                if !HTTPSyntax::is_field_value(continued) {
                    return Err(HTTPError::Malformed("an invalid field value"));
                }
                previous.value.push(b' ');
                previous.value.extend_from_slice(continued);
                continue;
            }
            let colon = line
                .iter()
                .position(|byte| *byte == b':')
                .ok_or(HTTPError::Malformed("a field line without a colon"))?;
            let name = &line[..colon];
            // §5.1: no whitespace between the name and the colon.
            if name.last().is_some_and(|byte| HTTPSyntax::is_whitespace(*byte)) {
                return Err(HTTPError::Malformed("whitespace before a colon"));
            }
            fields.append(name, HTTPSyntax::trim(&line[colon + 1..]))?;
        }
    }

    /// method SP request-target SP HTTP-version, each separated by one space (RFC 9112 §3).
    pub fn request_line(line: &[u8]) -> Result<H1StartLine, HTTPError> {
        let invalid = HTTPError::Malformed("an invalid request line");
        let mut parts = line.split(|byte| *byte == b' ');
        let (Some(method), Some(target), Some(version), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid);
        };
        let method = HTTPMethod::parse(method)?;
        if target.is_empty() || target.iter().any(|byte| *byte <= 0x20 || *byte == 0x7F) {
            return Err(invalid);
        }
        let version = HTTPVersion::parse(version).ok_or(invalid)?;
        Ok(H1StartLine::Request { method, target: target.to_vec(), version })
    }

    /// HTTP-version SP status-code SP [ reason-phrase ] (RFC 9112 §4); the reason is ignored.
    pub fn status_line(line: &[u8]) -> Result<H1StartLine, HTTPError> {
        let invalid = HTTPError::Malformed("an invalid status line");
        let version = HTTPVersion::parse(line.get(..8).ok_or(invalid)?).ok_or(invalid)?;
        if line.get(8) != Some(&b' ') {
            return Err(invalid);
        }
        let status = HTTPStatus::parse(line.get(9..12).ok_or(invalid)?).ok_or(invalid)?;
        match line.get(12) {
            None | Some(b' ') => {}
            Some(_) => return Err(invalid),
        }
        let reason = line.get(13..).unwrap_or_default();
        if reason.iter().any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7F) {
            return Err(invalid);
        }
        Ok(H1StartLine::Response { version, status })
    }

    /// The size of a chunk line (RFC 9112 §7.1): hexadecimal digits, then
    /// extensions, which are checked and ignored (§7.1.1). Fails for a size
    /// past 2^60 rather than overflowing (§7.1).
    pub fn chunk_size(line: &[u8]) -> Result<u64, HTTPError> {
        let invalid = HTTPError::Malformed("an invalid chunk size");
        let digits = line.iter().take_while(|byte| byte.is_ascii_hexdigit()).count();
        if digits == 0 {
            return Err(invalid);
        }
        let significant = line[..digits].iter().skip_while(|byte| **byte == b'0').count();
        if significant > 15 {
            return Err(HTTPError::TooLarge("a chunk size past 2^60"));
        }
        let size = line[..digits]
            .iter()
            .fold(0u64, |size, digit| size << 4 | (*digit as char).to_digit(16).unwrap_or(0) as u64);
        H1Parser::chunk_extensions(&line[digits..])?;
        Ok(size)
    }

    /// Checks chunk extensions: *( BWS ";" BWS name [ BWS "=" BWS value ] ),
    /// names tokens, values tokens or quoted strings (RFC 9112 §7.1.1).
    pub fn chunk_extensions(mut rest: &[u8]) -> Result<(), HTTPError> {
        let invalid = HTTPError::Malformed("an invalid chunk extension");
        let skip = |rest: &[u8]| -> usize { rest.iter().take_while(|byte| HTTPSyntax::is_whitespace(**byte)).count() };
        loop {
            rest = &rest[skip(rest)..];
            if rest.is_empty() {
                return Ok(());
            }
            if rest[0] != b';' {
                return Err(invalid);
            }
            rest = &rest[1..];
            rest = &rest[skip(rest)..];
            let name = rest.iter().take_while(|byte| HTTPSyntax::is_tchar(**byte)).count();
            if name == 0 {
                return Err(invalid);
            }
            rest = &rest[name..];
            let before = skip(rest);
            if rest.get(before) != Some(&b'=') {
                continue;
            }
            rest = &rest[before + 1..];
            rest = &rest[skip(rest)..];
            if rest.first() == Some(&b'"') {
                let mut index = 1;
                loop {
                    match rest.get(index) {
                        Some(b'"') => break,
                        Some(b'\\')
                            if rest
                                .get(index + 1)
                                .is_some_and(|byte| *byte >= 0x20 && *byte != 0x7F || *byte == b'\t') =>
                        {
                            index += 2
                        }
                        Some(byte) if *byte >= 0x20 && *byte != 0x7F || *byte == b'\t' => index += 1,
                        _ => return Err(invalid),
                    }
                }
                rest = &rest[index + 1..];
            } else {
                let value = rest.iter().take_while(|byte| HTTPSyntax::is_tchar(**byte)).count();
                if value == 0 {
                    return Err(invalid);
                }
                rest = &rest[value..];
            }
        }
    }
}
