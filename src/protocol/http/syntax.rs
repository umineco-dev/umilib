use alloc::vec::Vec;

/// The rules of syntax HTTP's messages share (RFC 9110 §5.5, §5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HTTPSyntax;

impl HTTPSyntax {
    /// Whether `byte` is a tchar (RFC 9110 §5.6.2).
    pub const fn is_tchar(byte: u8) -> bool {
        matches!(byte,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
    }

    /// Whether `bytes` is a token: one tchar or more.
    pub fn is_token(bytes: &[u8]) -> bool {
        !bytes.is_empty() && bytes.iter().all(|byte| HTTPSyntax::is_tchar(*byte))
    }

    /// Whether `byte` is optional whitespace: SP or HTAB (RFC 9110 §5.6.3).
    pub const fn is_whitespace(byte: u8) -> bool {
        byte == b' ' || byte == b'\t'
    }

    /// `bytes` without leading and trailing whitespace.
    pub fn trim(bytes: &[u8]) -> &[u8] {
        let start = bytes.iter().position(|byte| !HTTPSyntax::is_whitespace(*byte)).unwrap_or(bytes.len());
        let end = bytes.iter().rposition(|byte| !HTTPSyntax::is_whitespace(*byte)).map_or(start, |end| end + 1);
        &bytes[start..end]
    }

    /// Whether `bytes` is a field value (RFC 9110 §5.5): visible bytes,
    /// those of 0x80 and above (obs-text), and SP and HTAB between them;
    /// no other control, so neither CR, LF nor NUL.
    pub fn is_field_value(bytes: &[u8]) -> bool {
        let visible = |byte: u8| byte > 0x20 && byte != 0x7F;
        bytes.iter().all(|byte| visible(*byte) || HTTPSyntax::is_whitespace(*byte))
            && bytes.first().is_none_or(|byte| visible(*byte))
            && bytes.last().is_none_or(|byte| visible(*byte))
    }

    /// The elements of a comma-separated list (RFC 9110 §5.6.1), trimmed,
    /// empty ones left out. Commas inside quoted strings do not separate.
    pub fn list(value: &[u8]) -> Vec<&[u8]> {
        let mut elements = Vec::new();
        let mut start = 0;
        let mut quoted = false;
        let mut escaped = false;
        for (index, byte) in value.iter().enumerate() {
            match *byte {
                _ if escaped => escaped = false,
                b'\\' if quoted => escaped = true,
                b'"' => quoted = !quoted,
                b',' if !quoted => {
                    elements.push(HTTPSyntax::trim(&value[start..index]));
                    start = index + 1;
                }
                _ => {}
            }
        }
        elements.push(HTTPSyntax::trim(&value[start..]));
        elements.retain(|element| !element.is_empty());
        elements
    }

    /// Whether the list `value` has `token`, compared without case, as
    /// Connection, TE and Transfer-Encoding are (RFC 9110 §7.6.1).
    pub fn list_contains(value: &[u8], token: &[u8]) -> bool {
        HTTPSyntax::list(value).iter().any(|element| {
            let name = element.split(|byte| *byte == b';').next().map(HTTPSyntax::trim).unwrap_or(element);
            name.eq_ignore_ascii_case(token)
        })
    }
}
