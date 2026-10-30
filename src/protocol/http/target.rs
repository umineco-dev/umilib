use alloc::vec::Vec;

use super::HTTPError;

/// The authority of a URI as HTTP uses it (RFC 9110 §4.2, RFC 3986
/// §3.2.2): a host, lowercased, and a port if given; never userinfo,
/// which HTTP deprecates (RFC 9110 §4.2.4).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HTTPAuthority {
    /// A registered name, an IPv4 address, or an IP literal with its brackets.
    pub host: Vec<u8>,
    pub port: Option<u16>,
}

impl HTTPAuthority {
    /// The authority of `bytes`; fails for userinfo, an empty host (RFC 9110
    /// §4.2.1), characters a host does not have, or a port that is not one.
    pub fn parse(bytes: &[u8]) -> Result<HTTPAuthority, HTTPError> {
        let invalid = HTTPError::Malformed("an invalid authority");
        if bytes.contains(&b'@') {
            return Err(HTTPError::Malformed("an authority with userinfo"));
        }
        let (host, port) = if bytes.first() == Some(&b'[') {
            let end = bytes.iter().position(|byte| *byte == b']').ok_or(invalid)?;
            let literal = &bytes[1..end];
            if literal.is_empty()
                || !literal.iter().all(|byte| byte.is_ascii_hexdigit() || *byte == b':' || *byte == b'.')
            {
                return Err(invalid);
            }
            let rest = &bytes[end + 1..];
            let port = match rest {
                [] => None,
                [b':', port @ ..] => Some(port),
                _ => return Err(invalid),
            };
            (&bytes[..=end], port)
        } else {
            match bytes.iter().rposition(|byte| *byte == b':') {
                Some(colon) => (&bytes[..colon], Some(&bytes[colon + 1..])),
                None => (bytes, None),
            }
        };
        if host.is_empty() {
            return Err(HTTPError::Malformed("an authority without a host"));
        }
        if host[0] != b'[' && !host.iter().all(|byte| HTTPAuthority::is_host_byte(*byte)) {
            return Err(invalid);
        }
        let port = match port {
            None => None,
            Some(digits) => Some(HTTPAuthority::port(digits).ok_or(invalid)?),
        };
        Ok(HTTPAuthority { host: host.to_ascii_lowercase(), port })
    }

    /// The port of `digits`: 1 to 5 digits, at most 65535.
    pub fn port(digits: &[u8]) -> Option<u16> {
        if digits.is_empty() || digits.len() > 5 || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        u16::try_from(digits.iter().fold(0u32, |value, digit| value * 10 + u32::from(digit - b'0'))).ok()
    }

    /// Whether `byte` may be in a registered name or IPv4 address: an
    /// unreserved character, a sub-delimiter, or "%" of an escape (RFC 3986 §3.2.2).
    pub const fn is_host_byte(byte: u8) -> bool {
        HTTPTarget::is_unreserved(byte) || HTTPTarget::is_sub_delimiter(byte) || byte == b'%'
    }

    /// Appends the text of the authority.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.host);
        if let Some(port) = self.port {
            out.push(b':');
            out.extend_from_slice(alloc::format!("{port}").as_bytes());
        }
    }
}

/// A request target (RFC 9112 §3.2): origin-form, absolute-form,
/// authority-form (CONNECT) or asterisk-form (server-wide OPTIONS).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HTTPTarget {
    /// An absolute path and query.
    Origin(Vec<u8>),
    /// A scheme (lowercased), an authority, and the path and query, "/" if empty.
    Absolute {
        scheme: Vec<u8>,
        authority: Vec<u8>,
        path: Vec<u8>,
    },
    Authority(Vec<u8>),
    Asterisk,
}

impl HTTPTarget {
    /// The target of `bytes`, of the form its first bytes tell.
    pub fn parse(bytes: &[u8]) -> Result<HTTPTarget, HTTPError> {
        if bytes == b"*" {
            return Ok(HTTPTarget::Asterisk);
        }
        if bytes.first() == Some(&b'/') {
            HTTPTarget::check_path(bytes)?;
            return Ok(HTTPTarget::Origin(bytes.to_vec()));
        }
        if let Some(separator) = bytes.windows(3).position(|window| window == b"://") {
            let scheme = &bytes[..separator];
            HTTPTarget::check_scheme(scheme)?;
            let rest = &bytes[separator + 3..];
            let end = rest.iter().position(|byte| matches!(byte, b'/' | b'?' | b'#')).unwrap_or(rest.len());
            let authority = &rest[..end];
            HTTPAuthority::parse(authority)?;
            let path = match &rest[end..] {
                [] => b"/".to_vec(),
                [b'?', ..] => [b"/", &rest[end..]].concat(),
                path => path.to_vec(),
            };
            HTTPTarget::check_path(&path)?;
            return Ok(HTTPTarget::Absolute {
                scheme: scheme.to_ascii_lowercase(),
                authority: authority.to_vec(),
                path,
            });
        }
        HTTPAuthority::parse(bytes)?;
        Ok(HTTPTarget::Authority(bytes.to_vec()))
    }

    /// Whether `byte` is unreserved (RFC 3986 §2.3).
    pub const fn is_unreserved(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
    }

    /// Whether `byte` is a sub-delimiter (RFC 3986 §2.2).
    pub const fn is_sub_delimiter(byte: u8) -> bool {
        matches!(byte, b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=')
    }

    /// Checks an absolute path and query (RFC 9112 §3.2.1, RFC 3986 §3.3,
    /// §3.4): from "/", of pchar, "/" and "?", escapes of two hexadecimal
    /// digits; no fragment.
    pub fn check_path(path: &[u8]) -> Result<(), HTTPError> {
        let invalid = HTTPError::Malformed("an invalid path");
        if path.first() != Some(&b'/') {
            return Err(invalid);
        }
        let mut index = 0;
        while index < path.len() {
            let byte = path[index];
            match byte {
                b'%' => {
                    let escape = path.get(index + 1..index + 3).ok_or(invalid)?;
                    if !escape.iter().all(u8::is_ascii_hexdigit) {
                        return Err(invalid);
                    }
                    index += 2;
                }
                b'/' | b'?' | b':' | b'@' => {}
                _ if HTTPTarget::is_unreserved(byte) || HTTPTarget::is_sub_delimiter(byte) => {}
                _ => return Err(invalid),
            }
            index += 1;
        }
        Ok(())
    }

    /// Checks a scheme: a letter, then letters, digits, "+", "-", "." (RFC 3986 §3.1).
    pub fn check_scheme(scheme: &[u8]) -> Result<(), HTTPError> {
        let valid = scheme.first().is_some_and(u8::is_ascii_alphabetic)
            && scheme.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'));
        if valid { Ok(()) } else { Err(HTTPError::Malformed("an invalid scheme")) }
    }
}
