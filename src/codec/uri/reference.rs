use alloc::string::{String, ToString};
use core::fmt;

use super::{URIError, URIPercent};

/// A URI reference (RFC 3986 §4.1): a URI, or a relative reference to be
/// resolved against a base URI.
///
/// Each component is held as written, percent-encodings included, without
/// its delimiter. A component that is absent (`None`) differs from one that
/// is present and empty (`Some("")`): `http://a/b?` has an empty query and
/// `http://a/b` none (§5.3). The path is always present and may be empty.
/// [`URIReference::parse`] checks every component against the grammar of
/// RFC 3986 Appendix A; [`URIReference::check`] does the same for a value
/// built field by field, and `Display` writes the components back (§5.3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct URIReference {
    pub scheme: Option<String>,
    pub authority: Option<URIAuthority>,
    pub path: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
}

/// The authority of a URI (RFC 3986 §3.2): `[userinfo "@"] host [":" port]`.
///
/// `host` is as written, an IP literal with its brackets; `port` is the
/// digits after `:`, `Some("")` for a `:` with no digits.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct URIAuthority {
    pub userinfo: Option<String>,
    pub host: String,
    pub port: Option<String>,
}

/// The form of a host (RFC 3986 §3.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum URIHostKind {
    /// An IPv6 address in brackets.
    IPv6,
    /// A future IP literal in brackets, `v` and a version.
    IPvFuture,
    /// An IPv4 address in dotted-decimal form.
    IPv4,
    /// A registered name, which may be empty.
    RegName,
}

impl URIReference {
    /// The reference `text`, checked against the grammar of RFC 3986 Appendix A and split into
    /// its components as Appendix B does.
    pub fn parse(text: &str) -> Result<URIReference, URIError> {
        let bytes = text.as_bytes();
        let delimiter = bytes.iter().position(|byte| matches!(byte, b':' | b'/' | b'?' | b'#'));
        let (scheme, mut position) = match delimiter {
            Some(index) if bytes[index] == b':' => {
                URIReference::check_scheme(&text[..index])?;
                (Some(text[..index].to_string()), index + 1)
            }
            _ => (None, 0),
        };
        let rest = &text[position..];
        let (before_fragment, fragment) = match rest.find('#') {
            Some(index) => (&rest[..index], Some(&rest[index + 1..])),
            None => (rest, None),
        };
        let (before_query, query) = match before_fragment.find('?') {
            Some(index) => (&before_fragment[..index], Some(&before_fragment[index + 1..])),
            None => (before_fragment, None),
        };
        let (authority, path) = match before_query.strip_prefix("//") {
            Some(after) => {
                let end = after.find('/').unwrap_or(after.len());
                let authority = URIAuthority::parse_at(&after[..end], position + 2)?;
                position += 2 + end;
                (Some(authority), &after[end..])
            }
            None => (None, before_query),
        };
        // With the scheme and the authority taken, the path rules of §3.3 hold by construction:
        // a path after an authority begins with "/", a path without one cannot begin with "//",
        // and the first segment of a relative path holds no ":".
        URIReference::check_characters(
            path,
            position,
            URIReference::is_path_byte,
            "a character not allowed in a path",
        )?;
        position += path.len();
        if let Some(query) = query {
            URIReference::check_characters(
                query,
                position + 1,
                URIReference::is_query_byte,
                "a character not allowed in a query",
            )?;
            position += 1 + query.len();
        }
        if let Some(fragment) = fragment {
            URIReference::check_characters(
                fragment,
                position + 1,
                URIReference::is_query_byte,
                "a character not allowed in a fragment",
            )?;
        }
        Ok(URIReference {
            scheme,
            authority,
            path: path.to_string(),
            query: query.map(str::to_string),
            fragment: fragment.map(str::to_string),
        })
    }

    /// Checks that the components, written back, read as the same reference: each is of its
    /// grammar, and none would read as a delimiter of another.
    pub fn check(&self) -> Result<(), URIError> {
        let text = self.to_string();
        if URIReference::parse(&text)? == *self {
            Ok(())
        } else {
            Err(URIError::Syntax { position: 0, reason: "components that read back as others" })
        }
    }

    /// Whether this is a relative reference (§4.2): one without a scheme.
    pub fn is_relative(&self) -> bool {
        self.scheme.is_none()
    }

    /// Whether this is an absolute URI (§4.3): one with a scheme and without a fragment.
    pub fn is_absolute(&self) -> bool {
        self.scheme.is_some() && self.fragment.is_none()
    }

    /// The target of this reference resolved against `base` (§5.2.2, strict: a scheme in the
    /// reference is never taken as relative). The fragment of `base` is not used (§5.1).
    ///
    /// A path without an authority that comes out beginning with `//` gets `/.` before it, so
    /// that the target written back does not read its first segment as an authority; the two
    /// paths are the same once dot-segments are removed. RFC 3986 leaves this case open, and the
    /// WHATWG URL Standard serializes it the same way.
    pub fn resolve(&self, base: &URIReference) -> Result<URIReference, URIError> {
        let Some(base_scheme) = &base.scheme else {
            return Err(URIError::NotAbsolute);
        };
        let mut target = if let Some(scheme) = &self.scheme {
            URIReference {
                scheme: Some(scheme.clone()),
                authority: self.authority.clone(),
                path: URIReference::remove_dot_segments(&self.path),
                query: self.query.clone(),
                fragment: None,
            }
        } else if self.authority.is_some() {
            URIReference {
                scheme: Some(base_scheme.clone()),
                authority: self.authority.clone(),
                path: URIReference::remove_dot_segments(&self.path),
                query: self.query.clone(),
                fragment: None,
            }
        } else if self.path.is_empty() {
            URIReference {
                scheme: Some(base_scheme.clone()),
                authority: base.authority.clone(),
                path: base.path.clone(),
                query: self.query.clone().or_else(|| base.query.clone()),
                fragment: None,
            }
        } else {
            let path = if self.path.starts_with('/') {
                URIReference::remove_dot_segments(&self.path)
            } else {
                URIReference::remove_dot_segments(&URIReference::merge(base, &self.path))
            };
            URIReference {
                scheme: Some(base_scheme.clone()),
                authority: base.authority.clone(),
                path,
                query: self.query.clone(),
                fragment: None,
            }
        };
        target.fragment = self.fragment.clone();
        target.guard_path();
        Ok(target)
    }

    /// The path of `base` merged with the relative path `path` (§5.2.3).
    pub fn merge(base: &URIReference, path: &str) -> String {
        if base.authority.is_some() && base.path.is_empty() {
            let mut merged = String::with_capacity(path.len() + 1);
            merged.push('/');
            merged.push_str(path);
            return merged;
        }
        let kept = base.path.rfind('/').map_or(0, |index| index + 1);
        let mut merged = String::with_capacity(kept + path.len());
        merged.push_str(&base.path[..kept]);
        merged.push_str(path);
        merged
    }

    /// `path` with its `.` and `..` segments removed (§5.2.4).
    pub fn remove_dot_segments(path: &str) -> String {
        let mut input = path;
        let mut output = String::with_capacity(path.len());
        while !input.is_empty() {
            if let Some(rest) = input.strip_prefix("../") {
                input = rest;
            } else if let Some(rest) = input.strip_prefix("./") {
                input = rest;
            } else if input.starts_with("/./") {
                input = &input[2..];
            } else if input == "/." {
                input = "/";
            } else if input.starts_with("/../") {
                input = &input[3..];
                URIReference::remove_last_segment(&mut output);
            } else if input == "/.." {
                input = "/";
                URIReference::remove_last_segment(&mut output);
            } else if input == "." || input == ".." {
                input = "";
            } else {
                let start = usize::from(input.starts_with('/'));
                let end = input[start..].find('/').map_or(input.len(), |index| index + start);
                output.push_str(&input[..end]);
                input = &input[end..];
            }
        }
        output
    }

    /// This reference normalized by its syntax (§6.2.2): the scheme and the host in lower case,
    /// the digits of percent-encodings in upper case, percent-encoded unreserved characters
    /// decoded, and, in a reference with a scheme, dot-segments removed. An empty port is
    /// dropped with its `:` (§6.2.3). Dot-segments of a relative reference are kept, as they
    /// change its target; normalizations that depend on the scheme, such as a default port,
    /// are left to the user. The reference is taken to be valid, as [`URIReference::parse`]
    /// makes it.
    pub fn normalize(&self) -> URIReference {
        let scheme = self.scheme.as_ref().map(|scheme| scheme.to_ascii_lowercase());
        let authority = self.authority.as_ref().map(|authority| URIAuthority {
            userinfo: authority.userinfo.as_deref().map(URIReference::normalize_percent),
            host: URIReference::lowercase_host(&URIReference::normalize_percent(&authority.host)),
            port: authority.port.clone().filter(|port| !port.is_empty()),
        });
        let path = URIReference::normalize_percent(&self.path);
        let path = if scheme.is_some() { URIReference::remove_dot_segments(&path) } else { path };
        let mut normalized = URIReference {
            scheme,
            authority,
            path,
            query: self.query.as_deref().map(URIReference::normalize_percent),
            fragment: self.fragment.as_deref().map(URIReference::normalize_percent),
        };
        normalized.guard_path();
        normalized
    }

    /// Whether `byte` may stand in a path as it is: a `pchar` or `/` (§3.3).
    pub fn is_path_byte(byte: u8) -> bool {
        URIPercent::is_pchar(byte) || byte == b'/'
    }

    /// Whether `byte` may stand in a query or a fragment as it is: a `pchar`, `/` or `?`
    /// (§3.4, §3.5).
    pub fn is_query_byte(byte: u8) -> bool {
        URIPercent::is_pchar(byte) || matches!(byte, b'/' | b'?')
    }

    /// Checks `scheme` against `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` (§3.1).
    pub fn check_scheme(scheme: &str) -> Result<(), URIError> {
        let bytes = scheme.as_bytes();
        let valid = bytes.first().is_some_and(u8::is_ascii_alphabetic)
            && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'));
        if valid {
            Ok(())
        } else {
            Err(URIError::Syntax {
                position: 0,
                reason: "a scheme not of a letter and then letters, digits, +, - and .",
            })
        }
    }

    fn check_characters(
        text: &str,
        offset: usize,
        allowed: fn(u8) -> bool,
        reason: &'static str,
    ) -> Result<(), URIError> {
        URIPercent::check(text.as_bytes()).map_err(|error| match error {
            URIError::Percent { position } => URIError::Percent { position: offset + position },
            error => error,
        })?;
        match text.bytes().position(|byte| byte != b'%' && !allowed(byte)) {
            Some(index) => Err(URIError::Syntax { position: offset + index, reason }),
            None => Ok(()),
        }
    }

    fn remove_last_segment(output: &mut String) {
        match output.rfind('/') {
            Some(index) => output.truncate(index),
            None => output.clear(),
        }
    }

    fn guard_path(&mut self) {
        if self.authority.is_none() && self.path.starts_with("//") {
            self.path.insert_str(0, "/.");
        }
    }

    fn normalize_percent(text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out = String::with_capacity(text.len());
        let mut index = 0;
        while index < bytes.len() {
            let high = bytes.get(index + 1).copied().and_then(URIPercent::digit);
            let low = bytes.get(index + 2).copied().and_then(URIPercent::digit);
            match (bytes[index], high, low) {
                (b'%', Some(high), Some(low)) => {
                    let byte = high << 4 | low;
                    if URIPercent::is_unreserved(byte) {
                        out.push(char::from(byte));
                    } else {
                        out.push('%');
                        out.push(char::from(URIPercent::HEXADECIMAL[usize::from(high)]));
                        out.push(char::from(URIPercent::HEXADECIMAL[usize::from(low)]));
                    }
                    index += 3;
                }
                (b'%', _, _) => {
                    out.push('%');
                    index += 1;
                }
                _ => {
                    // Up to the next `%`, which is ASCII and so a character boundary.
                    let end = text[index..].find('%').map_or(bytes.len(), |next| index + next);
                    out.push_str(&text[index..end]);
                    index = end;
                }
            }
        }
        out
    }

    fn lowercase_host(host: &str) -> String {
        let mut out = String::with_capacity(host.len());
        let mut digits = 0;
        for character in host.chars() {
            if digits > 0 {
                out.push(character.to_ascii_uppercase());
                digits -= 1;
            } else {
                if character == '%' {
                    digits = 2;
                }
                out.push(character.to_ascii_lowercase());
            }
        }
        out
    }
}

impl fmt::Display for URIReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(scheme) = &self.scheme {
            write!(formatter, "{scheme}:")?;
        }
        if let Some(authority) = &self.authority {
            write!(formatter, "//{authority}")?;
        }
        formatter.write_str(&self.path)?;
        if let Some(query) = &self.query {
            write!(formatter, "?{query}")?;
        }
        if let Some(fragment) = &self.fragment {
            write!(formatter, "#{fragment}")?;
        }
        Ok(())
    }
}

impl URIAuthority {
    /// The authority `text` (§3.2), as it stands between `//` and the path.
    pub fn parse(text: &str) -> Result<URIAuthority, URIError> {
        URIAuthority::parse_at(text, 0)
    }

    /// The form of the host (§3.2.2): an IP literal by its brackets, an IPv4 address where the
    /// host is one (the first rule that matches wins), otherwise a registered name.
    pub fn host_kind(&self) -> URIHostKind {
        let bytes = self.host.as_bytes();
        match bytes.first() {
            Some(b'[') if matches!(bytes.get(1), Some(b'v' | b'V')) => URIHostKind::IPvFuture,
            Some(b'[') => URIHostKind::IPv6,
            _ if URIAuthority::is_ipv4(bytes) => URIHostKind::IPv4,
            _ => URIHostKind::RegName,
        }
    }

    /// Whether `text` is an `IPv4address` (§3.2.2): four decimal octets of 0 to 255 without
    /// leading zeros, joined by `.`.
    pub fn is_ipv4(text: &[u8]) -> bool {
        let mut count = 0;
        for octet in text.split(|byte| *byte == b'.') {
            count += 1;
            let decimal = !octet.is_empty() && octet.len() <= 3 && octet.iter().all(u8::is_ascii_digit);
            if !decimal || (octet.len() > 1 && octet[0] == b'0') {
                return false;
            }
            let value = octet.iter().fold(0u16, |value, digit| value * 10 + u16::from(digit - b'0'));
            if value > 255 {
                return false;
            }
        }
        count == 4
    }

    /// Whether `text` is an `IPv6address` (§3.2.2): at most eight groups of one to four
    /// hexadecimal digits joined by `:`, at most one `::` standing for one or more groups of
    /// zeros, and the last two groups optionally an IPv4 address.
    pub fn is_ipv6(text: &[u8]) -> bool {
        let (left, right, elided) = match text.windows(2).position(|pair| pair == b"::") {
            Some(index) => (&text[..index], &text[index + 2..], true),
            None => (text, &[][..], false),
        };
        let Some(left_count) = URIAuthority::count_groups(left, !elided) else {
            return false;
        };
        let right_count = if elided {
            match URIAuthority::count_groups(right, true) {
                Some(count) => count,
                None => return false,
            }
        } else {
            0
        };
        let count = left_count + right_count;
        if elided { count <= 7 } else { count == 8 }
    }

    /// Whether `text` is an `IPvFuture` (§3.2.2): `v`, hexadecimal digits, `.`, and one or more
    /// unreserved characters, sub-delimiters or `:`.
    pub fn is_ipvfuture(text: &[u8]) -> bool {
        let Some(rest) = text.strip_prefix(b"v").or_else(|| text.strip_prefix(b"V")) else {
            return false;
        };
        let Some(dot) = rest.iter().position(|byte| *byte == b'.') else {
            return false;
        };
        let (version, address) = (&rest[..dot], &rest[dot + 1..]);
        !version.is_empty()
            && version.iter().all(u8::is_ascii_hexdigit)
            && !address.is_empty()
            && address
                .iter()
                .all(|byte| URIPercent::is_unreserved(*byte) || URIPercent::is_sub_delim(*byte) || *byte == b':')
    }

    /// The number of 16-bit groups in `text`, groups of hexadecimal digits joined by `:`, with
    /// an IPv4 address counting two where `ipv4_last` allows one as the last group; `None` if
    /// `text` is not of that form. An empty `text` has none.
    fn count_groups(text: &[u8], ipv4_last: bool) -> Option<usize> {
        if text.is_empty() {
            return Some(0);
        }
        let mut count = 0;
        let mut groups = text.split(|byte| *byte == b':').peekable();
        while let Some(group) = groups.next() {
            let is_last = groups.peek().is_none();
            if is_last && ipv4_last && group.contains(&b'.') {
                if !URIAuthority::is_ipv4(group) {
                    return None;
                }
                count += 2;
            } else if !group.is_empty() && group.len() <= 4 && group.iter().all(u8::is_ascii_hexdigit) {
                count += 1;
            } else {
                return None;
            }
        }
        Some(count)
    }

    fn parse_at(text: &str, offset: usize) -> Result<URIAuthority, URIError> {
        let (userinfo, host_offset) = match text.find('@') {
            Some(index) => {
                let userinfo = &text[..index];
                URIReference::check_characters(
                    userinfo,
                    offset,
                    URIAuthority::is_userinfo_byte,
                    "a character not allowed in userinfo",
                )?;
                (Some(userinfo), index + 1)
            }
            None => (None, 0),
        };
        let host_port = &text[host_offset..];
        let host_position = offset + host_offset;
        let (host, port) = if host_port.starts_with('[') {
            let Some(end) = host_port.find(']') else {
                return Err(URIError::Syntax { position: host_position, reason: "an IP literal without its ]" });
            };
            let literal = &host_port.as_bytes()[1..end];
            let valid = if matches!(literal.first(), Some(b'v' | b'V')) {
                URIAuthority::is_ipvfuture(literal)
            } else {
                URIAuthority::is_ipv6(literal)
            };
            if !valid {
                return Err(URIError::Syntax {
                    position: host_position,
                    reason: "an IP literal that is neither an IPv6 address nor an IPvFuture",
                });
            }
            let after = &host_port[end + 1..];
            let port = match after.strip_prefix(':') {
                Some(port) => Some(port),
                None if after.is_empty() => None,
                None => {
                    return Err(URIError::Syntax {
                        position: host_position + end + 1,
                        reason: "text after an IP literal that is not a port",
                    });
                }
            };
            (&host_port[..=end], port)
        } else {
            let (host, port) = match host_port.find(':') {
                Some(index) => (&host_port[..index], Some(&host_port[index + 1..])),
                None => (host_port, None),
            };
            URIReference::check_characters(
                host,
                host_position,
                URIAuthority::is_reg_name_byte,
                "a character not allowed in a host",
            )?;
            (host, port)
        };
        if let Some(port) = port
            && let Some(index) = port.bytes().position(|byte| !byte.is_ascii_digit())
        {
            let position = host_position + host.len() + 1 + index;
            return Err(URIError::Syntax { position, reason: "a port not of decimal digits" });
        }
        Ok(URIAuthority {
            userinfo: userinfo.map(str::to_string),
            host: host.to_string(),
            port: port.map(str::to_string),
        })
    }

    fn is_userinfo_byte(byte: u8) -> bool {
        URIPercent::is_unreserved(byte) || URIPercent::is_sub_delim(byte) || byte == b':'
    }

    fn is_reg_name_byte(byte: u8) -> bool {
        URIPercent::is_unreserved(byte) || URIPercent::is_sub_delim(byte)
    }
}

impl fmt::Display for URIAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(userinfo) = &self.userinfo {
            write!(formatter, "{userinfo}@")?;
        }
        formatter.write_str(&self.host)?;
        if let Some(port) = &self.port {
            write!(formatter, ":{port}")?;
        }
        Ok(())
    }
}
