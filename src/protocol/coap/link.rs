use alloc::string::String;
use alloc::vec::Vec;

use super::CoAPError;

/// A link of the CoRE Link Format (RFC 6690 §2): its target and its
/// attributes, each with a value or none.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CoAPLink {
    pub target: String,
    pub attributes: Vec<(String, Option<String>)>,
}

impl CoAPLink {
    /// The path of resource discovery (RFC 6690 §4).
    pub const WELL_KNOWN_CORE: &'static str = "/.well-known/core";

    pub fn new(target: &str) -> CoAPLink {
        CoAPLink { target: String::from(target), attributes: Vec::new() }
    }

    pub fn with(mut self, name: &str, value: Option<&str>) -> CoAPLink {
        self.attributes.push((String::from(name), value.map(String::from)));
        self
    }

    /// The value of the first attribute `name` (none if it has none).
    pub fn attribute(&self, name: &str) -> Option<Option<&str>> {
        self.attributes.iter().find(|(found, _)| found.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_deref())
    }

    /// The links of `text` (§2): `<target>;name=value;name="quoted",...`.
    pub fn parse(text: &str) -> Result<Vec<CoAPLink>, CoAPError> {
        let malformed = CoAPError::Malformed("not of the link format");
        let bytes = text.as_bytes();
        let mut links = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != b'<' {
                return Err(malformed);
            }
            let end = index + text[index..].find('>').ok_or(malformed)?;
            let mut link = CoAPLink::new(&text[index + 1..end]);
            index = end + 1;
            while index < bytes.len() && bytes[index] == b';' {
                index += 1;
                let name_end =
                    index + bytes[index..].iter().take_while(|byte| !matches!(byte, b'=' | b';' | b',')).count();
                let name = &text[index..name_end];
                if name.is_empty()
                    || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"!#$&+-.^_`|~*".contains(&byte))
                {
                    return Err(malformed);
                }
                index = name_end;
                let mut value = None;
                if index < bytes.len() && bytes[index] == b'=' {
                    index += 1;
                    if bytes.get(index) == Some(&b'"') {
                        let mut quoted = String::new();
                        index += 1;
                        loop {
                            match bytes.get(index) {
                                None => return Err(malformed),
                                Some(b'"') => break,
                                Some(b'\\') => {
                                    // A quoted-pair: the backslash, then the character it quotes (RFC 6690 §2, RFC 2616 §2.2).
                                    let character = text[index + 1..].chars().next().ok_or(malformed)?;
                                    quoted.push(character);
                                    index += 1 + character.len_utf8();
                                }
                                Some(_) => {
                                    let character = text[index..].chars().next().ok_or(malformed)?;
                                    quoted.push(character);
                                    index += character.len_utf8();
                                }
                            }
                        }
                        index += 1;
                        value = Some(quoted);
                    } else {
                        let value_end =
                            index + bytes[index..].iter().take_while(|byte| !matches!(byte, b';' | b',')).count();
                        value = Some(String::from(&text[index..value_end]));
                        index = value_end;
                    }
                }
                link.attributes.push((String::from(name), value));
            }
            links.push(link);
            match bytes.get(index) {
                None => break,
                Some(b',') => index += 1,
                Some(_) => return Err(malformed),
            }
        }
        Ok(links)
    }

    /// The text of `links` (§2): values quoted unless they are tokens.
    pub fn format(links: &[CoAPLink]) -> String {
        let mut out = String::new();
        for (position, link) in links.iter().enumerate() {
            if position > 0 {
                out.push(',');
            }
            out.push('<');
            out.push_str(&link.target);
            out.push('>');
            for (name, value) in &link.attributes {
                out.push(';');
                out.push_str(name);
                if let Some(value) = value {
                    out.push('=');
                    let token = !value.is_empty()
                        && value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || b"!#$%&'()*+-.:<=>?@[]^_`{|}~/".contains(&byte)
                        });
                    if token {
                        out.push_str(value);
                    } else {
                        out.push('"');
                        for character in value.chars() {
                            if character == '"' || character == '\\' {
                                out.push('\\');
                            }
                            out.push(character);
                        }
                        out.push('"');
                    }
                }
            }
        }
        out
    }
}
