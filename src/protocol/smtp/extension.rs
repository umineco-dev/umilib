use alloc::string::String;
use alloc::vec::Vec;

use super::{SMTPError, SMTPReply};

/// A service extension of the reply to EHLO (RFC 5321 §4.1.1.1): a
/// keyword, in upper case, and its parameters.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SMTPExtension {
    pub keyword: String,
    pub parameters: Vec<String>,
}

/// The reply to EHLO: the server's domain and greeting, and the extensions it advertises.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SMTPExtensions {
    /// The first line: the server's domain and a greeting.
    pub greeting: String,
    pub entries: Vec<SMTPExtension>,
}

impl SMTPExtension {
    pub fn new(keyword: &str, parameters: &[&str]) -> SMTPExtension {
        SMTPExtension {
            keyword: keyword.to_ascii_uppercase(),
            parameters: parameters.iter().map(|parameter| String::from(*parameter)).collect(),
        }
    }

    /// The extension of an ehlo-line: `ehlo-keyword *(SP ehlo-param)`; `None` for a line that is not one.
    pub fn parse(line: &[u8]) -> Option<SMTPExtension> {
        let text = core::str::from_utf8(line).ok()?;
        let mut words = text.split(' ');
        let keyword = words.next()?;
        let keyword_valid = keyword.bytes().next().is_some_and(|byte| byte.is_ascii_alphanumeric())
            && keyword.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        let parameters: Vec<String> = words.map(String::from).collect();
        let parameters_valid = parameters
            .iter()
            .all(|parameter| !parameter.is_empty() && parameter.bytes().all(|byte| (33..=126).contains(&byte)));
        (keyword_valid && parameters_valid).then(|| SMTPExtension { keyword: keyword.to_ascii_uppercase(), parameters })
    }

    /// The line of the extension.
    pub fn line(&self) -> Vec<u8> {
        let mut line = self.keyword.clone();
        for parameter in &self.parameters {
            line.push(' ');
            line.push_str(parameter);
        }
        line.into_bytes()
    }
}

impl SMTPExtensions {
    /// The extensions of a positive reply to EHLO. Lines that are not
    /// ehlo-lines (such as the `AUTH=` of old servers) are ignored.
    pub fn from_reply(reply: &SMTPReply) -> Result<SMTPExtensions, SMTPError> {
        if reply.code != 250 {
            return Err(SMTPError::State { reason: "not a positive reply to EHLO" });
        }
        let greeting = String::from_utf8_lossy(reply.lines.first().map(Vec::as_slice).unwrap_or_default()).into_owned();
        let entries = reply.lines.iter().skip(1).filter_map(|line| SMTPExtension::parse(line)).collect();
        Ok(SMTPExtensions { greeting, entries })
    }

    /// The extension of `keyword`, in any case.
    pub fn get(&self, keyword: &str) -> Option<&SMTPExtension> {
        self.entries.iter().find(|extension| extension.keyword.eq_ignore_ascii_case(keyword))
    }

    pub fn has(&self, keyword: &str) -> bool {
        self.get(keyword).is_some()
    }

    /// The largest message the server takes (RFC 1870 §4): `Some(0)` for no fixed limit, or
    /// for SIZE without a number; `None` if SIZE is not advertised.
    pub fn size(&self) -> Option<u64> {
        let extension = self.get("SIZE")?;
        Some(extension.parameters.first().and_then(|size| size.parse().ok()).unwrap_or(0))
    }

    /// The SASL mechanisms of AUTH (RFC 4954 §3).
    pub fn auth_mechanisms(&self) -> Vec<&str> {
        self.get("AUTH").map(|extension| extension.parameters.iter().map(String::as_str).collect()).unwrap_or_default()
    }

    /// The reply to EHLO of these extensions (RFC 5321 §4.1.1.1).
    pub fn reply(&self) -> SMTPReply {
        let mut lines = alloc::vec![self.greeting.clone().into_bytes()];
        lines.extend(self.entries.iter().map(SMTPExtension::line));
        SMTPReply { code: 250, lines }
    }
}
