use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::codec::uri::{URIForm, URIReference};

use super::OAuthError;

/// The parameters of an OAuth request or response: the name and value pairs of a query or of a
/// form body (RFC 6749 Appendix B), in order.
///
/// Reading follows RFC 6749 §3.1 and §3.2: a parameter without a value is treated as omitted,
/// and a parameter given more than once fails with Repeated, except those named as repeatable
/// (such as `resource`, RFC 8707 §2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthParameters {
    pairs: Vec<(String, String)>,
}

impl OAuthParameters {
    /// The parameters that may be given more than once by the specifications this module
    /// implements: `resource` (RFC 8707 §2).
    pub const REPEATABLE: &'static [&'static str] = &["resource"];

    /// No parameters.
    pub fn new() -> OAuthParameters {
        OAuthParameters::default()
    }

    /// The parameters of the form-encoded `input`, any of [`OAuthParameters::REPEATABLE`] allowed
    /// more than once.
    pub fn parse(input: &[u8]) -> Result<OAuthParameters, OAuthError> {
        OAuthParameters::parse_with(input, OAuthParameters::REPEATABLE)
    }

    /// The parameters of the form-encoded `input`, those named in `repeatable` allowed more than
    /// once.
    pub fn parse_with(input: &[u8], repeatable: &[&str]) -> Result<OAuthParameters, OAuthError> {
        let mut parameters = OAuthParameters::new();
        let mut seen = BTreeSet::new();
        for (name, value) in URIForm::parse(input)? {
            if value.is_empty() {
                continue;
            }
            if !repeatable.contains(&name.as_str()) && !seen.insert(name.clone()) {
                return Err(OAuthError::Repeated { parameter: name });
            }
            parameters.pairs.push((name, value));
        }
        Ok(parameters)
    }

    /// The value of the parameter `name`: the first if it is repeatable.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.pairs.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    /// Every value of the parameter `name`, in order.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.pairs.iter().filter(move |(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    /// The value of the parameter `name`, which is required.
    pub fn required(&self, name: &'static str) -> Result<&str, OAuthError> {
        self.get(name).ok_or(OAuthError::Missing { parameter: name })
    }

    /// Appends the parameter `name` of `value`. An empty value is not added, as it would read
    /// as omitted.
    pub fn push(&mut self, name: &str, value: &str) {
        if !value.is_empty() {
            self.pairs.push((name.to_string(), value.to_string()));
        }
    }

    /// Appends the parameter `name` of `value` if there is a value.
    pub fn push_optional(&mut self, name: &str, value: Option<&str>) {
        if let Some(value) = value {
            self.push(name, value);
        }
    }

    /// Removes every value of the parameter `name`.
    pub fn remove(&mut self, name: &str) {
        self.pairs.retain(|(key, _)| key != name);
    }

    /// The pairs, in order.
    pub fn pairs(&self) -> &[(String, String)] {
        &self.pairs
    }

    /// The parameters in the form encoding.
    pub fn encode(&self) -> String {
        URIForm::encode(&self.pairs)
    }

    /// The parameters of the query of `uri`, none if it has no query.
    pub fn from_query(uri: &URIReference) -> Result<OAuthParameters, OAuthError> {
        OAuthParameters::parse(uri.query.as_deref().unwrap_or_default().as_bytes())
    }

    /// `uri` with these parameters added to its query, the query it has kept (RFC 6749 §3.1,
    /// §3.1.2).
    pub fn add_to_query(&self, uri: &URIReference) -> URIReference {
        let mut target = uri.clone();
        if self.pairs.is_empty() {
            return target;
        }
        let encoded = self.encode();
        target.query = Some(match uri.query.as_deref() {
            None | Some("") => encoded,
            Some(query) => alloc::format!("{query}&{encoded}"),
        });
        target
    }
}
