use alloc::vec::Vec;

use crate::service::{Pattern, PatternKind, Rule};

use super::{HTTPAuthority, HTTPMethod, HTTPRequest};

/// The rule of a [`Router`](crate::service::Router) that routes HTTP
/// requests, of any version, by their host, path, method and header fields:
/// `auth.example.com` with paths `/oauth/*` to one service and the rest of
/// the host to another, say.
///
/// The host is that of the request's authority, or of its Host field
/// ([`HTTPRequest::host`]), lowercased and without the port; a request
/// without one, or with one that is not an authority (RFC 9110 §4.2), has
/// no host and matches only [`Pattern::any`]. The path is matched with its
/// query, as the request carries it, without decoding (RFC 3986 §6.2.2: a
/// router that decoded would route `/a%2Fb` as `/a/b`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HTTPRule {
    /// Matched without ASCII case, as host names compare (RFC 9110 §4.2.3).
    pub host: Pattern,
    pub path: Pattern,
    /// The method the request must have; any if `None`.
    pub method: Option<HTTPMethod>,
    /// Fields the request must have, by lowercase name: each a field of
    /// that name whose value the pattern matches.
    pub fields: Vec<(Vec<u8>, Pattern)>,
}

impl Default for HTTPRule {
    fn default() -> HTTPRule {
        HTTPRule::new(Pattern::any(), Pattern::any())
    }
}

impl HTTPRule {
    /// The requests whose host `host` and path `path` match, of any method and fields.
    pub fn new(host: Pattern, path: Pattern) -> HTTPRule {
        HTTPRule { host: host.ignoring_ascii_case(true), path, method: None, fields: Vec::new() }
    }

    /// These requests, of `method` only.
    pub fn with_method(self, method: HTTPMethod) -> HTTPRule {
        HTTPRule { method: Some(method), ..self }
    }

    /// These requests, with a field `name` whose value `value` matches.
    pub fn with_field(mut self, name: &[u8], value: Pattern) -> HTTPRule {
        self.fields.push((name.to_ascii_lowercase(), value));
        self
    }

    /// Whether `request` has a host `host` matches.
    pub fn matches_host(&self, request: &HTTPRequest) -> bool {
        let host = request.host().and_then(|authority| HTTPAuthority::parse(authority).ok());
        match host {
            Some(authority) => self.host.matches_bytes(&authority.host),
            None => self.host.kind() == PatternKind::Any,
        }
    }
}

impl Rule<HTTPRequest> for HTTPRule {
    fn matches(&self, request: &HTTPRequest) -> bool {
        self.method.as_ref().is_none_or(|method| *method == request.method)
            && self.path.matches_bytes(&request.path)
            && self.matches_host(request)
            && self
                .fields
                .iter()
                .all(|(name, value)| request.fields.get_all(name).any(|field| value.matches_bytes(field)))
    }
}
