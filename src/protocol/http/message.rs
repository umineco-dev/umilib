use alloc::vec::Vec;

use super::{HTTPAuthority, HTTPError, HTTPFields, HTTPMethod, HTTPStatus, HTTPTarget};

/// The head of a request, as every version carries it (RFC 9110 §6, RFC
/// 9113 §8.3.1, RFC 9114 §4.3.1): the method, the target's parts — the
/// scheme, the authority and the path with its query — the protocol of an
/// extended CONNECT (RFC 8441 §4, RFC 9220 §3), and the header fields.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HTTPRequest {
    pub method: HTTPMethod,
    /// The scheme, lowercased: given by HTTP/2 and HTTP/3, by HTTP/1.1 only
    /// in absolute-form; none for CONNECT.
    pub scheme: Option<Vec<u8>>,
    /// The authority: of the target, or of the Host field in HTTP/1.1.
    pub authority: Option<Vec<u8>>,
    /// The path and query (origin-form), or "*"; empty for CONNECT.
    pub path: Vec<u8>,
    pub protocol: Option<Vec<u8>>,
    pub fields: HTTPFields,
}

impl HTTPRequest {
    /// A request of `method` for `path` of `authority` over `scheme`.
    pub fn new(method: HTTPMethod, scheme: &[u8], authority: &[u8], path: &[u8]) -> HTTPRequest {
        HTTPRequest {
            method,
            scheme: Some(scheme.to_ascii_lowercase()),
            authority: Some(authority.to_vec()),
            path: path.to_vec(),
            protocol: None,
            fields: HTTPFields::new(),
        }
    }

    /// A CONNECT request for a tunnel to `authority` (RFC 9110 §9.3.6).
    pub fn connect(authority: &[u8]) -> HTTPRequest {
        HTTPRequest {
            method: HTTPMethod::CONNECT,
            scheme: None,
            authority: Some(authority.to_vec()),
            path: Vec::new(),
            protocol: None,
            fields: HTTPFields::new(),
        }
    }

    /// This request with `fields`.
    pub fn with_fields(self, fields: HTTPFields) -> HTTPRequest {
        HTTPRequest { fields, ..self }
    }

    /// The authority the request is for: its own, else the Host field's.
    pub fn host(&self) -> Option<&[u8]> {
        self.authority.as_deref().or_else(|| self.fields.get(b"host"))
    }

    /// Checks the rules of the head all versions share (RFC 9110 §7.1,
    /// §9.3.6, RFC 8441 §4): a CONNECT has an authority with a port and no
    /// path; an extended CONNECT has a scheme, an authority and a path; any
    /// other request has a path ("*" only for OPTIONS); authorities are valid.
    pub fn check(&self) -> Result<(), HTTPError> {
        if let Some(authority) = &self.authority {
            HTTPAuthority::parse(authority)?;
        }
        if let Some(scheme) = &self.scheme {
            HTTPTarget::check_scheme(scheme)?;
        }
        match (&self.method, &self.protocol) {
            (HTTPMethod::CONNECT, None) => {
                let authority =
                    self.authority.as_deref().ok_or(HTTPError::Malformed("CONNECT without an authority"))?;
                if HTTPAuthority::parse(authority)?.port.is_none() {
                    return Err(HTTPError::Malformed("CONNECT without a port"));
                }
                if !self.path.is_empty() || self.scheme.is_some() {
                    return Err(HTTPError::Malformed("CONNECT with a path or a scheme"));
                }
            }
            (HTTPMethod::CONNECT, Some(_)) => {
                if self.scheme.is_none() || self.authority.is_none() {
                    return Err(HTTPError::Malformed("an extended CONNECT without a scheme or an authority"));
                }
                HTTPTarget::check_path(&self.path)?;
            }
            (_, Some(_)) => return Err(HTTPError::Malformed("a protocol without CONNECT")),
            (method, None) => {
                if self.path == b"*" {
                    if *method != HTTPMethod::OPTIONS {
                        return Err(HTTPError::Malformed("an asterisk target without OPTIONS"));
                    }
                } else {
                    HTTPTarget::check_path(&self.path)?;
                }
            }
        }
        Ok(())
    }
}

/// The head of a response (RFC 9110 §15): its status and header fields.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HTTPResponse {
    pub status: HTTPStatus,
    pub fields: HTTPFields,
}

impl HTTPResponse {
    pub fn new(status: HTTPStatus) -> HTTPResponse {
        HTTPResponse { status, fields: HTTPFields::new() }
    }

    /// This response with `fields`.
    pub fn with_fields(self, fields: HTTPFields) -> HTTPResponse {
        HTTPResponse { fields, ..self }
    }
}
