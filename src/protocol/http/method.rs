use alloc::boxed::Box;

use super::{HTTPError, HTTPSyntax};

/// A request method (RFC 9110 §9): the methods of the RFC and of RFC 5789
/// (PATCH) and RFC 10008 (QUERY), and any other token, kept as sent
/// (methods are case-sensitive).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HTTPMethod {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
    QUERY,
    Other(Box<[u8]>),
}

impl HTTPMethod {
    /// The method of the token `bytes`; fails for what is not a token (RFC 9110 §9.1).
    pub fn parse(bytes: &[u8]) -> Result<HTTPMethod, HTTPError> {
        Ok(match bytes {
            b"GET" => HTTPMethod::GET,
            b"HEAD" => HTTPMethod::HEAD,
            b"POST" => HTTPMethod::POST,
            b"PUT" => HTTPMethod::PUT,
            b"DELETE" => HTTPMethod::DELETE,
            b"CONNECT" => HTTPMethod::CONNECT,
            b"OPTIONS" => HTTPMethod::OPTIONS,
            b"TRACE" => HTTPMethod::TRACE,
            b"PATCH" => HTTPMethod::PATCH,
            b"QUERY" => HTTPMethod::QUERY,
            _ if HTTPSyntax::is_token(bytes) => HTTPMethod::Other(bytes.into()),
            _ => return Err(HTTPError::Malformed("a method that is not a token")),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            HTTPMethod::GET => b"GET",
            HTTPMethod::HEAD => b"HEAD",
            HTTPMethod::POST => b"POST",
            HTTPMethod::PUT => b"PUT",
            HTTPMethod::DELETE => b"DELETE",
            HTTPMethod::CONNECT => b"CONNECT",
            HTTPMethod::OPTIONS => b"OPTIONS",
            HTTPMethod::TRACE => b"TRACE",
            HTTPMethod::PATCH => b"PATCH",
            HTTPMethod::QUERY => b"QUERY",
            HTTPMethod::Other(bytes) => bytes,
        }
    }

    /// Whether the method is safe, read-only (RFC 9110 §9.2.1, RFC 10008 §2);
    /// an unknown one is not.
    pub fn is_safe(&self) -> bool {
        matches!(self, HTTPMethod::GET | HTTPMethod::HEAD | HTTPMethod::OPTIONS | HTTPMethod::TRACE | HTTPMethod::QUERY)
    }

    /// Whether repeating the request has the effect of one (RFC 9110 §9.2.2, RFC 10008 §2).
    pub fn is_idempotent(&self) -> bool {
        self.is_safe() || matches!(self, HTTPMethod::PUT | HTTPMethod::DELETE)
    }
}
