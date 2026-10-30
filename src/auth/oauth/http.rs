use alloc::string::String;
use alloc::vec::Vec;

/// An HTTP request that OAuth asks to send: the method, the target URI, the header fields and
/// the body. Sending it is left to the user, so that any HTTP version or library carries it.
///
/// The header fields and the body may hold secrets (a client secret, a code verifier, an
/// assertion); drop the request once it is sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthHTTPRequest {
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl OAuthHTTPRequest {
    /// The media type of form bodies (RFC 6749 Appendix B).
    pub const FORM: &'static str = "application/x-www-form-urlencoded";
    /// The media type of JSON bodies (RFC 8259 §11).
    pub const JSON: &'static str = "application/json";

    /// The value of the header field `name`, compared without regard to case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }
}

/// A request that reached an endpoint of the authorization server or of a protected resource:
/// what OAuth reads of it. The user's HTTP server fills it in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthEndpointRequest {
    /// `GET`, `POST`, ...
    pub method: String,
    /// The target URI of the request, absolute (RFC 9110 §7.1), as a DPoP proof's `htu` is
    /// compared with it.
    pub uri: String,
    /// The value of the `Authorization` header field, if there is one field; give `None` and
    /// refuse the request yourself if there are several.
    pub authorization: Option<String>,
    /// The value of the `DPoP` header field (RFC 9449 §4.1).
    pub dpop: Option<String>,
    /// The value of the `Content-Type` header field.
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

impl OAuthEndpointRequest {
    /// Whether the content type is the form encoding, its parameters left aside.
    pub fn is_form(&self) -> bool {
        self.content_type.as_deref().is_some_and(|value| {
            value.split(';').next().is_some_and(|media| media.trim().eq_ignore_ascii_case(OAuthHTTPRequest::FORM))
        })
    }
}

/// The response an endpoint gives: the status, the header fields and the body, which the user's
/// HTTP server sends.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuthHTTPResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl OAuthHTTPResponse {
    /// A JSON response of `status` and `body`, never cached (RFC 6749 §5.1: `Cache-Control:
    /// no-store`).
    pub fn json(status: u16, body: String) -> OAuthHTTPResponse {
        OAuthHTTPResponse {
            status,
            headers: alloc::vec![
                (String::from("content-type"), String::from(OAuthHTTPRequest::JSON)),
                (String::from("cache-control"), String::from("no-store")),
            ],
            body: body.into_bytes(),
        }
    }

    /// The value of the header field `name`, compared without regard to case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }
}
