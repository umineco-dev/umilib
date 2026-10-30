use alloc::string::{String, ToString};

use crate::codec::json::{JSONEncoder, JSONObject, JSONValue};

use super::{OAuthError, OAuthParameters};

/// An error code of OAuth, from the registry of RFC 6749 §11.4 and the specifications this
/// module implements; [`OAuthErrorCode::Other`] holds any other.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum OAuthErrorCode {
    /// RFC 6749 §4.1.2.1, §5.2; RFC 6750 §3.1.
    InvalidRequest,
    /// RFC 6749 §5.2.
    InvalidClient,
    /// RFC 6749 §5.2.
    InvalidGrant,
    /// RFC 6749 §4.1.2.1, §5.2.
    UnauthorizedClient,
    /// RFC 6749 §5.2.
    UnsupportedGrantType,
    /// RFC 6749 §4.1.2.1, §5.2.
    InvalidScope,
    /// RFC 6749 §4.1.2.1; RFC 8628 §3.5.
    AccessDenied,
    /// RFC 6749 §4.1.2.1.
    UnsupportedResponseType,
    /// RFC 6749 §4.1.2.1.
    ServerError,
    /// RFC 6749 §4.1.2.1.
    TemporarilyUnavailable,
    /// RFC 6750 §3.1.
    InvalidToken,
    /// RFC 6750 §3.1.
    InsufficientScope,
    /// RFC 7009 §2.2.1.
    UnsupportedTokenType,
    /// RFC 8628 §3.5.
    AuthorizationPending,
    /// RFC 8628 §3.5.
    SlowDown,
    /// RFC 8628 §3.5.
    ExpiredToken,
    /// RFC 8707 §2.
    InvalidTarget,
    /// RFC 9449 §5, §7.1.
    InvalidDPoPProof,
    /// RFC 9449 §8, §9.
    UseDPoPNonce,
    /// RFC 9470 §3.
    InsufficientUserAuthentication,
    /// Any other code: 1*NQSCHAR (RFC 6749 Appendix A.7).
    Other(String),
}

impl OAuthErrorCode {
    /// The code as it is sent.
    pub fn as_str(&self) -> &str {
        match self {
            OAuthErrorCode::InvalidRequest => "invalid_request",
            OAuthErrorCode::InvalidClient => "invalid_client",
            OAuthErrorCode::InvalidGrant => "invalid_grant",
            OAuthErrorCode::UnauthorizedClient => "unauthorized_client",
            OAuthErrorCode::UnsupportedGrantType => "unsupported_grant_type",
            OAuthErrorCode::InvalidScope => "invalid_scope",
            OAuthErrorCode::AccessDenied => "access_denied",
            OAuthErrorCode::UnsupportedResponseType => "unsupported_response_type",
            OAuthErrorCode::ServerError => "server_error",
            OAuthErrorCode::TemporarilyUnavailable => "temporarily_unavailable",
            OAuthErrorCode::InvalidToken => "invalid_token",
            OAuthErrorCode::InsufficientScope => "insufficient_scope",
            OAuthErrorCode::UnsupportedTokenType => "unsupported_token_type",
            OAuthErrorCode::AuthorizationPending => "authorization_pending",
            OAuthErrorCode::SlowDown => "slow_down",
            OAuthErrorCode::ExpiredToken => "expired_token",
            OAuthErrorCode::InvalidTarget => "invalid_target",
            OAuthErrorCode::InvalidDPoPProof => "invalid_dpop_proof",
            OAuthErrorCode::UseDPoPNonce => "use_dpop_nonce",
            OAuthErrorCode::InsufficientUserAuthentication => "insufficient_user_authentication",
            OAuthErrorCode::Other(code) => code,
        }
    }

    /// The code of `text`, which must be 1*NQSCHAR.
    pub fn parse(text: &str) -> Result<OAuthErrorCode, OAuthError> {
        if text.is_empty() || !text.bytes().all(OAuthErrorResponse::is_nqschar) {
            return Err(OAuthError::Invalid { parameter: "error" });
        }
        Ok(match text {
            "invalid_request" => OAuthErrorCode::InvalidRequest,
            "invalid_client" => OAuthErrorCode::InvalidClient,
            "invalid_grant" => OAuthErrorCode::InvalidGrant,
            "unauthorized_client" => OAuthErrorCode::UnauthorizedClient,
            "unsupported_grant_type" => OAuthErrorCode::UnsupportedGrantType,
            "invalid_scope" => OAuthErrorCode::InvalidScope,
            "access_denied" => OAuthErrorCode::AccessDenied,
            "unsupported_response_type" => OAuthErrorCode::UnsupportedResponseType,
            "server_error" => OAuthErrorCode::ServerError,
            "temporarily_unavailable" => OAuthErrorCode::TemporarilyUnavailable,
            "invalid_token" => OAuthErrorCode::InvalidToken,
            "insufficient_scope" => OAuthErrorCode::InsufficientScope,
            "unsupported_token_type" => OAuthErrorCode::UnsupportedTokenType,
            "authorization_pending" => OAuthErrorCode::AuthorizationPending,
            "slow_down" => OAuthErrorCode::SlowDown,
            "expired_token" => OAuthErrorCode::ExpiredToken,
            "invalid_target" => OAuthErrorCode::InvalidTarget,
            "invalid_dpop_proof" => OAuthErrorCode::InvalidDPoPProof,
            "use_dpop_nonce" => OAuthErrorCode::UseDPoPNonce,
            "insufficient_user_authentication" => OAuthErrorCode::InsufficientUserAuthentication,
            other => OAuthErrorCode::Other(other.to_string()),
        })
    }
}

/// An error response of OAuth: its code, and optionally a description for developers and a
/// URI of a page about it (RFC 6749 §4.1.2.1, §5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthErrorResponse {
    pub code: OAuthErrorCode,
    pub description: Option<String>,
    pub uri: Option<String>,
}

impl OAuthErrorResponse {
    /// A response of `code` without a description or a URI.
    pub fn new(code: OAuthErrorCode) -> OAuthErrorResponse {
        OAuthErrorResponse { code, description: None, uri: None }
    }

    /// A response of `code` and `description`.
    pub fn with_description(code: OAuthErrorCode, description: &str) -> OAuthErrorResponse {
        OAuthErrorResponse { code, description: Some(description.to_string()), uri: None }
    }

    /// Whether `byte` is an NQSCHAR (RFC 6749 Appendix A): `%x20-21 / %x23-5B / %x5D-7E`, the
    /// characters of `error` and `error_description`.
    pub fn is_nqschar(byte: u8) -> bool {
        matches!(byte, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E)
    }

    /// Checks the grammar of every member (RFC 6749 Appendix A.7 to A.9): the description of
    /// NQSCHAR, the URI of `%x21 / %x23-5B / %x5D-7E`.
    pub fn check(&self) -> Result<(), OAuthError> {
        OAuthErrorCode::parse(self.code.as_str())?;
        if let Some(description) = &self.description
            && !description.bytes().all(OAuthErrorResponse::is_nqschar)
        {
            return Err(OAuthError::Invalid { parameter: "error_description" });
        }
        if let Some(uri) = &self.uri
            && (uri.is_empty() || !uri.bytes().all(|byte| byte != b' ' && OAuthErrorResponse::is_nqschar(byte)))
        {
            return Err(OAuthError::Invalid { parameter: "error_uri" });
        }
        Ok(())
    }

    /// The response of the parameters of a redirect (RFC 6749 §4.1.2.1), or `None` if they have
    /// no `error`.
    pub fn from_parameters(parameters: &OAuthParameters) -> Option<Result<OAuthErrorResponse, OAuthError>> {
        let code = parameters.get("error")?;
        let response = OAuthErrorCode::parse(code).map(|code| OAuthErrorResponse {
            code,
            description: parameters.get("error_description").map(str::to_string),
            uri: parameters.get("error_uri").map(str::to_string),
        });
        Some(response.and_then(|response| response.check().map(|()| response)))
    }

    /// Appends the members as the parameters of a redirect.
    pub fn to_parameters(&self, parameters: &mut OAuthParameters) {
        parameters.push("error", self.code.as_str());
        parameters.push_optional("error_description", self.description.as_deref());
        parameters.push_optional("error_uri", self.uri.as_deref());
    }

    /// The response of a JSON object (RFC 6749 §5.2), as the token endpoint and others send it.
    pub fn from_object(object: &JSONObject) -> Result<OAuthErrorResponse, OAuthError> {
        let string = |name: &'static str| match object.get(name) {
            None => Ok(None),
            Some(JSONValue::String(text)) => Ok(Some(text.clone())),
            Some(_) => Err(OAuthError::Invalid { parameter: name }),
        };
        let code = string("error")?.ok_or(OAuthError::Missing { parameter: "error" })?;
        let response = OAuthErrorResponse {
            code: OAuthErrorCode::parse(&code)?,
            description: string("error_description")?,
            uri: string("error_uri")?,
        };
        response.check()?;
        Ok(response)
    }

    /// The members as a JSON object.
    pub fn to_object(&self) -> JSONObject {
        let mut object = JSONObject::new();
        object.insert("error".to_string(), JSONValue::String(self.code.as_str().to_string()));
        if let Some(description) = &self.description {
            object.insert("error_description".to_string(), JSONValue::String(description.clone()));
        }
        if let Some(uri) = &self.uri {
            object.insert("error_uri".to_string(), JSONValue::String(uri.clone()));
        }
        object
    }

    /// The members as the JSON text of a response body.
    pub fn encode(&self) -> String {
        JSONEncoder::COMPACT.encode(&JSONValue::Object(self.to_object()))
    }
}
