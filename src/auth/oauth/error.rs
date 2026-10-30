use alloc::string::String;
use core::fmt;

use crate::codec::json::JSONError;
use crate::codec::uri::URIError;
use crate::crypto::random::RandomError;
use crate::protocol::jwt::JWTError;

use super::OAuthErrorResponse;

/// An error of OAuth: a message that does not follow its specification, a check that failed, or
/// the error the other side answered with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OAuthError {
    /// A parameter given more than once where it may appear once (RFC 6749 §3.1, §3.2).
    Repeated {
        parameter: String,
    },
    /// A parameter or member that is required and absent.
    Missing {
        parameter: &'static str,
    },
    /// A parameter or member whose value is not of its grammar or not allowed.
    Invalid {
        parameter: &'static str,
    },
    /// The other side answered with an OAuth error.
    Response(OAuthErrorResponse),
    /// The `state` of a response matches no pending request (RFC 6749 §10.12).
    State,
    /// The issuer of a response or a document is not the one expected (RFC 9207, RFC 8414 §3.3).
    Issuer,
    /// A configured limit was reached.
    Limit,
    URI(URIError),
    JSON(JSONError),
    JWT(JWTError),
    Random(RandomError),
}

impl fmt::Display for OAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OAuthError::Repeated { parameter } => {
                write!(formatter, "the parameter {parameter} is given more than once")
            }
            OAuthError::Missing { parameter } => write!(formatter, "the parameter {parameter} is missing"),
            OAuthError::Invalid { parameter } => write!(formatter, "the parameter {parameter} is not valid"),
            OAuthError::Response(response) => write!(formatter, "the other side answered {}", response.code.as_str()),
            OAuthError::State => formatter.write_str("a state that matches no pending request"),
            OAuthError::Issuer => formatter.write_str("an issuer that is not the one expected"),
            OAuthError::Limit => formatter.write_str("a configured limit was reached"),
            OAuthError::URI(error) => write!(formatter, "URI: {error}"),
            OAuthError::JSON(error) => write!(formatter, "JSON: {error}"),
            OAuthError::JWT(error) => write!(formatter, "JWT: {error}"),
            OAuthError::Random(error) => write!(formatter, "random: {error}"),
        }
    }
}

impl From<URIError> for OAuthError {
    fn from(error: URIError) -> OAuthError {
        OAuthError::URI(error)
    }
}

impl From<JSONError> for OAuthError {
    fn from(error: JSONError) -> OAuthError {
        OAuthError::JSON(error)
    }
}

impl From<JWTError> for OAuthError {
    fn from(error: JWTError) -> OAuthError {
        OAuthError::JWT(error)
    }
}

impl From<RandomError> for OAuthError {
    fn from(error: RandomError) -> OAuthError {
        OAuthError::Random(error)
    }
}
