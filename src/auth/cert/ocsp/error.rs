use core::fmt;

use super::OCSPResponseStatus;
use crate::auth::cert::key::KeyError;
use crate::auth::cert::x509::X509Error;
use crate::codec::asn1::ASN1Error;

/// Why an OCSP request or response is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OCSPError {
    /// The DER encoding is malformed, or a part of it is refused.
    X509(X509Error),
    /// An algorithm, a key or a signature is refused.
    Key(KeyError),
    /// A version other than v1 (RFC 6960 §4.1.1, §4.2.2.3).
    Version,
    /// A response that is not successful (RFC 6960 §2.3).
    Status(OCSPResponseStatus),
    /// A response type other than the basic response (RFC 6960 §4.2.1).
    ResponseType,
    /// A signature algorithm the configuration does not accept.
    Algorithm,
    /// The signer is not the certificate's issuer nor a responder it
    /// authorized (RFC 6960 §4.2.2.2), or the responder identifier does not name it.
    Signer,
    /// The response has no status for the certificate asked about.
    NotFound,
    /// The status is not current: `thisUpdate` in the future, or `nextUpdate` past (RFC 6960 §3.2).
    Time,
    /// The response does not repeat the nonce of the request (RFC 8954).
    Nonce,
    /// A critical extension this module does not process.
    UnknownCriticalExtension,
}

impl From<X509Error> for OCSPError {
    fn from(error: X509Error) -> OCSPError {
        match error {
            X509Error::Key(error) => OCSPError::Key(error),
            error => OCSPError::X509(error),
        }
    }
}

impl From<ASN1Error> for OCSPError {
    fn from(error: ASN1Error) -> OCSPError {
        OCSPError::X509(X509Error::Encoding(error))
    }
}

impl From<KeyError> for OCSPError {
    fn from(error: KeyError) -> OCSPError {
        OCSPError::from(X509Error::from(error))
    }
}

impl fmt::Display for OCSPError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OCSPError::X509(error) => write!(formatter, "{error}"),
            OCSPError::Key(error) => write!(formatter, "{error}"),
            OCSPError::Version => formatter.write_str("unknown version"),
            OCSPError::Status(status) => write!(formatter, "the response is not successful ({status:?})"),
            OCSPError::ResponseType => formatter.write_str("not a basic response"),
            OCSPError::Algorithm => formatter.write_str("a signature algorithm not accepted"),
            OCSPError::Signer => formatter.write_str("the signer is not authorized"),
            OCSPError::NotFound => formatter.write_str("no status for the certificate"),
            OCSPError::Time => formatter.write_str("the status is not current"),
            OCSPError::Nonce => formatter.write_str("the nonce does not match"),
            OCSPError::UnknownCriticalExtension => formatter.write_str("an unknown critical extension"),
        }
    }
}

impl core::error::Error for OCSPError {}
