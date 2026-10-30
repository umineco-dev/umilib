use core::fmt;

use crate::auth::cert::key::KeyError;
use crate::codec::json::JSONError;
use crate::crypto::CryptoError;

/// Why a JOSE object (JWK, JWS, JWE) or a JWT is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JWTError {
    /// Text that is not base64url without padding (RFC 7515 §2), or not canonical.
    Base64,
    /// JSON that does not parse, or has a member twice (RFC 7515 §4, RFC 7519 §4).
    JSON(JSONError),
    /// A key that does not decode or is refused.
    Key(KeyError),
    /// A cryptographic operation that fails.
    Crypto(CryptoError),
    /// A malformed serialization: the parts of a compact serialization, or a
    /// member of a JSON serialization, a JWK or a JWK Set that is missing,
    /// misplaced or of another type.
    Format,
    /// A header parameter that is missing, of another type, or in more than
    /// one of the headers of an object (RFC 7515 §7.2.1, RFC 7516 §7.2.1).
    Header,
    /// An algorithm this library does not know or does not implement.
    UnknownAlgorithm,
    /// A key type (`kty`) or curve (`crv`) this library does not know.
    UnknownKeyType,
    /// An algorithm the configuration does not allow (RFC 8725 §3.1).
    AlgorithmNotAllowed,
    /// A key that does not fit the algorithm: another type or curve, too
    /// short, or its `use`, `key_ops` or `alg` exclude the operation.
    KeyMismatch,
    /// A critical header parameter that is not understood, or a `crit`
    /// that breaks its rules (RFC 7515 §4.1.11).
    Critical,
    /// No signature verifies.
    Signature,
    /// The JWE does not decrypt; nothing tells why (RFC 7516 §11.5).
    Decryption,
    /// Compression that the configuration refuses, or a payload that
    /// decompresses to more than its limit.
    Compression,
    /// More signatures or recipients than the configuration accepts.
    Limit,
    /// The JWT has expired (`exp`, RFC 7519 §4.1.4).
    Expired,
    /// The JWT is not valid yet (`nbf`, RFC 7519 §4.1.5).
    NotYetValid,
    /// The issuer is not the one expected (`iss`).
    Issuer,
    /// The audience does not include the one expected, or one is given
    /// but none expected (`aud`, RFC 7519 §4.1.3).
    Audience,
    /// The subject is not the one expected (`sub`).
    Subject,
    /// The type is not the one expected (`typ`, RFC 8725 §3.11).
    Type,
    /// A claim the validation requires is missing.
    MissingClaim,
    /// A claim of another type than its definition (a NumericDate that is
    /// not a number, an audience that is not a string or strings).
    InvalidClaim,
}

impl From<JSONError> for JWTError {
    fn from(error: JSONError) -> JWTError {
        JWTError::JSON(error)
    }
}

impl From<KeyError> for JWTError {
    fn from(error: KeyError) -> JWTError {
        JWTError::Key(error)
    }
}

impl From<CryptoError> for JWTError {
    fn from(error: CryptoError) -> JWTError {
        JWTError::Crypto(error)
    }
}

impl fmt::Display for JWTError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JWTError::Base64 => formatter.write_str("invalid base64url"),
            JWTError::JSON(error) => write!(formatter, "{error}"),
            JWTError::Key(error) => write!(formatter, "{error}"),
            JWTError::Crypto(error) => write!(formatter, "{error}"),
            JWTError::Format => formatter.write_str("malformed serialization"),
            JWTError::Header => formatter.write_str("invalid header parameter"),
            JWTError::UnknownAlgorithm => formatter.write_str("unknown algorithm"),
            JWTError::UnknownKeyType => formatter.write_str("unknown key type or curve"),
            JWTError::AlgorithmNotAllowed => formatter.write_str("algorithm not allowed"),
            JWTError::KeyMismatch => formatter.write_str("the key does not fit the algorithm"),
            JWTError::Critical => formatter.write_str("critical header parameter not understood"),
            JWTError::Signature => formatter.write_str("no signature verifies"),
            JWTError::Decryption => formatter.write_str("decryption failed"),
            JWTError::Compression => formatter.write_str("compression refused or beyond the limit"),
            JWTError::Limit => formatter.write_str("more signatures or recipients than the limit"),
            JWTError::Expired => formatter.write_str("the token has expired"),
            JWTError::NotYetValid => formatter.write_str("the token is not valid yet"),
            JWTError::Issuer => formatter.write_str("unexpected issuer"),
            JWTError::Audience => formatter.write_str("unexpected audience"),
            JWTError::Subject => formatter.write_str("unexpected subject"),
            JWTError::Type => formatter.write_str("unexpected type"),
            JWTError::MissingClaim => formatter.write_str("a required claim is missing"),
            JWTError::InvalidClaim => formatter.write_str("invalid claim"),
        }
    }
}

impl core::error::Error for JWTError {}
