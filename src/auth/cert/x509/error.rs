use core::fmt;

use crate::auth::cert::key::KeyError;
use crate::codec::asn1::ASN1Error;
use crate::codec::pem::PEMError;

/// Why a certificate, a CRL, a name or an extension is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X509Error {
    /// The DER encoding is malformed.
    Encoding(ASN1Error),
    /// The PEM text is malformed.
    PEM(PEMError),
    /// A PEM document of another label than the one expected.
    PEMLabel,
    /// An algorithm, a key or a signature is refused.
    Key(KeyError),
    /// A version this module does not know, or one that does not allow the
    /// fields present (RFC 5280 §4.1.2.1, §5.1.2.1).
    Version,
    /// The signature algorithm inside the signed data differs from the one
    /// outside it (RFC 5280 §4.1.1.2, §5.1.1.2).
    AlgorithmMismatch,
    /// Two extensions of the same type (RFC 5280 §4.2).
    DuplicateExtension,
    /// An extension whose value does not decode as its type, or that is not
    /// of the type asked for.
    InvalidExtension,
    /// A name, or an attribute of a name, that its type does not allow.
    InvalidName,
    /// A time that a certificate may not carry (RFC 5280 §4.1.2.5).
    InvalidTime,
    /// A serial number that is not positive or longer than 20 octets (RFC 5280 §4.1.2.2).
    InvalidSerialNumber,
    /// An attribute that its type does not allow.
    InvalidAttribute,
}

impl From<ASN1Error> for X509Error {
    fn from(error: ASN1Error) -> X509Error {
        X509Error::Encoding(error)
    }
}

impl From<PEMError> for X509Error {
    fn from(error: PEMError) -> X509Error {
        X509Error::PEM(error)
    }
}

impl From<KeyError> for X509Error {
    fn from(error: KeyError) -> X509Error {
        match error {
            KeyError::Encoding(error) => X509Error::Encoding(error),
            KeyError::PEM(error) => X509Error::PEM(error),
            KeyError::PEMLabel => X509Error::PEMLabel,
            error => X509Error::Key(error),
        }
    }
}

impl fmt::Display for X509Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            X509Error::Encoding(error) => write!(formatter, "malformed DER: {error}"),
            X509Error::PEM(error) => write!(formatter, "malformed PEM: {error}"),
            X509Error::PEMLabel => formatter.write_str("a PEM document of another label than expected"),
            X509Error::Key(error) => write!(formatter, "{error}"),
            X509Error::Version => formatter.write_str("unknown version, or one that does not allow the fields present"),
            X509Error::AlgorithmMismatch => {
                formatter.write_str("the signature algorithm inside the signed data differs from the one outside")
            }
            X509Error::DuplicateExtension => formatter.write_str("two extensions of the same type"),
            X509Error::InvalidExtension => formatter.write_str("invalid extension"),
            X509Error::InvalidName => formatter.write_str("invalid name"),
            X509Error::InvalidTime => formatter.write_str("invalid time"),
            X509Error::InvalidSerialNumber => formatter.write_str("invalid serial number"),
            X509Error::InvalidAttribute => formatter.write_str("invalid attribute"),
        }
    }
}

impl core::error::Error for X509Error {}
