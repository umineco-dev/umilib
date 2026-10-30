use core::fmt;

use crate::codec::asn1::ASN1Error;
use crate::codec::pem::PEMError;
use crate::crypto::CryptoError;

/// Why a key, an algorithm identifier or a signature is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The DER encoding is malformed.
    Encoding(ASN1Error),
    /// The PEM text is malformed.
    PEM(PEMError),
    /// A PEM document of another label than the one expected.
    PEMLabel,
    /// An algorithm this module does not know.
    UnknownAlgorithm,
    /// An algorithm this build does not include (its crypto feature is disabled).
    Unsupported,
    /// Parameters of an algorithm identifier that its specification does not allow.
    Parameters,
    /// A key whose encoding or value is invalid.
    InvalidKey,
    /// A key larger than the [`KeyLimits`](super::KeyLimits) accept.
    Limit,
    /// Parts of a key that do not belong together: a seed and an expanded
    /// key, or a private key and the public key given with it.
    Inconsistent,
    /// A signature algorithm that cannot be used with the key.
    Mismatch,
    /// A signature that does not verify.
    InvalidSignature,
    /// A wrong password, or encrypted data that does not decrypt.
    Decryption,
    /// The cryptographic operation failed.
    Crypto(CryptoError),
}

impl From<ASN1Error> for KeyError {
    fn from(error: ASN1Error) -> KeyError {
        KeyError::Encoding(error)
    }
}

impl From<PEMError> for KeyError {
    fn from(error: PEMError) -> KeyError {
        KeyError::PEM(error)
    }
}

impl From<CryptoError> for KeyError {
    fn from(error: CryptoError) -> KeyError {
        match error {
            CryptoError::InvalidSignature => KeyError::InvalidSignature,
            CryptoError::InvalidKey => KeyError::InvalidKey,
            error => KeyError::Crypto(error),
        }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Encoding(error) => write!(formatter, "malformed DER: {error}"),
            KeyError::PEM(error) => write!(formatter, "malformed PEM: {error}"),
            KeyError::PEMLabel => formatter.write_str("a PEM document of another label than expected"),
            KeyError::UnknownAlgorithm => formatter.write_str("unknown algorithm"),
            KeyError::Unsupported => formatter.write_str("the algorithm is not included in this build"),
            KeyError::Parameters => formatter.write_str("invalid algorithm parameters"),
            KeyError::InvalidKey => formatter.write_str("invalid key"),
            KeyError::Limit => formatter.write_str("the key is larger than the limits accept"),
            KeyError::Inconsistent => formatter.write_str("the parts of the key do not match"),
            KeyError::Mismatch => formatter.write_str("the signature algorithm cannot be used with the key"),
            KeyError::InvalidSignature => formatter.write_str("invalid signature"),
            KeyError::Decryption => formatter.write_str("wrong password or corrupted data"),
            KeyError::Crypto(error) => write!(formatter, "{error}"),
        }
    }
}

impl core::error::Error for KeyError {}
