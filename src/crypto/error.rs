use core::fmt;

/// The failures of the cryptographic primitives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// A key of `length` bytes is outside `minimum..=maximum`.
    KeyLength { length: usize, minimum: usize, maximum: usize },
    /// A nonce or initialization vector of `length` bytes is outside `minimum..=maximum`.
    NonceLength { length: usize, minimum: usize, maximum: usize },
    /// A tag of `length` bytes is outside `minimum..=maximum`.
    TagLength { length: usize, minimum: usize, maximum: usize },
    /// An input of `length` bytes has a length the operation does not accept
    /// (not a whole number of blocks, too short, or beyond its limit).
    InputLength { length: usize },
    /// A parameter is outside the range the algorithm allows.
    InvalidParameter,
    /// The tag does not authenticate the data; nothing was decrypted.
    AuthenticationFailed,
    /// The key has served as many inputs or bytes as the algorithm allows.
    LimitExceeded,
    /// The memory the operation needs could not be allocated.
    Allocation,
    /// A key or public value the algorithm refuses: an encoding of another
    /// length or form, a value out of range, a point not on the curve or of
    /// small order, or a shared secret of zero.
    InvalidKey,
    /// The signature is not a signature of the message under the key.
    InvalidSignature,
    /// The source of random bytes failed.
    RandomFailed,
    /// The ciphertext is not an encryption under the key; nothing about why
    /// is revealed.
    DecryptionFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyLength { length, minimum, maximum } => {
                write!(formatter, "key length {length} is outside {minimum} to {maximum}")
            }
            CryptoError::NonceLength { length, minimum, maximum } => {
                write!(formatter, "nonce length {length} is outside {minimum} to {maximum}")
            }
            CryptoError::TagLength { length, minimum, maximum } => {
                write!(formatter, "tag length {length} is outside {minimum} to {maximum}")
            }
            CryptoError::InputLength { length } => write!(formatter, "an input of {length} bytes is not accepted"),
            CryptoError::InvalidParameter => formatter.write_str("invalid parameter"),
            CryptoError::AuthenticationFailed => formatter.write_str("authentication failed"),
            CryptoError::LimitExceeded => formatter.write_str("the limit of the key is exceeded"),
            CryptoError::Allocation => formatter.write_str("the memory of the operation could not be allocated"),
            CryptoError::InvalidKey => formatter.write_str("the key is not accepted"),
            CryptoError::InvalidSignature => formatter.write_str("the signature is not valid"),
            CryptoError::RandomFailed => formatter.write_str("the source of random bytes failed"),
            CryptoError::DecryptionFailed => formatter.write_str("decryption failed"),
        }
    }
}

impl core::error::Error for CryptoError {}
