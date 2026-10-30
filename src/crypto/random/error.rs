use core::fmt;

/// The failures of random generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomError {
    /// The entropy input is shorter than the security strength needs.
    EntropyLength { length: usize, minimum: usize },
    /// The nonce, with the entropy input, is shorter than instantiation needs
    /// (SP 800-90A section 8.6.7: 3/2 of the security strength together).
    NonceLength { length: usize, minimum: usize },
    /// An input is longer than the 2^35 bits SP 800-90A allows.
    InputLength { length: usize, maximum: usize },
    /// One request asks for more bytes than the configuration allows.
    RequestLength { length: usize, maximum: usize },
    /// The generator has served its reseed interval and must be reseeded.
    ReseedRequired,
    /// The source of entropy failed.
    EntropySource,
    /// The generator was uninstantiated (section 9.4) and cannot be used.
    Uninstantiated,
}

impl fmt::Display for RandomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RandomError::EntropyLength { length, minimum } => {
                write!(formatter, "the entropy input has {length} bytes, fewer than {minimum}")
            }
            RandomError::NonceLength { length, minimum } => {
                write!(formatter, "the nonce has {length} bytes, fewer than {minimum}")
            }
            RandomError::InputLength { length, maximum } => {
                write!(formatter, "the input has {length} bytes, more than {maximum}")
            }
            RandomError::RequestLength { length, maximum } => {
                write!(formatter, "the request for {length} bytes exceeds {maximum}")
            }
            RandomError::ReseedRequired => formatter.write_str("the generator must be reseeded"),
            RandomError::EntropySource => formatter.write_str("the source of entropy failed"),
            RandomError::Uninstantiated => formatter.write_str("the generator was uninstantiated"),
        }
    }
}

impl core::error::Error for RandomError {}
