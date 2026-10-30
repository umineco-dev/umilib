use super::CryptoError;

/// A primitive created from a key alone, which generic code (modes,
/// constructions, the C ABI) can create from a byte string.
pub trait KeyInit: Sized {
    /// The shortest and the longest key in bytes; most algorithms have one size.
    const MINIMUM_KEY_SIZE: usize;
    const MAXIMUM_KEY_SIZE: usize;

    /// The primitive with `key`; fails if its length is not accepted.
    fn new_from_slice(key: &[u8]) -> Result<Self, CryptoError>;

    /// Fails unless `length` is within the key sizes.
    fn check_key_length(length: usize) -> Result<(), CryptoError> {
        if length < Self::MINIMUM_KEY_SIZE || length > Self::MAXIMUM_KEY_SIZE {
            return Err(CryptoError::KeyLength {
                length,
                minimum: Self::MINIMUM_KEY_SIZE,
                maximum: Self::MAXIMUM_KEY_SIZE,
            });
        }
        Ok(())
    }
}
