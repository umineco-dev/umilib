use super::CryptoError;

/// A stream cipher: encryption and decryption are the same xor with a key stream.
pub trait StreamCipher {
    /// Xors the next bytes of the key stream into `data`; fails, leaving
    /// `data` unchanged, if the key stream would run out.
    fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), CryptoError>;
}
