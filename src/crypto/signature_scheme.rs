use core::fmt;

use super::CryptoError;
use super::random::Random;
use crate::secret::Zeroize;

/// A digital signature scheme whose keys and signatures have fixed sizes:
/// the owner of a signing key signs messages, and anyone with the matching
/// verifying key checks the signatures.
///
/// The scheme is a type of no value, such as `ECDSA<P256, SHA256>` or
/// `Ed25519`, whose associated functions work on its key types. Keys and
/// signatures are written and read in the encodings of the scheme's
/// specification, at the sizes of the constants: a key encoding of another
/// length fails with [`CryptoError::InvalidKey`], a signature of another
/// length with [`CryptoError::InvalidSignature`], an output of another
/// length with [`CryptoError::InputLength`].
pub trait SignatureScheme {
    /// A signing key; zeroized when dropped.
    type SigningKey: Zeroize + fmt::Debug;
    type VerifyingKey: Clone + Eq + fmt::Debug;
    /// The bytes of an encoded signing key.
    const SIGNING_KEY_SIZE: usize;
    /// The bytes of an encoded verifying key (where the specification allows
    /// several forms, the one written).
    const VERIFYING_KEY_SIZE: usize;
    /// The bytes of a signature.
    const SIGNATURE_SIZE: usize;

    /// A new signing key from the bytes of `random`.
    fn generate<R: Random>(random: &mut R) -> Result<Self::SigningKey, CryptoError>;

    /// The signing key of the encoding `bytes`.
    fn signing_key_from_bytes(bytes: &[u8]) -> Result<Self::SigningKey, CryptoError>;

    /// Writes the encoding of `key` into `out` of [`SignatureScheme::SIGNING_KEY_SIZE`] bytes.
    fn write_signing_key(key: &Self::SigningKey, out: &mut [u8]) -> Result<(), CryptoError>;

    /// The verifying key of `key`.
    fn verifying_key(key: &Self::SigningKey) -> Self::VerifyingKey;

    /// The verifying key of the encoding `bytes`, validated as the
    /// specification requires.
    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<Self::VerifyingKey, CryptoError>;

    /// Writes the encoding of `key` into `out` of [`SignatureScheme::VERIFYING_KEY_SIZE`] bytes.
    fn write_verifying_key(key: &Self::VerifyingKey, out: &mut [u8]) -> Result<(), CryptoError>;

    /// Writes the signature of `message` under `key` into `out` of
    /// [`SignatureScheme::SIGNATURE_SIZE`] bytes; deterministic where the
    /// scheme defines a deterministic signature.
    fn sign(key: &Self::SigningKey, message: &[u8], out: &mut [u8]) -> Result<(), CryptoError>;

    /// Succeeds if `signature` is a signature of `message` under `key`;
    /// fails with [`CryptoError::InvalidSignature`] otherwise.
    fn verify(key: &Self::VerifyingKey, message: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}
