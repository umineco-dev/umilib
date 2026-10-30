use core::fmt;

use super::CryptoError;
use super::random::Random;
use crate::secret::Zeroize;

/// A key agreement (Diffie–Hellman) scheme: each party combines its private
/// key with the public key of the other into the same shared secret.
///
/// The scheme is a type of no value, such as `ECDH<P256>` or `X25519`, whose
/// associated functions work on its key types. Keys are written and read in
/// the encodings of the scheme's specification, at the sizes of the
/// constants: an encoding of another length fails with
/// [`CryptoError::InvalidKey`], an output of another length with
/// [`CryptoError::InputLength`].
pub trait KeyAgreement {
    /// A private key; zeroized when dropped.
    type PrivateKey: Zeroize + fmt::Debug;
    type PublicKey: Clone + Eq + fmt::Debug;
    /// The bytes of an encoded private key.
    const PRIVATE_KEY_SIZE: usize;
    /// The bytes of an encoded public key (where the specification allows
    /// several forms, the one written).
    const PUBLIC_KEY_SIZE: usize;
    /// The bytes of a shared secret.
    const SHARED_SECRET_SIZE: usize;

    /// A new private key from the bytes of `random`.
    fn generate<R: Random>(random: &mut R) -> Result<Self::PrivateKey, CryptoError>;

    /// The private key of the encoding `bytes`.
    fn private_key_from_bytes(bytes: &[u8]) -> Result<Self::PrivateKey, CryptoError>;

    /// Writes the encoding of `key` into `out` of [`KeyAgreement::PRIVATE_KEY_SIZE`] bytes.
    fn write_private_key(key: &Self::PrivateKey, out: &mut [u8]) -> Result<(), CryptoError>;

    /// The public key of `key`.
    fn public_key(key: &Self::PrivateKey) -> Self::PublicKey;

    /// The public key of the encoding `bytes`, validated as the specification
    /// requires.
    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError>;

    /// Writes the encoding of `key` into `out` of [`KeyAgreement::PUBLIC_KEY_SIZE`] bytes.
    fn write_public_key(key: &Self::PublicKey, out: &mut [u8]) -> Result<(), CryptoError>;

    /// Writes the secret shared by `private` and the owner of `public` into
    /// `out` of [`KeyAgreement::SHARED_SECRET_SIZE`] bytes; fails with
    /// [`CryptoError::InvalidKey`] where the specification rejects the
    /// result (the identity, or a secret of zero).
    fn agree(private: &Self::PrivateKey, public: &Self::PublicKey, out: &mut [u8]) -> Result<(), CryptoError>;
}
