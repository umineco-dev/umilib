use core::fmt;

use super::CryptoError;
use super::random::Random;
use crate::secret::Zeroize;

/// A key-encapsulation mechanism (KEM): anyone with the encapsulation key
/// derives a shared secret and a ciphertext, from which the owner of the
/// decapsulation key derives the same secret.
///
/// The scheme is a type of no value, such as `MLKEM<MLKEM768>`, whose
/// associated functions work on its key types. Keys and ciphertexts are
/// written and read in the encodings of the scheme's specification, at the
/// sizes of the constants: a key encoding of another length fails with
/// [`CryptoError::InvalidKey`], a ciphertext or an output of another length
/// with [`CryptoError::InputLength`].
pub trait KeyEncapsulation {
    /// A decapsulation key; zeroized when dropped.
    type DecapsulationKey: Zeroize + fmt::Debug;
    type EncapsulationKey: Clone + Eq + fmt::Debug;
    /// The bytes of an encoded decapsulation key.
    const DECAPSULATION_KEY_SIZE: usize;
    /// The bytes of an encoded encapsulation key.
    const ENCAPSULATION_KEY_SIZE: usize;
    /// The bytes of a ciphertext.
    const CIPHERTEXT_SIZE: usize;
    /// The bytes of a shared secret.
    const SHARED_SECRET_SIZE: usize;

    /// A new decapsulation key from the bytes of `random`.
    fn generate<R: Random>(random: &mut R) -> Result<Self::DecapsulationKey, CryptoError>;

    /// The decapsulation key of the encoding `bytes`, checked as the
    /// specification requires.
    fn decapsulation_key_from_bytes(bytes: &[u8]) -> Result<Self::DecapsulationKey, CryptoError>;

    /// Writes the encoding of `key` into `out` of
    /// [`KeyEncapsulation::DECAPSULATION_KEY_SIZE`] bytes.
    fn write_decapsulation_key(key: &Self::DecapsulationKey, out: &mut [u8]) -> Result<(), CryptoError>;

    /// The encapsulation key of `key`.
    fn encapsulation_key(key: &Self::DecapsulationKey) -> Self::EncapsulationKey;

    /// The encapsulation key of the encoding `bytes`, checked as the
    /// specification requires.
    fn encapsulation_key_from_bytes(bytes: &[u8]) -> Result<Self::EncapsulationKey, CryptoError>;

    /// Writes the encoding of `key` into `out` of
    /// [`KeyEncapsulation::ENCAPSULATION_KEY_SIZE`] bytes.
    fn write_encapsulation_key(key: &Self::EncapsulationKey, out: &mut [u8]) -> Result<(), CryptoError>;

    /// Writes a ciphertext for the owner of `key` into `ciphertext` and the
    /// secret it carries into `shared`, with the bytes of `random`.
    fn encapsulate<R: Random>(
        key: &Self::EncapsulationKey,
        random: &mut R,
        ciphertext: &mut [u8],
        shared: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// Writes the secret `ciphertext` carries for `key` into `shared`. A KEM
    /// with implicit rejection (as ML-KEM) gives a pseudorandom secret for a
    /// ciphertext that was not made for `key`, instead of failing.
    fn decapsulate(key: &Self::DecapsulationKey, ciphertext: &[u8], shared: &mut [u8]) -> Result<(), CryptoError>;
}
