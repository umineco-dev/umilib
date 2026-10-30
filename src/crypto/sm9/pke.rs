use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{SM9Encoding, SM9EncryptUserKey, SM9KEM};
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::math::ec::{AffinePoint, FieldElement};
use crate::math::pairing::PairingCurve;
use crate::secret::{ConstantTimeEq, Zeroize};

/// The encryption of the message by K1 in [`SM9PKE`] (GM/T 0044.4-2016
/// step A6): [`SM9StreamCipher`] (a) or [`SM9BlockCipher`] (b).
pub trait SM9Cipher {
    /// The bytes of K1 for a message, or a C2, of `length` bytes.
    fn key_length(length: usize) -> usize;

    /// C2, the message encrypted with K1.
    fn encrypt(key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// The message of C2 under K1; fails with `DecryptionFailed` if C2 is not
    /// the encryption of one.
    fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// The stream cipher of the KDF (step A6 a): K1 has the length of the
/// message and C2 = M ⊕ K1.
pub struct SM9StreamCipher;

impl SM9Cipher for SM9StreamCipher {
    fn key_length(length: usize) -> usize {
        length
    }

    fn encrypt(key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != message.len() {
            return Err(CryptoError::KeyLength { length: key.len(), minimum: message.len(), maximum: message.len() });
        }
        Ok(message.iter().zip(key).map(|(byte, mask)| byte ^ mask).collect())
    }

    fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        SM9StreamCipher::encrypt(key, ciphertext).map_err(|_| CryptoError::DecryptionFailed)
    }
}

/// The block cipher `B` combined with the KDF (step A6 b), in CBC mode with
/// a zero initial vector, as GM/T 0044.5-2016 annex D uses SM4: K1 is a key
/// of `B` (of its largest size, k bytes) and the message is padded with k -
/// (mlen mod k) bytes of that value.
#[cfg(umilib_feature = "crypto-mode-cbc")]
pub struct SM9BlockCipher<B: crate::crypto::BlockCipher + crate::crypto::KeyInit> {
    cipher: PhantomData<B>,
}

#[cfg(umilib_feature = "crypto-mode-cbc")]
impl<B: crate::crypto::BlockCipher + crate::crypto::KeyInit> SM9Cipher for SM9BlockCipher<B> {
    fn key_length(_: usize) -> usize {
        B::MAXIMUM_KEY_SIZE
    }

    /// Fails with `InvalidParameter` if the padding unit k is not a whole number of blocks.
    fn encrypt(key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use crate::crypto::mode::cbc::CBC;
        let unit = B::MAXIMUM_KEY_SIZE;
        if unit == 0 || !unit.is_multiple_of(B::BLOCK_SIZE) || unit > 255 {
            return Err(CryptoError::InvalidParameter);
        }
        let padding = unit - message.len() % unit;
        let mut buffer = Vec::with_capacity(message.len() + padding);
        buffer.extend_from_slice(message);
        buffer.resize(message.len() + padding, padding as u8);
        CBC::new(B::new_from_slice(key)?, &B::Block::default()).encrypt(&mut buffer)?;
        Ok(buffer)
    }

    fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use crate::crypto::mode::cbc::CBC;
        let unit = B::MAXIMUM_KEY_SIZE;
        if unit == 0 || ciphertext.is_empty() || !ciphertext.len().is_multiple_of(unit) || unit > 255 {
            return Err(CryptoError::DecryptionFailed);
        }
        let cipher = B::new_from_slice(key).map_err(|_| CryptoError::DecryptionFailed)?;
        let mut buffer = ciphertext.to_vec();
        CBC::new(cipher, &B::Block::default()).decrypt(&mut buffer).map_err(|_| CryptoError::DecryptionFailed)?;
        // The padding: its last byte p in [1, k], and the p bytes before the end all p.
        let padding = buffer[buffer.len() - 1] as usize;
        let mut valid = (padding >= 1) & (padding <= unit);
        let start = buffer.len() - padding.clamp(1, unit);
        for byte in &buffer[start..] {
            valid &= *byte as usize == padding;
        }
        if !valid {
            buffer.zeroize();
            return Err(CryptoError::DecryptionFailed);
        }
        buffer.truncate(start);
        Ok(buffer)
    }
}

/// The public key encryption algorithm of GM/T 0044.4-2016 clause 7 on the
/// curve `C` with the hash function `H` and the cipher `E`: the ciphertext
/// C1 || C3 || C2 of a message M, with C1 = \[r\]Q of the recipient's Q (x ||
/// y), K1 || K2 = KDF(C1 || w || ID) as in [`SM9KEM`], C2 the encryption of
/// M by `E` with K1, and C3 = MAC(K2, C2) = Hv(C2 || K2), K2 of the bytes of
/// Hv.
pub struct SM9PKE<C: PairingCurve, H: CryptographicDigest + Default, E: SM9Cipher = SM9StreamCipher> {
    types: PhantomData<(C, H, E)>,
}

impl<C: PairingCurve, H: CryptographicDigest + Default, E: SM9Cipher> SM9PKE<C, H, E> {
    /// The bytes of K2: those of Hv.
    pub const MAC_KEY_SIZE: usize = H::OUTPUT_SIZE;

    /// The bytes a ciphertext adds to C2: C1 and C3.
    pub fn overhead() -> usize {
        SM9Encoding::<C>::g1_length() + H::OUTPUT_SIZE
    }

    /// MAC(K2, Z) = Hv(Z || K2) (section 5.4.5).
    pub fn mac(key: &[u8], data: &[u8]) -> H::Output {
        let mut hash = H::default();
        hash.update(data);
        hash.update(key);
        hash.finalize()
    }

    /// Steps A1 to A8 with the random r given: the ciphertext of `message`
    /// for `identity` and `hid` under Ppub-e `master`. r must be secret,
    /// random and used once; fails with `InvalidParameter` if K1 is zero,
    /// when another r is needed.
    pub fn encrypt_with_ephemeral(
        master: &AffinePoint<C::G1>,
        identity: &[u8],
        hid: u8,
        message: &[u8],
        ephemeral: &FieldElement<C::Scalar>,
    ) -> Result<Vec<u8>, CryptoError> {
        let first = E::key_length(message.len());
        let mut keys = vec![0u8; first + SM9PKE::<C, H, E>::MAC_KEY_SIZE];
        let result = SM9PKE::<C, H, E>::seal(master, identity, hid, message, ephemeral, &mut keys, first);
        keys.zeroize();
        result
    }

    /// The body of [`SM9PKE::encrypt_with_ephemeral`] with the buffer of K1 || K2.
    fn seal(
        master: &AffinePoint<C::G1>,
        identity: &[u8],
        hid: u8,
        message: &[u8],
        ephemeral: &FieldElement<C::Scalar>,
        keys: &mut [u8],
        first: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let encapsulated = SM9KEM::<C, H>::derive_sender(master, identity, hid, ephemeral, keys)?;
        let (key1, key2) = keys.split_at(first);
        // An empty K1, of an empty message, encrypts nothing and is never "all zero".
        if !key1.is_empty() && SM9KEM::<C, H>::is_zero(key1) {
            return Err(CryptoError::InvalidParameter);
        }
        let encrypted = E::encrypt(key1, message)?;
        let tag = SM9PKE::<C, H, E>::mac(key2, &encrypted);
        let mut out = SM9Encoding::<C>::g1(&encapsulated)?;
        out.extend_from_slice(tag.as_ref());
        out.extend_from_slice(&encrypted);
        Ok(out)
    }

    /// Clause 7.1 with r drawn from `random`, drawn again when K1 is zero.
    pub fn encrypt<R: Random>(
        master: &AffinePoint<C::G1>,
        identity: &[u8],
        hid: u8,
        message: &[u8],
        random: &mut R,
    ) -> Result<Vec<u8>, CryptoError> {
        loop {
            let mut ephemeral =
                FieldElement::random_nonzero(|bytes| random.fill(bytes)).map_err(|_| CryptoError::RandomFailed)?;
            let result = SM9PKE::<C, H, E>::encrypt_with_ephemeral(master, identity, hid, message, &ephemeral);
            ephemeral.zeroize();
            match result {
                Err(CryptoError::InvalidParameter) => continue,
                result => return result,
            }
        }
    }

    /// Clause 7.2: the message of `ciphertext` for `key`. C3 is checked
    /// (B4) before C2 is decrypted, so that nothing of K1 is used on an
    /// unauthenticated C2; every failure is `DecryptionFailed`.
    pub fn decrypt(key: &SM9EncryptUserKey<C>, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let (point_length, tag_length) = (SM9Encoding::<C>::g1_length(), H::OUTPUT_SIZE);
        if ciphertext.len() < point_length + tag_length {
            return Err(CryptoError::DecryptionFailed);
        }
        let (point, rest) = ciphertext.split_at(point_length);
        let (tag, encrypted) = rest.split_at(tag_length);
        let failed = |_| CryptoError::DecryptionFailed;
        let encapsulated = SM9Encoding::<C>::g1_from_bytes(point).map_err(failed)?;
        let first = E::key_length(encrypted.len());
        let mut keys = vec![0u8; first + SM9PKE::<C, H, E>::MAC_KEY_SIZE];
        let result = SM9PKE::<C, H, E>::open(key, &encapsulated, tag, encrypted, &mut keys, first);
        keys.zeroize();
        result
    }

    /// The body of [`SM9PKE::decrypt`] with the buffer of K1' || K2'.
    fn open(
        key: &SM9EncryptUserKey<C>,
        encapsulated: &AffinePoint<C::G1>,
        tag: &[u8],
        encrypted: &[u8],
        keys: &mut [u8],
        first: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        SM9KEM::<C, H>::derive_receiver(key, encapsulated, keys).map_err(|_| CryptoError::DecryptionFailed)?;
        let (key1, key2) = keys.split_at(first);
        let expected = SM9PKE::<C, H, E>::mac(key2, encrypted);
        if !expected.as_ref().ct_eq(tag).into_bool() | (!key1.is_empty() && SM9KEM::<C, H>::is_zero(key1)) {
            return Err(CryptoError::DecryptionFailed);
        }
        E::decrypt(key1, encrypted)
    }
}
