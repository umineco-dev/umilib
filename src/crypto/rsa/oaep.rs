use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{MGF1, RSAPrivateKey, RSAPublicKey};
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::secret::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize};

/// RSAES-OAEP of RFC 8017 section 7.1 with the hash function `H` and MGF1
/// over `G`. Ciphertexts have the bytes of the modulus; a message has at
/// most k - 2 hLen - 2 bytes ([`RSAOAEP::maximum_message`]).
pub struct RSAOAEP<H: CryptographicDigest + Default, G: CryptographicDigest + Default = H> {
    hashes: PhantomData<(H, G)>,
}

impl<H: CryptographicDigest + Default, G: CryptographicDigest + Default> RSAOAEP<H, G> {
    /// The longest message `key` encrypts, or `None` for a key too short.
    pub fn maximum_message(key: &RSAPublicKey) -> Option<usize> {
        key.size().checked_sub(2 * H::OUTPUT_SIZE + 2)
    }

    /// The encryption of `message` with the label `label` (section 7.1.1),
    /// with a seed of the bytes of `random`; fails with `InputLength` for a
    /// message too long for the key.
    pub fn encrypt<R: Random>(
        key: &RSAPublicKey,
        message: &[u8],
        label: &[u8],
        random: &mut R,
    ) -> Result<Vec<u8>, CryptoError> {
        let maximum = RSAOAEP::<H, G>::maximum_message(key).ok_or(CryptoError::InvalidKey)?;
        if message.len() > maximum {
            return Err(CryptoError::InputLength { length: message.len() });
        }
        let length = key.size();
        let mut encoded = alloc::vec![0u8; length];
        let (seed, data) = encoded[1..].split_at_mut(H::OUTPUT_SIZE);
        data[..H::OUTPUT_SIZE].copy_from_slice(H::digest(label).as_ref());
        let separator = data.len() - message.len() - 1;
        data[separator] = 0x01;
        data[separator + 1..].copy_from_slice(message);
        random.fill(seed).map_err(|_| CryptoError::RandomFailed)?;
        MGF1::<G>::apply(seed, data);
        MGF1::<G>::apply(data, seed);
        let ciphertext = key.apply(&key.integer(&encoded)?);
        encoded.zeroize();
        let mut out = alloc::vec![0u8; length];
        ciphertext?.write_be_bytes(&mut out).map_err(|_| CryptoError::InvalidKey)?;
        Ok(out)
    }

    /// The message of `ciphertext` with the label `label` (section 7.1.2);
    /// `random` blinds the private operation. Fails with `DecryptionFailed`
    /// for every malformed ciphertext alike, in time that does not reveal
    /// which check failed.
    pub fn decrypt<R: Random>(
        key: &RSAPrivateKey,
        ciphertext: &[u8],
        label: &[u8],
        random: &mut R,
    ) -> Result<Vec<u8>, CryptoError> {
        let public = key.public_key();
        let length = public.size();
        if ciphertext.len() != length || length < 2 * H::OUTPUT_SIZE + 2 {
            return Err(CryptoError::DecryptionFailed);
        }
        let integer = public.integer(ciphertext).map_err(|_| CryptoError::DecryptionFailed)?;
        let message = key.apply(&integer, random)?;
        let mut encoded = alloc::vec![0u8; length];
        let written = message.write_be_bytes(&mut encoded);
        drop(message);
        written.map_err(|_| CryptoError::DecryptionFailed)?;
        let first = encoded[0];
        let (seed, data) = encoded[1..].split_at_mut(H::OUTPUT_SIZE);
        MGF1::<G>::apply(data, seed);
        MGF1::<G>::apply(seed, data);
        let mut valid = first.ct_eq(&0) & data[..H::OUTPUT_SIZE].ct_eq(H::digest(label).as_ref());
        // The first 01 after zeros, found without branches on the data.
        let mut looking = Choice::TRUE;
        let mut invalid_padding = Choice::FALSE;
        let mut separator = 0usize;
        for (index, byte) in data.iter().enumerate().skip(H::OUTPUT_SIZE) {
            let is_one = byte.ct_eq(&1);
            let is_zero = byte.ct_eq(&0);
            let found = looking & is_one;
            separator = usize::select(&separator, &index, found);
            invalid_padding |= looking & !is_one & !is_zero;
            looking &= !is_one;
        }
        valid &= !looking & !invalid_padding;
        let result =
            if valid.into_bool() { Ok(data[separator + 1..].to_vec()) } else { Err(CryptoError::DecryptionFailed) };
        encoded.zeroize();
        result
    }
}
