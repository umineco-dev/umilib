use alloc::vec::Vec;

use crate::crypto::CryptoError;
use crate::secret::{Choice, ConstantTimeEq};

/// The padding of PKCS #7 (RFC 5652 section 6.3): `n` bytes of value `n`,
/// from 1 to the block size, so that the data fills whole blocks.
pub struct PKCS7;

impl PKCS7 {
    /// Appends the padding of `data` for blocks of `block_size` bytes (1 to 255).
    pub fn pad(data: &mut Vec<u8>, block_size: usize) -> Result<(), CryptoError> {
        if !(1..=255).contains(&block_size) {
            return Err(CryptoError::InvalidParameter);
        }
        let count = block_size - data.len() % block_size;
        data.resize(data.len() + count, count as u8);
        Ok(())
    }

    /// The length of `data` without its padding. The padding is checked in
    /// time that depends only on the length of `data`, so that a failure
    /// reveals nothing about which byte was wrong (a padding oracle still
    /// reveals that the padding was wrong: authenticate the ciphertext).
    pub fn unpad_length(data: &[u8], block_size: usize) -> Result<usize, CryptoError> {
        if !(1..=255).contains(&block_size) || data.is_empty() || !data.len().is_multiple_of(block_size) {
            return Err(CryptoError::InputLength { length: data.len() });
        }
        let last = data[data.len() - 1];
        let mut valid = !last.ct_eq(&0) & Choice::from((last as usize) <= block_size);
        // Every byte of the last block that is inside the padding must equal `last`.
        let block = &data[data.len() - block_size..];
        for (index, &byte) in block.iter().rev().enumerate() {
            let inside = Choice::from_bit(((index as u16).wrapping_sub(last as u16) >> 15) as u8);
            valid &= !inside | byte.ct_eq(&last);
        }
        if !valid.into_bool() {
            return Err(CryptoError::InvalidParameter);
        }
        Ok(data.len() - last as usize)
    }

    /// Removes the padding of `data`.
    pub fn unpad(data: &mut Vec<u8>, block_size: usize) -> Result<(), CryptoError> {
        let length = PKCS7::unpad_length(data, block_size)?;
        data.truncate(length);
        Ok(())
    }
}
