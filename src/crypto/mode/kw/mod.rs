//! Key wrapping (SP 800-38F): KW and TKW, the wrapping function W of
//! RFC 3394 over a block cipher of 128 or 64 bits, and KWP, KW with
//! padding (RFC 5649), over a block cipher of 128 bits.

use core::fmt;
use core::marker::PhantomData;

use crate::crypto::{BlockCipher, CryptoError};
use crate::secret::{Choice, ConstantTimeEq, Zeroize};

/// The wrapping function W of SP 800-38F §6.1 and its inverse over the
/// block cipher `C`, which [`KW`] and [`KWP`] build on. A semiblock is half
/// a block: 8 bytes for a cipher of 128 bits, 4 for one of 64 bits.
pub struct Wrapping<C: BlockCipher> {
    cipher: PhantomData<C>,
}

impl<C: BlockCipher> Wrapping<C> {
    /// The bytes of a semiblock.
    pub const SEMIBLOCK: usize = C::BLOCK_SIZE / 2;

    /// The most semiblocks W may wrap: for 128-bit ciphers 2^54 (SP 800-38F
    /// §5.3.1), for 64-bit ciphers 2^28 (so that the step counter fits in a
    /// semiblock of 32 bits).
    pub const fn maximum_semiblocks() -> u64 {
        if C::BLOCK_SIZE >= 16 { 1 << 54 } else { 1 << 28 }
    }

    /// W (SP 800-38F Algorithm 1) in the indexed form of RFC 3394 §2.2.1:
    /// `data` is the first semiblock (the integrity value) and then the
    /// semiblocks to wrap, at least three in all; it is replaced by the
    /// wrapping.
    pub fn wrap(cipher: &C, data: &mut [u8]) -> Result<(), CryptoError> {
        let semiblocks = Wrapping::<C>::check(data)?;
        let s = Wrapping::<C>::SEMIBLOCK;
        let (integrity, rest) = data.split_at_mut(s);
        let mut block = C::Block::default();
        let mut step: u64 = 0;
        for _ in 0..6 {
            for semiblock in rest.chunks_exact_mut(s) {
                step += 1;
                block.as_mut()[..s].copy_from_slice(integrity);
                block.as_mut()[s..].copy_from_slice(semiblock);
                cipher.encrypt_block(&mut block);
                integrity.copy_from_slice(&block.as_ref()[..s]);
                Wrapping::<C>::xor_step(integrity, step);
                semiblock.copy_from_slice(&block.as_ref()[s..]);
            }
        }
        block.as_mut().zeroize();
        debug_assert_eq!(step, 6 * (semiblocks - 1));
        Ok(())
    }

    /// W⁻¹ (SP 800-38F Algorithm 2): the inverse of [`Wrapping::wrap`], in
    /// place; the first semiblock is then the integrity value to check.
    pub fn unwrap(cipher: &C, data: &mut [u8]) -> Result<(), CryptoError> {
        let semiblocks = Wrapping::<C>::check(data)?;
        let s = Wrapping::<C>::SEMIBLOCK;
        let (integrity, rest) = data.split_at_mut(s);
        let mut block = C::Block::default();
        let mut step: u64 = 6 * (semiblocks - 1);
        for _ in 0..6 {
            for semiblock in rest.chunks_exact_mut(s).rev() {
                Wrapping::<C>::xor_step(integrity, step);
                step -= 1;
                block.as_mut()[..s].copy_from_slice(integrity);
                block.as_mut()[s..].copy_from_slice(semiblock);
                cipher.decrypt_block(&mut block);
                integrity.copy_from_slice(&block.as_ref()[..s]);
                semiblock.copy_from_slice(&block.as_ref()[s..]);
            }
        }
        block.as_mut().zeroize();
        Ok(())
    }

    /// The number of semiblocks of `data`, if W can take it ([`Wrapping::check_length`]).
    pub fn check(data: &[u8]) -> Result<u64, CryptoError> {
        Wrapping::<C>::check_length(data.len())
    }

    /// The number of semiblocks of `length` bytes, if W can take them:
    /// whole semiblocks, at least three, at most
    /// [`Wrapping::maximum_semiblocks`] after the first.
    pub fn check_length(length: usize) -> Result<u64, CryptoError> {
        let s = Wrapping::<C>::SEMIBLOCK;
        let semiblocks = (length / s) as u64;
        if !length.is_multiple_of(s) || semiblocks < 3 || semiblocks - 1 > Wrapping::<C>::maximum_semiblocks() {
            return Err(CryptoError::InputLength { length });
        }
        Ok(semiblocks)
    }

    /// XORs the step counter `step`, big-endian, into the semiblock `integrity`.
    pub fn xor_step(integrity: &mut [u8], step: u64) {
        let counter = step.to_be_bytes();
        for (byte, counter) in integrity.iter_mut().rev().zip(counter.iter().rev()) {
            *byte ^= counter;
        }
    }
}

/// KW (SP 800-38F §6.2, RFC 3394) over a block cipher of 128 bits, and TKW
/// (SP 800-38F §6.4) over one of 64 bits: wraps keys (data of whole
/// semiblocks, at least two) with an integrity check, adding one semiblock.
#[derive(Clone)]
pub struct KW<C: BlockCipher> {
    cipher: C,
}

impl<C: BlockCipher> KW<C> {
    /// The initial value ICV1 (SP 800-38F §6.2, RFC 3394 §2.2.3.1): 0xA6
    /// repeated over a semiblock.
    pub const ICV: [u8; 8] = [0xA6; 8];

    /// KW over `cipher`; fails with [`CryptoError::InvalidParameter`] for a
    /// cipher of another block size than 128 bits (KW) or 64 bits (TKW),
    /// which SP 800-38F does not define.
    pub fn new(cipher: C) -> Result<KW<C>, CryptoError> {
        if C::BLOCK_SIZE != 16 && C::BLOCK_SIZE != 8 {
            return Err(CryptoError::InvalidParameter);
        }
        Ok(KW { cipher })
    }

    /// The bytes of the wrapping of `length` bytes; fails unless `length` is
    /// whole semiblocks, at least two, within the limit of the cipher.
    pub fn wrapped_length(length: usize) -> Result<usize, CryptoError> {
        let s = Wrapping::<C>::SEMIBLOCK;
        let wrapped = length.checked_add(s).ok_or(CryptoError::InputLength { length })?;
        Wrapping::<C>::check_length(wrapped).map_err(|_| CryptoError::InputLength { length })?;
        Ok(wrapped)
    }

    /// Writes the wrapping of `key` into `out` of [`KW::wrapped_length`] bytes.
    pub fn wrap(&self, key: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let s = Wrapping::<C>::SEMIBLOCK;
        if out.len() != KW::<C>::wrapped_length(key.len())? {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        out[..s].copy_from_slice(&KW::<C>::ICV[..s]);
        out[s..].copy_from_slice(key);
        Wrapping::wrap(&self.cipher, out)
    }

    /// Writes the key `wrapped` holds into `out` of one semiblock fewer;
    /// fails with [`CryptoError::AuthenticationFailed`], `out` zeroed, if
    /// the integrity check fails.
    pub fn unwrap(&self, wrapped: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let s = Wrapping::<C>::SEMIBLOCK;
        if wrapped.len() < s || out.len() != wrapped.len() - s {
            return Err(CryptoError::InputLength { length: wrapped.len() });
        }
        Wrapping::<C>::check(wrapped)?;
        let mut data = alloc::vec::Vec::from(wrapped);
        Wrapping::unwrap(&self.cipher, &mut data)?;
        let valid = data[..s].ct_eq(&KW::<C>::ICV[..s]);
        out.copy_from_slice(&data[s..]);
        data.zeroize();
        if !valid.into_bool() {
            out.zeroize();
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

/// KWP (SP 800-38F §6.3, RFC 5649): KW with padding, over a block cipher of
/// 128 bits, for keys of any length from 1 byte to 2^32 − 1 bytes. The
/// integrity value holds the length; the key is padded with zeros to whole
/// semiblocks.
#[derive(Clone)]
pub struct KWP<C: BlockCipher> {
    cipher: C,
}

impl<C: BlockCipher> KWP<C> {
    /// The constant first half of the integrity value ICV2 (SP 800-38F
    /// §6.3, RFC 5649 §3), followed by the length in bytes.
    pub const ICV: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];
    /// The longest key: 2^32 − 1 bytes.
    pub const MAXIMUM_LENGTH: usize = u32::MAX as usize;

    /// KWP over `cipher`; fails with [`CryptoError::InvalidParameter`] for a
    /// cipher of another block size than 128 bits, which KWP is not defined for.
    pub fn new(cipher: C) -> Result<KWP<C>, CryptoError> {
        if C::BLOCK_SIZE != 16 {
            return Err(CryptoError::InvalidParameter);
        }
        Ok(KWP { cipher })
    }

    /// The bytes of the wrapping of `length` bytes: the length rounded up to
    /// a semiblock, plus one semiblock.
    pub fn wrapped_length(length: usize) -> Result<usize, CryptoError> {
        let error = CryptoError::InputLength { length };
        if length == 0 || u32::try_from(length).is_err() {
            return Err(error);
        }
        length.div_ceil(8).checked_mul(8).and_then(|padded| padded.checked_add(8)).ok_or(error)
    }

    /// Writes the wrapping of `key` into `out` of [`KWP::wrapped_length`] bytes.
    pub fn wrap(&self, key: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != KWP::<C>::wrapped_length(key.len())? {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        out[..4].copy_from_slice(&KWP::<C>::ICV);
        out[4..8].copy_from_slice(&(key.len() as u32).to_be_bytes());
        out[8..8 + key.len()].copy_from_slice(key);
        out[8 + key.len()..].fill(0);
        if out.len() == 16 {
            // A single semiblock is encrypted as one block (RFC 5649 §4.1).
            let mut block = C::Block::default();
            block.as_mut().copy_from_slice(out);
            self.cipher.encrypt_block(&mut block);
            out.copy_from_slice(block.as_ref());
            block.as_mut().zeroize();
            return Ok(());
        }
        Wrapping::wrap(&self.cipher, out)
    }

    /// Writes the key `wrapped` holds into the start of `out` (of at least
    /// `wrapped.len() − 8` bytes) and returns its length; fails with
    /// [`CryptoError::AuthenticationFailed`], `out` zeroed, if the integrity
    /// value, the length or the padding is wrong.
    pub fn unwrap(&self, wrapped: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
        if wrapped.len() < 16 || !wrapped.len().is_multiple_of(8) || out.len() < wrapped.len() - 8 {
            return Err(CryptoError::InputLength { length: wrapped.len() });
        }
        let mut data = alloc::vec::Vec::from(wrapped);
        if data.len() == 16 {
            let mut block = C::Block::default();
            block.as_mut().copy_from_slice(&data);
            self.cipher.decrypt_block(&mut block);
            data.copy_from_slice(block.as_ref());
            block.as_mut().zeroize();
        } else {
            Wrapping::unwrap(&self.cipher, &mut data)?;
        }
        let padded = (data.len() - 8) as u64;
        let length = u64::from(u32::from_be_bytes([data[4], data[5], data[6], data[7]]));
        let mut valid = data[..4].ct_eq(&KWP::<C>::ICV);
        // 8(n − 1) < length ≤ 8n, as differences of values below 2^63.
        valid &= Choice::from_bit(((padded - 8).wrapping_sub(length) >> 63) as u8);
        valid &= Choice::from_bit((length.wrapping_sub(padded + 1) >> 63) as u8);
        // The bytes after the length, within the last semiblock, are zero.
        let mut padding: u64 = 0;
        for (offset, byte) in data[data.len() - 8..].iter().enumerate() {
            let position = padded - 8 + offset as u64;
            let beyond = (length.wrapping_sub(position + 1) >> 63) & 1;
            padding |= u64::from(*byte) & beyond.wrapping_neg();
        }
        valid &= padding.ct_eq(&0);
        let length = length as usize;
        out[..data.len() - 8].copy_from_slice(&data[8..]);
        data.zeroize();
        if !valid.into_bool() {
            out.zeroize();
            return Err(CryptoError::AuthenticationFailed);
        }
        out[length..].zeroize();
        Ok(length)
    }
}

impl<C: BlockCipher> Zeroize for KW<C> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
    }
}

impl<C: BlockCipher> Zeroize for KWP<C> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
    }
}

impl<C: BlockCipher> fmt::Debug for KW<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KW(..)")
    }
}

impl<C: BlockCipher> fmt::Debug for KWP<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KWP(..)")
    }
}
