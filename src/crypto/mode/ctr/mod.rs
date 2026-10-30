//! The counter mode (SP 800-38A section 6.5).

use core::fmt;

use crate::crypto::mode::Blocks;
use crate::crypto::{BlockCipher, CryptoError, StreamCipher};
use crate::secret::Zeroize;

/// CTR over the block cipher `C`: the key stream is the cipher applied to
/// successive counter blocks, which the cipher encrypts in groups.
///
/// The counter is the last `counter_bits` bits of the block, incremented
/// modulo 2^`counter_bits` as a big-endian number (the standard incrementing
/// function of SP 800-38A appendix B.1); the other bits stay fixed. When
/// every counter value has been used, further key stream fails with
/// [`CryptoError::LimitExceeded`] instead of repeating.
#[derive(Clone)]
pub struct CTR<C: BlockCipher> {
    cipher: C,
    counter: C::Block,
    counter_bits: u32,
    /// The counter blocks still allowed, or `None` for a counter of 128 bits,
    /// whose 2^128 values no computation can exhaust.
    remaining: Option<u128>,
    keystream: [C::Block; Blocks::GROUP],
    /// The bytes of `keystream` used, up to `available`.
    position: usize,
    available: usize,
}

impl<C: BlockCipher> CTR<C> {
    /// CTR with the whole block as the counter.
    pub fn new(cipher: C, initial: &C::Block) -> CTR<C> {
        CTR::with_counter_bits(cipher, initial, 8 * C::BLOCK_SIZE as u32).expect("the whole block is a valid counter")
    }

    /// CTR with the last `counter_bits` bits (1 to the block size) of the block as the counter.
    pub fn with_counter_bits(cipher: C, initial: &C::Block, counter_bits: u32) -> Result<CTR<C>, CryptoError> {
        if counter_bits == 0 || counter_bits as usize > 8 * C::BLOCK_SIZE {
            return Err(CryptoError::InvalidParameter);
        }
        let remaining = 1u128.checked_shl(counter_bits);
        Ok(CTR {
            cipher,
            counter: *initial,
            counter_bits,
            remaining,
            keystream: [C::Block::default(); Blocks::GROUP],
            position: 0,
            available: 0,
        })
    }

    /// Adds one to the counter bits of `block`, modulo 2^`counter_bits`.
    pub fn increment(block: &mut C::Block, counter_bits: u32) {
        let bytes = block.as_mut();
        let mut carry = 1u16;
        let mut bits = counter_bits;
        for byte in bytes.iter_mut().rev() {
            if bits == 0 {
                break;
            }
            let width = bits.min(8);
            let mask = (0xFFu16 >> (8 - width)) as u8;
            let sum = (*byte & mask) as u16 + carry;
            carry = sum >> width;
            *byte = (*byte & !mask) | (sum as u8 & mask);
            bits -= width;
        }
    }

    /// Fills the key stream buffer with the next group of counter blocks.
    pub fn refill(&mut self) -> Result<(), CryptoError> {
        let count = match self.remaining {
            Some(0) => return Err(CryptoError::LimitExceeded),
            Some(remaining) => remaining.min(Blocks::GROUP as u128) as usize,
            None => Blocks::GROUP,
        };
        for block in self.keystream[..count].iter_mut() {
            *block = self.counter;
            CTR::<C>::increment(&mut self.counter, self.counter_bits);
        }
        self.cipher.encrypt_blocks(&mut self.keystream[..count]);
        if let Some(remaining) = &mut self.remaining {
            *remaining -= count as u128;
        }
        self.position = 0;
        self.available = count * C::BLOCK_SIZE;
        Ok(())
    }

    /// The number of key stream bytes left before the counter runs out, or
    /// `None` if it does not fit in a `u128` (counters of 124 bits or more
    /// with 16-byte blocks).
    pub fn remaining_bytes(&self) -> Option<u128> {
        self.remaining?.checked_mul(C::BLOCK_SIZE as u128)?.checked_add((self.available - self.position) as u128)
    }
}

impl<C: BlockCipher> StreamCipher for CTR<C> {
    fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        if self.remaining_bytes().is_some_and(|remaining| (data.len() as u128) > remaining) {
            return Err(CryptoError::LimitExceeded);
        }
        let mut data = data;
        while !data.is_empty() {
            if self.position == self.available {
                self.refill()?;
            }
            let take = (self.available - self.position).min(data.len());
            for (index, byte) in data[..take].iter_mut().enumerate() {
                let offset = self.position + index;
                *byte ^= self.keystream[offset / C::BLOCK_SIZE].as_ref()[offset % C::BLOCK_SIZE];
            }
            self.position += take;
            data = &mut data[take..];
        }
        Ok(())
    }
}

impl<C: BlockCipher> Zeroize for CTR<C> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.counter.as_mut().zeroize();
        self.keystream.iter_mut().for_each(|block| block.as_mut().zeroize());
    }
}

impl<C: BlockCipher> Drop for CTR<C> {
    fn drop(&mut self) {
        self.counter.as_mut().zeroize();
        self.keystream.iter_mut().for_each(|block| block.as_mut().zeroize());
    }
}

impl<C: BlockCipher> fmt::Debug for CTR<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CTR(..)")
    }
}
