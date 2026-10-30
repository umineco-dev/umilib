//! The XTS mode for storage (SP 800-38E, IEEE 1619): each data unit (such as
//! a disk sector) is encrypted under a tweak, without expansion.

use core::fmt;

use crate::crypto::{BlockCipher, CryptoError, KeyInit};
use crate::secret::{ConstantTimeEq, Zeroize};

/// XTS over the 128-bit block cipher `C`, with one key for the data and one
/// for the tweaks.
///
/// A data unit has at least 16 bytes; a last partial block is handled by
/// ciphertext stealing. Data units of a number of bits that is not a whole
/// number of bytes, which IEEE 1619 allows, are not supported.
#[derive(Clone)]
pub struct XTS<C: BlockCipher<Block = [u8; 16]>> {
    data: C,
    tweak: C,
}

impl<C: BlockCipher<Block = [u8; 16]>> XTS<C> {
    pub const MINIMUM_DATA_UNIT: usize = 16;
    /// The longest data unit: 2^20 blocks (SP 800-38E section 4).
    pub const MAXIMUM_DATA_UNIT: usize = 16 << 20;

    /// XTS with the cipher of the data key and the cipher of the tweak key,
    /// which must be different keys (SP 800-38E section 4): check them with
    /// [`XTS::check_keys`] ([`KeyInit`] does).
    pub fn new(data: C, tweak: C) -> XTS<C> {
        XTS { data, tweak }
    }

    /// Fails with InvalidParameter unless the data key and the tweak key have
    /// the same length and differ (compared in constant time).
    pub fn check_keys(data: &[u8], tweak: &[u8]) -> Result<(), CryptoError> {
        if data.len() != tweak.len() || data.ct_eq(tweak).into_bool() {
            return Err(CryptoError::InvalidParameter);
        }
        Ok(())
    }

    /// The tweak of data unit number `unit`: its little-endian encoding (IEEE 1619 section 5.1).
    pub fn tweak_of(unit: u128) -> [u8; 16] {
        unit.to_le_bytes()
    }

    /// Multiplication by α = x in GF(2^128), little-endian (IEEE 1619 section 5.2).
    pub fn double(tweak: &mut [u8; 16]) {
        let value = u128::from_le_bytes(*tweak);
        let carry = value >> 127;
        let doubled = (value << 1) ^ (0x87 & carry.wrapping_neg());
        *tweak = doubled.to_le_bytes();
    }

    /// Encrypts the data unit `data` (16 bytes to 2^20 blocks) under `tweak`.
    pub fn encrypt(&self, tweak: &[u8; 16], data: &mut [u8]) -> Result<(), CryptoError> {
        self.process(tweak, data, true)
    }

    /// Decrypts the data unit `data` (16 bytes to 2^20 blocks) under `tweak`.
    pub fn decrypt(&self, tweak: &[u8; 16], data: &mut [u8]) -> Result<(), CryptoError> {
        self.process(tweak, data, false)
    }

    pub fn process(&self, tweak: &[u8; 16], data: &mut [u8], encrypt: bool) -> Result<(), CryptoError> {
        if !(XTS::<C>::MINIMUM_DATA_UNIT..=XTS::<C>::MAXIMUM_DATA_UNIT).contains(&data.len()) {
            return Err(CryptoError::InputLength { length: data.len() });
        }
        let mut t = *tweak;
        self.tweak.encrypt_block(&mut t);
        let whole = data.len() / 16;
        let remainder = data.len() % 16;
        // With a partial last block, the last whole block is processed with the ciphertext stealing below.
        let simple = if remainder == 0 { whole } else { whole - 1 };
        let mut blocks = [[0u8; 16]; 8];
        let mut tweaks = [[0u8; 16]; 8];
        let mut index = 0;
        while index < simple {
            let count = (simple - index).min(8);
            for slot in 0..count {
                tweaks[slot] = t;
                XTS::<C>::double(&mut t);
                let offset = 16 * (index + slot);
                for (byte, (value, mask)) in
                    blocks[slot].iter_mut().zip(data[offset..offset + 16].iter().zip(&tweaks[slot]))
                {
                    *byte = value ^ mask;
                }
            }
            if encrypt {
                self.data.encrypt_blocks(&mut blocks[..count])
            } else {
                self.data.decrypt_blocks(&mut blocks[..count])
            }
            for slot in 0..count {
                let offset = 16 * (index + slot);
                for (byte, (value, mask)) in
                    data[offset..offset + 16].iter_mut().zip(blocks[slot].iter().zip(&tweaks[slot]))
                {
                    *byte = value ^ mask;
                }
            }
            index += count;
        }
        if remainder != 0 {
            // Ciphertext stealing (IEEE 1619 section 5.3.2): the last whole block and the
            // partial block swap their tails; decryption uses the two tweaks in reverse order.
            let mut next = t;
            XTS::<C>::double(&mut next);
            let (first, second) = if encrypt { (t, next) } else { (next, t) };
            let offset = 16 * simple;
            let mut block: [u8; 16] = data[offset..offset + 16].try_into().expect("a whole block");
            self.block(&first, &mut block, encrypt);
            let mut last = [0u8; 16];
            last[..remainder].copy_from_slice(&data[offset + 16..]);
            last[remainder..].copy_from_slice(&block[remainder..]);
            data[offset + 16..].copy_from_slice(&block[..remainder]);
            self.block(&second, &mut last, encrypt);
            data[offset..offset + 16].copy_from_slice(&last);
            block.zeroize();
            last.zeroize();
            next.zeroize();
        }
        blocks.zeroize();
        tweaks.zeroize();
        t.zeroize();
        Ok(())
    }

    /// One block: xor with the tweak, the cipher, xor with the tweak.
    pub fn block(&self, tweak: &[u8; 16], block: &mut [u8; 16], encrypt: bool) {
        for (byte, mask) in block.iter_mut().zip(tweak) {
            *byte ^= mask;
        }
        if encrypt {
            self.data.encrypt_block(block)
        } else {
            self.data.decrypt_block(block)
        }
        for (byte, mask) in block.iter_mut().zip(tweak) {
            *byte ^= mask;
        }
    }
}

impl<C: BlockCipher<Block = [u8; 16]> + KeyInit> KeyInit for XTS<C> {
    const MINIMUM_KEY_SIZE: usize = 2 * C::MINIMUM_KEY_SIZE;
    const MAXIMUM_KEY_SIZE: usize = 2 * C::MAXIMUM_KEY_SIZE;

    /// XTS with the double-length key `key`: the data key, then the tweak
    /// key, which must differ (compared in constant time).
    fn new_from_slice(key: &[u8]) -> Result<XTS<C>, CryptoError> {
        if !key.len().is_multiple_of(2) {
            return Err(CryptoError::KeyLength {
                length: key.len(),
                minimum: XTS::<C>::MINIMUM_KEY_SIZE,
                maximum: XTS::<C>::MAXIMUM_KEY_SIZE,
            });
        }
        XTS::<C>::check_key_length(key.len())?;
        let (data, tweak) = key.split_at(key.len() / 2);
        XTS::<C>::check_keys(data, tweak)?;
        Ok(XTS::new(C::new_from_slice(data)?, C::new_from_slice(tweak)?))
    }
}

impl<C: BlockCipher<Block = [u8; 16]>> Zeroize for XTS<C> {
    fn zeroize(&mut self) {
        self.data.zeroize();
        self.tweak.zeroize();
    }
}

impl<C: BlockCipher<Block = [u8; 16]>> fmt::Debug for XTS<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XTS(..)")
    }
}
