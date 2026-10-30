//! The cipher feedback mode (SP 800-38A section 6.3) with segments of a
//! whole block ([`CFB`]), of 8 bits ([`CFB8`]) and of 1 bit ([`CFB1`]).

use core::fmt;

use crate::crypto::{BlockCipher, CryptoError};
use crate::secret::Zeroize;

/// Defines the functions and traits that every segment size shares.
macro_rules! cfb_common {
    ($name:ident) => {
        impl<C: BlockCipher> Zeroize for $name<C> {
            fn zeroize(&mut self) {
                self.cipher.zeroize();
                self.register.as_mut().zeroize();
                self.output.as_mut().zeroize();
            }
        }

        impl<C: BlockCipher> Drop for $name<C> {
            fn drop(&mut self) {
                self.register.as_mut().zeroize();
                self.output.as_mut().zeroize();
            }
        }

        impl<C: BlockCipher> fmt::Debug for $name<C> {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

/// CFB with segments of a whole block over the block cipher `C`, for data
/// of any length, processed in pieces of any length.
#[derive(Clone)]
pub struct CFB<C: BlockCipher> {
    cipher: C,
    /// The input block of the cipher: the IV, then the last ciphertext block,
    /// overwritten byte by byte as the current block's ciphertext is made.
    register: C::Block,
    /// The output of the cipher for the current segment.
    output: C::Block,
    position: usize,
}

impl<C: BlockCipher> CFB<C> {
    pub fn new(cipher: C, iv: &C::Block) -> CFB<C> {
        CFB { cipher, register: *iv, output: C::Block::default(), position: C::BLOCK_SIZE }
    }

    /// The next byte of output, after which the byte of ciphertext `ciphertext` is fed back.
    pub fn step(&mut self, ciphertext: impl FnOnce(u8) -> u8) -> u8 {
        if self.position == C::BLOCK_SIZE {
            self.output = self.register;
            self.cipher.encrypt_block(&mut self.output);
            self.position = 0;
        }
        let key = self.output.as_ref()[self.position];
        let byte = ciphertext(key);
        self.register.as_mut()[self.position] = byte;
        self.position += 1;
        key
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            let plaintext = *byte;
            self.step(|key| {
                let ciphertext = plaintext ^ key;
                *byte = ciphertext;
                ciphertext
            });
        }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            let ciphertext = *byte;
            let key = self.step(|_| ciphertext);
            *byte = ciphertext ^ key;
        }
    }
}

cfb_common!(CFB);

/// CFB with segments of 8 bits (CFB8) over the block cipher `C`: one
/// encryption of the cipher per byte.
#[derive(Clone)]
pub struct CFB8<C: BlockCipher> {
    cipher: C,
    register: C::Block,
    output: C::Block,
}

impl<C: BlockCipher> CFB8<C> {
    pub fn new(cipher: C, iv: &C::Block) -> CFB8<C> {
        CFB8 { cipher, register: *iv, output: C::Block::default() }
    }

    /// The key byte of the next segment, after which `ciphertext` is shifted into the register.
    pub fn step(&mut self, ciphertext: impl FnOnce(u8) -> u8) -> u8 {
        self.output = self.register;
        self.cipher.encrypt_block(&mut self.output);
        let key = self.output.as_ref()[0];
        let byte = ciphertext(key);
        let register = self.register.as_mut();
        register.copy_within(1.., 0);
        register[C::BLOCK_SIZE - 1] = byte;
        key
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            let plaintext = *byte;
            self.step(|key| {
                *byte = plaintext ^ key;
                *byte
            });
        }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            let ciphertext = *byte;
            let key = self.step(|_| ciphertext);
            *byte = ciphertext ^ key;
        }
    }
}

cfb_common!(CFB8);

/// CFB with segments of 1 bit (CFB1) over the block cipher `C`: one
/// encryption of the cipher per bit, the bits of each byte from the most
/// significant one.
#[derive(Clone)]
pub struct CFB1<C: BlockCipher> {
    cipher: C,
    register: C::Block,
    output: C::Block,
}

impl<C: BlockCipher> CFB1<C> {
    pub fn new(cipher: C, iv: &C::Block) -> CFB1<C> {
        CFB1 { cipher, register: *iv, output: C::Block::default() }
    }

    /// The key bit of the next segment, after which the ciphertext bit is shifted into the register.
    pub fn step(&mut self, ciphertext: impl FnOnce(u8) -> u8) -> u8 {
        self.output = self.register;
        self.cipher.encrypt_block(&mut self.output);
        let key = self.output.as_ref()[0] >> 7;
        let bit = ciphertext(key) & 1;
        let register = self.register.as_mut();
        for index in 0..C::BLOCK_SIZE {
            let next = if index + 1 < C::BLOCK_SIZE { register[index + 1] >> 7 } else { bit };
            register[index] = (register[index] << 1) | next;
        }
        key
    }

    /// Encrypts the first `bits` bits of `data`; fails if `data` has fewer.
    pub fn encrypt_bits(&mut self, data: &mut [u8], bits: usize) -> Result<(), CryptoError> {
        CFB1::<C>::check(data, bits)?;
        for index in 0..bits {
            let (byte, shift) = (index / 8, 7 - index % 8);
            let plaintext = (data[byte] >> shift) & 1;
            let key = self.step(|key| plaintext ^ key);
            data[byte] ^= key << shift;
        }
        Ok(())
    }

    /// Decrypts the first `bits` bits of `data`; fails if `data` has fewer.
    pub fn decrypt_bits(&mut self, data: &mut [u8], bits: usize) -> Result<(), CryptoError> {
        CFB1::<C>::check(data, bits)?;
        for index in 0..bits {
            let (byte, shift) = (index / 8, 7 - index % 8);
            let ciphertext = (data[byte] >> shift) & 1;
            let key = self.step(|_| ciphertext);
            data[byte] ^= key << shift;
        }
        Ok(())
    }

    pub fn check(data: &[u8], bits: usize) -> Result<(), CryptoError> {
        if bits.div_ceil(8) > data.len() {
            return Err(CryptoError::InputLength { length: data.len() });
        }
        Ok(())
    }
}

cfb_common!(CFB1);
