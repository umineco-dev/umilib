//! The counter with CBC-MAC mode (SP 800-38C, RFC 3610).

use core::fmt;

use crate::crypto::mode::Blocks;
use crate::crypto::{AEAD, BlockCipher, CryptoError, KeyInit};
use crate::secret::{ConstantTimeEq, Zeroize};

/// CCM over the 128-bit block cipher `C` with tags of `TAG` bytes (4, 6, 8,
/// 10, 12, 14 or 16).
///
/// The nonce has 7 to 13 bytes; a nonce of `n` bytes leaves `15 - n` bytes
/// for the payload length, so it limits the payload to 2^(8 × (15 - n)) - 1
/// bytes. CCM authenticates the plaintext, so decryption decrypts first; when
/// the tag does not match it encrypts again, so the buffer holds the
/// ciphertext as it was and no plaintext.
#[derive(Clone)]
pub struct CCM<C: BlockCipher<Block = [u8; 16]>, const TAG: usize> {
    cipher: C,
}

impl<C: BlockCipher<Block = [u8; 16]>, const TAG: usize> CCM<C, TAG> {
    pub const MINIMUM_NONCE_SIZE: usize = 7;
    pub const MAXIMUM_NONCE_SIZE: usize = 13;
    const TAG_IS_VALID: () =
        assert!(matches!(TAG, 4 | 6 | 8 | 10 | 12 | 14 | 16), "CCM tags have 4 to 16 bytes, an even number");

    pub fn new(cipher: C) -> CCM<C, TAG> {
        #[allow(clippy::let_unit_value)]
        let () = CCM::<C, TAG>::TAG_IS_VALID;
        CCM { cipher }
    }

    /// Checks the nonce and the payload length; the length field has `15 - nonce.len()` bytes.
    pub fn check(nonce: &[u8], payload: usize) -> Result<(), CryptoError> {
        if !(CCM::<C, TAG>::MINIMUM_NONCE_SIZE..=CCM::<C, TAG>::MAXIMUM_NONCE_SIZE).contains(&nonce.len()) {
            return Err(CryptoError::NonceLength { length: nonce.len(), minimum: 7, maximum: 13 });
        }
        let length_bytes = 15 - nonce.len();
        if length_bytes < 8 && (payload as u64) >> (8 * length_bytes) != 0 {
            return Err(CryptoError::InputLength { length: payload });
        }
        Ok(())
    }

    /// The counter block Ctr_i (SP 800-38C appendix A.3).
    pub fn counter(nonce: &[u8], index: u64) -> [u8; 16] {
        let length_bytes = 15 - nonce.len();
        let mut block = [0u8; 16];
        block[0] = (length_bytes - 1) as u8;
        block[1..1 + nonce.len()].copy_from_slice(nonce);
        let bytes = index.to_be_bytes();
        block[16 - length_bytes.min(8)..].copy_from_slice(&bytes[8 - length_bytes.min(8)..]);
        block
    }

    /// The CBC-MAC of the formatted input (appendix A.2) before encryption by S0.
    pub fn mac(&self, nonce: &[u8], associated: &[u8], payload: &[u8]) -> [u8; 16] {
        let length_bytes = 15 - nonce.len();
        let mut block = [0u8; 16];
        block[0] = ((!associated.is_empty() as u8) << 6) | ((((TAG - 2) / 2) as u8) << 3) | (length_bytes - 1) as u8;
        block[1..1 + nonce.len()].copy_from_slice(nonce);
        let length = (payload.len() as u64).to_be_bytes();
        block[16 - length_bytes.min(8)..].copy_from_slice(&length[8 - length_bytes.min(8)..]);
        self.cipher.encrypt_block(&mut block);
        let mut mac = CBCMAC::new(&self.cipher, block);
        if !associated.is_empty() {
            let length = associated.len() as u64;
            if length < 0xFF00 {
                mac.update(&(length as u16).to_be_bytes());
            } else if length <= u32::MAX as u64 {
                mac.update(&[0xFF, 0xFE]);
                mac.update(&(length as u32).to_be_bytes());
            } else {
                mac.update(&[0xFF, 0xFF]);
                mac.update(&length.to_be_bytes());
            }
            mac.update(associated);
            mac.pad();
        }
        mac.update(payload);
        mac.pad();
        *mac.state()
    }

    /// The key stream from Ctr_1, applied to `data`.
    pub fn apply(&self, nonce: &[u8], data: &mut [u8]) {
        let mut index = 1u64;
        for chunk in data.chunks_mut(16 * Blocks::GROUP) {
            let mut keystream = [[0u8; 16]; Blocks::GROUP];
            let count = chunk.len().div_ceil(16);
            for block in keystream[..count].iter_mut() {
                *block = CCM::<C, TAG>::counter(nonce, index);
                index += 1;
            }
            self.cipher.encrypt_blocks(&mut keystream[..count]);
            Blocks::xor(chunk, keystream.as_flattened());
            keystream.zeroize();
        }
    }

    /// The tag of a payload: the MAC encrypted by S0 = E(Ctr_0), cut to `TAG` bytes.
    pub fn tag(&self, nonce: &[u8], associated: &[u8], payload: &[u8]) -> [u8; TAG] {
        let mut mac = self.mac(nonce, associated, payload);
        let mut s0 = CCM::<C, TAG>::counter(nonce, 0);
        self.cipher.encrypt_block(&mut s0);
        let mut tag = [0u8; TAG];
        for ((byte, value), mask) in tag.iter_mut().zip(&mac).zip(&s0) {
            *byte = value ^ mask;
        }
        mac.zeroize();
        s0.zeroize();
        tag
    }
}

/// The CBC-MAC that CCM computes over its formatted input, in blocks
/// completed with zeros by [`CBCMAC::pad`]. It is not a MAC on its own: it is
/// secure only for the prefix-free inputs that CCM formats.
pub struct CBCMAC<'a, C: BlockCipher<Block = [u8; 16]>> {
    cipher: &'a C,
    state: [u8; 16],
    position: usize,
}

impl<'a, C: BlockCipher<Block = [u8; 16]>> CBCMAC<'a, C> {
    /// The MAC from the encrypted first block `state`.
    pub fn new(cipher: &'a C, state: [u8; 16]) -> CBCMAC<'a, C> {
        CBCMAC { cipher, state, position: 0 }
    }

    /// The current chaining value.
    pub fn state(&self) -> &[u8; 16] {
        &self.state
    }

    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.state[self.position] ^= byte;
            self.position += 1;
            if self.position == 16 {
                self.cipher.encrypt_block(&mut self.state);
                self.position = 0;
            }
        }
    }

    /// Completes a partial block with zeros.
    pub fn pad(&mut self) {
        if self.position != 0 {
            self.cipher.encrypt_block(&mut self.state);
            self.position = 0;
        }
    }
}

impl<C: BlockCipher<Block = [u8; 16]>> Drop for CBCMAC<'_, C> {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

impl<C: BlockCipher<Block = [u8; 16]>, const TAG: usize> AEAD for CCM<C, TAG> {
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = TAG;
    type Tag = [u8; TAG];

    fn encrypt_in_place(&self, nonce: &[u8], associated: &[u8], buffer: &mut [u8]) -> Result<[u8; TAG], CryptoError> {
        CCM::<C, TAG>::check(nonce, buffer.len())?;
        let tag = self.tag(nonce, associated, buffer);
        self.apply(nonce, buffer);
        Ok(tag)
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        associated: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        if tag.len() != TAG {
            return Err(CryptoError::TagLength { length: tag.len(), minimum: TAG, maximum: TAG });
        }
        CCM::<C, TAG>::check(nonce, buffer.len())?;
        self.apply(nonce, buffer);
        let mut expected = self.tag(nonce, associated, buffer);
        let valid = expected[..].ct_eq(tag).into_bool();
        expected.zeroize();
        if !valid {
            self.apply(nonce, buffer);
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

impl<C: BlockCipher<Block = [u8; 16]> + KeyInit, const TAG: usize> KeyInit for CCM<C, TAG> {
    const MINIMUM_KEY_SIZE: usize = C::MINIMUM_KEY_SIZE;
    const MAXIMUM_KEY_SIZE: usize = C::MAXIMUM_KEY_SIZE;

    fn new_from_slice(key: &[u8]) -> Result<CCM<C, TAG>, CryptoError> {
        Ok(CCM::new(C::new_from_slice(key)?))
    }
}

impl<C: BlockCipher<Block = [u8; 16]>, const TAG: usize> Zeroize for CCM<C, TAG> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
    }
}

impl<C: BlockCipher<Block = [u8; 16]>, const TAG: usize> fmt::Debug for CCM<C, TAG> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CCM({TAG}-byte tags, ..)")
    }
}
