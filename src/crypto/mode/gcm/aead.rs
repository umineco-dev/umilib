use core::fmt;

use super::GHASH;
use crate::crypto::mode::ctr::CTR;
use crate::crypto::{AEAD, BlockCipher, CryptoError, KeyInit, StreamCipher};
use crate::secret::{ConstantTimeEq, Zeroize};

/// GCM (SP 800-38D) over the 128-bit block cipher `C` with tags of `TAG`
/// bytes: 16 (the default), 15 to 12, or, only where SP 800-38D appendix C
/// allows, 8 and 4.
///
/// The IV may have any length from 1 byte; 12 bytes is the recommended one,
/// the counter block of every other length is derived with GHASH. One key
/// encrypts at most 2^36 - 32 bytes per message. Decryption authenticates the
/// ciphertext before it decrypts any of it.
#[derive(Clone)]
pub struct GCM<C: BlockCipher<Block = [u8; 16]>, const TAG: usize = 16> {
    cipher: C,
    /// The hash subkey H = E(0^128).
    h: [u8; 16],
}

impl<C: BlockCipher<Block = [u8; 16]>, const TAG: usize> GCM<C, TAG> {
    /// The longest plaintext of a message: 2^39 - 256 bits.
    pub const MAXIMUM_INPUT: u64 = (1 << 36) - 32;
    /// The recommended IV length.
    pub const IV_SIZE: usize = 12;
    const TAG_IS_VALID: () = assert!(matches!(TAG, 4 | 8 | 12..=16), "GCM tags have 4, 8 or 12 to 16 bytes");

    pub fn new(cipher: C) -> GCM<C, TAG> {
        #[allow(clippy::let_unit_value)]
        let () = GCM::<C, TAG>::TAG_IS_VALID;
        let mut h = [0u8; 16];
        cipher.encrypt_block(&mut h);
        GCM { cipher, h }
    }

    /// The pre-counter block J0 of `iv` (section 7.1, step 2).
    pub fn initial_counter(&self, iv: &[u8]) -> Result<[u8; 16], CryptoError> {
        if iv.is_empty() || iv.len() as u64 > u64::MAX / 8 {
            return Err(CryptoError::NonceLength { length: iv.len(), minimum: 1, maximum: (u64::MAX / 8) as usize });
        }
        let mut counter = [0u8; 16];
        if iv.len() == GCM::<C, TAG>::IV_SIZE {
            counter[..12].copy_from_slice(iv);
            counter[15] = 1;
            return Ok(counter);
        }
        let mut ghash = GHASH::new(&self.h);
        ghash.update(iv);
        ghash.pad();
        let mut lengths = [0u8; 16];
        lengths[8..].copy_from_slice(&(8 * iv.len() as u64).to_be_bytes());
        ghash.update(&lengths);
        Ok(ghash.finalize())
    }

    /// The tag of `associated` and `ciphertext` for the pre-counter block `counter` (section 7.1, steps 5 and 6).
    pub fn tag(&self, counter: &[u8; 16], associated: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        let mut ghash = GHASH::new(&self.h);
        ghash.update(associated);
        ghash.pad();
        ghash.update(ciphertext);
        ghash.pad();
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&(8 * associated.len() as u64).to_be_bytes());
        lengths[8..].copy_from_slice(&(8 * ciphertext.len() as u64).to_be_bytes());
        ghash.update(&lengths);
        let mut tag = ghash.finalize();
        let mut mask = *counter;
        self.cipher.encrypt_block(&mut mask);
        for (byte, value) in tag.iter_mut().zip(&mask) {
            *byte ^= value;
        }
        mask.zeroize();
        tag
    }

    /// The key stream from inc32(J0), applied to `data` (GCTR, section 6.5).
    pub fn apply(&self, counter: &[u8; 16], data: &mut [u8]) -> Result<(), CryptoError> {
        let mut first = *counter;
        CTR::<C>::increment(&mut first, 32);
        let mut ctr = CTR::with_counter_bits(self.cipher.clone(), &first, 32)?;
        ctr.apply_keystream(data)
    }

    /// Checks the lengths of a message (section 5.2.1.1).
    pub fn check(associated: &[u8], data: &[u8]) -> Result<(), CryptoError> {
        if data.len() as u64 > GCM::<C, TAG>::MAXIMUM_INPUT {
            return Err(CryptoError::InputLength { length: data.len() });
        }
        if associated.len() as u64 > u64::MAX / 8 {
            return Err(CryptoError::InputLength { length: associated.len() });
        }
        Ok(())
    }
}

impl<C: BlockCipher<Block = [u8; 16]>, const TAG: usize> AEAD for GCM<C, TAG> {
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = TAG;
    type Tag = [u8; TAG];

    fn encrypt_in_place(&self, nonce: &[u8], associated: &[u8], buffer: &mut [u8]) -> Result<[u8; TAG], CryptoError> {
        GCM::<C, TAG>::check(associated, buffer)?;
        let mut counter = self.initial_counter(nonce)?;
        self.apply(&counter, buffer)?;
        let mut full = self.tag(&counter, associated, buffer);
        let mut tag = [0u8; TAG];
        tag.copy_from_slice(&full[..TAG]);
        full.zeroize();
        counter.zeroize();
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
        GCM::<C, TAG>::check(associated, buffer)?;
        let mut counter = self.initial_counter(nonce)?;
        let mut expected = self.tag(&counter, associated, buffer);
        let valid = expected[..TAG].ct_eq(tag).into_bool();
        expected.zeroize();
        if !valid {
            counter.zeroize();
            return Err(CryptoError::AuthenticationFailed);
        }
        let result = self.apply(&counter, buffer);
        counter.zeroize();
        result
    }
}

impl<C: BlockCipher<Block = [u8; 16]> + KeyInit, const TAG: usize> KeyInit for GCM<C, TAG> {
    const MINIMUM_KEY_SIZE: usize = C::MINIMUM_KEY_SIZE;
    const MAXIMUM_KEY_SIZE: usize = C::MAXIMUM_KEY_SIZE;

    fn new_from_slice(key: &[u8]) -> Result<GCM<C, TAG>, CryptoError> {
        Ok(GCM::new(C::new_from_slice(key)?))
    }
}

impl<C: BlockCipher<Block = [u8; 16]>, const TAG: usize> Zeroize for GCM<C, TAG> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.h.zeroize();
    }
}

impl<C: BlockCipher<Block = [u8; 16]>, const TAG: usize> Drop for GCM<C, TAG> {
    fn drop(&mut self) {
        self.h.zeroize();
    }
}

impl<C: BlockCipher<Block = [u8; 16]>, const TAG: usize> fmt::Debug for GCM<C, TAG> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GCM({TAG}-byte tags, ..)")
    }
}
