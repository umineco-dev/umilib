use core::fmt;

use super::{DRBG, DRBGConfig, Random, RandomError};
use crate::crypto::{BlockCipher, KeyInit};
use crate::secret::Zeroize;

/// CTR_DRBG over the 128-bit block cipher `C` (SP 800-90A section 10.2.1)
/// with AES-128, AES-192 or AES-256: the counter is the whole block.
///
/// [`DRBG::instantiate`] uses the derivation function Block_Cipher_df
/// (section 10.3.2), which accepts entropy inputs of any length;
/// [`CTRDRBG::instantiate_without_derivation`] takes an entropy input of
/// exactly seedlen bits of full entropy and no nonce. The TDEA variant of
/// table 3 is not provided: its keys are not keys of `C`, and SP 800-131A
/// no longer allows it. It cannot be cloned: two copies would generate the
/// same bytes.
pub struct CTRDRBG<C: BlockCipher<Block = [u8; 16]> + KeyInit> {
    /// The cipher keyed with Key.
    cipher: C,
    value: [u8; 16],
    derivation: bool,
    /// The number of requests since the last reseed, from 1; 0 once uninstantiated.
    reseed_counter: u64,
    config: DRBGConfig,
}

impl<C: BlockCipher<Block = [u8; 16]> + KeyInit> CTRDRBG<C> {
    /// keylen in bytes.
    pub const KEY_LENGTH: usize = C::MAXIMUM_KEY_SIZE;
    /// seedlen = outlen + keylen, in bytes (table 3).
    pub const SEED_LENGTH: usize = 16 + C::MAXIMUM_KEY_SIZE;
    /// The seed material is held in 48 bytes: at most 32 bytes of key and 16 of block.
    const SEED_FITS: () = assert!(
        16 + C::MAXIMUM_KEY_SIZE <= 48 && C::MINIMUM_KEY_SIZE == C::MAXIMUM_KEY_SIZE,
        "CTR_DRBG takes a cipher with one key size of at most 32 bytes"
    );

    /// Instantiates the generator with the derivation function and the default limits.
    pub fn new(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<CTRDRBG<C>, RandomError> {
        CTRDRBG::instantiate(DRBGConfig::default(), entropy, nonce, personalization)
    }

    /// Instantiates the generator without a derivation function (section
    /// 10.2.1.3.1): the entropy input has exactly seedlen bytes and the
    /// personalization string at most seedlen.
    pub fn instantiate_without_derivation(
        config: DRBGConfig,
        entropy: &[u8],
        personalization: &[u8],
    ) -> Result<CTRDRBG<C>, RandomError> {
        let seed_length = CTRDRBG::<C>::SEED_LENGTH;
        if entropy.len() != seed_length {
            return Err(RandomError::EntropyLength { length: entropy.len(), minimum: seed_length });
        }
        if personalization.len() > seed_length {
            return Err(RandomError::InputLength { length: personalization.len(), maximum: seed_length });
        }
        let mut seed = [0u8; 48];
        seed[..personalization.len()].copy_from_slice(personalization);
        for (byte, value) in seed.iter_mut().zip(entropy) {
            *byte ^= value;
        }
        let mut state = CTRDRBG::<C>::zero(config, false);
        state.update(&seed[..seed_length]);
        seed.zeroize();
        Ok(state)
    }

    /// Key = 0^keylen and V = 0^outlen, before the first update.
    fn zero(config: DRBGConfig, derivation: bool) -> CTRDRBG<C> {
        #[allow(clippy::let_unit_value)]
        let () = CTRDRBG::<C>::SEED_FITS;
        let cipher =
            C::new_from_slice(&[0u8; 32][..CTRDRBG::<C>::KEY_LENGTH]).expect("keylen is a key size of the cipher");
        CTRDRBG { cipher, value: [0; 16], derivation, reseed_counter: 1, config: config.clamped() }
    }

    /// Adds one to V modulo 2^128.
    pub fn increment(value: &mut [u8; 16]) {
        *value = u128::from_be_bytes(*value).wrapping_add(1).to_be_bytes();
    }

    /// CTR_DRBG_Update (section 10.2.1.2) with the seedlen bytes `provided`.
    pub fn update(&mut self, provided: &[u8]) {
        let seed_length = CTRDRBG::<C>::SEED_LENGTH;
        let mut temp = [0u8; 48];
        for block in temp[..seed_length].chunks_mut(16) {
            CTRDRBG::<C>::increment(&mut self.value);
            let mut output = self.value;
            self.cipher.encrypt_block(&mut output);
            block.copy_from_slice(&output[..block.len()]);
            output.zeroize();
        }
        for (byte, value) in temp.iter_mut().zip(provided) {
            *byte ^= value;
        }
        self.cipher = C::new_from_slice(&temp[..CTRDRBG::<C>::KEY_LENGTH]).expect("keylen is a key size of the cipher");
        self.value.copy_from_slice(&temp[CTRDRBG::<C>::KEY_LENGTH..seed_length]);
        temp.zeroize();
    }

    /// BCC(Key, data) (section 10.3.3): the CBC-MAC of `data`, whole blocks, with a zero chaining value.
    pub fn bcc<'a>(cipher: &C, pieces: impl IntoIterator<Item = &'a [u8]>) -> [u8; 16] {
        let mut chaining = [0u8; 16];
        let mut position = 0;
        for piece in pieces {
            for &byte in piece {
                chaining[position] ^= byte;
                position += 1;
                if position == 16 {
                    cipher.encrypt_block(&mut chaining);
                    position = 0;
                }
            }
        }
        debug_assert_eq!(position, 0, "BCC takes whole blocks");
        chaining
    }

    /// Block_Cipher_df (section 10.3.2): `out.len()` bytes (at most 512 bits)
    /// from the concatenation of `input` (at most 2^32 - 1 bytes, the limit of
    /// its 32-bit length L).
    pub fn derive(input: &[&[u8]], out: &mut [u8]) -> Result<(), RandomError> {
        let length: usize = input.iter().map(|piece| piece.len()).sum();
        let length_value =
            u32::try_from(length).map_err(|_| RandomError::InputLength { length, maximum: u32::MAX as usize })?;
        if out.len() > 64 {
            return Err(RandomError::RequestLength { length: out.len(), maximum: 64 });
        }
        // S = L || N || input || 0x80, padded with zeros to whole blocks.
        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&length_value.to_be_bytes());
        header[4..].copy_from_slice(&(out.len() as u32).to_be_bytes());
        let padding_length = (16 - (8 + length + 1) % 16) % 16 + 1;
        let mut padding = [0u8; 16];
        padding[0] = 0x80;
        let mut key = [0u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let cipher = C::new_from_slice(&key[..CTRDRBG::<C>::KEY_LENGTH]).expect("keylen is a key size of the cipher");
        let mut temp = [0u8; 48];
        let seed_length = CTRDRBG::<C>::KEY_LENGTH + 16;
        for (index, block) in temp[..seed_length].chunks_mut(16).enumerate() {
            let mut iv = [0u8; 16];
            iv[..4].copy_from_slice(&(index as u32).to_be_bytes());
            let pieces =
                [&iv[..], &header].into_iter().chain(input.iter().copied()).chain([&padding[..padding_length]]);
            let mut chained = CTRDRBG::<C>::bcc(&cipher, pieces);
            block.copy_from_slice(&chained[..block.len()]);
            chained.zeroize();
        }
        let cipher = C::new_from_slice(&temp[..CTRDRBG::<C>::KEY_LENGTH]).expect("keylen is a key size of the cipher");
        let mut x: [u8; 16] = temp[CTRDRBG::<C>::KEY_LENGTH..seed_length].try_into().expect("one block");
        for block in out.chunks_mut(16) {
            cipher.encrypt_block(&mut x);
            block.copy_from_slice(&x[..block.len()]);
        }
        x.zeroize();
        temp.zeroize();
        key.zeroize();
        Ok(())
    }

    /// The seedlen bytes of seed material from `input`: Block_Cipher_df with
    /// the derivation function, the single input padded with zeros without it.
    pub fn seed_material(&self, input: &[&[u8]], out: &mut [u8]) -> Result<(), RandomError> {
        if self.derivation {
            return CTRDRBG::<C>::derive(input, out);
        }
        out.fill(0);
        let mut position = 0;
        for piece in input {
            if position + piece.len() > out.len() {
                return Err(RandomError::InputLength { length: position + piece.len(), maximum: out.len() });
            }
            for (byte, value) in out[position..].iter_mut().zip(*piece) {
                *byte ^= value;
            }
            position += piece.len();
        }
        Ok(())
    }

    /// Fails unless the generator is instantiated.
    pub fn check_instantiated(&self) -> Result<(), RandomError> {
        if !self.is_instantiated() {
            return Err(RandomError::Uninstantiated);
        }
        Ok(())
    }
}

impl<C: BlockCipher<Block = [u8; 16]> + KeyInit> DRBG for CTRDRBG<C> {
    const SECURITY_STRENGTH: usize = 8 * C::MAXIMUM_KEY_SIZE;

    /// Section 10.2.1.3.2: Block_Cipher_df of the entropy input, the nonce and the personalization string.
    fn instantiate(
        config: DRBGConfig,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<CTRDRBG<C>, RandomError> {
        CTRDRBG::<C>::check_instantiation(entropy, nonce, personalization)?;
        let mut seed = [0u8; 48];
        let seed_length = CTRDRBG::<C>::SEED_LENGTH;
        CTRDRBG::<C>::derive(&[entropy, nonce, personalization], &mut seed[..seed_length])?;
        let mut state = CTRDRBG::<C>::zero(config, true);
        state.update(&seed[..seed_length]);
        seed.zeroize();
        Ok(state)
    }

    /// Sections 10.2.1.4.1 and 10.2.1.4.2; without the derivation function the
    /// entropy input has exactly seedlen bytes and the additional input at most seedlen.
    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<(), RandomError> {
        self.check_instantiated()?;
        CTRDRBG::<C>::check_entropy(entropy)?;
        CTRDRBG::<C>::check_input(additional)?;
        let seed_length = CTRDRBG::<C>::SEED_LENGTH;
        if !self.derivation && entropy.len() != seed_length {
            return Err(RandomError::EntropyLength { length: entropy.len(), minimum: seed_length });
        }
        let mut seed = [0u8; 48];
        let result = if self.derivation {
            self.seed_material(&[entropy, additional], &mut seed[..seed_length])
        } else {
            // seed_material = entropy_input ⊕ additional_input padded with zeros.
            self.seed_material(&[additional], &mut seed[..seed_length]).map(|()| {
                for (byte, value) in seed.iter_mut().zip(entropy) {
                    *byte ^= value;
                }
            })
        };
        if result.is_ok() {
            self.update(&seed[..seed_length]);
            self.reseed_counter = 1;
        }
        seed.zeroize();
        result
    }

    /// Sections 10.2.1.5.1 and 10.2.1.5.2.
    fn generate(&mut self, out: &mut [u8], additional: &[u8]) -> Result<(), RandomError> {
        self.check_instantiated()?;
        if out.len() > self.config.maximum_request {
            return Err(RandomError::RequestLength { length: out.len(), maximum: self.config.maximum_request });
        }
        CTRDRBG::<C>::check_input(additional)?;
        if self.reseed_counter > self.config.reseed_interval {
            return Err(RandomError::ReseedRequired);
        }
        let seed_length = CTRDRBG::<C>::SEED_LENGTH;
        let mut processed = [0u8; 48];
        if !additional.is_empty() {
            self.seed_material(&[additional], &mut processed[..seed_length])?;
            self.update(&processed[..seed_length]);
        }
        for block in out.chunks_mut(16) {
            CTRDRBG::<C>::increment(&mut self.value);
            let mut output = self.value;
            self.cipher.encrypt_block(&mut output);
            block.copy_from_slice(&output[..block.len()]);
            output.zeroize();
        }
        self.update(&processed[..seed_length]);
        processed.zeroize();
        self.reseed_counter += 1;
        Ok(())
    }

    /// Section 9.4.
    fn uninstantiate(&mut self) {
        self.cipher.zeroize();
        self.value.zeroize();
        self.reseed_counter = 0;
    }

    fn is_instantiated(&self) -> bool {
        self.reseed_counter != 0
    }

    fn config(&self) -> &DRBGConfig {
        &self.config
    }
}

impl<C: BlockCipher<Block = [u8; 16]> + KeyInit> Random for CTRDRBG<C> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        self.generate_all(out)
    }
}

impl<C: BlockCipher<Block = [u8; 16]> + KeyInit> Zeroize for CTRDRBG<C> {
    fn zeroize(&mut self) {
        self.uninstantiate();
    }
}

impl<C: BlockCipher<Block = [u8; 16]> + KeyInit> Drop for CTRDRBG<C> {
    fn drop(&mut self) {
        self.uninstantiate();
    }
}

impl<C: BlockCipher<Block = [u8; 16]> + KeyInit> fmt::Debug for CTRDRBG<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CTRDRBG({} derivation function, ..)", if self.derivation { "with" } else { "without" })
    }
}
