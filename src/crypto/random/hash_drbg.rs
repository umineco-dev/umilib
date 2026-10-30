use core::fmt;

use super::{DRBG, DRBGConfig, Random, RandomError};
use crate::hash::CryptographicDigest;
use crate::secret::Zeroize;

/// Hash_DRBG over the hash function `H` (SP 800-90A section 10.1.1).
///
/// The values V and C have the seed length of `H` (table 2): 440 bits for
/// outputs of up to 256 bits, 888 bits for longer ones, held in arrays of
/// the longer length because stable Rust cannot size them from `H`. It
/// cannot be cloned: two copies would generate the same bytes.
pub struct HashDRBG<H: CryptographicDigest + Default> {
    value: [u8; 111],
    constant: [u8; 111],
    /// The number of requests since the last reseed, from 1; 0 once uninstantiated.
    reseed_counter: u64,
    config: DRBGConfig,
    hash: core::marker::PhantomData<H>,
}

impl<H: CryptographicDigest + Default> HashDRBG<H> {
    /// The seed length in bytes.
    pub const SEED_SIZE: usize = if H::OUTPUT_SIZE <= 32 { 55 } else { 111 };
    /// The longest seed length, the size of the arrays that hold V and C.
    pub const MAXIMUM_SEED_SIZE: usize = 111;

    /// Instantiates the generator with the default limits.
    pub fn new(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<HashDRBG<H>, RandomError> {
        HashDRBG::instantiate(DRBGConfig::default(), entropy, nonce, personalization)
    }

    /// Instantiates the generator with the limits `config`.
    pub fn with_config(
        config: DRBGConfig,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<HashDRBG<H>, RandomError> {
        HashDRBG::instantiate(config, entropy, nonce, personalization)
    }

    /// Fails unless the generator is instantiated.
    pub fn check_instantiated(&self) -> Result<(), RandomError> {
        if !self.is_instantiated() {
            return Err(RandomError::Uninstantiated);
        }
        Ok(())
    }

    /// V from `material` and C from V, as instantiation and reseeding end:
    /// the raw step, which checks no length; [`DRBG::instantiate`] and
    /// [`DRBG::reseed`] check them.
    pub fn seed(&mut self, material: &[&[u8]]) {
        let size = HashDRBG::<H>::SEED_SIZE;
        let mut value = [0u8; 111];
        HashDRBG::<H>::derive(material, &mut value[..size]);
        self.value = value;
        value.zeroize();
        HashDRBG::<H>::derive(&[&[0x00], &self.value[..size]], &mut self.constant[..size]);
        self.reseed_counter = 1;
    }

    /// The derivation function Hash_df (section 10.3.1) of the concatenation
    /// of `input`, filling `out`.
    ///
    /// # Panics
    ///
    /// If `out` is longer than 255 output blocks, which Hash_df cannot produce.
    pub fn derive(input: &[&[u8]], out: &mut [u8]) {
        assert!(out.len() <= 255 * H::OUTPUT_SIZE, "Hash_df returns at most 255 blocks");
        let bits = (8 * out.len() as u32).to_be_bytes();
        for (counter, piece) in out.chunks_mut(H::OUTPUT_SIZE).enumerate() {
            let mut hash = H::default();
            hash.update(&[counter as u8 + 1]);
            hash.update(&bits);
            for part in input {
                hash.update(part);
            }
            let mut block = hash.finalize();
            piece.copy_from_slice(&block.as_ref()[..piece.len()]);
            block.as_mut().zeroize();
        }
    }

    /// `value = (value + addend) mod 2^(8 × value.len())`, both big-endian;
    /// an addend longer than `value` is reduced to its last bytes.
    pub fn add(value: &mut [u8], addend: &[u8]) {
        let addend = &addend[addend.len().saturating_sub(value.len())..];
        let offset = value.len() - addend.len();
        let mut carry = 0u16;
        for index in (0..value.len()).rev() {
            let other = if index >= offset { addend[index - offset] } else { 0 };
            let sum = value[index] as u16 + other as u16 + carry;
            value[index] = sum as u8;
            carry = sum >> 8;
        }
    }

    /// The hash of the concatenation of `input`.
    pub fn hash(input: &[&[u8]]) -> H::Output {
        let mut hash = H::default();
        for part in input {
            hash.update(part);
        }
        hash.finalize()
    }
}

impl<H: CryptographicDigest + Default> DRBG for HashDRBG<H> {
    const SECURITY_STRENGTH: usize = match H::OUTPUT_SIZE {
        0..=27 => 128,
        28..=31 => 192,
        _ => 256,
    };

    /// Section 10.1.1.2.
    fn instantiate(
        config: DRBGConfig,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<HashDRBG<H>, RandomError> {
        HashDRBG::<H>::check_instantiation(entropy, nonce, personalization)?;
        let mut state = HashDRBG {
            value: [0; 111],
            constant: [0; 111],
            reseed_counter: 1,
            config: config.clamped(),
            hash: core::marker::PhantomData,
        };
        state.seed(&[entropy, nonce, personalization]);
        Ok(state)
    }

    /// Section 10.1.1.3.
    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<(), RandomError> {
        self.check_instantiated()?;
        HashDRBG::<H>::check_entropy(entropy)?;
        HashDRBG::<H>::check_input(additional)?;
        let mut previous = self.value;
        self.seed(&[&[0x01], &previous[..HashDRBG::<H>::SEED_SIZE], entropy, additional]);
        previous.zeroize();
        Ok(())
    }

    /// Section 10.1.1.4, with Hashgen.
    fn generate(&mut self, out: &mut [u8], additional: &[u8]) -> Result<(), RandomError> {
        self.check_instantiated()?;
        if out.len() > self.config.maximum_request {
            return Err(RandomError::RequestLength { length: out.len(), maximum: self.config.maximum_request });
        }
        HashDRBG::<H>::check_input(additional)?;
        if self.reseed_counter > self.config.reseed_interval {
            return Err(RandomError::ReseedRequired);
        }
        let size = HashDRBG::<H>::SEED_SIZE;
        if !additional.is_empty() {
            let mut w = HashDRBG::<H>::hash(&[&[0x02], &self.value[..size], additional]);
            HashDRBG::<H>::add(&mut self.value[..size], w.as_ref());
            w.as_mut().zeroize();
        }
        let mut data = self.value;
        for piece in out.chunks_mut(H::OUTPUT_SIZE) {
            let mut block = HashDRBG::<H>::hash(&[&data[..size]]);
            piece.copy_from_slice(&block.as_ref()[..piece.len()]);
            block.as_mut().zeroize();
            HashDRBG::<H>::add(&mut data[..size], &[1]);
        }
        data.zeroize();
        let mut h = HashDRBG::<H>::hash(&[&[0x03], &self.value[..size]]);
        HashDRBG::<H>::add(&mut self.value[..size], h.as_ref());
        HashDRBG::<H>::add(&mut self.value[..size], &self.constant[..size]);
        HashDRBG::<H>::add(&mut self.value[..size], &self.reseed_counter.to_be_bytes());
        h.as_mut().zeroize();
        self.reseed_counter += 1;
        Ok(())
    }

    /// Section 9.4.
    fn uninstantiate(&mut self) {
        self.value.zeroize();
        self.constant.zeroize();
        self.reseed_counter = 0;
    }

    fn is_instantiated(&self) -> bool {
        self.reseed_counter != 0
    }

    fn config(&self) -> &DRBGConfig {
        &self.config
    }
}

impl<H: CryptographicDigest + Default> Random for HashDRBG<H> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        self.generate_all(out)
    }
}

impl<H: CryptographicDigest + Default> Zeroize for HashDRBG<H> {
    /// Uninstantiates the generator.
    fn zeroize(&mut self) {
        self.uninstantiate();
    }
}

impl<H: CryptographicDigest + Default> Drop for HashDRBG<H> {
    fn drop(&mut self) {
        self.uninstantiate();
    }
}

impl<H: CryptographicDigest + Default> fmt::Debug for HashDRBG<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HashDRBG(..)")
    }
}
