use core::fmt;

use super::{DRBG, DRBGConfig, Random, RandomError};
use crate::crypto::hmac::HMAC;
use crate::hash::CryptographicDigest;
use crate::secret::Zeroize;

/// HMAC_DRBG over the hash function `H` (SP 800-90A section 10.1.2).
///
/// It cannot be cloned: two copies would generate the same bytes.
pub struct HMACDRBG<H: CryptographicDigest + Default> {
    /// HMAC keyed with the key K of the state.
    key: HMAC<H>,
    value: H::Output,
    /// The number of requests since the last reseed, from 1; 0 once uninstantiated.
    reseed_counter: u64,
    config: DRBGConfig,
}

impl<H: CryptographicDigest + Default> HMACDRBG<H> {
    /// Instantiates the generator with the default limits.
    pub fn new(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<HMACDRBG<H>, RandomError> {
        HMACDRBG::instantiate(DRBGConfig::default(), entropy, nonce, personalization)
    }

    /// Instantiates the generator with the limits `config`.
    pub fn with_config(
        config: DRBGConfig,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<HMACDRBG<H>, RandomError> {
        HMACDRBG::instantiate(config, entropy, nonce, personalization)
    }

    /// Instantiates the generator with the limits `config` on the seed
    /// material `seed`, the concatenation of its pieces, as given: without the
    /// checks of SP 800-90A on the lengths of the entropy input and the nonce.
    /// For constructions that define their own inputs to HMAC_DRBG, such as
    /// the nonces of RFC 6979 section 3.3; anything else uses [`HMACDRBG::new`].
    pub fn with_seed(config: DRBGConfig, seed: &[&[u8]]) -> HMACDRBG<H> {
        // A hash output is the only way to make an `H::Output`.
        let mut key = H::digest(&[]);
        key.as_mut().fill(0);
        let mut value = key;
        value.as_mut().fill(1);
        let mut state = HMACDRBG { key: HMAC::new(key.as_ref()), value, reseed_counter: 1, config: config.clamped() };
        state.update(seed);
        state
    }

    /// HMAC of `data` under the key K.
    pub fn mac(&self, data: &[u8]) -> H::Output {
        let mut hmac = self.key.clone();
        hmac.update(data);
        hmac.finalize()
    }

    /// The update function (section 10.1.2.2) with the concatenation of `provided`.
    pub fn update(&mut self, provided: &[&[u8]]) {
        let empty = provided.iter().all(|piece| piece.is_empty());
        for separator in [0x00u8, 0x01] {
            let mut hmac = self.key.clone();
            hmac.update(self.value.as_ref());
            hmac.update(&[separator]);
            for piece in provided {
                hmac.update(piece);
            }
            let mut key = hmac.finalize();
            self.key = HMAC::new(key.as_ref());
            key.as_mut().zeroize();
            self.value = self.mac(self.value.as_ref());
            if empty {
                break;
            }
        }
    }

    /// Fails unless the generator is instantiated.
    pub fn check_instantiated(&self) -> Result<(), RandomError> {
        if !self.is_instantiated() {
            return Err(RandomError::Uninstantiated);
        }
        Ok(())
    }
}

impl<H: CryptographicDigest + Default> DRBG for HMACDRBG<H> {
    const SECURITY_STRENGTH: usize = match H::OUTPUT_SIZE {
        0..=27 => 128,
        28..=31 => 192,
        _ => 256,
    };

    /// Section 10.1.2.3.
    fn instantiate(
        config: DRBGConfig,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<HMACDRBG<H>, RandomError> {
        HMACDRBG::<H>::check_instantiation(entropy, nonce, personalization)?;
        Ok(HMACDRBG::with_seed(config, &[entropy, nonce, personalization]))
    }

    /// Section 10.1.2.4.
    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<(), RandomError> {
        self.check_instantiated()?;
        HMACDRBG::<H>::check_entropy(entropy)?;
        HMACDRBG::<H>::check_input(additional)?;
        self.update(&[entropy, additional]);
        self.reseed_counter = 1;
        Ok(())
    }

    /// Section 10.1.2.5.
    fn generate(&mut self, out: &mut [u8], additional: &[u8]) -> Result<(), RandomError> {
        self.check_instantiated()?;
        if out.len() > self.config.maximum_request {
            return Err(RandomError::RequestLength { length: out.len(), maximum: self.config.maximum_request });
        }
        HMACDRBG::<H>::check_input(additional)?;
        if self.reseed_counter > self.config.reseed_interval {
            return Err(RandomError::ReseedRequired);
        }
        if !additional.is_empty() {
            self.update(&[additional]);
        }
        for piece in out.chunks_mut(H::OUTPUT_SIZE) {
            self.value = self.mac(self.value.as_ref());
            piece.copy_from_slice(&self.value.as_ref()[..piece.len()]);
        }
        self.update(&[additional]);
        self.reseed_counter += 1;
        Ok(())
    }

    /// Section 9.4.
    fn uninstantiate(&mut self) {
        self.key.zeroize();
        self.value.as_mut().zeroize();
        self.reseed_counter = 0;
    }

    fn is_instantiated(&self) -> bool {
        self.reseed_counter != 0
    }

    fn config(&self) -> &DRBGConfig {
        &self.config
    }
}

impl<H: CryptographicDigest + Default> Random for HMACDRBG<H> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        self.generate_all(out)
    }
}

impl<H: CryptographicDigest + Default> Zeroize for HMACDRBG<H> {
    /// Uninstantiates the generator.
    fn zeroize(&mut self) {
        self.uninstantiate();
    }
}

impl<H: CryptographicDigest + Default> Drop for HMACDRBG<H> {
    fn drop(&mut self) {
        self.uninstantiate();
    }
}

impl<H: CryptographicDigest + Default> fmt::Debug for HMACDRBG<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HMACDRBG(..)")
    }
}
