use alloc::boxed::Box;
use core::fmt;

use super::XXH3;
use crate::hash::HashError;
use crate::secret::Zeroize;

/// The key of XXH3: a seed, from which a secret is derived for large inputs,
/// or a secret of at least [`XXH3::MINIMUM_SECRET_SIZE`] bytes. Its
/// constructors are the only way to make one, so a secret is always long
/// enough. A seed that protects a hash table from chosen collisions is a key,
/// so it is hidden from `Debug` and zeroized on drop with the secret.
#[derive(Clone)]
pub struct XXH3Secret {
    seed: u64,
    /// The secret derived from the seed, used unless a custom secret is given.
    derived: [u8; XXH3::DEFAULT_SECRET_SIZE],
    custom: Option<Box<[u8]>>,
}

impl XXH3Secret {
    /// The secret derived from `seed`; the seed 0 gives the default secret.
    pub fn with_seed(seed: u64) -> XXH3Secret {
        let mut derived = XXH3::DEFAULT_SECRET;
        for (index, word) in derived.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            let value = u64::from_le_bytes(*word);
            let value = if index % 2 == 0 { value.wrapping_add(seed) } else { value.wrapping_sub(seed) };
            *word = value.to_le_bytes();
        }
        XXH3Secret { seed, derived, custom: None }
    }

    /// A copy of `secret`, which must hold at least [`XXH3::MINIMUM_SECRET_SIZE`] bytes; the seed is 0.
    pub fn with_secret(secret: &[u8]) -> Result<XXH3Secret, HashError> {
        if secret.len() < XXH3::MINIMUM_SECRET_SIZE {
            return Err(HashError::KeyLength {
                length: secret.len(),
                minimum: XXH3::MINIMUM_SECRET_SIZE,
                maximum: usize::MAX,
            });
        }
        Ok(XXH3Secret { seed: 0, derived: XXH3::DEFAULT_SECRET, custom: Some(secret.into()) })
    }

    /// The seed of small and medium inputs.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Whether the secret was given rather than derived from a seed.
    pub fn is_custom(&self) -> bool {
        self.custom.is_some()
    }

    /// The secret of large inputs.
    pub fn secret(&self) -> &[u8] {
        match &self.custom {
            Some(secret) => secret,
            None => &self.derived,
        }
    }

    /// The secret of small and medium inputs: the default one with a seed.
    pub fn short_secret(&self) -> &[u8] {
        match &self.custom {
            Some(secret) => secret,
            None => &XXH3::DEFAULT_SECRET,
        }
    }
}

impl Default for XXH3Secret {
    /// The seed 0 and the default secret.
    fn default() -> XXH3Secret {
        XXH3Secret { seed: 0, derived: XXH3::DEFAULT_SECRET, custom: None }
    }
}

impl Zeroize for XXH3Secret {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.derived.zeroize();
        if let Some(secret) = &mut self.custom {
            secret.zeroize();
        }
    }
}

impl Drop for XXH3Secret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for XXH3Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.custom {
            Some(secret) => write!(formatter, "XXH3Secret(custom, {} bytes, ..)", secret.len()),
            None => formatter.write_str("XXH3Secret(seed, ..)"),
        }
    }
}
