use super::RandomError;

/// The limits of a deterministic random bit generator, which may be tightened
/// but not loosened beyond SP 800-90A table 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct DRBGConfig {
    /// The number of requests between reseeds, 1 to 2^48.
    pub reseed_interval: u64,
    /// The largest request in bytes, 1 to 2^16 (2^19 bits).
    pub maximum_request: usize,
}

impl DRBGConfig {
    pub const MAXIMUM_RESEED_INTERVAL: u64 = 1 << 48;
    pub const MAXIMUM_REQUEST: usize = 1 << 16;
    /// The longest entropy input, nonce, personalization string or
    /// additional input in bytes (2^35 bits).
    pub const MAXIMUM_INPUT: u64 = 1 << 32;

    /// The configuration with every limit within table 2; a limit of 0 becomes 1.
    pub fn clamped(self) -> DRBGConfig {
        DRBGConfig {
            reseed_interval: self.reseed_interval.clamp(1, DRBGConfig::MAXIMUM_RESEED_INTERVAL),
            maximum_request: self.maximum_request.clamp(1, DRBGConfig::MAXIMUM_REQUEST),
        }
    }
}

impl Default for DRBGConfig {
    fn default() -> DRBGConfig {
        DRBGConfig {
            reseed_interval: DRBGConfig::MAXIMUM_RESEED_INTERVAL,
            maximum_request: DRBGConfig::MAXIMUM_REQUEST,
        }
    }
}

/// A deterministic random bit generator of SP 800-90A with its functions of
/// section 9: instantiate, reseed, generate and uninstantiate.
///
/// Prediction resistance is a reseed with fresh entropy right before each
/// request. After [`DRBG::uninstantiate`] (also reached through `Zeroize` and
/// on drop) the state is erased and every function fails with
/// [`RandomError::Uninstantiated`].
pub trait DRBG: Sized {
    /// The security strength in bits.
    const SECURITY_STRENGTH: usize;

    /// Instantiates the generator (section 9.1) with the limits `config`,
    /// clamped to table 2.
    fn instantiate(
        config: DRBGConfig,
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, RandomError>;

    /// Mixes fresh `entropy` and optional `additional` input into the state (section 9.2).
    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<(), RandomError>;

    /// Fills `out` with one request, with optional `additional` input (section 9.3).
    fn generate(&mut self, out: &mut [u8], additional: &[u8]) -> Result<(), RandomError>;

    /// Erases the state (section 9.4).
    fn uninstantiate(&mut self);

    fn is_instantiated(&self) -> bool;

    fn config(&self) -> &DRBGConfig;

    /// Fills `out` of any length with requests of at most the maximum size
    /// and no additional input, as the generators implement
    /// [`Random::fill`](super::Random::fill).
    fn generate_all(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        let maximum = self.config().maximum_request;
        for piece in out.chunks_mut(maximum) {
            self.generate(piece, &[])?;
        }
        Ok(())
    }

    /// Checks that `input` is within [`DRBGConfig::MAXIMUM_INPUT`].
    fn check_input(input: &[u8]) -> Result<(), RandomError> {
        if input.len() as u64 > DRBGConfig::MAXIMUM_INPUT {
            return Err(RandomError::InputLength { length: input.len(), maximum: DRBGConfig::MAXIMUM_INPUT as usize });
        }
        Ok(())
    }

    /// Checks the entropy input of a reseed: the security strength, and the maximum length.
    fn check_entropy(entropy: &[u8]) -> Result<(), RandomError> {
        let minimum = Self::SECURITY_STRENGTH / 8;
        if entropy.len() < minimum {
            return Err(RandomError::EntropyLength { length: entropy.len(), minimum });
        }
        Self::check_input(entropy)
    }

    /// Checks the inputs of instantiation: the entropy input has the
    /// security strength, and with the nonce 3/2 of it (section 8.6.7: the
    /// nonce has half the security strength, or the entropy input carries it).
    fn check_instantiation(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<(), RandomError> {
        Self::check_entropy(entropy)?;
        let minimum = (3 * Self::SECURITY_STRENGTH / 16).saturating_sub(entropy.len());
        if nonce.len() < minimum {
            return Err(RandomError::NonceLength { length: nonce.len(), minimum });
        }
        Self::check_input(nonce)?;
        Self::check_input(personalization)
    }
}
