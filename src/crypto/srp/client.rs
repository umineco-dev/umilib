use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use super::{SRP, SRPGroup};
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::hash::sha::v1::SHA1;
use crate::math::bigint::BoxedUint;
use crate::secret::Zeroize;

/// The client of SRP: the secret exponent a and A = g^a % N (RFC 5054
/// section 2.5.4); zeroized when dropped.
pub struct SRPClient<G: SRPGroup, H: CryptographicDigest + Default = SHA1> {
    secret: BoxedUint,
    public: BoxedUint,
    types: PhantomData<(G, H)>,
}

impl<G: SRPGroup, H: CryptographicDigest + Default> SRPClient<G, H> {
    /// The client of the secret exponent a of the big-endian `secret`;
    /// fails with `InvalidKey` for a = 0 or more bytes than N.
    pub fn new(secret: &[u8]) -> Result<SRPClient<G, H>, CryptoError> {
        if secret.len() > G::bytes() {
            return Err(CryptoError::InvalidKey);
        }
        let failed = |_| CryptoError::InvalidKey;
        let secret = BoxedUint::from_be_bytes(secret, G::BITS).map_err(failed)?;
        if secret.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let modulus = G::modulus()?;
        let generator = BoxedUint::from_u64(G::GENERATOR, G::BITS).map_err(failed)?;
        let public =
            modulus.retrieve(&modulus.pow(&modulus.residue(&generator), &secret).map_err(failed)?).map_err(failed)?;
        Ok(SRPClient { secret, public, types: PhantomData })
    }

    /// A client with a random exponent of [`SRPGroup::SECRET_BITS`] bits.
    pub fn generate<R: Random>(random: &mut R) -> Result<SRPClient<G, H>, CryptoError> {
        let mut secret = SRP::<G, H>::secret(random)?;
        let client = SRPClient::new(&secret);
        secret.zeroize();
        client
    }

    /// A, as the client sends it (without leading zeros).
    pub fn public_value(&self) -> Vec<u8> {
        SRP::<G, H>::unpadded(&self.public)
    }

    /// The premaster secret (B - k g^x)^(a + u x) % N of section 2.6, for the
    /// user `identity` with `password` and the salt and B of the server;
    /// fails with `InvalidKey` for B % N = 0 or u = 0.
    pub fn premaster_secret(
        &self,
        identity: &[u8],
        password: &[u8],
        salt: &[u8],
        server_public: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let server = SRP::<G, H>::public_value(server_public)?;
        let u = SRP::<G, H>::scrambling(&self.public, &server)?;
        let k = SRP::<G, H>::multiplier()?;
        let mut x = SRP::<G, H>::private_key(salt, identity, password)?;
        let modulus = G::modulus()?;
        let failed = |_| CryptoError::InvalidKey;
        let generator = modulus.residue(&BoxedUint::from_u64(G::GENERATOR, G::BITS).map_err(failed)?);
        let gx = modulus.pow(&generator, &x).map_err(failed)?;
        let base = modulus.sub(&modulus.residue(&server), &modulus.mul(&modulus.residue(&k), &gx).map_err(failed)?);
        // a + u x, in a precision that holds it.
        let product = u.mul_wide(&x);
        x.zeroize();
        let precision = product.precision().max(self.secret.precision()) + 64;
        let (mut exponent, _) =
            product.resize(precision).map_err(failed)?.overflowing_add(&self.secret.resize(precision).map_err(failed)?);
        let mut shared = modulus.pow(&base.map_err(failed)?, &exponent).map_err(failed)?;
        exponent.zeroize();
        let secret = SRP::<G, H>::unpadded(&modulus.retrieve(&shared).map_err(failed)?);
        shared.zeroize();
        Ok(secret)
    }
}

impl<G: SRPGroup, H: CryptographicDigest + Default> Zeroize for SRPClient<G, H> {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl<G: SRPGroup, H: CryptographicDigest + Default> Drop for SRPClient<G, H> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints A, not a.
impl<G: SRPGroup, H: CryptographicDigest + Default> fmt::Debug for SRPClient<G, H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SRPClient(A: {:?}, ..)", self.public)
    }
}
