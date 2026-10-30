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

/// The server of SRP for one user: the verifier v, the secret exponent b
/// and B = k v + g^b % N (RFC 5054 section 2.5.3); zeroized when dropped.
pub struct SRPServer<G: SRPGroup, H: CryptographicDigest + Default = SHA1> {
    verifier: BoxedUint,
    secret: BoxedUint,
    public: BoxedUint,
    types: PhantomData<(G, H)>,
}

impl<G: SRPGroup, H: CryptographicDigest + Default> SRPServer<G, H> {
    /// The server of the verifier `verifier` (as [`SRP::verifier`] gives it)
    /// and the secret exponent b of the big-endian `secret`; fails with
    /// `InvalidKey` for b = 0, v % N = 0 or values longer than N.
    pub fn new(verifier: &[u8], secret: &[u8]) -> Result<SRPServer<G, H>, CryptoError> {
        if secret.len() > G::bytes() {
            return Err(CryptoError::InvalidKey);
        }
        let failed = |_| CryptoError::InvalidKey;
        let verifier = SRP::<G, H>::public_value(verifier)?;
        let secret = BoxedUint::from_be_bytes(secret, G::BITS).map_err(failed)?;
        if secret.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let modulus = G::modulus()?;
        let generator = modulus.residue(&BoxedUint::from_u64(G::GENERATOR, G::BITS).map_err(failed)?);
        let k = modulus.residue(&SRP::<G, H>::multiplier()?);
        let kv = modulus.mul(&k, &modulus.residue(&verifier)).map_err(failed)?;
        let public = modulus.add(&kv, &modulus.pow(&generator, &secret).map_err(failed)?).map_err(failed)?;
        let public = modulus.retrieve(&public).map_err(failed)?;
        Ok(SRPServer { verifier, secret, public, types: PhantomData })
    }

    /// A server with a random exponent of [`SRPGroup::SECRET_BITS`] bits.
    pub fn generate<R: Random>(verifier: &[u8], random: &mut R) -> Result<SRPServer<G, H>, CryptoError> {
        let mut secret = SRP::<G, H>::secret(random)?;
        let server = SRPServer::new(verifier, &secret);
        secret.zeroize();
        server
    }

    /// B, as the server sends it (without leading zeros).
    pub fn public_value(&self) -> Vec<u8> {
        SRP::<G, H>::unpadded(&self.public)
    }

    /// The premaster secret (A v^u)^b % N of section 2.6 for the client's
    /// A; fails with `InvalidKey` for A % N = 0 or u = 0.
    pub fn premaster_secret(&self, client_public: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let client = SRP::<G, H>::public_value(client_public)?;
        let u = SRP::<G, H>::scrambling(&client, &self.public)?;
        let modulus = G::modulus()?;
        let failed = |_| CryptoError::InvalidKey;
        let vu = modulus.pow(&modulus.residue(&self.verifier), &u).map_err(failed)?;
        let base = modulus.mul(&modulus.residue(&client), &vu).map_err(failed)?;
        let mut shared = modulus.pow(&base, &self.secret).map_err(failed)?;
        let secret = SRP::<G, H>::unpadded(&modulus.retrieve(&shared).map_err(failed)?);
        shared.zeroize();
        Ok(secret)
    }
}

impl<G: SRPGroup, H: CryptographicDigest + Default> Zeroize for SRPServer<G, H> {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl<G: SRPGroup, H: CryptographicDigest + Default> Drop for SRPServer<G, H> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints B, not b.
impl<G: SRPGroup, H: CryptographicDigest + Default> fmt::Debug for SRPServer<G, H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SRPServer(B: {:?}, ..)", self.public)
    }
}
