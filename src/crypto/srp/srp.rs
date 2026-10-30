use alloc::vec::Vec;
use core::marker::PhantomData;

use super::SRPGroup;
use crate::crypto::CryptoError;
use crate::hash::CryptographicDigest;
use crate::hash::sha::v1::SHA1;
use crate::math::bigint::BoxedUint;
use crate::secret::Zeroize;

/// The computations of SRP in the group `G` with the hash function `H`
/// (RFC 5054 section 2).
pub struct SRP<G: SRPGroup, H: CryptographicDigest + Default = SHA1> {
    types: PhantomData<(G, H)>,
}

impl<G: SRPGroup, H: CryptographicDigest + Default> SRP<G, H> {
    /// PAD(value): the bytes of N, most significant first.
    pub fn pad(value: &BoxedUint) -> Result<Vec<u8>, CryptoError> {
        let mut bytes = alloc::vec![0u8; G::bytes()];
        value.write_be_bytes(&mut bytes).map_err(|_| CryptoError::InvalidParameter)?;
        Ok(bytes)
    }

    /// The implicit conversion of `value`: most significant first, without
    /// leading zeros.
    pub fn unpadded(value: &BoxedUint) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
        bytes[zeros..].to_vec()
    }

    /// The integer of a hash, in the precision of N.
    pub fn integer(hash: &[u8]) -> Result<BoxedUint, CryptoError> {
        BoxedUint::from_be_bytes(hash, G::BITS.max(8 * hash.len() as u32)).map_err(|_| CryptoError::InvalidParameter)
    }

    /// k = H(N | PAD(g)).
    pub fn multiplier() -> Result<BoxedUint, CryptoError> {
        let modulus = G::modulus()?;
        let generator = BoxedUint::from_u64(G::GENERATOR, G::BITS).map_err(|_| CryptoError::InvalidParameter)?;
        let mut hash = H::default();
        hash.update(&SRP::<G, H>::unpadded(modulus.value()));
        hash.update(&SRP::<G, H>::pad(&generator)?);
        SRP::<G, H>::integer(hash.finalize().as_ref())
    }

    /// x = H(s | H(I | ":" | P)) of the salt, the identity and the password
    /// (section 2.4).
    pub fn private_key(salt: &[u8], identity: &[u8], password: &[u8]) -> Result<BoxedUint, CryptoError> {
        let mut inner = H::default();
        inner.update(identity);
        inner.update(b":");
        inner.update(password);
        let mut inner = inner.finalize();
        let mut hash = H::default();
        hash.update(salt);
        hash.update(inner.as_ref());
        inner.as_mut().zeroize();
        let mut digest = hash.finalize();
        let x = SRP::<G, H>::integer(digest.as_ref());
        digest.as_mut().zeroize();
        x
    }

    /// The verifier v = g^x % N of section 2.4, as PAD(v).
    pub fn verifier(salt: &[u8], identity: &[u8], password: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut x = SRP::<G, H>::private_key(salt, identity, password)?;
        let modulus = G::modulus()?;
        let failed = |_| CryptoError::InvalidParameter;
        let generator = BoxedUint::from_u64(G::GENERATOR, G::BITS).map_err(failed)?;
        let v = modulus.retrieve(&modulus.pow(&modulus.residue(&generator), &x).map_err(failed)?).map_err(failed)?;
        x.zeroize();
        SRP::<G, H>::pad(&v)
    }

    /// u = H(PAD(A) | PAD(B)); fails with `InvalidKey` for u = 0 (SRP-6a).
    pub fn scrambling(client: &BoxedUint, server: &BoxedUint) -> Result<BoxedUint, CryptoError> {
        let mut hash = H::default();
        hash.update(&SRP::<G, H>::pad(client)?);
        hash.update(&SRP::<G, H>::pad(server)?);
        let u = SRP::<G, H>::integer(hash.finalize().as_ref())?;
        if u.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(u)
    }

    /// The public value of `bytes`, at most the bytes of N; fails with
    /// `InvalidKey` if it is 0 modulo N (sections 2.5.3 and 2.5.4).
    pub fn public_value(bytes: &[u8]) -> Result<BoxedUint, CryptoError> {
        if bytes.len() > G::bytes() {
            return Err(CryptoError::InvalidKey);
        }
        let modulus = G::modulus()?;
        let value = BoxedUint::from_be_bytes(bytes, G::BITS).map_err(|_| CryptoError::InvalidKey)?;
        let reduced = value.rem(modulus.value()).map_err(|_| CryptoError::InvalidKey)?;
        if reduced.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(reduced)
    }

    /// A secret exponent of [`SRPGroup::SECRET_BITS`] bits of `random`, not zero.
    pub fn secret<R: crate::crypto::random::Random>(random: &mut R) -> Result<Vec<u8>, CryptoError> {
        let mut bytes = alloc::vec![0u8; G::SECRET_BITS.div_ceil(8) as usize];
        loop {
            random.fill(&mut bytes).map_err(|_| CryptoError::RandomFailed)?;
            bytes[0] &= 0xFF >> (8 * bytes.len() as u32 - G::SECRET_BITS);
            if bytes.iter().any(|byte| *byte != 0) {
                return Ok(bytes);
            }
        }
    }
}
