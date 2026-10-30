use core::fmt;
use core::marker::PhantomData;

use super::DHGroup;
use crate::crypto::random::Random;
use crate::crypto::{CryptoError, KeyAgreement};
use crate::math::bigint::BoxedUint;
use crate::secret::{ConstantTimeEq, Zeroize};

/// The key agreement of SP 800-56A section 5.7.1.1 in the group `G`.
pub struct DH<G: DHGroup> {
    group: PhantomData<G>,
}

/// A private key of [`DH`]: an exponent x with 1 ≤ x < q, zeroized when dropped.
pub struct DHPrivateKey<G: DHGroup> {
    exponent: BoxedUint,
    group: PhantomData<G>,
}

impl<G: DHGroup> DHPrivateKey<G> {
    pub fn exponent(&self) -> &BoxedUint {
        &self.exponent
    }
}

impl<G: DHGroup> Clone for DHPrivateKey<G> {
    fn clone(&self) -> DHPrivateKey<G> {
        DHPrivateKey { exponent: self.exponent.clone(), group: PhantomData }
    }
}

impl<G: DHGroup> Zeroize for DHPrivateKey<G> {
    fn zeroize(&mut self) {
        self.exponent.zeroize();
    }
}

impl<G: DHGroup> Drop for DHPrivateKey<G> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the group, not the key.
impl<G: DHGroup> fmt::Debug for DHPrivateKey<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = core::any::type_name::<G>();
        write!(formatter, "DHPrivateKey<{}>(..)", name.rsplit("::").next().unwrap_or(name))
    }
}

/// A public key of [`DH`]: an element y of the subgroup of order q, 1 < y < p - 1.
pub struct DHPublicKey<G: DHGroup> {
    element: BoxedUint,
    group: PhantomData<G>,
}

impl<G: DHGroup> DHPublicKey<G> {
    pub fn element(&self) -> &BoxedUint {
        &self.element
    }
}

impl<G: DHGroup> Clone for DHPublicKey<G> {
    fn clone(&self) -> DHPublicKey<G> {
        DHPublicKey { element: self.element.clone(), group: PhantomData }
    }
}

impl<G: DHGroup> PartialEq for DHPublicKey<G> {
    fn eq(&self, other: &DHPublicKey<G>) -> bool {
        self.element.ct_eq(&other.element).into_bool()
    }
}

impl<G: DHGroup> Eq for DHPublicKey<G> {}

impl<G: DHGroup> fmt::Debug for DHPublicKey<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = core::any::type_name::<G>();
        write!(formatter, "DHPublicKey<{}>({:?})", name.rsplit("::").next().unwrap_or(name), self.element)
    }
}

impl<G: DHGroup> KeyAgreement for DH<G> {
    type PrivateKey = DHPrivateKey<G>;
    type PublicKey = DHPublicKey<G>;
    /// x big-endian in the bytes of p.
    const PRIVATE_KEY_SIZE: usize = G::BITS.div_ceil(8) as usize;
    /// y big-endian in the bytes of p.
    const PUBLIC_KEY_SIZE: usize = G::BITS.div_ceil(8) as usize;
    /// Z big-endian in the bytes of p.
    const SHARED_SECRET_SIZE: usize = G::BITS.div_ceil(8) as usize;

    /// x of [`DHGroup::PRIVATE_KEY_BITS`] random bits, not zero
    /// (SP 800-56A section 5.6.1.1.4).
    fn generate<R: Random>(random: &mut R) -> Result<DHPrivateKey<G>, CryptoError> {
        let bits = G::PRIVATE_KEY_BITS;
        let mut bytes = alloc::vec![0u8; bits.div_ceil(8) as usize];
        loop {
            random.fill(&mut bytes).map_err(|_| CryptoError::RandomFailed)?;
            let value = BoxedUint::from_be_bytes(&bytes, G::BITS).map_err(|_| CryptoError::InvalidParameter)?;
            let exponent = value.shl(G::BITS - bits).shr(G::BITS - bits);
            if !exponent.is_zero().into_bool() {
                bytes.zeroize();
                return Ok(DHPrivateKey { exponent, group: PhantomData });
            }
        }
    }

    /// x of [`DH::PRIVATE_KEY_SIZE`] big-endian bytes, with 1 ≤ x < q.
    fn private_key_from_bytes(bytes: &[u8]) -> Result<DHPrivateKey<G>, CryptoError> {
        if bytes.len() != G::bytes() {
            return Err(CryptoError::InvalidKey);
        }
        let exponent = BoxedUint::from_be_bytes(bytes, G::BITS).map_err(|_| CryptoError::InvalidKey)?;
        if (exponent.is_zero() | !exponent.ct_lt(&G::order()?)).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(DHPrivateKey { exponent, group: PhantomData })
    }

    fn write_private_key(key: &DHPrivateKey<G>, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != G::bytes() {
            return Err(CryptoError::InputLength { length });
        }
        key.exponent.write_be_bytes(out).map_err(|_| CryptoError::InputLength { length })
    }

    /// y = g^x mod p.
    fn public_key(key: &DHPrivateKey<G>) -> DHPublicKey<G> {
        let element = (|| {
            let modulus = G::modulus().ok()?;
            let generator = BoxedUint::from_u64(G::GENERATOR, G::BITS).ok()?;
            modulus.retrieve(&modulus.pow(&modulus.residue(&generator), &key.exponent).ok()?).ok()
        })();
        // The constants of the group are valid, so every step succeeds.
        DHPublicKey { element: element.unwrap_or_else(|| BoxedUint::with_limbs(1)), group: PhantomData }
    }

    /// y of [`DH::PUBLIC_KEY_SIZE`] big-endian bytes, fully validated
    /// (SP 800-56A section 5.6.2.3.1): 2 ≤ y ≤ p - 2 and y^q = 1 mod p.
    fn public_key_from_bytes(bytes: &[u8]) -> Result<DHPublicKey<G>, CryptoError> {
        if bytes.len() != G::bytes() {
            return Err(CryptoError::InvalidKey);
        }
        let invalid = |_| CryptoError::InvalidKey;
        let element = BoxedUint::from_be_bytes(bytes, G::BITS).map_err(invalid)?;
        let modulus = G::modulus()?;
        let two = BoxedUint::from_u64(2, 64).map_err(invalid)?;
        let p_minus_1 = modulus.value().wrapping_sub(&BoxedUint::one(64).map_err(invalid)?);
        if (element.ct_lt(&two) | !element.ct_lt(&p_minus_1)).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let power = modulus.pow_vartime(&modulus.residue(&element), &G::order()?).map_err(invalid)?;
        if power != modulus.one() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(DHPublicKey { element, group: PhantomData })
    }

    fn write_public_key(key: &DHPublicKey<G>, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != G::bytes() {
            return Err(CryptoError::InputLength { length });
        }
        key.element.write_be_bytes(out).map_err(|_| CryptoError::InputLength { length })
    }

    /// Z = y^x mod p (SP 800-56A section 5.7.1.1); fails with `InvalidKey`
    /// for Z = 1, which a validated key never gives.
    fn agree(private: &DHPrivateKey<G>, public: &DHPublicKey<G>, out: &mut [u8]) -> Result<(), CryptoError> {
        let length = out.len();
        if length != G::bytes() {
            return Err(CryptoError::InputLength { length });
        }
        let invalid = |_| CryptoError::InvalidKey;
        let modulus = G::modulus()?;
        let mut shared = modulus.pow(&modulus.residue(&public.element), &private.exponent).map_err(invalid)?;
        let one = shared == modulus.one();
        let result = if one {
            Err(CryptoError::InvalidKey)
        } else {
            modulus
                .retrieve(&shared)
                .map_err(invalid)?
                .write_be_bytes(out)
                .map_err(|_| CryptoError::InputLength { length })
        };
        shared.zeroize();
        result
    }
}
