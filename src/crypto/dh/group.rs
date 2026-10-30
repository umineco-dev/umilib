use core::fmt;

use crate::crypto::CryptoError;
use crate::math::bigint::BoxedUint;
use crate::math::modular::BoxedModulus;

/// A group of the multiplicative group modulo a safe prime p = 2q + 1, with
/// the generator 2 of the subgroup of prime order q.
pub trait DHGroup: Copy + fmt::Debug + 'static {
    /// p in hexadecimal.
    const PRIME: &'static str;
    /// The bits of p.
    const BITS: u32;
    /// The bits of generated private keys: twice the security strength of
    /// the group (SP 800-56A revision 3 section 5.6.1.1.4 and appendix D).
    const PRIVATE_KEY_BITS: u32;
    /// The generator.
    const GENERATOR: u64 = 2;

    /// The bytes of p.
    fn bytes() -> usize {
        Self::BITS.div_ceil(8) as usize
    }

    /// p, with its Montgomery constants.
    fn modulus() -> Result<BoxedModulus, CryptoError> {
        let prime = BoxedUint::from_hex_vartime(Self::PRIME, Self::BITS).map_err(|_| CryptoError::InvalidParameter)?;
        BoxedModulus::new(prime).map_err(|_| CryptoError::InvalidParameter)
    }

    /// q = (p - 1) / 2, the order of the generator.
    fn order() -> Result<BoxedUint, CryptoError> {
        let prime = BoxedUint::from_hex_vartime(Self::PRIME, Self::BITS).map_err(|_| CryptoError::InvalidParameter)?;
        Ok(prime.shr(1))
    }
}
