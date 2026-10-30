use core::fmt;

use crate::crypto::CryptoError;
use crate::math::bigint::BoxedUint;
use crate::math::modular::BoxedModulus;

/// A group of SRP: a safe prime N and a generator g of the integers modulo N.
pub trait SRPGroup: Copy + fmt::Debug + 'static {
    /// N in hexadecimal.
    const PRIME: &'static str;
    /// The bits of N.
    const BITS: u32;
    const GENERATOR: u64;
    /// The bits of the secret exponents a and b that [`SRPClient::generate`](super::SRPClient::generate)
    /// and [`SRPServer::generate`](super::SRPServer::generate) draw: at least
    /// 256 (RFC 5054 sections 2.5.3 and 2.5.4), and twice the security
    /// strength of the group.
    const SECRET_BITS: u32;

    /// The bytes of N, the length of PAD().
    fn bytes() -> usize {
        Self::BITS.div_ceil(8) as usize
    }

    /// N, with its Montgomery constants.
    fn modulus() -> Result<BoxedModulus, CryptoError> {
        let prime = BoxedUint::from_hex_vartime(Self::PRIME, Self::BITS).map_err(|_| CryptoError::InvalidParameter)?;
        BoxedModulus::new(prime).map_err(|_| CryptoError::InvalidParameter)
    }
}
