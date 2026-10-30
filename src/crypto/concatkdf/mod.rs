//! The one-step key derivation function of SP 800-56C Rev. 2 §4 (the
//! "Concat KDF" of SP 800-56A, which JOSE uses for ECDH-ES, RFC 7518
//! §4.6.2): K(i) = H(counter_i || Z || FixedInfo), with H a hash function
//! (option 1) or a MAC keyed with a salt (option 2, HMAC; option 3, KMAC).

use core::fmt;

use crate::crypto::{CryptoError, PRF};
use crate::hash::CryptographicDigest;
use crate::secret::Zeroize;

/// The auxiliary function H of the one-step KDF (SP 800-56C Rev. 2
/// §4.1): a hash function ([`HashFunction`]) or a pseudorandom function
/// keyed with the salt (every [`PRF`]).
pub trait AuxiliaryFunction: Clone {
    /// The bytes of one output of H.
    const OUTPUT_SIZE: usize;

    fn update(&mut self, data: &[u8]);

    /// Writes the output into `out` of [`AuxiliaryFunction::OUTPUT_SIZE`] bytes.
    fn finalize_into(self, out: &mut [u8]);
}

impl<P: PRF> AuxiliaryFunction for P {
    const OUTPUT_SIZE: usize = P::OUTPUT_SIZE;

    fn update(&mut self, data: &[u8]) {
        crate::crypto::MAC::update(self, data);
    }

    fn finalize_into(self, out: &mut [u8]) {
        let mut output = crate::crypto::MAC::finalize(self);
        out.copy_from_slice(output.as_ref());
        output.as_mut().zeroize();
    }
}

/// The hash function `H` as the auxiliary function (option 1).
#[derive(Clone, Default)]
pub struct HashFunction<H: CryptographicDigest + Default> {
    hash: H,
}

impl<H: CryptographicDigest + Default> HashFunction<H> {
    pub fn new() -> HashFunction<H> {
        HashFunction { hash: H::default() }
    }
}

impl<H: CryptographicDigest + Default> AuxiliaryFunction for HashFunction<H> {
    const OUTPUT_SIZE: usize = H::OUTPUT_SIZE;

    fn update(&mut self, data: &[u8]) {
        self.hash.update(data);
    }

    fn finalize_into(self, out: &mut [u8]) {
        let mut output = self.hash.finalize();
        out.copy_from_slice(output.as_ref());
        output.as_mut().zeroize();
    }
}

/// The one-step KDF over the auxiliary function `F` (with its key, the
/// salt, for options 2 and 3).
#[derive(Clone)]
pub struct ConcatKDF<F: AuxiliaryFunction> {
    function: F,
}

impl<H: CryptographicDigest + Default> ConcatKDF<HashFunction<H>> {
    /// The KDF over the hash function `H` (option 1).
    pub fn hash() -> ConcatKDF<HashFunction<H>> {
        ConcatKDF { function: HashFunction::new() }
    }
}

impl<F: AuxiliaryFunction> ConcatKDF<F> {
    /// The most outputs of H: the counter is 32 bits (SP 800-56C Rev. 2 §4.1).
    pub const MAXIMUM_REPETITIONS: u64 = u32::MAX as u64;

    /// The KDF over `function`, keyed with the salt for options 2 and 3.
    pub fn new(function: F) -> ConcatKDF<F> {
        ConcatKDF { function }
    }

    /// Derives `out` (its length is L) from the shared secret `z` and
    /// `fixed_info` (SP 800-56C Rev. 2 §4.1): the first L bytes of
    /// K(1) || K(2) || ..., where K(i) = H(\[i\]_32 || Z || FixedInfo).
    pub fn derive(&self, z: &[u8], fixed_info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        let repetitions = out.len().div_ceil(F::OUTPUT_SIZE) as u64;
        if repetitions > ConcatKDF::<F>::MAXIMUM_REPETITIONS {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        let mut block = alloc::vec![0u8; F::OUTPUT_SIZE];
        for (index, piece) in out.chunks_mut(F::OUTPUT_SIZE).enumerate() {
            let mut function = self.function.clone();
            function.update(&(index as u32 + 1).to_be_bytes());
            function.update(z);
            function.update(fixed_info);
            function.finalize_into(&mut block);
            piece.copy_from_slice(&block[..piece.len()]);
        }
        block.zeroize();
        Ok(())
    }
}

impl<F: AuxiliaryFunction + Zeroize> Zeroize for ConcatKDF<F> {
    fn zeroize(&mut self) {
        self.function.zeroize();
    }
}

impl<F: AuxiliaryFunction> fmt::Debug for ConcatKDF<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConcatKDF(..)")
    }
}
