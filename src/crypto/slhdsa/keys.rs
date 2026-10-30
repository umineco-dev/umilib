use core::fmt;
use core::marker::PhantomData;

use super::SLHDSAParameters;
use crate::crypto::CryptoError;
use crate::secret::{ConstantTimeEq, Zeroize};

/// A public key of SLH-DSA with the parameters `P`: PK.seed and PK.root, n bytes each.
pub struct SLHDSAVerifyingKey<P: SLHDSAParameters> {
    pk_seed: [u8; 32],
    pk_root: [u8; 32],
    parameters: PhantomData<P>,
}

impl<P: SLHDSAParameters> SLHDSAVerifyingKey<P> {
    /// The key of PK.seed and PK.root (n bytes each).
    pub fn new(pk_seed: &[u8], pk_root: &[u8]) -> SLHDSAVerifyingKey<P> {
        let (mut seed, mut root) = ([0u8; 32], [0u8; 32]);
        seed[..P::N].copy_from_slice(pk_seed);
        root[..P::N].copy_from_slice(pk_root);
        SLHDSAVerifyingKey { pk_seed: seed, pk_root: root, parameters: PhantomData }
    }

    /// The key PK.seed || PK.root of 2 n bytes (the check of FIPS 205
    /// section 3.1); fails with `InvalidKey` for another length.
    pub fn from_bytes(bytes: &[u8]) -> Result<SLHDSAVerifyingKey<P>, CryptoError> {
        if bytes.len() != P::PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }
        Ok(SLHDSAVerifyingKey::new(&bytes[..P::N], &bytes[P::N..]))
    }

    /// Writes PK.seed || PK.root into `out` of 2 n bytes.
    pub fn write_bytes(&self, out: &mut [u8]) {
        out[..P::N].copy_from_slice(self.pk_seed());
        out[P::N..].copy_from_slice(self.pk_root());
    }

    pub fn pk_seed(&self) -> &[u8] {
        &self.pk_seed[..P::N]
    }

    pub fn pk_root(&self) -> &[u8] {
        &self.pk_root[..P::N]
    }
}

impl<P: SLHDSAParameters> Clone for SLHDSAVerifyingKey<P> {
    fn clone(&self) -> SLHDSAVerifyingKey<P> {
        SLHDSAVerifyingKey { pk_seed: self.pk_seed, pk_root: self.pk_root, parameters: PhantomData }
    }
}

impl<P: SLHDSAParameters> PartialEq for SLHDSAVerifyingKey<P> {
    fn eq(&self, other: &SLHDSAVerifyingKey<P>) -> bool {
        self.pk_seed == other.pk_seed && self.pk_root == other.pk_root
    }
}

impl<P: SLHDSAParameters> Eq for SLHDSAVerifyingKey<P> {}

/// Prints the parameter set and the key.
impl<P: SLHDSAParameters> fmt::Debug for SLHDSAVerifyingKey<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SLHDSAVerifyingKey({}, ", P::NAME)?;
        for byte in self.pk_seed().iter().chain(self.pk_root()) {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

/// A private key of SLH-DSA with the parameters `P`: SK.seed, SK.prf and
/// the public key; zeroized when dropped.
pub struct SLHDSASigningKey<P: SLHDSAParameters> {
    sk_seed: [u8; 32],
    sk_prf: [u8; 32],
    verifying: SLHDSAVerifyingKey<P>,
}

impl<P: SLHDSAParameters> SLHDSASigningKey<P> {
    /// The key of SK.seed and SK.prf (n bytes each) and its public key.
    pub fn new(sk_seed: &[u8], sk_prf: &[u8], verifying: SLHDSAVerifyingKey<P>) -> SLHDSASigningKey<P> {
        let (mut seed, mut prf) = ([0u8; 32], [0u8; 32]);
        seed[..P::N].copy_from_slice(sk_seed);
        prf[..P::N].copy_from_slice(sk_prf);
        SLHDSASigningKey { sk_seed: seed, sk_prf: prf, verifying }
    }

    /// Writes SK.seed || SK.prf || PK.seed || PK.root into `out` of 4 n bytes.
    pub fn write_bytes(&self, out: &mut [u8]) {
        out[..P::N].copy_from_slice(self.sk_seed());
        out[P::N..2 * P::N].copy_from_slice(self.sk_prf());
        self.verifying.write_bytes(&mut out[2 * P::N..]);
    }

    pub fn sk_seed(&self) -> &[u8] {
        &self.sk_seed[..P::N]
    }

    pub fn sk_prf(&self) -> &[u8] {
        &self.sk_prf[..P::N]
    }

    pub fn verifying_key(&self) -> &SLHDSAVerifyingKey<P> {
        &self.verifying
    }

    /// Whether `pk_root` is the root of the key, in constant time.
    pub fn has_root(&self, pk_root: &[u8]) -> bool {
        self.verifying.pk_root().ct_eq(pk_root).into_bool()
    }
}

impl<P: SLHDSAParameters> Zeroize for SLHDSASigningKey<P> {
    fn zeroize(&mut self) {
        self.sk_seed.zeroize();
        self.sk_prf.zeroize();
    }
}

impl<P: SLHDSAParameters> Drop for SLHDSASigningKey<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the public key, not the secrets.
impl<P: SLHDSAParameters> fmt::Debug for SLHDSASigningKey<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SLHDSASigningKey({:?}, ..)", self.verifying)
    }
}
