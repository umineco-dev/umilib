use alloc::vec::Vec;
use core::fmt;

use super::SM9Hash;
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::math::ec::{AffinePoint, FieldElement, ProjectivePoint};
use crate::math::pairing::{G2Affine, G2Projective, PairingCurve};
use crate::secret::Zeroize;

/// The encryption master key of a KGC (GM/T 0044.3-2016 and 0044.4-2016
/// section 5.3): ke in \[1, N - 1\] and Ppub-e = \[ke\]P1 in G_1; zeroized
/// when dropped.
pub struct SM9EncryptMasterKey<C: PairingCurve> {
    secret: FieldElement<C::Scalar>,
    public: AffinePoint<C::G1>,
}

impl<C: PairingCurve> SM9EncryptMasterKey<C> {
    /// The master key of ke `secret`; fails with `InvalidKey` for zero.
    pub fn new(secret: FieldElement<C::Scalar>) -> Result<SM9EncryptMasterKey<C>, CryptoError> {
        if secret.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(SM9EncryptMasterKey { secret, public: ProjectivePoint::generator().mul(&secret).to_affine() })
    }

    /// A master key with ke drawn from `random`.
    pub fn generate<R: Random>(random: &mut R) -> Result<SM9EncryptMasterKey<C>, CryptoError> {
        let secret = FieldElement::random_nonzero(|bytes| random.fill(bytes)).map_err(|_| CryptoError::RandomFailed)?;
        SM9EncryptMasterKey::new(secret)
    }

    /// ke.
    pub fn secret(&self) -> &FieldElement<C::Scalar> {
        &self.secret
    }

    /// Ppub-e.
    pub fn public_key(&self) -> &AffinePoint<C::G1> {
        &self.public
    }

    /// The encryption key of `identity` with the identifier `hid` (section
    /// 5.3): t1 = H1(ID || hid, N) + ke, t2 = ke t1^-1, de = \[t2\]P2. Fails
    /// with `InvalidParameter` if t1 = 0, when the master key must be
    /// generated again.
    pub fn extract<H: CryptographicDigest + Default>(
        &self,
        identity: &[u8],
        hid: u8,
    ) -> Result<SM9EncryptUserKey<C>, CryptoError> {
        let h1 = SM9Hash::<C, H>::hash(SM9Hash::<C, H>::H1, &[identity, &[hid]])?;
        let mut t1 = h1.add(&self.secret);
        let inverse = t1.invert();
        t1.zeroize();
        let mut inverse = inverse.map_err(|_| CryptoError::InvalidParameter)?;
        let mut t2 = self.secret.mul(&inverse);
        inverse.zeroize();
        let key = G2Projective::<C>::generator().mul(&t2).to_affine();
        t2.zeroize();
        Ok(SM9EncryptUserKey::new(identity, hid, key, self.public))
    }
}

impl<C: PairingCurve> Zeroize for SM9EncryptMasterKey<C> {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl<C: PairingCurve> Drop for SM9EncryptMasterKey<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints Ppub-e, not ke.
impl<C: PairingCurve> fmt::Debug for SM9EncryptMasterKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SM9EncryptMasterKey({:?}, ..)", self.public)
    }
}

/// The encryption key of a user: its identity, the identifier hid it was
/// generated with, de in G_2 and the master public key Ppub-e; zeroized
/// when dropped.
pub struct SM9EncryptUserKey<C: PairingCurve> {
    identity: Vec<u8>,
    hid: u8,
    key: G2Affine<C>,
    master: AffinePoint<C::G1>,
}

impl<C: PairingCurve> SM9EncryptUserKey<C> {
    /// The key de `key` of `identity` and `hid` under Ppub-e `master`, as
    /// [`SM9EncryptMasterKey::extract`] gives it; a wrong key decrypts nothing.
    pub fn new(identity: &[u8], hid: u8, key: G2Affine<C>, master: AffinePoint<C::G1>) -> SM9EncryptUserKey<C> {
        SM9EncryptUserKey { identity: identity.to_vec(), hid, key, master }
    }

    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// The identifier of the key generating function.
    pub fn hid(&self) -> u8 {
        self.hid
    }

    /// de.
    pub fn key(&self) -> &G2Affine<C> {
        &self.key
    }

    /// Ppub-e.
    pub fn master(&self) -> &AffinePoint<C::G1> {
        &self.master
    }
}

impl<C: PairingCurve> Zeroize for SM9EncryptUserKey<C> {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<C: PairingCurve> Drop for SM9EncryptUserKey<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the identity, not the key.
impl<C: PairingCurve> fmt::Debug for SM9EncryptUserKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SM9EncryptUserKey({:?}, {:#04x}, ..)", self.identity, self.hid)
    }
}
