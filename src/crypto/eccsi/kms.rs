use core::fmt;

use super::ECCSIUserKey;
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::math::ec::{AffinePoint, FieldElement, ProjectivePoint, WeierstrassCurve};
use crate::secret::Zeroize;

/// The key management service of ECCSI: the KMS secret authentication key
/// KSAK, non-zero modulo q, and the KMS public authentication key KPAK =
/// \[KSAK\]G (RFC 6507 section 4.2); zeroized when dropped.
pub struct ECCSIKMS<C: WeierstrassCurve> {
    secret: FieldElement<C::Scalar>,
    public: AffinePoint<C>,
}

impl<C: WeierstrassCurve> ECCSIKMS<C> {
    /// The service of the KSAK `secret`; fails with `InvalidKey` for zero.
    pub fn new(secret: FieldElement<C::Scalar>) -> Result<ECCSIKMS<C>, CryptoError> {
        if secret.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(ECCSIKMS { secret, public: ProjectivePoint::generator().mul(&secret).to_affine() })
    }

    /// A service with a random KSAK.
    pub fn generate<R: Random>(random: &mut R) -> Result<ECCSIKMS<C>, CryptoError> {
        let secret = FieldElement::random_nonzero(|bytes| random.fill(bytes)).map_err(|_| CryptoError::RandomFailed)?;
        ECCSIKMS::new(secret)
    }

    /// KSAK, the secret of the service.
    pub fn secret(&self) -> &FieldElement<C::Scalar> {
        &self.secret
    }

    /// KPAK, the root of trust of the community.
    pub fn public_key(&self) -> &AffinePoint<C> {
        &self.public
    }

    /// The (SSK, PVT) pair of `identity` (section 5.1.1) with v drawn from `random`.
    pub fn issue<H: CryptographicDigest + Default, R: Random>(
        &self,
        identity: &[u8],
        random: &mut R,
    ) -> Result<ECCSIUserKey<C, H>, CryptoError> {
        loop {
            let mut ephemeral =
                FieldElement::random_nonzero(|bytes| random.fill(bytes)).map_err(|_| CryptoError::RandomFailed)?;
            let key = self.issue_with_ephemeral(identity, &ephemeral);
            ephemeral.zeroize();
            match key {
                Err(CryptoError::InvalidParameter) => continue,
                key => return key,
            }
        }
    }

    /// The (SSK, PVT) pair of `identity` with the ephemeral v given (section
    /// 5.1.1 steps 2 to 6): PVT = \[v\]G, HS = hash(G || KPAK || ID || PVT),
    /// SSK = (KSAK + HS v) mod q. v must be secret, random and used once;
    /// fails with `InvalidParameter` if SSK or HS is zero, when another v is needed.
    pub fn issue_with_ephemeral<H: CryptographicDigest + Default>(
        &self,
        identity: &[u8],
        ephemeral: &FieldElement<C::Scalar>,
    ) -> Result<ECCSIUserKey<C, H>, CryptoError> {
        let token = ProjectivePoint::generator().mul(ephemeral).to_affine();
        let hash = ECCSIUserKey::<C, H>::identity_hash(&self.public, identity, &token)?;
        let secret = self.secret.add(&hash.mul(ephemeral));
        if (secret.is_zero() | hash.is_zero()).into_bool() {
            return Err(CryptoError::InvalidParameter);
        }
        ECCSIUserKey::new(&self.public, identity, secret, token)
    }
}

impl<C: WeierstrassCurve> Zeroize for ECCSIKMS<C> {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl<C: WeierstrassCurve> Drop for ECCSIKMS<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints KPAK, not KSAK.
impl<C: WeierstrassCurve> fmt::Debug for ECCSIKMS<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ECCSIKMS({:?}, ..)", self.public)
    }
}
