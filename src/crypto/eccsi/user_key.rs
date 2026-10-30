use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use crate::crypto::CryptoError;
use crate::hash::CryptographicDigest;
use crate::math::ec::{AffinePoint, CoefficientA, FieldElement, PrimeField, ProjectivePoint, WeierstrassCurve};
use crate::secret::Zeroize;

/// The key of an ECCSI signer: its identity, the secret signing key SSK,
/// the public validation token PVT, HS and the community's KPAK, validated
/// as RFC 6507 section 5.1.2 requires; zeroized when dropped.
pub struct ECCSIUserKey<C: WeierstrassCurve, H: CryptographicDigest + Default> {
    identity: Vec<u8>,
    secret: FieldElement<C::Scalar>,
    token: AffinePoint<C>,
    hash: FieldElement<C::Scalar>,
    authority: AffinePoint<C>,
    types: PhantomData<H>,
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> ECCSIUserKey<C, H> {
    /// The canonical form of a point (RFC 6509 section 3.2): 04 || x || y.
    pub fn canonical(point: &AffinePoint<C>) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0u8; AffinePoint::<C>::encoded_length(false)];
        point.write_encoded(&mut out, false).map_err(|_| CryptoError::InvalidKey)?;
        Ok(out)
    }

    /// Checks the parameters of section 4.1: a = -3 and N = the bytes of the hash.
    pub fn check_parameters() -> Result<(), CryptoError> {
        if C::SHAPE != CoefficientA::MinusThree || H::OUTPUT_SIZE != <C::Field as PrimeField>::BYTES {
            return Err(CryptoError::InvalidParameter);
        }
        Ok(())
    }

    /// HS = hash(G || KPAK || ID || PVT) as an integer modulo q.
    pub fn identity_hash(
        authority: &AffinePoint<C>,
        identity: &[u8],
        token: &AffinePoint<C>,
    ) -> Result<FieldElement<C::Scalar>, CryptoError> {
        ECCSIUserKey::<C, H>::check_parameters()?;
        let mut hash = H::default();
        hash.update(&ECCSIUserKey::<C, H>::canonical(&AffinePoint::generator())?);
        hash.update(&ECCSIUserKey::<C, H>::canonical(authority)?);
        hash.update(identity);
        hash.update(&ECCSIUserKey::<C, H>::canonical(token)?);
        Ok(FieldElement::from_be_bytes_reduced(hash.finalize().as_ref()))
    }

    /// The key of `identity` from the (SSK, PVT) pair of the KMS whose KPAK
    /// is `authority`, validated (section 5.1.2): PVT on the curve and not
    /// the identity, and KPAK = \[SSK\]G - \[HS\]PVT. Fails with `InvalidKey`
    /// otherwise.
    pub fn new(
        authority: &AffinePoint<C>,
        identity: &[u8],
        secret: FieldElement<C::Scalar>,
        token: AffinePoint<C>,
    ) -> Result<ECCSIUserKey<C, H>, CryptoError> {
        if (authority.is_identity() | token.is_identity() | secret.is_zero()).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let hash = ECCSIUserKey::<C, H>::identity_hash(authority, identity, &token)?;
        let expected = ProjectivePoint::generator().mul(&secret).sub(&token.to_projective().mul_vartime(&hash));
        if expected != authority.to_projective() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(ECCSIUserKey { identity: identity.to_vec(), secret, token, hash, authority: *authority, types: PhantomData })
    }

    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// SSK.
    pub fn secret(&self) -> &FieldElement<C::Scalar> {
        &self.secret
    }

    /// PVT.
    pub fn token(&self) -> &AffinePoint<C> {
        &self.token
    }

    /// HS.
    pub fn hash(&self) -> &FieldElement<C::Scalar> {
        &self.hash
    }

    /// KPAK.
    pub fn authority(&self) -> &AffinePoint<C> {
        &self.authority
    }
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> Zeroize for ECCSIUserKey<C, H> {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> Drop for ECCSIUserKey<C, H> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the public values, not SSK.
impl<C: WeierstrassCurve, H: CryptographicDigest + Default> fmt::Debug for ECCSIUserKey<C, H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ECCSIUserKey(PVT: {:?}, ..)", self.token)
    }
}
