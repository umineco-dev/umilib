use core::marker::PhantomData;

use super::{SM9Encoding, SM9EncryptUserKey, SM9Hash, SM9KDF};
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::math::ec::{AffinePoint, FieldElement};
use crate::math::pairing::{G2Affine, Pairing, PairingCurve};
use crate::secret::{ConstantTimeEq, Zeroize};

/// The key encapsulation mechanism of GM/T 0044.4-2016 clause 6 on the curve
/// `C` with the hash function `H`: C = \[r\]Q of the recipient's Q and K =
/// KDF(C || w || ID, klen) with w = e(Ppub-e, P2)^r.
pub struct SM9KEM<C: PairingCurve, H: CryptographicDigest + Default> {
    types: PhantomData<(C, H)>,
}

impl<C: PairingCurve, H: CryptographicDigest + Default> SM9KEM<C, H> {
    /// Steps A1 to A6 without the check of K: C = \[r\]Q of `identity` and
    /// `hid` under Ppub-e `master`, and K = KDF(C || w || ID) into `out`
    /// (the encryption of clause 7 checks only a part of K).
    pub fn derive_sender(
        master: &AffinePoint<C::G1>,
        identity: &[u8],
        hid: u8,
        ephemeral: &FieldElement<C::Scalar>,
        out: &mut [u8],
    ) -> Result<AffinePoint<C::G1>, CryptoError> {
        if ephemeral.is_zero().into_bool() {
            return Err(CryptoError::InvalidParameter);
        }
        let point = SM9Hash::<C, H>::identity_point(master, identity, hid)?;
        let encapsulated = point.to_projective().mul(ephemeral).to_affine();
        let g = Pairing::<C>::pairing(master, &G2Affine::generator()).map_err(|_| CryptoError::InvalidKey)?;
        let mut w = SM9Encoding::<C>::gt(&g.pow(ephemeral));
        SM9KDF::<H>::derive(&[&SM9Encoding::<C>::g1(&encapsulated)?, &w, identity], out);
        w.zeroize();
        Ok(encapsulated)
    }

    /// Steps B1 and B2 and the KDF of B3 without the check of K: w' = e(C,
    /// de) and K' = KDF(C || w' || ID) into `out`. Fails with `InvalidKey`
    /// unless C is a point of G_1 other than the identity.
    pub fn derive_receiver(
        key: &SM9EncryptUserKey<C>,
        encapsulated: &AffinePoint<C::G1>,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if (encapsulated.is_identity() | !encapsulated.is_in_subgroup()).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let w = Pairing::<C>::pairing(encapsulated, key.key()).map_err(|_| CryptoError::InvalidKey)?;
        let mut w = SM9Encoding::<C>::gt(&w);
        SM9KDF::<H>::derive(&[&SM9Encoding::<C>::g1(encapsulated)?, &w, key.identity()], out);
        w.zeroize();
        Ok(())
    }

    /// Whether `bytes` are all zero, in constant time.
    pub fn is_zero(bytes: &[u8]) -> bool {
        bytes.iter().fold(0u8, |any, byte| any | byte).ct_eq(&0).into_bool()
    }

    /// Steps A1 to A7 with the random r given: writes K into `out` of klen /
    /// 8 bytes and gives the encapsulation C. r must be secret, random and
    /// used once; fails with `InvalidParameter` if K is zero (step A6), when
    /// another r is needed, and with `InputLength` for an empty `out`.
    pub fn encapsulate_with_ephemeral(
        master: &AffinePoint<C::G1>,
        identity: &[u8],
        hid: u8,
        ephemeral: &FieldElement<C::Scalar>,
        out: &mut [u8],
    ) -> Result<AffinePoint<C::G1>, CryptoError> {
        if out.is_empty() {
            return Err(CryptoError::InputLength { length: 0 });
        }
        let encapsulated = SM9KEM::<C, H>::derive_sender(master, identity, hid, ephemeral, out)?;
        if SM9KEM::<C, H>::is_zero(out) {
            out.zeroize();
            return Err(CryptoError::InvalidParameter);
        }
        Ok(encapsulated)
    }

    /// Clause 6.1 with r drawn from `random`, drawn again when K is zero:
    /// writes K for `identity` and `hid` under Ppub-e `master` into `out`
    /// and gives C.
    pub fn encapsulate<R: Random>(
        master: &AffinePoint<C::G1>,
        identity: &[u8],
        hid: u8,
        out: &mut [u8],
        random: &mut R,
    ) -> Result<AffinePoint<C::G1>, CryptoError> {
        loop {
            let mut ephemeral =
                FieldElement::random_nonzero(|bytes| random.fill(bytes)).map_err(|_| CryptoError::RandomFailed)?;
            let result = SM9KEM::<C, H>::encapsulate_with_ephemeral(master, identity, hid, &ephemeral, out);
            ephemeral.zeroize();
            match result {
                Err(CryptoError::InvalidParameter) => continue,
                result => return result,
            }
        }
    }

    /// Clause 6.2: writes K' of the encapsulation C for `key` into `out` of
    /// klen / 8 bytes. Fails with `InvalidKey` unless C is a point of G_1
    /// other than the identity, with `DecryptionFailed` if K' is zero and
    /// with `InputLength` for an empty `out`.
    pub fn decapsulate(
        key: &SM9EncryptUserKey<C>,
        encapsulated: &AffinePoint<C::G1>,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if out.is_empty() {
            return Err(CryptoError::InputLength { length: 0 });
        }
        SM9KEM::<C, H>::derive_receiver(key, encapsulated, out)?;
        if SM9KEM::<C, H>::is_zero(out) {
            return Err(CryptoError::DecryptionFailed);
        }
        Ok(())
    }
}
