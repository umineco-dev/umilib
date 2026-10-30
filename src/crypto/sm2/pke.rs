use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{SM2KDF, SM2PrivateKey, SM2PublicKey};
use crate::crypto::CryptoError;
use crate::crypto::curve::sm2::SM2;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::hash::sm3::SM3;
use crate::math::bigint::UnsignedInteger;
use crate::math::ec::{AffinePoint, FieldElement, FieldValue, PrimeField, ProjectivePoint, WeierstrassCurve};
use crate::secret::{ConstantTimeEq, Zeroize};

/// The order of the parts of a ciphertext of [`SM2PKE`]: C1 the point
/// \[k\]G, C2 the masked message and C3 the hash H(x2 || M || y2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SM2CiphertextOrder {
    /// C1 || C3 || C2, of GB/T 32918.4-2016 and GM/T 0009-2012.
    C1C3C2,
    /// C1 || C2 || C3, of GM/T 0003.4-2012 and draft-shen-sm2-ecdsa.
    C1C2C3,
}

/// The public key encryption of GB/T 32918.4 on the curve `C` with the
/// hash function `H`. C1 is the uncompressed point; a ciphertext is
/// [`SM2PKE::OVERHEAD`] bytes longer than its message.
pub struct SM2PKE<C: WeierstrassCurve = SM2, H: CryptographicDigest + Default = SM3> {
    types: PhantomData<(C, H)>,
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> SM2PKE<C, H> {
    /// The bytes of C1 and C3.
    pub const OVERHEAD: usize = AffinePoint::<C>::encoded_length(false) + H::OUTPUT_SIZE;

    /// \[h\]P, which must not be the identity (steps A3 and B1).
    pub fn check_cofactor(point: &AffinePoint<C>) -> Result<(), CryptoError> {
        let cofactor =
            FieldValue::<C::Scalar>::from_be_bytes(&C::COFACTOR.to_be_bytes()).map_err(|_| CryptoError::InvalidKey)?;
        if point.to_projective().mul_value_vartime(&cofactor).is_identity().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(())
    }

    /// The encryption of `message` for `key` (section 6.1), with the k of
    /// the bytes of `random`, in the order `order`.
    pub fn encrypt<R: Random>(
        key: &SM2PublicKey<C>,
        message: &[u8],
        order: SM2CiphertextOrder,
        random: &mut R,
    ) -> Result<Vec<u8>, CryptoError> {
        SM2PKE::<C, H>::check_cofactor(key.point())?;
        let size = <C::Field as PrimeField>::BYTES;
        let point_size = AffinePoint::<C>::encoded_length(false);
        let mut c1 = vec![0u8; point_size];
        let mut shared = vec![0u8; 2 * size];
        let mut mask = vec![0u8; message.len()];
        loop {
            let mut k = FieldElement::<C::Scalar>::random_nonzero(|bytes| random.fill(bytes))
                .map_err(|_| CryptoError::RandomFailed)?;
            ProjectivePoint::<C>::generator()
                .mul(&k)
                .to_affine()
                .write_encoded(&mut c1, false)
                .map_err(|_| CryptoError::InvalidKey)?;
            let mut point = key.point().to_projective().mul(&k).to_affine();
            k.zeroize();
            point.x().write_be_bytes(&mut shared[..size]).map_err(|_| CryptoError::InvalidKey)?;
            point.y().write_be_bytes(&mut shared[size..]).map_err(|_| CryptoError::InvalidKey)?;
            point.zeroize();
            SM2KDF::<H>::derive(&[&shared], &mut mask);
            // Step A5: a mask of zeros is drawn again.
            if message.is_empty() || mask.iter().any(|byte| *byte != 0) {
                break;
            }
        }
        let mut hash = H::default();
        hash.update(&shared[..size]);
        hash.update(message);
        hash.update(&shared[size..]);
        let c3 = hash.finalize();
        shared.zeroize();
        for (byte, message) in mask.iter_mut().zip(message) {
            *byte ^= message;
        }
        let mut ciphertext = Vec::with_capacity(SM2PKE::<C, H>::OVERHEAD + message.len());
        ciphertext.extend_from_slice(&c1);
        match order {
            SM2CiphertextOrder::C1C3C2 => {
                ciphertext.extend_from_slice(c3.as_ref());
                ciphertext.extend_from_slice(&mask);
            }
            SM2CiphertextOrder::C1C2C3 => {
                ciphertext.extend_from_slice(&mask);
                ciphertext.extend_from_slice(c3.as_ref());
            }
        }
        Ok(ciphertext)
    }

    /// The message of `ciphertext` in the order `order` for `key` (section
    /// 7.1); fails with `DecryptionFailed` for a C1 not on the curve, a mask
    /// of zeros or a hash C3 that does not match, releasing nothing.
    pub fn decrypt(
        key: &SM2PrivateKey<C>,
        ciphertext: &[u8],
        order: SM2CiphertextOrder,
    ) -> Result<Vec<u8>, CryptoError> {
        let point_size = AffinePoint::<C>::encoded_length(false);
        let length = ciphertext.len().checked_sub(SM2PKE::<C, H>::OVERHEAD).ok_or(CryptoError::DecryptionFailed)?;
        let (c1, rest) = ciphertext.split_at(point_size);
        let (c2, c3) = match order {
            SM2CiphertextOrder::C1C3C2 => {
                let (c3, c2) = rest.split_at(H::OUTPUT_SIZE);
                (c2, c3)
            }
            SM2CiphertextOrder::C1C2C3 => rest.split_at(length),
        };
        let point = AffinePoint::<C>::from_encoded(c1).map_err(|_| CryptoError::DecryptionFailed)?;
        SM2PKE::<C, H>::check_cofactor(&point).map_err(|_| CryptoError::DecryptionFailed)?;
        let size = <C::Field as PrimeField>::BYTES;
        let mut shared = vec![0u8; 2 * size];
        let mut product = point.to_projective().mul(key.scalar()).to_affine();
        product.x().write_be_bytes(&mut shared[..size]).map_err(|_| CryptoError::DecryptionFailed)?;
        product.y().write_be_bytes(&mut shared[size..]).map_err(|_| CryptoError::DecryptionFailed)?;
        product.zeroize();
        let mut message = vec![0u8; c2.len()];
        SM2KDF::<H>::derive(&[&shared], &mut message);
        let zero = !message.is_empty() && message.iter().all(|byte| *byte == 0);
        for (byte, masked) in message.iter_mut().zip(c2) {
            *byte ^= masked;
        }
        let mut hash = H::default();
        hash.update(&shared[..size]);
        hash.update(&message);
        hash.update(&shared[size..]);
        shared.zeroize();
        if zero || !hash.finalize().as_ref().ct_eq(c3).into_bool() {
            message.zeroize();
            return Err(CryptoError::DecryptionFailed);
        }
        Ok(message)
    }
}
