use alloc::vec;
use core::fmt;
use core::marker::PhantomData;

use super::{SM2KDF, SM2PrivateKey, SM2PublicKey};
use crate::crypto::CryptoError;
use crate::crypto::curve::sm2::SM2;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::hash::sm3::SM3;
use crate::math::bigint::UnsignedInteger;
use crate::math::ec::{AffinePoint, FieldElement, FieldValue, PrimeField, WeierstrassCurve};
use crate::math::modular::ModularArithmetic;
use crate::secret::{ConstantTimeEq, Zeroize};

/// The part a user plays in [`SM2KEP`]: A, who starts, or B, who responds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SM2Role {
    Initiator,
    Responder,
}

/// The optional confirmations of GB/T 32918.3 section 6.1: B sends
/// [`SM2KeyConfirmation::responder`] (S_B, checked by A as S_1) and A sends
/// [`SM2KeyConfirmation::initiator`] (S_A, checked by B as S_2).
pub struct SM2KeyConfirmation<H: CryptographicDigest> {
    responder: H::Output,
    initiator: H::Output,
}

impl<H: CryptographicDigest> SM2KeyConfirmation<H> {
    /// H(0x02 || yV || H(xV || ZA || ZB || x1 || y1 || x2 || y2)).
    pub fn responder(&self) -> &[u8] {
        self.responder.as_ref()
    }

    /// H(0x03 || yV || H(xV || ZA || ZB || x1 || y1 || x2 || y2)).
    pub fn initiator(&self) -> &[u8] {
        self.initiator.as_ref()
    }
}

impl<H: CryptographicDigest> fmt::Debug for SM2KeyConfirmation<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SM2KeyConfirmation({:?}, {:?})", self.responder, self.initiator)
    }
}

/// One side of the key exchange protocol of GB/T 32918.3 on the curve `C`
/// with the hash function `H`: the user's key, the hash Z of its identity
/// and its ephemeral key r with R = \[r\]G.
pub struct SM2KEP<C: WeierstrassCurve = SM2, H: CryptographicDigest + Default = SM3> {
    role: SM2Role,
    key: SM2PrivateKey<C>,
    identity_hash: H::Output,
    ephemeral: SM2PrivateKey<C>,
    types: PhantomData<(C, H)>,
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> SM2KEP<C, H> {
    /// The side of `role` for the user of `key` with the identity
    /// `identity` and the ephemeral key `ephemeral` (steps A1-A2 or B1-B2).
    pub fn new(
        role: SM2Role,
        key: SM2PrivateKey<C>,
        identity: &[u8],
        ephemeral: SM2PrivateKey<C>,
    ) -> Result<SM2KEP<C, H>, CryptoError> {
        let identity_hash = key.public_key().identity_hash::<H>(identity)?;
        Ok(SM2KEP { role, key, identity_hash, ephemeral, types: PhantomData })
    }

    /// [`SM2KEP::new`] with an ephemeral key of the bytes of `random`.
    pub fn generate<R: Random>(
        role: SM2Role,
        key: SM2PrivateKey<C>,
        identity: &[u8],
        random: &mut R,
    ) -> Result<SM2KEP<C, H>, CryptoError> {
        SM2KEP::new(role, key, identity, SM2PrivateKey::generate(random)?)
    }

    pub fn role(&self) -> SM2Role {
        self.role
    }

    /// R, which the user sends to the other.
    pub fn ephemeral_public_key(&self) -> &SM2PublicKey<C> {
        self.ephemeral.public_key()
    }

    /// The hash Z of the user's identity.
    pub fn identity_hash(&self) -> &[u8] {
        self.identity_hash.as_ref()
    }

    /// x̄ = 2^w + (x mod 2^w) with w = ⌈⌈log2 n⌉ / 2⌉ - 1 (section 6.1, steps A4 and B3).
    pub fn reduced_coordinate(point: &AffinePoint<C>) -> Result<FieldElement<C::Scalar>, CryptoError> {
        let w = <C::Scalar as PrimeField>::MODULUS.value().bit_length().div_ceil(2) - 1;
        let size = <C::Field as PrimeField>::BYTES;
        let mut x = vec![0u8; size];
        point.x().write_be_bytes(&mut x).map_err(|_| CryptoError::InvalidKey)?;
        // The low w bits lie in the last ⌈w / 8⌉ bytes, which fit the precision of the scalars.
        let low = &x[size - (w as usize).div_ceil(8)..];
        let value = FieldValue::<C::Scalar>::from_be_bytes(low).map_err(|_| CryptoError::InvalidKey)?;
        let unused = <FieldValue<C::Scalar> as UnsignedInteger>::BITS - w;
        let value = value.shl(unused).shr(unused).wrapping_add(&FieldValue::<C::Scalar>::ONE.shl(w));
        Ok(FieldElement::from_value_reduced(&value))
    }

    /// The shared key of `out.len()` bytes with the user of `peer`, of the
    /// identity `peer_identity`, who sent `peer_ephemeral`, and the
    /// confirmations (steps A4-A8 or B3-B7): t = (d + x̄ r) mod n,
    /// V = [h t](P' + [x̄'] R'), K = KDF(xV || yV || ZA || ZB). Fails with
    /// `InvalidKey` if V is the identity.
    pub fn agree(
        &self,
        peer: &SM2PublicKey<C>,
        peer_identity: &[u8],
        peer_ephemeral: &SM2PublicKey<C>,
        out: &mut [u8],
    ) -> Result<SM2KeyConfirmation<H>, CryptoError> {
        let peer_hash = peer.identity_hash::<H>(peer_identity)?;
        let own = SM2KEP::<C, H>::reduced_coordinate(self.ephemeral.public_key().point())?;
        let other = SM2KEP::<C, H>::reduced_coordinate(peer_ephemeral.point())?;
        let mut t = self.key.scalar().add(&own.mul(self.ephemeral.scalar()));
        let cofactor =
            FieldValue::<C::Scalar>::from_be_bytes(&C::COFACTOR.to_be_bytes()).map_err(|_| CryptoError::InvalidKey)?;
        let sum = peer.point().to_projective().add(&peer_ephemeral.point().to_projective().mul_vartime(&other));
        let mut shared = sum.mul(&t).mul_value_vartime(&cofactor).to_affine();
        t.zeroize();
        if shared.is_identity().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let (z_a, z_b) = match self.role {
            SM2Role::Initiator => (self.identity_hash.as_ref(), peer_hash.as_ref()),
            SM2Role::Responder => (peer_hash.as_ref(), self.identity_hash.as_ref()),
        };
        let (initiator, responder) = match self.role {
            SM2Role::Initiator => (self.ephemeral.public_key().point(), peer_ephemeral.point()),
            SM2Role::Responder => (peer_ephemeral.point(), self.ephemeral.public_key().point()),
        };
        let size = <C::Field as PrimeField>::BYTES;
        let mut v = vec![0u8; 2 * size];
        let mut points = vec![0u8; 4 * size];
        let failed = |_| CryptoError::InvalidKey;
        shared.x().write_be_bytes(&mut v[..size]).map_err(failed)?;
        shared.y().write_be_bytes(&mut v[size..]).map_err(failed)?;
        shared.zeroize();
        for (index, coordinate) in [initiator.x(), initiator.y(), responder.x(), responder.y()].iter().enumerate() {
            coordinate.write_be_bytes(&mut points[index * size..(index + 1) * size]).map_err(failed)?;
        }
        SM2KDF::<H>::derive(&[&v, z_a, z_b], out);
        let mut inner = H::default();
        inner.update(&v[..size]);
        inner.update(z_a);
        inner.update(z_b);
        inner.update(&points);
        let inner = inner.finalize();
        let confirmation = |tag: u8| {
            let mut hash = H::default();
            hash.update(&[tag]);
            hash.update(&v[size..]);
            hash.update(inner.as_ref());
            hash.finalize()
        };
        let result = SM2KeyConfirmation { responder: confirmation(0x02), initiator: confirmation(0x03) };
        v.zeroize();
        Ok(result)
    }

    /// Whether `received` is the confirmation the other user must send:
    /// S_B for the initiator, S_A for the responder; compared in constant time.
    pub fn confirm(&self, confirmation: &SM2KeyConfirmation<H>, received: &[u8]) -> bool {
        let expected = match self.role {
            SM2Role::Initiator => confirmation.responder(),
            SM2Role::Responder => confirmation.initiator(),
        };
        expected.ct_eq(received).into_bool()
    }
}

/// Prints the role and the public keys, not the private ones.
impl<C: WeierstrassCurve, H: CryptographicDigest + Default> fmt::Debug for SM2KEP<C, H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SM2KEP({:?}, {:?}, ..)", self.role, self.ephemeral.public_key())
    }
}
