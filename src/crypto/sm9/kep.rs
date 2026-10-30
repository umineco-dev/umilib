use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use super::{SM9Encoding, SM9EncryptUserKey, SM9Hash, SM9KDF};
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::math::ec::{AffinePoint, FieldElement};
use crate::math::pairing::{G2Affine, Pairing, PairingCurve};
use crate::secret::{ConstantTimeEq, Zeroize};

/// The part a user plays in [`SM9KEP`]: A, who starts, or B, who responds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SM9Role {
    Initiator,
    Responder,
}

/// The optional confirmations of GM/T 0044.3-2016 section 6.1: B sends
/// [`SM9KeyConfirmation::responder`] (S_B, checked by A as S_1) and A sends
/// [`SM9KeyConfirmation::initiator`] (S_A, checked by B as S_2).
pub struct SM9KeyConfirmation<H: CryptographicDigest> {
    responder: H::Output,
    initiator: H::Output,
}

impl<H: CryptographicDigest> SM9KeyConfirmation<H> {
    /// Hv(0x82 || g1 || Hv(g2 || g3 || IDA || IDB || RA || RB)).
    pub fn responder(&self) -> &[u8] {
        self.responder.as_ref()
    }

    /// Hv(0x83 || g1 || Hv(g2 || g3 || IDA || IDB || RA || RB)).
    pub fn initiator(&self) -> &[u8] {
        self.initiator.as_ref()
    }
}

impl<H: CryptographicDigest> fmt::Debug for SM9KeyConfirmation<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SM9KeyConfirmation({:?}, {:?})", self.responder, self.initiator)
    }
}

/// One side of the key exchange protocol of GM/T 0044.3-2016 on the curve
/// `C` with the hash function `H`: the user's encryption key, the identity
/// of the other user and the ephemeral r with R = \[r\]Q of the other user's
/// Q = \[H1(ID || hid, N)\]P1 + Ppub-e; zeroized when dropped.
pub struct SM9KEP<C: PairingCurve, H: CryptographicDigest + Default> {
    role: SM9Role,
    key: SM9EncryptUserKey<C>,
    peer_identity: Vec<u8>,
    ephemeral: FieldElement<C::Scalar>,
    ephemeral_public_key: AffinePoint<C::G1>,
    hash: PhantomData<H>,
}

impl<C: PairingCurve, H: CryptographicDigest + Default> SM9KEP<C, H> {
    /// The side of `role` for the user of `key` with the user `peer_identity`
    /// and the ephemeral r `ephemeral` in \[1, N - 1\] (steps A1 to A3 or B1
    /// to B3). r must be secret, random and used once; fails with
    /// `InvalidKey` for zero.
    pub fn new(
        role: SM9Role,
        key: SM9EncryptUserKey<C>,
        peer_identity: &[u8],
        ephemeral: FieldElement<C::Scalar>,
    ) -> Result<SM9KEP<C, H>, CryptoError> {
        if ephemeral.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let peer = SM9Hash::<C, H>::identity_point(key.master(), peer_identity, key.hid())?;
        let ephemeral_public_key = peer.to_projective().mul(&ephemeral).to_affine();
        Ok(SM9KEP {
            role,
            key,
            peer_identity: peer_identity.to_vec(),
            ephemeral,
            ephemeral_public_key,
            hash: PhantomData,
        })
    }

    /// [`SM9KEP::new`] with r drawn from `random`.
    pub fn generate<R: Random>(
        role: SM9Role,
        key: SM9EncryptUserKey<C>,
        peer_identity: &[u8],
        random: &mut R,
    ) -> Result<SM9KEP<C, H>, CryptoError> {
        let mut ephemeral =
            FieldElement::random_nonzero(|bytes| random.fill(bytes)).map_err(|_| CryptoError::RandomFailed)?;
        let side = SM9KEP::new(role, key, peer_identity, ephemeral);
        ephemeral.zeroize();
        side
    }

    pub fn role(&self) -> SM9Role {
        self.role
    }

    /// R, which this side sends to the other (steps A4 and B7).
    pub fn ephemeral_public_key(&self) -> &AffinePoint<C::G1> {
        &self.ephemeral_public_key
    }

    /// Writes the shared key SK of the other side's R `peer_ephemeral` into
    /// `out` of the length of the key to derive (klen / 8 bytes) and gives
    /// the confirmations (steps B4 to B6, or A5 to A8). Fails with
    /// `InvalidKey` unless R is a point of G_1 other than the identity.
    pub fn agree(
        &self,
        peer_ephemeral: &AffinePoint<C::G1>,
        out: &mut [u8],
    ) -> Result<SM9KeyConfirmation<H>, CryptoError> {
        if (peer_ephemeral.is_identity() | !peer_ephemeral.is_in_subgroup()).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let invalid = |_| CryptoError::InvalidKey;
        let own =
            Pairing::<C>::pairing(self.key.master(), &G2Affine::generator()).map_err(invalid)?.pow(&self.ephemeral);
        let peer = Pairing::<C>::pairing(peer_ephemeral, self.key.key()).map_err(invalid)?;
        let shared = peer.pow(&self.ephemeral);
        let (own, peer, shared) =
            (SM9Encoding::<C>::gt(&own), SM9Encoding::<C>::gt(&peer), SM9Encoding::<C>::gt(&shared));
        let own_point = SM9Encoding::<C>::g1(&self.ephemeral_public_key)?;
        let peer_point = SM9Encoding::<C>::g1(peer_ephemeral)?;
        // A: g1 = e(Ppub-e, P2)^rA, g2 = e(RB, deA), g3 = g2^rA; B: g1 = e(RA, deB), g2 = e(Ppub-e, P2)^rB, g3 = g1^rB.
        let (mut g1, mut g2, mut g3, identities, points) = match self.role {
            SM9Role::Initiator => {
                (own, peer, shared, [self.key.identity(), &self.peer_identity], [&own_point, &peer_point])
            }
            SM9Role::Responder => {
                (peer, own, shared, [self.peer_identity.as_slice(), self.key.identity()], [&peer_point, &own_point])
            }
        };
        SM9KDF::<H>::derive(&[identities[0], identities[1], points[0], points[1], &g1, &g2, &g3], out);
        let mut inner = H::default();
        for part in [g2.as_slice(), &g3, identities[0], identities[1], points[0], points[1]] {
            inner.update(part);
        }
        let mut inner = inner.finalize();
        let confirm = |prefix: u8| {
            let mut hash = H::default();
            hash.update(&[prefix]);
            hash.update(&g1);
            hash.update(inner.as_ref());
            hash.finalize()
        };
        let confirmation = SM9KeyConfirmation { responder: confirm(0x82), initiator: confirm(0x83) };
        g1.zeroize();
        g2.zeroize();
        g3.zeroize();
        inner.as_mut().zeroize();
        Ok(confirmation)
    }

    /// Whether `received` is the confirmation the other user must send:
    /// S_B for the initiator, S_A for the responder; compared in constant time.
    pub fn confirm(&self, confirmation: &SM9KeyConfirmation<H>, received: &[u8]) -> bool {
        let expected = match self.role {
            SM9Role::Initiator => confirmation.responder(),
            SM9Role::Responder => confirmation.initiator(),
        };
        expected.ct_eq(received).into_bool()
    }
}

impl<C: PairingCurve, H: CryptographicDigest + Default> Zeroize for SM9KEP<C, H> {
    fn zeroize(&mut self) {
        self.ephemeral.zeroize();
        self.key.zeroize();
    }
}

impl<C: PairingCurve, H: CryptographicDigest + Default> Drop for SM9KEP<C, H> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the role, the other user and R, not the keys.
impl<C: PairingCurve, H: CryptographicDigest + Default> fmt::Debug for SM9KEP<C, H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SM9KEP({:?}, {:?}, {:?}, ..)", self.role, self.peer_identity, self.ephemeral_public_key)
    }
}
