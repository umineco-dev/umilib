use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use super::{Dragonfly, DragonflyConfig};
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::math::ec::{AffinePoint, FieldElement, PrimeField, WeierstrassCurve};
use crate::secret::{ConstantTimeEq, Zeroize};

/// The commit of a peer (section 3.3): its scalar and its element.
pub struct DragonflyCommit<C: WeierstrassCurve> {
    scalar: FieldElement<C::Scalar>,
    element: AffinePoint<C>,
}

impl<C: WeierstrassCurve> DragonflyCommit<C> {
    /// The bytes of the encoding: the scalar big-endian of the bytes of the
    /// order, then the uncompressed SEC 1 element.
    pub const BYTES: usize = <C::Scalar as PrimeField>::BYTES + AffinePoint::<C>::encoded_length(false);

    /// The commit of the encoding `bytes`, validated (section 3.3): 1 < scalar
    /// < q and an element of the curve other than the identity. Fails with
    /// `InvalidKey` otherwise.
    pub fn from_bytes(bytes: &[u8]) -> Result<DragonflyCommit<C>, CryptoError> {
        if bytes.len() != DragonflyCommit::<C>::BYTES {
            return Err(CryptoError::InvalidKey);
        }
        let (scalar, element) = bytes.split_at(<C::Scalar as PrimeField>::BYTES);
        let scalar = FieldElement::<C::Scalar>::from_be_bytes(scalar).map_err(|_| CryptoError::InvalidKey)?;
        let element = AffinePoint::<C>::from_encoded(element).map_err(|_| CryptoError::InvalidKey)?;
        let one = FieldElement::<C::Scalar>::one();
        if (scalar.is_zero() | scalar.ct_eq(&one) | element.is_identity() | !element.is_in_subgroup()).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(DragonflyCommit { scalar, element })
    }

    /// The encoding of [`DragonflyCommit::BYTES`] bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = <C::Scalar as PrimeField>::BYTES;
        let mut out = vec![0u8; DragonflyCommit::<C>::BYTES];
        // The buffer has the length of each part.
        let _ = self.scalar.write_be_bytes(&mut out[..size]);
        let _ = self.element.write_encoded(&mut out[size..], false);
        out
    }

    pub fn scalar(&self) -> &FieldElement<C::Scalar> {
        &self.scalar
    }

    pub fn element(&self) -> &AffinePoint<C> {
        &self.element
    }
}

impl<C: WeierstrassCurve> PartialEq for DragonflyCommit<C> {
    fn eq(&self, other: &DragonflyCommit<C>) -> bool {
        self.scalar == other.scalar && self.element == other.element
    }
}

impl<C: WeierstrassCurve> Eq for DragonflyCommit<C> {}

impl<C: WeierstrassCurve> fmt::Debug for DragonflyCommit<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "DragonflyCommit({:?}, {:?})", self.scalar, self.element)
    }
}

/// One side of a Dragonfly exchange on the curve `C` with the hash `H`: its
/// identity, the password element, the private value and its commit, and
/// after the peer's commit, kck and mk; zeroized when dropped.
pub struct DragonflyPeer<C: WeierstrassCurve, H: CryptographicDigest + Default> {
    identity: Vec<u8>,
    peer_identity: Vec<u8>,
    element: AffinePoint<C>,
    private: FieldElement<C::Scalar>,
    commit: DragonflyCommit<C>,
    peer_commit: Option<DragonflyCommit<C>>,
    confirmation_key: Vec<u8>,
    master_key: Vec<u8>,
    types: PhantomData<H>,
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> DragonflyPeer<C, H> {
    /// The side of `identity`, sharing `password` with `peer_identity`,
    /// with private and mask drawn from `random` (section 3.3): scalar =
    /// (private + mask) mod q and Element = -(mask PE), drawn again while the
    /// scalar is below 2.
    pub fn new<R: Random>(
        config: &DragonflyConfig,
        identity: &[u8],
        peer_identity: &[u8],
        password: &[u8],
        random: &mut R,
    ) -> Result<DragonflyPeer<C, H>, CryptoError> {
        let element = Dragonfly::<C, H>::password_element(config, identity, peer_identity, password)?;
        let one = FieldElement::<C::Scalar>::one();
        let mut draw = || -> Result<FieldElement<C::Scalar>, CryptoError> {
            loop {
                let value =
                    FieldElement::random_nonzero(|bytes| random.fill(bytes)).map_err(|_| CryptoError::RandomFailed)?;
                if !value.ct_eq(&one).into_bool() {
                    return Ok(value);
                }
            }
        };
        loop {
            let private = draw()?;
            let mut mask = draw()?;
            let scalar = private.add(&mask);
            if (scalar.is_zero() | scalar.ct_eq(&one)).into_bool() {
                mask.zeroize();
                continue;
            }
            let commit_element = element.to_projective().mul(&mask).neg().to_affine();
            mask.zeroize();
            let commit = DragonflyCommit { scalar, element: commit_element };
            return Ok(DragonflyPeer {
                identity: identity.to_vec(),
                peer_identity: peer_identity.to_vec(),
                element,
                private,
                commit,
                peer_commit: None,
                confirmation_key: Vec::new(),
                master_key: Vec::new(),
                types: PhantomData,
            });
        }
    }

    /// The commit to send.
    pub fn commit(&self) -> &DragonflyCommit<C> {
        &self.commit
    }

    /// Processes the peer's commit (section 3.3) and returns the confirm to
    /// send (section 3.4): a commit equal to ours is a reflection and fails
    /// with `InvalidKey`; ss = F(private (Peer-Element + peer-scalar PE)) and
    /// kck | mk = KDF-n(ss, "Dragonfly Key Derivation") with n = 2 len(p).
    pub fn process(&mut self, peer: DragonflyCommit<C>) -> Result<Vec<u8>, CryptoError> {
        if peer == self.commit {
            return Err(CryptoError::InvalidKey);
        }
        let sum = peer.element.to_projective().add(&self.element.to_projective().mul(&peer.scalar));
        let mut shared = sum.mul(&self.private).to_affine();
        if shared.is_identity().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        let size = <C::Field as PrimeField>::BYTES;
        let mut ss = vec![0u8; size];
        shared.x().write_be_bytes(&mut ss).map_err(|_| CryptoError::InvalidKey)?;
        shared.zeroize();
        let mut keys = vec![0u8; 2 * size];
        Dragonfly::<C, H>::kdf(&ss, Dragonfly::<C, H>::DERIVATION_LABEL, &mut keys)?;
        ss.zeroize();
        self.master_key = keys.split_off(size);
        self.confirmation_key = keys;
        self.private.zeroize();
        let confirm = self.confirm(&self.commit, &peer, &self.identity);
        self.peer_commit = Some(peer);
        Ok(confirm)
    }

    /// H(kck | scalar | peer-scalar | Element | Peer-Element | sender-id), the
    /// confirm of `sender` whose commit is `own`.
    pub fn confirm(&self, own: &DragonflyCommit<C>, other: &DragonflyCommit<C>, sender: &[u8]) -> Vec<u8> {
        let size = <C::Scalar as PrimeField>::BYTES;
        let (own_bytes, other_bytes) = (own.to_bytes(), other.to_bytes());
        let mut hash = H::default();
        hash.update(&self.confirmation_key);
        hash.update(&own_bytes[..size]);
        hash.update(&other_bytes[..size]);
        hash.update(&own_bytes[size..]);
        hash.update(&other_bytes[size..]);
        hash.update(sender);
        hash.finalize().as_ref().to_vec()
    }

    /// Checks the confirm of the peer the exchange was created with, which
    /// it made under its identity (section 3.4), in constant time, and
    /// returns mk; fails with `AuthenticationFailed` for a wrong confirm and
    /// `InvalidParameter` before [`DragonflyPeer::process`].
    pub fn finish(&self, confirm: &[u8]) -> Result<&[u8], CryptoError> {
        let peer = self.peer_commit.as_ref().ok_or(CryptoError::InvalidParameter)?;
        let expected = self.confirm(peer, &self.commit, &self.peer_identity);
        if !expected.ct_eq(confirm).into_bool() {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(&self.master_key)
    }
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> Zeroize for DragonflyPeer<C, H> {
    fn zeroize(&mut self) {
        self.element.zeroize();
        self.private.zeroize();
        self.confirmation_key.zeroize();
        self.master_key.zeroize();
    }
}

impl<C: WeierstrassCurve, H: CryptographicDigest + Default> Drop for DragonflyPeer<C, H> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the commit, not the secrets.
impl<C: WeierstrassCurve, H: CryptographicDigest + Default> fmt::Debug for DragonflyPeer<C, H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "DragonflyPeer({:?}, ..)", self.commit)
    }
}
