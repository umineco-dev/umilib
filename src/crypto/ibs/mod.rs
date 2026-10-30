//! Identity-based signatures on pairing-friendly curves.
//!
//! A private key generator holds the master secret s and publishes the
//! master public key P_pub = s P in G_2 ([`IBSMasterKey`]); a user's
//! private key is a point of G_1 that the scheme derives from s and the
//! identity ([`IBSUserKey`]), so that anyone can verify a signature from the
//! identity and P_pub alone. [`IdentityBasedSignature`] is the interface of
//! every scheme: [`hess`] (Hess, 2002), [`chacheon`] (Cha and Cheon, 2003)
//! and [`sm9`] (GM/T 0044.2-2016), in the asymmetric setting e: G_1 × G_2 →
//! G_T of [`crate::math::pairing`].
//!
//! The papers of Hess and of Cha and Cheon leave the hash functions to the
//! implementation: H1 is [`IBSHash::hash_to_g1`] and H2 is
//! [`IBSHash::hash_to_scalar`], both over a hash function `H` with separate
//! domain tags; their key of an identity is s H1(ID). SM9 defines its own.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::hash::CryptographicDigest;
use crate::math::bigint::UnsignedInteger;
use crate::math::ec::{AffinePoint, FieldElement, FieldValue, PrimeField, WeierstrassCurve};
use crate::math::pairing::{G2Affine, G2Projective, PairingCurve};
use crate::secret::{ConditionallySelectable, Zeroize};

#[cfg(umilib_feature = "crypto-ibs-chacheon")]
pub mod chacheon;
#[cfg(umilib_feature = "crypto-ibs-hess")]
pub mod hess;
#[cfg(umilib_feature = "crypto-ibs-sm9")]
pub mod sm9;

/// An identity-based signature scheme on the pairing-friendly curve
/// [`IdentityBasedSignature::Curve`], whose keys are [`IBSMasterKey`] and
/// [`IBSUserKey`].
pub trait IdentityBasedSignature {
    type Curve: PairingCurve;
    type Signature: IBSSignature;

    /// The master key of a new private key generator from `random` (Setup).
    fn setup<R: Random>(random: &mut R) -> Result<IBSMasterKey<Self::Curve>, CryptoError> {
        IBSMasterKey::generate(random)
    }

    /// The private key of `identity` (Extract).
    fn extract(master: &IBSMasterKey<Self::Curve>, identity: &[u8]) -> Result<IBSUserKey<Self::Curve>, CryptoError>;

    /// The signature of `message` by the owner of `key`, with random values of `random`.
    fn sign<R: Random>(
        key: &IBSUserKey<Self::Curve>,
        message: &[u8],
        random: &mut R,
    ) -> Result<Self::Signature, CryptoError>;

    /// The bytes of the encoding of a master public key.
    fn master_public_key_size() -> usize {
        G2Affine::<Self::Curve>::encoded_length()
    }

    /// The encoding of a master public key in the scheme: that of
    /// [`G2Affine::write_encoded`] unless the scheme defines its own.
    fn master_public_key_to_bytes(key: &G2Affine<Self::Curve>) -> Vec<u8> {
        let mut out = vec![0u8; G2Affine::<Self::Curve>::encoded_length()];
        // A master public key is s P for a nonzero s below r, never the identity.
        let _ = key.write_encoded(&mut out);
        out
    }

    /// The master public key of the encoding of
    /// [`IdentityBasedSignature::master_public_key_to_bytes`], a point of
    /// G_2 other than the identity; fails with `InvalidKey` otherwise.
    fn master_public_key_from_bytes(bytes: &[u8]) -> Result<G2Affine<Self::Curve>, CryptoError> {
        let key = G2Affine::<Self::Curve>::from_encoded(bytes).map_err(|_| CryptoError::InvalidKey)?;
        if (key.is_identity() | !key.is_in_subgroup()).into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(key)
    }

    /// Succeeds if `signature` is a signature of `message` by `identity`
    /// under the master public key `master`; fails with `InvalidSignature` otherwise.
    fn verify(
        master: &G2Affine<Self::Curve>,
        identity: &[u8],
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), CryptoError>;
}

/// The encoding of the signatures of a scheme.
pub trait IBSSignature: Sized {
    /// The bytes of the encoding.
    fn encoded_length() -> usize;

    fn to_bytes(&self) -> Vec<u8>;

    /// The signature of the encoding of [`IBSSignature::to_bytes`]; fails
    /// with `InvalidSignature` otherwise.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>;
}

/// The hash functions H1 and H2 of the schemes over the hash `H` on the curve `C`.
pub struct IBSHash<C: PairingCurve, H: CryptographicDigest + Default> {
    types: PhantomData<(C, H)>,
}

impl<C: PairingCurve, H: CryptographicDigest + Default> IBSHash<C, H> {
    /// `out.len()` bytes of H(tag || counter || parts...) for the 32-bit
    /// big-endian counters 0, 1, ...
    pub fn expand(tag: &[u8], parts: &[&[u8]], out: &mut [u8]) {
        for (counter, chunk) in out.chunks_mut(H::OUTPUT_SIZE).enumerate() {
            let mut hash = H::default();
            hash.update(&(tag.len() as u32).to_be_bytes());
            hash.update(tag);
            hash.update(&(counter as u32).to_be_bytes());
            for part in parts {
                hash.update(&(part.len() as u64).to_be_bytes());
                hash.update(part);
            }
            let mut block = hash.finalize();
            chunk.copy_from_slice(&block.as_ref()[..chunk.len()]);
            block.as_mut().zeroize();
        }
    }

    /// H2: an integer modulo r of the bytes of r plus 16 of [`IBSHash::expand`]
    /// with the tag `tag`, reduced (a bias below 2^-128).
    pub fn hash_to_scalar(tag: &[u8], parts: &[&[u8]]) -> FieldElement<C::Scalar> {
        let mut bytes = vec![0u8; <C::Scalar as PrimeField>::BYTES + 16];
        IBSHash::<C, H>::expand(tag, parts, &mut bytes);
        let scalar = FieldElement::from_be_bytes_reduced(&bytes);
        bytes.zeroize();
        scalar
    }

    /// H1: a point of G_1 by try-and-increment: for the counters 0 to 255,
    /// x = H(tag, counter, identity) mod p; the first x on the curve, with
    /// the root y of the parity of the last byte, times the cofactor. The
    /// time depends on the identity, which is public. Fails with
    /// `InvalidParameter` if no counter gives a point.
    pub fn hash_to_g1(tag: &[u8], identity: &[u8]) -> Result<AffinePoint<C::G1>, CryptoError> {
        let mut bytes = vec![0u8; <C::Field as PrimeField>::BYTES + 16];
        for counter in 0..=255u8 {
            IBSHash::<C, H>::expand(tag, &[&[counter], identity], &mut bytes);
            let x = FieldElement::<C::Field>::from_be_bytes_reduced(&bytes);
            let curve = <C::G1 as WeierstrassCurve>::A;
            let right = x.square().add(&curve).mul(&x).add(&<C::G1 as WeierstrassCurve>::B);
            let (y, square) = right.sqrt();
            if !square.into_bool() {
                continue;
            }
            let odd = crate::secret::Choice::from_bit(bytes[bytes.len() - 1] & 1);
            let y = FieldElement::select(&y, &y.neg(), y.is_odd() ^ odd);
            let point = AffinePoint::<C::G1>::new(x, y).map_err(|_| CryptoError::InvalidParameter)?;
            let cofactor = FieldValue::<C::Scalar>::from_be_bytes(&<C::G1 as WeierstrassCurve>::COFACTOR.to_be_bytes())
                .map_err(|_| CryptoError::InvalidParameter)?;
            let cleared = point.to_projective().mul_value_vartime(&cofactor).to_affine();
            if !cleared.is_identity().into_bool() {
                return Ok(cleared);
            }
        }
        Err(CryptoError::InvalidParameter)
    }

    /// The uncompressed SEC 1 encoding of a point of G_1.
    pub fn encode_g1(point: &AffinePoint<C::G1>) -> Vec<u8> {
        let mut bytes = vec![0u8; AffinePoint::<C::G1>::encoded_length(false)];
        if point.write_encoded(&mut bytes, false).is_err() {
            // The identity has the encoding 00.
            return vec![0];
        }
        bytes
    }
}

/// The master key of a private key generator: s and P_pub = s P, with P
/// the generator of G_2; zeroized when dropped.
pub struct IBSMasterKey<C: PairingCurve> {
    secret: FieldElement<C::Scalar>,
    public: G2Affine<C>,
}

impl<C: PairingCurve> IBSMasterKey<C> {
    /// The master key of `secret`; fails with `InvalidKey` for zero.
    pub fn new(secret: FieldElement<C::Scalar>) -> Result<IBSMasterKey<C>, CryptoError> {
        if secret.is_zero().into_bool() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(IBSMasterKey { secret, public: G2Projective::generator().mul(&secret).to_affine() })
    }

    pub fn generate<R: Random>(random: &mut R) -> Result<IBSMasterKey<C>, CryptoError> {
        let secret = FieldElement::random_nonzero(|bytes| random.fill(bytes)).map_err(|_| CryptoError::RandomFailed)?;
        IBSMasterKey::new(secret)
    }

    /// P_pub, the master public key.
    pub fn public_key(&self) -> &G2Affine<C> {
        &self.public
    }

    /// s H1(identity), the user key of `identity`.
    pub fn extract<H: CryptographicDigest + Default>(
        &self,
        tag: &[u8],
        identity: &[u8],
    ) -> Result<IBSUserKey<C>, CryptoError> {
        let point = IBSHash::<C, H>::hash_to_g1(tag, identity)?;
        let key = point.to_projective().mul(&self.secret).to_affine();
        Ok(IBSUserKey::new(identity, key, self.public))
    }
}

impl<C: PairingCurve> Zeroize for IBSMasterKey<C> {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl<C: PairingCurve> Drop for IBSMasterKey<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints P_pub, not s.
impl<C: PairingCurve> fmt::Debug for IBSMasterKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "IBSMasterKey({:?}, ..)", self.public)
    }
}

/// The private key of a user: its identity, the point of G_1 that the
/// scheme derives for it from the master secret and the master public key;
/// zeroized when dropped.
pub struct IBSUserKey<C: PairingCurve> {
    identity: Vec<u8>,
    key: AffinePoint<C::G1>,
    master: G2Affine<C>,
}

impl<C: PairingCurve> IBSUserKey<C> {
    /// The key `key` of `identity` under the master public key `master`, as
    /// the Extract of a scheme gives it; the scheme's signatures with a
    /// wrong key do not verify.
    pub fn new(identity: &[u8], key: AffinePoint<C::G1>, master: G2Affine<C>) -> IBSUserKey<C> {
        IBSUserKey { identity: identity.to_vec(), key, master }
    }

    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// The point of G_1 of the key: s H1(ID) for Hess and Cha–Cheon, \[ks / (H1(ID || hid) + ks)\] P1 for SM9.
    pub fn key(&self) -> &AffinePoint<C::G1> {
        &self.key
    }

    /// P_pub.
    pub fn master(&self) -> &G2Affine<C> {
        &self.master
    }
}

impl<C: PairingCurve> Zeroize for IBSUserKey<C> {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<C: PairingCurve> Drop for IBSUserKey<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Prints the identity, not the key.
impl<C: PairingCurve> fmt::Debug for IBSUserKey<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "IBSUserKey({:?}, ..)", self.identity)
    }
}

impl<C: PairingCurve> IBSMasterKey<C> {
    /// s.
    pub fn secret(&self) -> &FieldElement<C::Scalar> {
        &self.secret
    }
}
