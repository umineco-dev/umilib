use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{HPKEKDF, HPKELabels};
use crate::crypto::random::Random;
use crate::crypto::{CryptoError, KeyAgreement};
use crate::secret::Zeroize;

/// A key encapsulation mechanism of HPKE (RFC 9180 section 4).
pub trait HPKEKEM {
    /// The kem_id of section 7.1.
    const ID: u16;
    /// Nsecret, Nenc, Npk and Nsk.
    const SHARED_SECRET_SIZE: usize;
    const ENCAPSULATED_SIZE: usize;
    const PUBLIC_KEY_SIZE: usize;
    const PRIVATE_KEY_SIZE: usize;
    type PrivateKey;
    type PublicKey;

    /// DeriveKeyPair(ikm) of section 7.1.3.
    fn derive_key_pair(ikm: &[u8]) -> Result<(Self::PrivateKey, Self::PublicKey), CryptoError>;

    /// GenerateKeyPair(): a pair of random keys.
    fn generate_key_pair<R: Random>(random: &mut R) -> Result<(Self::PrivateKey, Self::PublicKey), CryptoError>;

    /// The public key of a private key.
    fn public_key(key: &Self::PrivateKey) -> Self::PublicKey;

    /// SerializePublicKey and DeserializePublicKey (section 7.1.1),
    /// validating the key (section 7.1.4).
    fn serialize_public_key(key: &Self::PublicKey) -> Vec<u8>;
    fn deserialize_public_key(bytes: &[u8]) -> Result<Self::PublicKey, CryptoError>;

    /// SerializePrivateKey and DeserializePrivateKey (section 7.1.2).
    fn serialize_private_key(key: &Self::PrivateKey) -> Vec<u8>;
    fn deserialize_private_key(bytes: &[u8]) -> Result<Self::PrivateKey, CryptoError>;

    /// Encap(pkR) with the ephemeral key `ephemeral` (section 4.1): the
    /// shared secret and enc. Unauthenticated when `sender` is `None`,
    /// AuthEncap(pkR, skS) otherwise.
    fn encapsulate(
        recipient: &Self::PublicKey,
        ephemeral: &Self::PrivateKey,
        sender: Option<&Self::PrivateKey>,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;

    /// Decap(enc, skR) (section 4.1), or AuthDecap(enc, skR, pkS) when
    /// `sender` is given: the shared secret.
    fn decapsulate(
        encapsulated: &[u8],
        recipient: &Self::PrivateKey,
        sender: Option<&Self::PublicKey>,
    ) -> Result<Vec<u8>, CryptoError>;
}

/// A key agreement that is a group of DHKEM (RFC 9180 section 7.1), with
/// the kem_id and the derivation of keys of its group.
pub trait DHKEMGroup: KeyAgreement {
    /// The kem_id of the DHKEM of the group.
    const KEM_ID: u16;
    /// The mask of the first byte of a candidate private key of the NIST
    /// curves (section 7.1.3: 0xFF for P-256 and P-384, 0x01 for P-521), or
    /// `None` for X25519 and X448, whose private keys are any Nsk bytes.
    const CANDIDATE_MASK: Option<u8>;
}

#[cfg(umilib_feature = "crypto-curve-p256")]
impl DHKEMGroup for crate::crypto::ecdh::ECDH<crate::crypto::curve::p256::P256> {
    const KEM_ID: u16 = 0x0010;
    const CANDIDATE_MASK: Option<u8> = Some(0xFF);
}

#[cfg(umilib_feature = "crypto-curve-p384")]
impl DHKEMGroup for crate::crypto::ecdh::ECDH<crate::crypto::curve::p384::P384> {
    const KEM_ID: u16 = 0x0011;
    const CANDIDATE_MASK: Option<u8> = Some(0xFF);
}

#[cfg(umilib_feature = "crypto-curve-p521")]
impl DHKEMGroup for crate::crypto::ecdh::ECDH<crate::crypto::curve::p521::P521> {
    const KEM_ID: u16 = 0x0012;
    const CANDIDATE_MASK: Option<u8> = Some(0x01);
}

#[cfg(umilib_feature = "crypto-curve-curve25519")]
impl DHKEMGroup for crate::crypto::ecdh::X25519 {
    const KEM_ID: u16 = 0x0020;
    const CANDIDATE_MASK: Option<u8> = None;
}

#[cfg(umilib_feature = "crypto-curve-curve448")]
impl DHKEMGroup for crate::crypto::ecdh::X448 {
    const KEM_ID: u16 = 0x0021;
    const CANDIDATE_MASK: Option<u8> = None;
}

/// DHKEM(`G`, HKDF-`H`) of RFC 9180 section 4.1, such as DHKEM(X25519,
/// HKDF-SHA256).
pub struct DHKEM<G: DHKEMGroup, H: HPKEKDF> {
    types: PhantomData<(G, H)>,
}

impl<G: DHKEMGroup, H: HPKEKDF> DHKEM<G, H> {
    /// suite_id = "KEM" || I2OSP(kem_id, 2).
    pub fn suite() -> [u8; 5] {
        let id = G::KEM_ID.to_be_bytes();
        [b'K', b'E', b'M', id[0], id[1]]
    }

    /// ExtractAndExpand(dh, kem_context) of section 4.1.
    pub fn extract_and_expand(dh: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let suite = DHKEM::<G, H>::suite();
        let labels = HPKELabels::new(&suite);
        let mut prk = labels.extract::<H>(&[], b"eae_prk", dh);
        let mut shared = vec![0u8; H::OUTPUT_SIZE];
        let result = labels.expand::<H>(prk.as_ref(), b"shared_secret", context, &mut shared);
        prk.as_mut().zeroize();
        result.map(|_| shared)
    }

    /// DH(sk, pk) of `G`, of the bytes of its shared secrets.
    pub fn agree(private: &G::PrivateKey, public: &G::PublicKey) -> Result<Vec<u8>, CryptoError> {
        let mut shared = vec![0u8; G::SHARED_SECRET_SIZE];
        G::agree(private, public, &mut shared)?;
        Ok(shared)
    }
}

impl<G: DHKEMGroup, H: HPKEKDF> HPKEKEM for DHKEM<G, H> {
    const ID: u16 = G::KEM_ID;
    const SHARED_SECRET_SIZE: usize = H::OUTPUT_SIZE;
    const ENCAPSULATED_SIZE: usize = G::PUBLIC_KEY_SIZE;
    const PUBLIC_KEY_SIZE: usize = G::PUBLIC_KEY_SIZE;
    const PRIVATE_KEY_SIZE: usize = G::PRIVATE_KEY_SIZE;
    type PrivateKey = G::PrivateKey;
    type PublicKey = G::PublicKey;

    fn derive_key_pair(ikm: &[u8]) -> Result<(G::PrivateKey, G::PublicKey), CryptoError> {
        let suite = DHKEM::<G, H>::suite();
        let labels = HPKELabels::new(&suite);
        let mut prk = labels.extract::<H>(&[], b"dkp_prk", ikm);
        let mut bytes = vec![0u8; G::PRIVATE_KEY_SIZE];
        let result = match G::CANDIDATE_MASK {
            None => {
                labels.expand::<H>(prk.as_ref(), b"sk", &[], &mut bytes).and_then(|_| G::private_key_from_bytes(&bytes))
            }
            Some(mask) => (|| {
                for counter in 0..=255u8 {
                    labels.expand::<H>(prk.as_ref(), b"candidate", &[counter], &mut bytes)?;
                    bytes[0] &= mask;
                    if let Ok(key) = G::private_key_from_bytes(&bytes) {
                        return Ok(key);
                    }
                }
                Err(CryptoError::InvalidParameter)
            })(),
        };
        prk.as_mut().zeroize();
        bytes.zeroize();
        let private = result?;
        let public = G::public_key(&private);
        Ok((private, public))
    }

    fn generate_key_pair<R: Random>(random: &mut R) -> Result<(G::PrivateKey, G::PublicKey), CryptoError> {
        let private = G::generate(random)?;
        let public = G::public_key(&private);
        Ok((private, public))
    }

    fn public_key(key: &G::PrivateKey) -> G::PublicKey {
        G::public_key(key)
    }

    fn serialize_public_key(key: &G::PublicKey) -> Vec<u8> {
        let mut bytes = vec![0u8; G::PUBLIC_KEY_SIZE];
        // The buffer has the size of the encoding.
        let _ = G::write_public_key(key, &mut bytes);
        bytes
    }

    /// Only the encoding of Npk bytes is accepted (the uncompressed point
    /// for the NIST curves, section 7.1.1).
    fn deserialize_public_key(bytes: &[u8]) -> Result<G::PublicKey, CryptoError> {
        if bytes.len() != G::PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }
        G::public_key_from_bytes(bytes)
    }

    fn serialize_private_key(key: &G::PrivateKey) -> Vec<u8> {
        let mut bytes = vec![0u8; G::PRIVATE_KEY_SIZE];
        // The buffer has the size of the encoding.
        let _ = G::write_private_key(key, &mut bytes);
        bytes
    }

    fn deserialize_private_key(bytes: &[u8]) -> Result<G::PrivateKey, CryptoError> {
        G::private_key_from_bytes(bytes)
    }

    fn encapsulate(
        recipient: &G::PublicKey,
        ephemeral: &G::PrivateKey,
        sender: Option<&G::PrivateKey>,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut dh = DHKEM::<G, H>::agree(ephemeral, recipient)?;
        let encapsulated = DHKEM::<G, H>::serialize_public_key(&G::public_key(ephemeral));
        let mut context = encapsulated.clone();
        context.extend(DHKEM::<G, H>::serialize_public_key(recipient));
        if let Some(sender) = sender {
            dh.extend(DHKEM::<G, H>::agree(sender, recipient)?);
            context.extend(DHKEM::<G, H>::serialize_public_key(&G::public_key(sender)));
        }
        let shared = DHKEM::<G, H>::extract_and_expand(&dh, &context);
        dh.zeroize();
        Ok((shared?, encapsulated))
    }

    fn decapsulate(
        encapsulated: &[u8],
        recipient: &G::PrivateKey,
        sender: Option<&G::PublicKey>,
    ) -> Result<Vec<u8>, CryptoError> {
        let ephemeral = DHKEM::<G, H>::deserialize_public_key(encapsulated)?;
        let mut dh = DHKEM::<G, H>::agree(recipient, &ephemeral)?;
        let mut context = encapsulated.to_vec();
        context.extend(DHKEM::<G, H>::serialize_public_key(&G::public_key(recipient)));
        if let Some(sender) = sender {
            dh.extend(DHKEM::<G, H>::agree(recipient, sender)?);
            context.extend(DHKEM::<G, H>::serialize_public_key(sender));
        }
        let shared = DHKEM::<G, H>::extract_and_expand(&dh, &context);
        dh.zeroize();
        shared
    }
}
