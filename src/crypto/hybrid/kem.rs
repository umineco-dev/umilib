use core::fmt;
use core::marker::PhantomData;

use super::HybridKEMParameters;
use crate::crypto::random::Random;
use crate::crypto::{CryptoError, KeyAgreement, KeyEncapsulation};
use crate::secret::Zeroize;

/// The encapsulation key of a hybrid group: the client's key_exchange of
/// RFC 10024 section 3, the KEM's encapsulation key and the key agreement's
/// public key.
pub struct HybridEncapsulationKey<P: HybridKEMParameters> {
    kem: <P::KEM as KeyEncapsulation>::EncapsulationKey,
    agreement: <P::KeyAgreement as KeyAgreement>::PublicKey,
}

impl<P: HybridKEMParameters> HybridEncapsulationKey<P> {
    pub fn new(
        kem: <P::KEM as KeyEncapsulation>::EncapsulationKey,
        agreement: <P::KeyAgreement as KeyAgreement>::PublicKey,
    ) -> HybridEncapsulationKey<P> {
        HybridEncapsulationKey { kem, agreement }
    }

    pub fn kem(&self) -> &<P::KEM as KeyEncapsulation>::EncapsulationKey {
        &self.kem
    }

    pub fn agreement(&self) -> &<P::KeyAgreement as KeyAgreement>::PublicKey {
        &self.agreement
    }
}

impl<P: HybridKEMParameters> Clone for HybridEncapsulationKey<P> {
    fn clone(&self) -> HybridEncapsulationKey<P> {
        HybridEncapsulationKey { kem: self.kem.clone(), agreement: self.agreement.clone() }
    }
}

impl<P: HybridKEMParameters> PartialEq for HybridEncapsulationKey<P> {
    fn eq(&self, other: &HybridEncapsulationKey<P>) -> bool {
        self.kem == other.kem && self.agreement == other.agreement
    }
}

impl<P: HybridKEMParameters> Eq for HybridEncapsulationKey<P> {}

impl<P: HybridKEMParameters> fmt::Debug for HybridEncapsulationKey<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "HybridEncapsulationKey({}, {:?}, {:?})", P::NAME, self.kem, self.agreement)
    }
}

/// The decapsulation key of a hybrid group: the KEM's decapsulation key and
/// the key agreement's private key; zeroized when dropped (by its parts).
pub struct HybridDecapsulationKey<P: HybridKEMParameters> {
    kem: <P::KEM as KeyEncapsulation>::DecapsulationKey,
    agreement: <P::KeyAgreement as KeyAgreement>::PrivateKey,
}

impl<P: HybridKEMParameters> HybridDecapsulationKey<P> {
    pub fn new(
        kem: <P::KEM as KeyEncapsulation>::DecapsulationKey,
        agreement: <P::KeyAgreement as KeyAgreement>::PrivateKey,
    ) -> HybridDecapsulationKey<P> {
        HybridDecapsulationKey { kem, agreement }
    }

    pub fn kem(&self) -> &<P::KEM as KeyEncapsulation>::DecapsulationKey {
        &self.kem
    }

    pub fn agreement(&self) -> &<P::KeyAgreement as KeyAgreement>::PrivateKey {
        &self.agreement
    }
}

impl<P: HybridKEMParameters> Zeroize for HybridDecapsulationKey<P> {
    fn zeroize(&mut self) {
        self.kem.zeroize();
        self.agreement.zeroize();
    }
}

/// Prints the parts as they print themselves, without secrets.
impl<P: HybridKEMParameters> fmt::Debug for HybridDecapsulationKey<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "HybridDecapsulationKey({}, {:?}, {:?})", P::NAME, self.kem, self.agreement)
    }
}

/// A hybrid group of RFC 10024 as a KEM: `HybridKEM<X25519MLKEM768>`. The
/// encapsulation key is the client's share, the ciphertext the server's
/// share (the KEM's ciphertext and an ephemeral public key of the key
/// agreement), and the shared secret the concatenation of the two secrets,
/// all in the order of the group. The KEM's encapsulation key is checked
/// when it is read, and the length of the ciphertext before
/// decapsulation (section 3); a key agreement that rejects its result
/// (X25519 giving zero) fails with `InvalidKey`. A decapsulation key is
/// written as the KEM's decapsulation key followed by the private key.
pub struct HybridKEM<P: HybridKEMParameters> {
    parameters: PhantomData<P>,
}

impl<P: HybridKEMParameters> HybridKEM<P> {
    /// Splits `bytes` into the KEM's part of `kem` bytes and the key agreement's part, in the order of the group.
    pub fn split(bytes: &[u8], kem: usize) -> (&[u8], &[u8]) {
        if P::KEM_FIRST {
            bytes.split_at(kem)
        } else {
            let (agreement, kem_part) = bytes.split_at(bytes.len() - kem);
            (kem_part, agreement)
        }
    }

    /// Splits `bytes` as [`HybridKEM::split`] does, mutably.
    pub fn split_mut(bytes: &mut [u8], kem: usize) -> (&mut [u8], &mut [u8]) {
        if P::KEM_FIRST {
            bytes.split_at_mut(kem)
        } else {
            let length = bytes.len();
            let (agreement, kem_part) = bytes.split_at_mut(length - kem);
            (kem_part, agreement)
        }
    }
}

impl<P: HybridKEMParameters> KeyEncapsulation for HybridKEM<P> {
    type DecapsulationKey = HybridDecapsulationKey<P>;
    type EncapsulationKey = HybridEncapsulationKey<P>;
    const DECAPSULATION_KEY_SIZE: usize =
        <P::KEM as KeyEncapsulation>::DECAPSULATION_KEY_SIZE + <P::KeyAgreement as KeyAgreement>::PRIVATE_KEY_SIZE;
    const ENCAPSULATION_KEY_SIZE: usize =
        <P::KEM as KeyEncapsulation>::ENCAPSULATION_KEY_SIZE + <P::KeyAgreement as KeyAgreement>::PUBLIC_KEY_SIZE;
    const CIPHERTEXT_SIZE: usize =
        <P::KEM as KeyEncapsulation>::CIPHERTEXT_SIZE + <P::KeyAgreement as KeyAgreement>::PUBLIC_KEY_SIZE;
    const SHARED_SECRET_SIZE: usize =
        <P::KEM as KeyEncapsulation>::SHARED_SECRET_SIZE + <P::KeyAgreement as KeyAgreement>::SHARED_SECRET_SIZE;

    fn generate<R: Random>(random: &mut R) -> Result<HybridDecapsulationKey<P>, CryptoError> {
        let kem = P::KEM::generate(random)?;
        let agreement = P::KeyAgreement::generate(random)?;
        Ok(HybridDecapsulationKey { kem, agreement })
    }

    /// The KEM's decapsulation key followed by the key agreement's private
    /// key, each checked as its scheme requires.
    fn decapsulation_key_from_bytes(bytes: &[u8]) -> Result<HybridDecapsulationKey<P>, CryptoError> {
        if bytes.len() != Self::DECAPSULATION_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }
        let (kem, agreement) = bytes.split_at(<P::KEM as KeyEncapsulation>::DECAPSULATION_KEY_SIZE);
        let kem = P::KEM::decapsulation_key_from_bytes(kem)?;
        let agreement = P::KeyAgreement::private_key_from_bytes(agreement)?;
        Ok(HybridDecapsulationKey { kem, agreement })
    }

    fn write_decapsulation_key(key: &HybridDecapsulationKey<P>, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != Self::DECAPSULATION_KEY_SIZE {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        let (kem, agreement) = out.split_at_mut(<P::KEM as KeyEncapsulation>::DECAPSULATION_KEY_SIZE);
        P::KEM::write_decapsulation_key(&key.kem, kem)?;
        P::KeyAgreement::write_private_key(&key.agreement, agreement)
    }

    fn encapsulation_key(key: &HybridDecapsulationKey<P>) -> HybridEncapsulationKey<P> {
        HybridEncapsulationKey {
            kem: P::KEM::encapsulation_key(&key.kem),
            agreement: P::KeyAgreement::public_key(&key.agreement),
        }
    }

    /// The client's share, its parts checked as their schemes require.
    fn encapsulation_key_from_bytes(bytes: &[u8]) -> Result<HybridEncapsulationKey<P>, CryptoError> {
        if bytes.len() != Self::ENCAPSULATION_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }
        let (kem, agreement) = HybridKEM::<P>::split(bytes, <P::KEM as KeyEncapsulation>::ENCAPSULATION_KEY_SIZE);
        let kem = P::KEM::encapsulation_key_from_bytes(kem)?;
        let agreement = P::KeyAgreement::public_key_from_bytes(agreement)?;
        Ok(HybridEncapsulationKey { kem, agreement })
    }

    fn write_encapsulation_key(key: &HybridEncapsulationKey<P>, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != Self::ENCAPSULATION_KEY_SIZE {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        let (kem, agreement) = HybridKEM::<P>::split_mut(out, <P::KEM as KeyEncapsulation>::ENCAPSULATION_KEY_SIZE);
        P::KEM::write_encapsulation_key(&key.kem, kem)?;
        P::KeyAgreement::write_public_key(&key.agreement, agreement)
    }

    /// The server's side: the KEM encapsulates to the client's key, and an
    /// ephemeral key of the key agreement agrees with the client's share.
    fn encapsulate<R: Random>(
        key: &HybridEncapsulationKey<P>,
        random: &mut R,
        ciphertext: &mut [u8],
        shared: &mut [u8],
    ) -> Result<(), CryptoError> {
        if ciphertext.len() != Self::CIPHERTEXT_SIZE {
            return Err(CryptoError::InputLength { length: ciphertext.len() });
        }
        if shared.len() != Self::SHARED_SECRET_SIZE {
            return Err(CryptoError::InputLength { length: shared.len() });
        }
        let (kem_ciphertext, agreement_share) =
            HybridKEM::<P>::split_mut(ciphertext, <P::KEM as KeyEncapsulation>::CIPHERTEXT_SIZE);
        let (kem_secret, agreement_secret) =
            HybridKEM::<P>::split_mut(shared, <P::KEM as KeyEncapsulation>::SHARED_SECRET_SIZE);
        let ephemeral = P::KeyAgreement::generate(random)?;
        let result = P::KeyAgreement::agree(&ephemeral, &key.agreement, agreement_secret)
            .and_then(|_| P::KeyAgreement::write_public_key(&P::KeyAgreement::public_key(&ephemeral), agreement_share))
            .and_then(|_| P::KEM::encapsulate(&key.kem, random, kem_ciphertext, kem_secret));
        if result.is_err() {
            shared.zeroize();
        }
        result
    }

    /// The client's side: the KEM decapsulates its ciphertext, and the
    /// private key agrees with the server's share.
    fn decapsulate(key: &HybridDecapsulationKey<P>, ciphertext: &[u8], shared: &mut [u8]) -> Result<(), CryptoError> {
        if ciphertext.len() != Self::CIPHERTEXT_SIZE {
            return Err(CryptoError::InputLength { length: ciphertext.len() });
        }
        if shared.len() != Self::SHARED_SECRET_SIZE {
            return Err(CryptoError::InputLength { length: shared.len() });
        }
        let (kem_ciphertext, agreement_share) =
            HybridKEM::<P>::split(ciphertext, <P::KEM as KeyEncapsulation>::CIPHERTEXT_SIZE);
        let (kem_secret, agreement_secret) =
            HybridKEM::<P>::split_mut(shared, <P::KEM as KeyEncapsulation>::SHARED_SECRET_SIZE);
        let result = P::KeyAgreement::public_key_from_bytes(agreement_share)
            .and_then(|peer| P::KeyAgreement::agree(&key.agreement, &peer, agreement_secret))
            .and_then(|_| P::KEM::decapsulate(&key.kem, kem_ciphertext, kem_secret));
        if result.is_err() {
            shared.zeroize();
        }
        result
    }
}
