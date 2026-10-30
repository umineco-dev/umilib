use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{HPKEAEAD, HPKEContext, HPKEKDF, HPKEKEM, HPKELabels, HPKEReceiverContext, HPKESenderContext};
use crate::crypto::CryptoError;
use crate::crypto::random::Random;
use crate::secret::Zeroize;

/// The modes of HPKE (RFC 9180 section 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HPKEMode {
    Base = 0x00,
    PSK = 0x01,
    Auth = 0x02,
    AuthPSK = 0x03,
}

impl HPKEMode {
    /// The mode of the inputs: with a PSK or not, with a sender's key or not.
    pub fn of(psk: bool, auth: bool) -> HPKEMode {
        match (psk, auth) {
            (false, false) => HPKEMode::Base,
            (true, false) => HPKEMode::PSK,
            (false, true) => HPKEMode::Auth,
            (true, true) => HPKEMode::AuthPSK,
        }
    }
}

/// HPKE with the KEM `K`, the KDF `F` and the AEAD `A`.
pub struct HPKE<K: HPKEKEM, F: HPKEKDF, A: HPKEAEAD> {
    types: PhantomData<(K, F, A)>,
}

impl<K: HPKEKEM, F: HPKEKDF, A: HPKEAEAD> HPKE<K, F, A> {
    /// suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2).
    pub fn suite() -> [u8; 10] {
        let (kem, kdf, aead) = (K::ID.to_be_bytes(), F::ID.to_be_bytes(), A::ID.to_be_bytes());
        [b'H', b'P', b'K', b'E', kem[0], kem[1], kdf[0], kdf[1], aead[0], aead[1]]
    }

    /// KeySchedule(mode, shared_secret, info, psk, psk_id) of section 5.1;
    /// `psk` is the pair (psk, psk_id), both non-empty, or `None`.
    /// VerifyPSKInputs fails with `InvalidParameter`.
    pub fn key_schedule(
        mode: HPKEMode,
        shared: &[u8],
        info: &[u8],
        psk: Option<(&[u8], &[u8])>,
    ) -> Result<HPKEContext<F, A>, CryptoError> {
        let (key, identifier) = psk.unwrap_or((&[], &[]));
        let needs = matches!(mode, HPKEMode::PSK | HPKEMode::AuthPSK);
        if key.is_empty() != identifier.is_empty() || needs == key.is_empty() {
            return Err(CryptoError::InvalidParameter);
        }
        let suite = HPKE::<K, F, A>::suite();
        let labels = HPKELabels::new(&suite);
        let identifier_hash = labels.extract::<F>(&[], b"psk_id_hash", identifier);
        let info_hash = labels.extract::<F>(&[], b"info_hash", info);
        let mut context = vec![mode as u8];
        context.extend_from_slice(identifier_hash.as_ref());
        context.extend_from_slice(info_hash.as_ref());
        let mut secret = labels.extract::<F>(shared, b"secret", key);
        let mut aead_key = vec![0u8; A::KEY_SIZE];
        let mut base_nonce = vec![0u8; A::NONCE_SIZE];
        let mut exporter_secret = vec![0u8; F::OUTPUT_SIZE];
        let result = labels
            .expand::<F>(secret.as_ref(), b"key", &context, &mut aead_key)
            .and_then(|_| labels.expand::<F>(secret.as_ref(), b"base_nonce", &context, &mut base_nonce))
            .and_then(|_| labels.expand::<F>(secret.as_ref(), b"exp", &context, &mut exporter_secret));
        secret.as_mut().zeroize();
        result?;
        Ok(HPKEContext::new(suite, aead_key, base_nonce, exporter_secret))
    }

    /// SetupBaseS, SetupPSKS, SetupAuthS or SetupAuthPSKS (section 5.1) for
    /// `recipient`, with a random ephemeral key: enc and the sender's context.
    pub fn setup_sender<R: Random>(
        recipient: &K::PublicKey,
        info: &[u8],
        psk: Option<(&[u8], &[u8])>,
        sender: Option<&K::PrivateKey>,
        random: &mut R,
    ) -> Result<(Vec<u8>, HPKESenderContext<F, A>), CryptoError> {
        let (ephemeral, _) = K::generate_key_pair(random)?;
        HPKE::<K, F, A>::setup_sender_with_ephemeral(recipient, info, psk, sender, &ephemeral)
    }

    /// [`HPKE::setup_sender`] with the ephemeral key `ephemeral` given
    /// (as DeriveKeyPair(ikmE) gives it in the test vectors of appendix A).
    /// The ephemeral key must be fresh and secret.
    pub fn setup_sender_with_ephemeral(
        recipient: &K::PublicKey,
        info: &[u8],
        psk: Option<(&[u8], &[u8])>,
        sender: Option<&K::PrivateKey>,
        ephemeral: &K::PrivateKey,
    ) -> Result<(Vec<u8>, HPKESenderContext<F, A>), CryptoError> {
        let mode = HPKEMode::of(psk.is_some(), sender.is_some());
        let (mut shared, encapsulated) = K::encapsulate(recipient, ephemeral, sender)?;
        let context = HPKE::<K, F, A>::key_schedule(mode, &shared, info, psk);
        shared.zeroize();
        Ok((encapsulated, HPKESenderContext::new(context?)))
    }

    /// SetupBaseR, SetupPSKR, SetupAuthR or SetupAuthPSKR (section 5.1) for
    /// the enc `encapsulated` received by `recipient`.
    pub fn setup_receiver(
        encapsulated: &[u8],
        recipient: &K::PrivateKey,
        info: &[u8],
        psk: Option<(&[u8], &[u8])>,
        sender: Option<&K::PublicKey>,
    ) -> Result<HPKEReceiverContext<F, A>, CryptoError> {
        let mode = HPKEMode::of(psk.is_some(), sender.is_some());
        let mut shared = K::decapsulate(encapsulated, recipient, sender)?;
        let context = HPKE::<K, F, A>::key_schedule(mode, &shared, info, psk);
        shared.zeroize();
        Ok(HPKEReceiverContext::new(context?))
    }

    /// The single-shot encryption of section 6.1: enc and the ciphertext.
    pub fn seal<R: Random>(
        recipient: &K::PublicKey,
        info: &[u8],
        associated: &[u8],
        plaintext: &[u8],
        psk: Option<(&[u8], &[u8])>,
        sender: Option<&K::PrivateKey>,
        random: &mut R,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let (encapsulated, mut context) = HPKE::<K, F, A>::setup_sender(recipient, info, psk, sender, random)?;
        Ok((encapsulated, context.seal(associated, plaintext)?))
    }

    /// The single-shot decryption of section 6.1.
    pub fn open(
        encapsulated: &[u8],
        recipient: &K::PrivateKey,
        info: &[u8],
        associated: &[u8],
        ciphertext: &[u8],
        psk: Option<(&[u8], &[u8])>,
        sender: Option<&K::PublicKey>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut context = HPKE::<K, F, A>::setup_receiver(encapsulated, recipient, info, psk, sender)?;
        context.open(associated, ciphertext)
    }
}
