use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::BlockCipher;
use crate::crypto::StreamCipher;
use crate::crypto::aes::{AES128, AES256};
use crate::crypto::chacha20::ChaCha20;
use crate::crypto::hkdf::HKDF;
use crate::hash::sha::v2::SHA256;
use crate::protocol::tls::v1_3::TLS13KeySchedule;
use crate::protocol::tls::{TLSAEAD, TLSAEADAlgorithm, TLSCipherSuite, TLSHashAlgorithm};
use crate::secret::Secret;

use super::{QUICConnectionID, QUICError, QUICRole, QUICVersionProfile};

/// A traffic secret of one direction (RFC 9001 §5.1) with the hash and AEAD
/// of its cipher suite: what TLS gives QUIC at each encryption level, and
/// what QUIC derives its packet and header protection keys from.
#[derive(Clone, Debug)]
pub struct QUICSecret {
    pub hash: TLSHashAlgorithm,
    pub aead: TLSAEADAlgorithm,
    pub secret: Secret<Vec<u8>>,
}

impl QUICSecret {
    /// The secret of a TLS 1.3 cipher suite; fails with
    /// [`QUICError::Config`] for a suite QUIC cannot use: one without a
    /// header protection scheme, TLS_AES_128_CCM_8_SHA256 (RFC 9001 §5.3).
    pub fn new(cipher_suite: TLSCipherSuite, secret: Secret<Vec<u8>>) -> Result<QUICSecret, QUICError> {
        let hash = cipher_suite.hash().ok_or(QUICError::Config)?;
        let aead = cipher_suite.aead().ok_or(QUICError::Config)?;
        if !QUICHeaderProtection::supports(aead) {
            return Err(QUICError::Config);
        }
        Ok(QUICSecret { hash, aead, secret })
    }

    /// The Initial secret of the packets `sender` sends, from the
    /// Destination Connection ID of the client's first Initial packet (RFC
    /// 9001 §5.2): HKDF-Extract with the version's salt, then
    /// HKDF-Expand-Label "client in" or "server in", with SHA-256 and
    /// AEAD_AES_128_GCM.
    pub fn initial(
        profile: &QUICVersionProfile,
        destination: &QUICConnectionID,
        sender: QUICRole,
    ) -> Result<QUICSecret, QUICError> {
        // HKDF-Extract of the ID itself: an empty ID is not "0" here, unlike TLS's key schedule.
        let initial = Secret::new(HKDF::<SHA256>::extract(&profile.initial_salt, destination.as_slice()).to_vec());
        let label: &[u8] = match sender {
            QUICRole::Client => b"client in",
            QUICRole::Server => b"server in",
        };
        let schedule = TLS13KeySchedule::new(TLSHashAlgorithm::SHA256);
        let secret = schedule.expand_label(initial.expose(), label, &[], 32).map_err(|_| QUICError::Config)?;
        Ok(QUICSecret { hash: TLSHashAlgorithm::SHA256, aead: TLSAEADAlgorithm::AES128GCM, secret })
    }

    /// HKDF-Expand-Label(secret, `label`, "", `length`) (RFC 9001 §5.1).
    pub fn expand(&self, label: &[u8], length: usize) -> Result<Secret<Vec<u8>>, QUICError> {
        TLS13KeySchedule::new(self.hash)
            .expand_label(self.secret.expose(), label, &[], length)
            .map_err(|_| QUICError::Config)
    }

    /// The packet protection key and IV (RFC 9001 §5.1).
    pub fn packet_key(&self, profile: &QUICVersionProfile) -> Result<QUICPacketKey, QUICError> {
        let key = self.expand(profile.key_label, self.aead.key_length())?;
        let iv = self.expand(profile.iv_label, 12)?;
        Ok(QUICPacketKey {
            aead: TLSAEAD::new(self.aead, key.expose()).map_err(|_| QUICError::Config)?,
            iv: iv.expose().as_slice().try_into().map_err(|_| QUICError::Config)?,
            algorithm: self.aead,
        })
    }

    /// The header protection key (RFC 9001 §5.4), which key updates keep.
    pub fn header_protection(&self, profile: &QUICVersionProfile) -> Result<QUICHeaderProtection, QUICError> {
        let key = self.expand(profile.hp_label, self.aead.key_length())?;
        QUICHeaderProtection::new(self.aead, key.expose())
    }

    /// The secret of the next key phase (RFC 9001 §6.1):
    /// HKDF-Expand-Label(secret, "quic ku", "", Hash.length).
    pub fn next(&self, profile: &QUICVersionProfile) -> Result<QUICSecret, QUICError> {
        let secret = self.expand(profile.ku_label, self.hash.length())?;
        Ok(QUICSecret { hash: self.hash, aead: self.aead, secret })
    }
}

/// The packet protection of one key (RFC 9001 §5.3): the AEAD, keyed, and
/// the IV that makes each packet's nonce.
#[derive(Debug)]
pub struct QUICPacketKey {
    pub aead: TLSAEAD,
    pub iv: [u8; 12],
    pub algorithm: TLSAEADAlgorithm,
}

impl QUICPacketKey {
    /// The length of the AEAD tag: 16 for every suite QUIC uses.
    pub const TAG_LENGTH: usize = 16;

    /// The nonce of `number`: the IV XOR the packet number, left-padded
    /// with zeros (RFC 9001 §5.3).
    pub fn nonce(&self, number: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        for (byte, number) in nonce[4..].iter_mut().zip(number.to_be_bytes()) {
            *byte ^= number;
        }
        nonce
    }

    /// Protects the payload of `packet`, all after the first `header`
    /// bytes, in place, and appends the tag: the header is the associated
    /// data (RFC 9001 §5.3).
    pub fn seal(&self, number: u64, header: usize, packet: &mut Vec<u8>) -> Result<(), QUICError> {
        let length = packet.len();
        if header > length {
            return Err(QUICError::Config);
        }
        packet.resize(length + QUICPacketKey::TAG_LENGTH, 0);
        let (associated, rest) = packet.split_at_mut(header);
        let (payload, tag) = rest.split_at_mut(length - header);
        self.aead.seal_in_place(&self.nonce(number), associated, payload, tag).map_err(|_| QUICError::Config)
    }

    /// Removes the protection of `packet`, its header of `header` bytes
    /// unprotected already, and returns the length of the plaintext payload
    /// that follows the header. Fails with [`QUICError::InvalidPacket`]
    /// unless it authenticates.
    pub fn open(&self, number: u64, header: usize, packet: &mut [u8]) -> Result<usize, QUICError> {
        let end = packet.len().checked_sub(QUICPacketKey::TAG_LENGTH).filter(|end| *end >= header);
        let end = end.ok_or(QUICError::InvalidPacket)?;
        let (associated, rest) = packet.split_at_mut(header);
        let (payload, tag) = rest.split_at_mut(end - header);
        self.aead.open_in_place(&self.nonce(number), associated, payload, tag).map_err(|_| QUICError::InvalidPacket)?;
        Ok(end - header)
    }

    /// The most packets protected with one key (RFC 9001 §6.6, Appendix B):
    /// 2^23 for AES-GCM, 2^21.5 for AES-CCM, none that matters for ChaCha20.
    pub fn confidentiality_limit(&self) -> u64 {
        match self.algorithm {
            TLSAEADAlgorithm::AES128GCM | TLSAEADAlgorithm::AES256GCM => 1 << 23,
            TLSAEADAlgorithm::ChaCha20Poly1305 => u64::MAX,
            TLSAEADAlgorithm::AES128CCM | TLSAEADAlgorithm::AES128CCM8 => 2_965_820,
        }
    }

    /// The most packets that may fail authentication in a connection (RFC
    /// 9001 §6.6): 2^52 for AES-GCM, 2^36 for ChaCha20-Poly1305, 2^21.5 for AES-CCM.
    pub fn integrity_limit(&self) -> u64 {
        match self.algorithm {
            TLSAEADAlgorithm::AES128GCM | TLSAEADAlgorithm::AES256GCM => 1 << 52,
            TLSAEADAlgorithm::ChaCha20Poly1305 => 1 << 36,
            TLSAEADAlgorithm::AES128CCM | TLSAEADAlgorithm::AES128CCM8 => 2_965_820,
        }
    }
}

/// Header protection (RFC 9001 §5.4): a mask from a sample of the
/// ciphertext hides the packet number and the low bits of the first byte.
pub enum QUICHeaderProtection {
    /// AES-ECB, for AEAD_AES_128_GCM and AEAD_AES_128_CCM (RFC 9001 §5.4.3).
    AES128(Box<AES128>),
    /// AES-ECB, for AEAD_AES_256_GCM.
    AES256(Box<AES256>),
    /// The raw ChaCha20 function (RFC 9001 §5.4.4).
    ChaCha20(Secret<[u8; 32]>),
}

impl core::fmt::Debug for QUICHeaderProtection {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("QUICHeaderProtection(..)")
    }
}

impl QUICHeaderProtection {
    /// The bytes of ciphertext sampled.
    pub const SAMPLE_LENGTH: usize = 16;

    /// Whether `aead` has a header protection scheme: all of TLS 1.3 but
    /// AEAD_AES_128_CCM_8 (RFC 9001 §5.3).
    pub fn supports(aead: TLSAEADAlgorithm) -> bool {
        aead != TLSAEADAlgorithm::AES128CCM8
    }

    pub fn new(aead: TLSAEADAlgorithm, key: &[u8]) -> Result<QUICHeaderProtection, QUICError> {
        let invalid = |_| QUICError::Config;
        Ok(match aead {
            TLSAEADAlgorithm::AES128GCM | TLSAEADAlgorithm::AES128CCM => {
                QUICHeaderProtection::AES128(Box::new(AES128::new(key.try_into().map_err(invalid)?)))
            }
            TLSAEADAlgorithm::AES256GCM => {
                QUICHeaderProtection::AES256(Box::new(AES256::new(key.try_into().map_err(invalid)?)))
            }
            TLSAEADAlgorithm::ChaCha20Poly1305 => {
                QUICHeaderProtection::ChaCha20(Secret::new(key.try_into().map_err(invalid)?))
            }
            TLSAEADAlgorithm::AES128CCM8 => return Err(QUICError::Config),
        })
    }

    /// The 5-byte mask of `sample` (RFC 9001 §5.4.3, §5.4.4).
    pub fn mask(&self, sample: &[u8; 16]) -> [u8; 5] {
        let mut mask = [0u8; 5];
        match self {
            QUICHeaderProtection::AES128(cipher) => {
                let mut block = *sample;
                cipher.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            QUICHeaderProtection::AES256(cipher) => {
                let mut block = *sample;
                cipher.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            QUICHeaderProtection::ChaCha20(key) => {
                // The counter is the first 4 bytes, little-endian; the nonce the other 12.
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let nonce: &[u8; 12] = sample[4..].try_into().unwrap_or(&[0; 12]);
                // Five bytes never run out a fresh key stream.
                let _ = ChaCha20::new(key.expose(), nonce, counter).apply_keystream(&mut mask);
            }
        }
        mask
    }

    /// The sample of a packet whose Packet Number field starts at
    /// `number_offset`: 16 bytes from 4 bytes after it (RFC 9001 §5.4.2).
    /// Fails with [`QUICError::InvalidPacket`] for a packet too short to
    /// hold one, which is discarded.
    pub fn sample(packet: &[u8], number_offset: usize) -> Result<[u8; 16], QUICError> {
        let start = number_offset + 4;
        packet
            .get(start..start + QUICHeaderProtection::SAMPLE_LENGTH)
            .and_then(|sample| sample.try_into().ok())
            .ok_or(QUICError::InvalidPacket)
    }

    /// The low bits of the first byte that header protection covers: four
    /// for a long header, five for a short one (RFC 9001 §5.4.1).
    pub const fn first_byte_bits(first: u8) -> u8 {
        if first & 0x80 != 0 { 0x0F } else { 0x1F }
    }

    /// Protects the header of `packet` whose packet number of
    /// `number_length` bytes, 1 to 4, starts at `number_offset`, its payload
    /// protected already (RFC 9001 §5.4.1).
    pub fn apply(&self, packet: &mut [u8], number_offset: usize, number_length: usize) -> Result<(), QUICError> {
        if !(1..=4).contains(&number_length) {
            return Err(QUICError::Config);
        }
        let mask = self.mask(&QUICHeaderProtection::sample(packet, number_offset)?);
        packet[0] ^= mask[0] & QUICHeaderProtection::first_byte_bits(packet[0]);
        for (byte, mask) in packet[number_offset..number_offset + number_length].iter_mut().zip(&mask[1..]) {
            *byte ^= mask;
        }
        Ok(())
    }

    /// Removes the header protection of `packet` and returns the length of
    /// its packet number and the truncated number (RFC 9001 §5.4.1).
    pub fn remove(&self, packet: &mut [u8], number_offset: usize) -> Result<(usize, u64), QUICError> {
        let mask = self.mask(&QUICHeaderProtection::sample(packet, number_offset)?);
        packet[0] ^= mask[0] & QUICHeaderProtection::first_byte_bits(packet[0]);
        let length = usize::from(packet[0] & 0x03) + 1;
        let mut truncated = 0u64;
        for (byte, mask) in packet[number_offset..number_offset + length].iter_mut().zip(&mask[1..]) {
            *byte ^= mask;
            truncated = (truncated << 8) | u64::from(*byte);
        }
        Ok((length, truncated))
    }
}

/// The Retry Integrity Tag (RFC 9001 §5.8): AEAD_AES_128_GCM under the
/// version's fixed key and nonce, over the Retry Pseudo-Packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QUICRetryIntegrity;

impl QUICRetryIntegrity {
    /// The tag of `retry`, a Retry packet without its tag, answering an
    /// Initial packet whose Destination Connection ID was `original`.
    pub fn tag(profile: &QUICVersionProfile, original: &QUICConnectionID, retry: &[u8]) -> Result<[u8; 16], QUICError> {
        let mut pseudo = Vec::with_capacity(1 + original.len() + retry.len());
        pseudo.push(original.len() as u8);
        pseudo.extend_from_slice(original.as_slice());
        pseudo.extend_from_slice(retry);
        let aead = TLSAEAD::new(TLSAEADAlgorithm::AES128GCM, &profile.retry_key).map_err(|_| QUICError::Config)?;
        let mut tag = [0u8; 16];
        aead.seal_in_place(&profile.retry_nonce, &pseudo, &mut [], &mut tag).map_err(|_| QUICError::Config)?;
        Ok(tag)
    }

    /// Whether `packet`, a whole Retry packet, carries the tag of `original`.
    pub fn verify(profile: &QUICVersionProfile, original: &QUICConnectionID, packet: &[u8]) -> bool {
        let Some(split) = packet.len().checked_sub(16) else { return false };
        let (retry, tag) = packet.split_at(split);
        QUICRetryIntegrity::tag(profile, original, retry)
            .is_ok_and(|expected| crate::secret::ConstantTimeEq::ct_eq(&expected[..], tag).into_bool())
    }
}
