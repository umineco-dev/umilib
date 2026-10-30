use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::secret::Secret;

use super::{TLSAEADAlgorithm, TLSCipherSuite, TLSConfig, TLSError, TLSHashAlgorithm, TLSVersion};

/// The encryption levels of a TLS 1.3 handshake (RFC 9001 §4.1.3): the
/// keys that protect each part of it. QUIC carries the handshake messages of
/// each level in its own stream of CRYPTO frames; early data has no
/// handshake messages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TLSEncryptionLevel {
    #[default]
    Initial,
    EarlyData,
    Handshake,
    Application,
}

/// Which way a secret protects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLSDirection {
    Reading,
    Writing,
}

/// A traffic secret that TLS gives the transport (RFC 9001 §4.1.4): its
/// level and direction, the secret, and the hash and AEAD of the cipher
/// suite, from which the transport derives its keys.
#[derive(Clone, Debug)]
pub struct TLSTrafficSecret {
    pub level: TLSEncryptionLevel,
    pub direction: TLSDirection,
    pub hash: TLSHashAlgorithm,
    pub aead: TLSAEADAlgorithm,
    pub secret: Secret<Vec<u8>>,
}

/// What TLS exchanges with QUIC instead of records (RFC 9001 §4.1): the
/// handshake bytes to send at each level, the secrets of each level, and
/// the levels of the messages written and expected. With it, a record layer
/// writes no records; QUIC protects the handshake in its own packets.
///
/// Its presence also applies the rules of RFC 9001 §4 and §8 to the
/// handshake: TLS 1.3 only, ALPN and the `quic_transport_parameters`
/// extension required, no middlebox compatibility mode, no EndOfEarlyData,
/// no KeyUpdate, no post-handshake authentication.
#[derive(Clone, Debug, Default)]
pub struct TLSQUIC {
    /// This end's `quic_transport_parameters` (RFC 9001 §8.2), encoded by QUIC.
    pub transport_parameters: Vec<u8>,
    /// The level handshake messages are written at.
    pub writing: TLSEncryptionLevel,
    /// The level handshake messages are expected at.
    pub reading: TLSEncryptionLevel,
    /// The handshake bytes to send, each run with its level.
    pub outgoing: VecDeque<(TLSEncryptionLevel, Vec<u8>)>,
    /// The secrets not yet taken, in the order they became available.
    pub secrets: VecDeque<TLSTrafficSecret>,
}

impl TLSQUIC {
    /// The most early data a NewSessionTicket can allow with QUIC: the
    /// sentinel that says 0-RTT is accepted, its amount being QUIC's
    /// `initial_max_data` (RFC 9001 §4.6.1).
    pub const EARLY_DATA: u32 = 0xFFFF_FFFF;

    pub fn new(transport_parameters: Vec<u8>) -> TLSQUIC {
        TLSQUIC { transport_parameters, ..TLSQUIC::default() }
    }

    /// Fails with [`TLSError::Config`] unless `config` can carry QUIC: TLS
    /// 1.3 among its versions (RFC 9001 §4.2), a protocol for ALPN (§8.1),
    /// and no cipher suite without header protection, TLS_AES_128_CCM_8_SHA256 (§5.3).
    pub fn check(config: &TLSConfig) -> Result<(), TLSError> {
        let working = TLSVersion::TLS1_3.is_supported()
            && config.versions.contains(&TLSVersion::TLS1_3)
            && !config.protocols.is_empty()
            && !config.cipher_suites.contains(&TLSCipherSuite::TLS_AES_128_CCM_8_SHA256);
        if working { Ok(()) } else { Err(TLSError::Config) }
    }

    /// Appends handshake bytes at the current writing level.
    pub fn write(&mut self, bytes: &[u8]) {
        match self.outgoing.back_mut() {
            Some((level, run)) if *level == self.writing => run.extend_from_slice(bytes),
            _ => self.outgoing.push_back((self.writing, bytes.to_vec())),
        }
    }

    /// Hands over `secret`, and moves the level of its direction to its
    /// own, except for early data, which carries no handshake messages.
    pub fn install(&mut self, secret: TLSTrafficSecret) {
        if secret.level != TLSEncryptionLevel::EarlyData {
            match secret.direction {
                TLSDirection::Reading => self.reading = secret.level,
                TLSDirection::Writing => self.writing = secret.level,
            }
        }
        self.secrets.push_back(secret);
    }
}
