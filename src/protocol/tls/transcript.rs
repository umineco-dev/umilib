use alloc::vec::Vec;

use crate::crypto::hmac::HMAC;
use crate::hash::Digest;
use crate::hash::sha::v2::{SHA256, SHA384};

use super::{TLSHandshakeType, TLSHashAlgorithm};

impl TLSHashAlgorithm {
    /// The digest of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            TLSHashAlgorithm::SHA256 => {
                let mut hash = SHA256::default();
                hash.update(data);
                hash.finalize().to_vec()
            }
            TLSHashAlgorithm::SHA384 => {
                let mut hash = SHA384::default();
                hash.update(data);
                hash.finalize().to_vec()
            }
        }
    }

    /// HMAC of `data` under `key` (RFC 2104).
    pub fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            TLSHashAlgorithm::SHA256 => HMAC::<SHA256>::mac(key, data).to_vec(),
            TLSHashAlgorithm::SHA384 => HMAC::<SHA384>::mac(key, data).to_vec(),
        }
    }
}

/// The running hash of a handshake's messages (RFC 9846 §4.1, RFC 5246
/// §7.4.9). Until the cipher suite names the hash, the messages are kept
/// whole; [`TLSTranscript::select`] then hashes them.
#[derive(Clone, Debug)]
pub struct TLSTranscript {
    pub state: TLSTranscriptState,
}

/// The state of a [`TLSTranscript`].
#[derive(Clone, Debug)]
pub enum TLSTranscriptState {
    /// The messages so far, before the hash is known.
    Buffered(Vec<u8>),
    SHA256(SHA256),
    SHA384(SHA384),
}

impl Default for TLSTranscript {
    fn default() -> TLSTranscript {
        TLSTranscript::new()
    }
}

impl TLSTranscript {
    pub fn new() -> TLSTranscript {
        TLSTranscript { state: TLSTranscriptState::Buffered(Vec::new()) }
    }

    /// Adds a whole handshake message, header included.
    pub fn update(&mut self, message: &[u8]) {
        match &mut self.state {
            TLSTranscriptState::Buffered(buffer) => buffer.extend_from_slice(message),
            TLSTranscriptState::SHA256(hash) => hash.update(message),
            TLSTranscriptState::SHA384(hash) => hash.update(message),
        }
    }

    /// Starts hashing with `hash`, the messages kept so far first. Does
    /// nothing once a hash is in use.
    pub fn select(&mut self, hash: TLSHashAlgorithm) {
        if !matches!(self.state, TLSTranscriptState::Buffered(_)) {
            return;
        }
        let fresh = match hash {
            TLSHashAlgorithm::SHA256 => TLSTranscriptState::SHA256(SHA256::default()),
            TLSHashAlgorithm::SHA384 => TLSTranscriptState::SHA384(SHA384::default()),
        };
        if let TLSTranscriptState::Buffered(buffer) = core::mem::replace(&mut self.state, fresh) {
            self.update(&buffer);
        }
    }

    /// The hash of the messages so far; empty while they are only kept.
    pub fn hash(&self) -> Vec<u8> {
        match &self.state {
            TLSTranscriptState::Buffered(_) => Vec::new(),
            TLSTranscriptState::SHA256(hash) => hash.clone().finalize().to_vec(),
            TLSTranscriptState::SHA384(hash) => hash.clone().finalize().to_vec(),
        }
    }

    /// Replaces the messages so far, which must be ClientHello1 alone, by
    /// the synthetic `message_hash` message of its hash, as a
    /// HelloRetryRequest requires (RFC 9846 §4.1).
    pub fn restart_after_retry(&mut self, hash: TLSHashAlgorithm) {
        self.select(hash);
        let digest = self.hash();
        let mut message = Vec::with_capacity(4 + digest.len());
        message.extend_from_slice(&[TLSHandshakeType::MESSAGE_HASH.0, 0, 0, digest.len() as u8]);
        message.extend_from_slice(&digest);
        self.state = TLSTranscriptState::Buffered(Vec::new());
        self.select(hash);
        self.update(&message);
    }

    /// The messages kept, while the hash is not known yet.
    pub fn buffered(&self) -> Option<&[u8]> {
        match &self.state {
            TLSTranscriptState::Buffered(buffer) => Some(buffer),
            _ => None,
        }
    }
}
