use alloc::vec;
use alloc::vec::Vec;

use crate::protocol::tls::{
    TLSError, TLSExtension, TLSExtensionType, TLSPSKIdentity, TLSPreSharedKey, TLSSessionState, TLSSessionTicket,
    TLSTranscript,
};
use crate::secret::Secret;

use super::TLS13KeySchedule;

/// What resumption with a PSK adds to the key schedule of TLS 1.3 (RFC 9846
/// §4.3.11, §7.1): the `pre_shared_key` a client offers, the binder that
/// proves it holds the PSK, and the keys of early data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TLS13Resumption;

impl TLS13Resumption {
    /// The client's `pre_shared_key` of `ticket` at `time`, its binder
    /// zeros until [`TLS13Resumption::bind`] computes it.
    pub fn offer(ticket: &TLSSessionTicket, time: i64) -> Result<TLSExtension, TLSError> {
        let length = ticket.state.cipher_suite.hash().ok_or(TLSError::Config)?.length();
        let offered = TLSPreSharedKey::Offered {
            identities: vec![TLSPSKIdentity {
                identity: ticket.ticket.clone(),
                obfuscated_ticket_age: ticket.state.obfuscated_age(time),
            }],
            binders: vec![vec![0; length]],
        };
        TLSExtension::with(TLSExtensionType::PRE_SHARED_KEY, |data| offered.encode(data))
    }

    /// The binder of `state` (RFC 9846 §4.3.11.2): the Finished of the
    /// binder key over `transcript_hash`, the hash of the messages before
    /// the ClientHello and of the ClientHello truncated before its binders.
    pub fn binder(state: &TLSSessionState, transcript_hash: &[u8]) -> Result<Vec<u8>, TLSError> {
        let schedule = TLS13KeySchedule::new(state.cipher_suite.hash().ok_or(TLSError::illegal())?);
        let early = schedule.early_secret(Some(state.psk.expose()));
        let empty = schedule.hash.digest(&[]);
        let key = schedule.derive_secret(early.expose(), b"res binder", &empty)?;
        schedule.finished(key.expose(), transcript_hash)
    }

    /// The hash the binder of the ClientHello `message` (header included)
    /// covers: `transcript` (the messages before it), then `message` but
    /// its binders list, `binders_length` bytes at its end.
    pub fn binder_hash(
        state: &TLSSessionState,
        transcript: &TLSTranscript,
        message: &[u8],
        binders_length: usize,
    ) -> Result<Vec<u8>, TLSError> {
        let hash = state.cipher_suite.hash().ok_or(TLSError::illegal())?;
        let truncated = message.len().checked_sub(binders_length).ok_or(TLSError::decode())?;
        let mut transcript = transcript.clone();
        transcript.select(hash);
        transcript.update(&message[..truncated]);
        Ok(transcript.hash())
    }

    /// Writes the binder of the one PSK offered into the ClientHello
    /// `message`, whose last bytes it is.
    pub fn bind(message: &mut [u8], state: &TLSSessionState, transcript: &TLSTranscript) -> Result<(), TLSError> {
        let length = state.cipher_suite.hash().ok_or(TLSError::illegal())?.length();
        let binders_length = TLSPreSharedKey::binders_length(&[vec![0; length]]);
        let hash = TLS13Resumption::binder_hash(state, transcript, message, binders_length)?;
        let binder = TLS13Resumption::binder(state, &hash)?;
        let start = message.len() - length;
        message[start..].copy_from_slice(&binder);
        Ok(())
    }

    /// The client's early traffic secret of `state` (RFC 9846 §7.1):
    /// Derive-Secret(Early Secret, "c e traffic", ClientHello), given the
    /// transcript through the ClientHello.
    pub fn early_traffic_secret(
        state: &TLSSessionState,
        transcript: &TLSTranscript,
    ) -> Result<Secret<Vec<u8>>, TLSError> {
        let hash = state.cipher_suite.hash().ok_or(TLSError::illegal())?;
        let schedule = TLS13KeySchedule::new(hash);
        let early = schedule.early_secret(Some(state.psk.expose()));
        let mut transcript = transcript.clone();
        transcript.select(hash);
        schedule.derive_secret(early.expose(), b"c e traffic", &transcript.hash())
    }
}
