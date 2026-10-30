use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::crypto::hmac::HMAC;
use crate::hash::sha::v2::SHA256;

use super::{QUICConnectionID, QUICError, QUICErrorCode, QUICFrameType, QUICRangeSet};

/// Stateless reset tokens (RFC 9000 §10.3.2): HMAC-SHA256 of the connection
/// ID under a static key, truncated to 16 bytes, so that an endpoint that
/// lost a connection's state can still make the token of its IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QUICResetToken;

impl QUICResetToken {
    pub fn of(key: &[u8; 32], id: &QUICConnectionID) -> [u8; 16] {
        let mac = HMAC::<SHA256>::mac(key, id.as_slice());
        let mut token = [0u8; 16];
        token.copy_from_slice(&mac.as_ref()[..16]);
        token
    }
}

/// A connection ID and its stateless reset token, which only the ID of a
/// client's handshake lacks (RFC 9000 §10.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QUICIssuedID {
    pub id: QUICConnectionID,
    pub reset_token: Option<[u8; 16]>,
}

/// The connection IDs this end issued, by sequence number (RFC 9000 §5.1.1):
/// the peer sends to any of them until it retires it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QUICLocalConnectionIDs {
    pub ids: BTreeMap<u64, QUICIssuedID>,
    pub next_sequence: u64,
}

impl QUICLocalConnectionIDs {
    /// Issues `issued` under the next sequence number and returns it.
    pub fn issue(&mut self, issued: QUICIssuedID) -> u64 {
        let sequence = self.next_sequence;
        self.ids.insert(sequence, issued);
        self.next_sequence += 1;
        sequence
    }

    pub fn contains(&self, id: &QUICConnectionID) -> bool {
        self.ids.values().any(|issued| issued.id == *id)
    }

    /// The peer retired `sequence` (RFC 9000 §19.16): PROTOCOL_VIOLATION for
    /// one never issued, or the one the packet was sent to. Returns the ID
    /// retired, if it was still active.
    pub fn retire(&mut self, sequence: u64, destination: &QUICConnectionID) -> Result<Option<QUICIssuedID>, QUICError> {
        let frame = QUICFrameType::RETIRE_CONNECTION_ID;
        if sequence >= self.next_sequence {
            return Err(QUICError::violation(frame, "retiring a connection ID never issued"));
        }
        if self.ids.get(&sequence).is_some_and(|issued| issued.id == *destination) {
            return Err(QUICError::violation(frame, "retiring the connection ID of its own packet"));
        }
        Ok(self.ids.remove(&sequence))
    }
}

/// The connection IDs the peer issued (RFC 9000 §5.1): those this end may
/// send to, the one it uses, and those it must retire.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QUICPeerConnectionIDs {
    pub ids: BTreeMap<u64, QUICIssuedID>,
    /// The sequence number of the ID in use.
    pub active: u64,
    /// The largest Retire Prior To received.
    pub retire_prior_to: u64,
    /// The sequence numbers to send RETIRE_CONNECTION_ID for.
    pub retiring: Vec<u64>,
    /// The sequence numbers retired whose RETIRE_CONNECTION_ID the peer has
    /// not acknowledged yet (RFC 9000 §5.1.2).
    pub unacknowledged: BTreeSet<u64>,
    /// The sequence numbers received from Retire Prior To up, so that a
    /// repeated NEW_CONNECTION_ID of one retired does not bring it back.
    pub seen: QUICRangeSet,
    /// The most IDs kept: this end's active_connection_id_limit.
    pub limit: u64,
}

impl QUICPeerConnectionIDs {
    /// The IDs of a peer that gave `first` in the handshake, sequence 0,
    /// with its stateless reset token if any.
    pub fn new(first: QUICConnectionID, reset_token: Option<[u8; 16]>, limit: u64) -> QUICPeerConnectionIDs {
        let mut ids = BTreeMap::new();
        ids.insert(0, QUICIssuedID { id: first, reset_token });
        let mut seen = QUICRangeSet::new();
        seen.insert(0..=0);
        QUICPeerConnectionIDs {
            ids,
            active: 0,
            retire_prior_to: 0,
            retiring: Vec::new(),
            unacknowledged: BTreeSet::new(),
            seen,
            limit,
        }
    }

    /// The most retirements not yet acknowledged: twice the limit, which
    /// RFC 9000 §5.1.2 asks an endpoint to allow.
    pub fn retirement_limit(&self) -> usize {
        usize::try_from(self.limit.saturating_mul(2)).unwrap_or(usize::MAX)
    }

    /// Retires `sequence`: RETIRE_CONNECTION_ID is due for it.
    pub fn retire(&mut self, sequence: u64) {
        if self.unacknowledged.insert(sequence) {
            self.retiring.push(sequence);
        }
    }

    /// The peer acknowledged the RETIRE_CONNECTION_ID of `sequence`.
    pub fn retired(&mut self, sequence: u64) {
        self.unacknowledged.remove(&sequence);
    }

    /// The ID in use.
    pub fn current(&self) -> Option<&QUICIssuedID> {
        self.ids.get(&self.active)
    }

    /// A NEW_CONNECTION_ID (RFC 9000 §5.1.2, §19.15): repeated frames are
    /// fine, an ID or number reused otherwise is PROTOCOL_VIOLATION, more
    /// than `limit` active IDs CONNECTION_ID_LIMIT_ERROR, as are more
    /// retirements waiting for acknowledgment than [`QUICPeerConnectionIDs::retirement_limit`].
    /// IDs below Retire Prior To are retired, the one in use for another if needed.
    pub fn insert(&mut self, sequence: u64, retire_prior_to: u64, issued: QUICIssuedID) -> Result<(), QUICError> {
        let frame = QUICFrameType::NEW_CONNECTION_ID;
        match self.ids.get(&sequence) {
            Some(existing) if *existing == issued => return Ok(()),
            Some(_) => return Err(QUICError::violation(frame, "a sequence number reused")),
            None => {}
        }
        if self.ids.values().any(|existing| existing.id == issued.id) {
            return Err(QUICError::violation(frame, "a connection ID reused"));
        }
        let limit_error =
            QUICError::transport(QUICErrorCode::CONNECTION_ID_LIMIT_ERROR, "too many connection IDs").in_frame(frame);
        // An ID already retired by Retire Prior To is retired at once; one
        // this end retired otherwise stays retired.
        if sequence < self.retire_prior_to || self.seen.contains(sequence) {
            if sequence < self.retire_prior_to {
                self.retire(sequence);
            }
            return if self.unacknowledged.len() > self.retirement_limit() { Err(limit_error) } else { Ok(()) };
        }
        self.seen.insert(sequence..=sequence);
        self.ids.insert(sequence, issued);
        if retire_prior_to > self.retire_prior_to {
            self.retire_prior_to = retire_prior_to;
            self.seen.remove_below(retire_prior_to);
            let old: Vec<u64> = self.ids.range(..retire_prior_to).map(|(sequence, _)| *sequence).collect();
            for sequence in old {
                self.ids.remove(&sequence);
                self.retire(sequence);
            }
        }
        if self.ids.len() as u64 > self.limit || self.unacknowledged.len() > self.retirement_limit() {
            return Err(limit_error);
        }
        if !self.ids.contains_key(&self.active)
            && let Some(next) = self.ids.keys().next()
        {
            self.active = *next;
        }
        Ok(())
    }

    /// Moves to an unused ID, retiring the one in use (RFC 9000 §9.5), for a
    /// new path; false if there is none.
    pub fn rotate(&mut self) -> bool {
        let Some(next) = self.ids.keys().copied().find(|sequence| *sequence > self.active) else { return false };
        self.ids.remove(&self.active);
        self.retire(self.active);
        self.active = next;
        true
    }

    /// Whether `token` is the stateless reset token of the ID in use: those
    /// of IDs never used or retired do not count (RFC 9000 §10.3.1).
    pub fn is_reset_token(&self, token: &[u8; 16]) -> bool {
        self.current()
            .and_then(|issued| issued.reset_token)
            .is_some_and(|known| crate::secret::ConstantTimeEq::ct_eq(&known[..], &token[..]).into_bool())
    }
}
