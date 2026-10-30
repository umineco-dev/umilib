use alloc::vec::Vec;

use crate::protocol::tls::{
    TLSAEAD, TLSAEADAlgorithm, TLSAlertDescription, TLSContentType, TLSError, TLSRecordHeader, TLSRecordProtector,
    TLSVersion,
};

use super::TLS13KeySchedule;

/// The protection of TLS 1.3 records in one direction (RFC 9846 §5.2–§5.4):
/// the AEAD keyed from a traffic secret, the IV, and the sequence number
/// that makes each record's nonce.
pub struct TLS13RecordProtection {
    pub aead: TLSAEAD,
    pub iv: [u8; 12],
    pub sequence: u64,
    /// The padding added to each record, up to the record's limit (RFC 9846 §5.4).
    pub padding: usize,
}

impl TLS13RecordProtection {
    /// The protection of the traffic secret `secret` with `algorithm`.
    pub fn new(
        schedule: &TLS13KeySchedule,
        algorithm: TLSAEADAlgorithm,
        secret: &[u8],
    ) -> Result<TLS13RecordProtection, TLSError> {
        let keys = schedule.traffic_keys(secret, algorithm.key_length())?;
        let aead = TLSAEAD::new(algorithm, keys.key.expose())?;
        let iv: [u8; 12] = keys
            .iv
            .expose()
            .as_slice()
            .try_into()
            .map_err(|_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR))?;
        Ok(TLS13RecordProtection { aead, iv, sequence: 0, padding: 0 })
    }

    /// The nonce of the current sequence number: the IV XOR the number,
    /// left-padded to 12 bytes (RFC 9846 §5.3). Fails once the sequence
    /// number would wrap, which RFC 9846 §5.3 forbids.
    pub fn nonce(&self) -> Result<[u8; 12], TLSError> {
        if self.sequence == u64::MAX {
            return Err(TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR));
        }
        let mut nonce = self.iv;
        for (byte, sequence) in nonce[4..].iter_mut().zip(self.sequence.to_be_bytes()) {
            *byte ^= sequence;
        }
        Ok(nonce)
    }
}

impl TLSRecordProtector for TLS13RecordProtection {
    /// TLSInnerPlaintext (content, type, zeros) under the AEAD, with the
    /// record header as additional data (RFC 9846 §5.2).
    fn seal(&mut self, content_type: TLSContentType, fragment: &[u8], out: &mut Vec<u8>) -> Result<(), TLSError> {
        let nonce = self.nonce()?;
        let mut inner = Vec::with_capacity(fragment.len() + 1 + self.padding + self.aead.tag_length());
        inner.extend_from_slice(fragment);
        inner.push(content_type.0);
        // The inner plaintext, padding included, stays within 2^14 + 1 bytes.
        let room = (TLSRecordHeader::MAXIMUM_PLAINTEXT + 1).saturating_sub(inner.len());
        inner.resize(inner.len() + self.padding.min(room), 0);
        let length = inner.len() + self.aead.tag_length();
        let header = TLSRecordHeader {
            content_type: TLSContentType::APPLICATION_DATA,
            version: TLSVersion::TLS1_2,
            length: length as u16,
        };
        let associated = header.to_bytes();
        self.aead.seal(&nonce, &associated, &mut inner)?;
        self.sequence += 1;
        out.extend_from_slice(&associated);
        out.extend_from_slice(&inner);
        Ok(())
    }

    /// Opens the record and strips the padding. Fails with `bad_record_mac`
    /// unless it authenticates, `unexpected_message` if it is all zeros
    /// (no content type), and `record_overflow` for an inner plaintext
    /// above 2^14 + 1 bytes (RFC 9846 §5.2, §5.4).
    fn open(&mut self, header: &TLSRecordHeader, fragment: &[u8]) -> Result<(TLSContentType, Vec<u8>), TLSError> {
        if header.content_type != TLSContentType::APPLICATION_DATA {
            return Err(TLSError::unexpected());
        }
        let nonce = self.nonce()?;
        let mut inner = fragment.to_vec();
        self.aead.open(&nonce, &header.to_bytes(), &mut inner)?;
        self.sequence += 1;
        if inner.len() > TLSRecordHeader::MAXIMUM_PLAINTEXT + 1 {
            return Err(TLSError::Protocol(TLSAlertDescription::RECORD_OVERFLOW));
        }
        let end = inner.iter().rposition(|byte| *byte != 0).ok_or(TLSError::unexpected())?;
        let content_type = TLSContentType(inner[end]);
        inner.truncate(end);
        Ok((content_type, inner))
    }

    fn maximum_plaintext(&self, limit: usize) -> usize {
        limit.saturating_sub(1).min(TLSRecordHeader::MAXIMUM_PLAINTEXT)
    }
}
