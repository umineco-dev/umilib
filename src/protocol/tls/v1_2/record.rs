use alloc::vec::Vec;

use crate::protocol::tls::{
    TLSAEAD, TLSAEADAlgorithm, TLSAlertDescription, TLSContentType, TLSError, TLSRecordHeader, TLSRecordProtector,
    TLSVersion,
};

/// The protection of TLS 1.2 records in one direction with an AEAD (RFC
/// 5246 §6.2.3.3): AES-GCM with a 4-byte salt and an 8-byte explicit nonce,
/// which is the sequence number (RFC 5288 §3), or ChaCha20-Poly1305 with a
/// 12-byte IV XOR the sequence number (RFC 7905 §2). The additional data
/// is the sequence number, the type, the version and the plaintext's length.
pub struct TLS12RecordProtection {
    pub aead: TLSAEAD,
    pub algorithm: TLSAEADAlgorithm,
    /// The salt of GCM (4 bytes) or the IV of ChaCha20-Poly1305 (12 bytes).
    pub iv: Vec<u8>,
    pub sequence: u64,
}

impl TLS12RecordProtection {
    pub fn new(algorithm: TLSAEADAlgorithm, key: &[u8], iv: &[u8]) -> Result<TLS12RecordProtection, TLSError> {
        Ok(TLS12RecordProtection { aead: TLSAEAD::new(algorithm, key)?, algorithm, iv: iv.to_vec(), sequence: 0 })
    }

    /// The length of the IV the key block gives (RFC 5288 §3, RFC 7905 §2).
    pub fn iv_length(algorithm: TLSAEADAlgorithm) -> usize {
        match algorithm {
            TLSAEADAlgorithm::ChaCha20Poly1305 => 12,
            _ => 4,
        }
    }

    /// The length of the explicit nonce in each record.
    pub fn explicit_length(&self) -> usize {
        if self.algorithm == TLSAEADAlgorithm::ChaCha20Poly1305 { 0 } else { 8 }
    }

    /// The nonce of the current sequence number; fails once it would wrap.
    pub fn nonce(&self) -> Result<[u8; 12], TLSError> {
        if self.sequence == u64::MAX {
            return Err(TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR));
        }
        let mut nonce = [0u8; 12];
        if self.algorithm == TLSAEADAlgorithm::ChaCha20Poly1305 {
            nonce.copy_from_slice(&self.iv);
            for (byte, sequence) in nonce[4..].iter_mut().zip(self.sequence.to_be_bytes()) {
                *byte ^= sequence;
            }
        } else {
            nonce[..4].copy_from_slice(&self.iv);
            nonce[4..].copy_from_slice(&self.sequence.to_be_bytes());
        }
        Ok(nonce)
    }

    /// The additional data: seq_num, type, version, length (RFC 5246 §6.2.3.3).
    pub fn associated(&self, content_type: TLSContentType, length: usize) -> [u8; 13] {
        let mut associated = [0u8; 13];
        associated[..8].copy_from_slice(&self.sequence.to_be_bytes());
        associated[8] = content_type.0;
        associated[9..11].copy_from_slice(&TLSVersion::TLS1_2.0.to_be_bytes());
        associated[11..].copy_from_slice(&(length as u16).to_be_bytes());
        associated
    }
}

impl TLSRecordProtector for TLS12RecordProtection {
    fn seal(&mut self, content_type: TLSContentType, fragment: &[u8], out: &mut Vec<u8>) -> Result<(), TLSError> {
        let nonce = self.nonce()?;
        let associated = self.associated(content_type, fragment.len());
        let mut body = fragment.to_vec();
        self.aead.seal(&nonce, &associated, &mut body)?;
        let explicit = &nonce[4..4 + self.explicit_length()];
        let header =
            TLSRecordHeader { content_type, version: TLSVersion::TLS1_2, length: (explicit.len() + body.len()) as u16 };
        header.encode(out)?;
        out.extend_from_slice(explicit);
        out.extend_from_slice(&body);
        self.sequence += 1;
        Ok(())
    }

    /// Opens the record: with GCM, the explicit nonce comes first. Fails
    /// with `bad_record_mac` unless it authenticates.
    fn open(&mut self, header: &TLSRecordHeader, fragment: &[u8]) -> Result<(TLSContentType, Vec<u8>), TLSError> {
        let bad = TLSError::Protocol(TLSAlertDescription::BAD_RECORD_MAC);
        let explicit = self.explicit_length();
        if fragment.len() < explicit + self.aead.tag_length() {
            return Err(bad);
        }
        let mut nonce = self.nonce()?;
        nonce[4..4 + explicit].copy_from_slice(&fragment[..explicit]);
        let mut body = fragment[explicit..].to_vec();
        let plaintext = body.len() - self.aead.tag_length();
        let associated = self.associated(header.content_type, plaintext);
        self.aead.open(&nonce, &associated, &mut body)?;
        self.sequence += 1;
        Ok((header.content_type, body))
    }

    fn maximum_plaintext(&self, limit: usize) -> usize {
        limit.min(TLSRecordHeader::MAXIMUM_PLAINTEXT)
    }
}
