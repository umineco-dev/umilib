use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{
    TLSAlertDescription, TLSContentType, TLSError, TLSHandshake, TLSHandshakeReassembler, TLSQUIC, TLSRecord,
    TLSRecordHeader, TLSVersion,
};

/// The protection of records in one direction, as a version defines it:
/// TLS 1.3's (RFC 9846 §5.2) or TLS 1.2's AEAD records (RFC 5246 §6.2.3.3).
pub trait TLSRecordProtector: Send {
    /// Writes `fragment` of `content_type` as one protected record, header included.
    fn seal(&mut self, content_type: TLSContentType, fragment: &[u8], out: &mut Vec<u8>) -> Result<(), TLSError>;

    /// The content type and plaintext of the protected record of `header`
    /// and `fragment`; fails with `bad_record_mac` unless it authenticates.
    fn open(&mut self, header: &TLSRecordHeader, fragment: &[u8]) -> Result<(TLSContentType, Vec<u8>), TLSError>;

    /// The largest plaintext of a record when the peer accepts `limit`
    /// bytes of plaintext (RFC 8449 §4: TLS 1.3 counts the content type).
    fn maximum_plaintext(&self, limit: usize) -> usize;
}

/// The record layer (RFC 9846 §5): the bytes received and to send, the
/// protection of each direction, and the joining of handshake messages.
pub struct TLSRecordLayer {
    /// The bytes received; those before `consumed` are read already.
    pub incoming: Vec<u8>,
    pub consumed: usize,
    pub outgoing: Vec<u8>,
    pub reader: Option<Box<dyn TLSRecordProtector>>,
    pub writer: Option<Box<dyn TLSRecordProtector>>,
    /// The `legacy_record_version` of the records written: 0x0301 for an
    /// initial ClientHello, 0x0303 otherwise (RFC 9846 §5.1).
    pub version: TLSVersion,
    /// The peer's `record_size_limit` (RFC 8449 §4), as its version counts
    /// it: TLS 1.3 counts the content type, so without the extension it is
    /// 2^14 + 1; the record protection subtracts what it must.
    pub peer_limit: usize,
    /// The largest plaintext this end accepts in a record.
    pub own_limit: usize,
    pub handshake: TLSHandshakeReassembler,
    /// Bytes of early data the server may still drop: records that do not
    /// decrypt, or application data before it reads protected records, from
    /// a client whose 0-RTT it refused (RFC 9846 §4.2.10). Each record
    /// dropped counts as its plaintext at most: [`TLSRecordLayer::skipped`].
    pub skippable: usize,
    /// The records dropped without effect since the last application data,
    /// and how many are allowed ([`TLSRecordLayer::ignore`]).
    pub ignored: u32,
    pub maximum_ignored: u32,
    /// Whether `close_notify` was sent: nothing more is (RFC 9846 §6.1).
    pub closed: bool,
    /// What QUIC takes instead of records, when it carries the handshake
    /// (RFC 9001 §4): then no record is written or read.
    pub quic: Option<TLSQUIC>,
}

impl core::fmt::Debug for TLSRecordLayer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TLSRecordLayer")
            .field("incoming", &self.incoming.len())
            .field("outgoing", &self.outgoing.len())
            .field("reading_protected", &self.reader.is_some())
            .field("writing_protected", &self.writer.is_some())
            .finish()
    }
}

impl TLSRecordLayer {
    /// The least a record of TLS 1.3 adds to its plaintext: the content
    /// type and a tag of 16 bytes (RFC 9846 §5.2).
    pub const MINIMUM_EXPANSION: usize = 17;

    /// Drops a record of `fragment_length` bytes from the early data that
    /// may be skipped; false if it does not fit. A record counts as its
    /// plaintext, and at least one byte, so a run of records is bounded.
    pub fn skipped(&mut self, fragment_length: usize) -> bool {
        let plaintext = fragment_length.saturating_sub(TLSRecordLayer::MINIMUM_EXPANSION).max(1);
        match self.skippable.checked_sub(plaintext) {
            Some(rest) => {
                self.skippable = rest;
                true
            }
            None => false,
        }
    }

    pub fn new(maximum_handshake_message: usize, own_limit: usize) -> TLSRecordLayer {
        TLSRecordLayer {
            incoming: Vec::new(),
            consumed: 0,
            outgoing: Vec::new(),
            reader: None,
            writer: None,
            version: TLSVersion::TLS1_2,
            peer_limit: TLSRecordHeader::MAXIMUM_PLAINTEXT + 1,
            own_limit,
            handshake: TLSHandshakeReassembler::new(maximum_handshake_message),
            skippable: 0,
            ignored: 0,
            maximum_ignored: 32,
            closed: false,
            quic: None,
        }
    }

    /// Writes `data` of `content_type` in records of at most the peer's
    /// limit, protected if a writer is installed. Handshake data is never
    /// written as a zero-length fragment; empty application data is one
    /// empty record (RFC 9846 §5.1).
    pub fn write(&mut self, content_type: TLSContentType, data: &[u8]) -> Result<(), TLSError> {
        // QUIC carries handshake messages only: alerts become its errors,
        // and application data is its own (RFC 9001 §4.1.3).
        if let Some(quic) = &mut self.quic {
            if content_type != TLSContentType::HANDSHAKE {
                return Err(TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR));
            }
            quic.write(data);
            return Ok(());
        }
        let limit = match &self.writer {
            Some(writer) => writer.maximum_plaintext(self.peer_limit),
            None => self.peer_limit.min(TLSRecordHeader::MAXIMUM_PLAINTEXT),
        }
        .max(1);
        if data.is_empty() {
            if content_type == TLSContentType::APPLICATION_DATA {
                return self.write_record(content_type, &[]);
            }
            return Ok(());
        }
        for fragment in data.chunks(limit) {
            self.write_record(content_type, fragment)?;
        }
        Ok(())
    }

    /// Writes one record of `fragment`. Application data is never written
    /// unprotected (RFC 9846 §5.1), and no record is written for QUIC.
    pub fn write_record(&mut self, content_type: TLSContentType, fragment: &[u8]) -> Result<(), TLSError> {
        if self.quic.is_some() {
            return Err(TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR));
        }
        // A ChangeCipherSpec is never protected (RFC 9846 §5).
        let writer = self.writer.as_mut().filter(|_| content_type != TLSContentType::CHANGE_CIPHER_SPEC);
        match writer {
            Some(writer) => writer.seal(content_type, fragment, &mut self.outgoing),
            None if content_type == TLSContentType::APPLICATION_DATA => {
                Err(TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR))
            }
            None => {
                let header = TLSRecordHeader { content_type, version: self.version, length: fragment.len() as u16 };
                TLSRecord { header, fragment }.encode(&mut self.outgoing)
            }
        }
    }

    /// Writes a handshake message and returns it with its header, as the
    /// transcript hashes it.
    pub fn write_handshake(&mut self, message: &TLSHandshake) -> Result<Vec<u8>, TLSError> {
        let bytes = message.to_bytes()?;
        self.write(TLSContentType::HANDSHAKE, &bytes)?;
        Ok(bytes)
    }

    /// The next record received, opened, or `None` until one is whole.
    /// Fails with `record_overflow` for a record or plaintext above the
    /// limits (RFC 9846 §5.1, §5.2, RFC 8449 §4).
    pub fn read(&mut self) -> Result<Option<(TLSContentType, Vec<u8>)>, TLSError> {
        loop {
            // Early data that may be skipped was sized by a client that knew no limit of this end.
            let maximum = match &self.reader {
                _ if self.skippable > 0 => TLSRecordHeader::MAXIMUM_CIPHERTEXT,
                Some(_) => self.own_limit + 256,
                None => TLSRecordHeader::MAXIMUM_PLAINTEXT,
            }
            .min(TLSRecordHeader::MAXIMUM_CIPHERTEXT);
            let Some((record, length)) = TLSRecord::decode(&self.incoming[self.consumed..], maximum)? else {
                // What was read goes once per call, not once per record.
                self.incoming.drain(..self.consumed);
                self.consumed = 0;
                return Ok(None);
            };
            let header = record.header;
            let fragment = record.fragment.to_vec();
            self.consumed += length;
            let Some(reader) = &mut self.reader else {
                if header.content_type == TLSContentType::APPLICATION_DATA && self.skipped(fragment.len()) {
                    continue;
                }
                return Ok(Some((header.content_type, fragment)));
            };
            // A ChangeCipherSpec is never protected (RFC 9846 §5).
            if header.content_type == TLSContentType::CHANGE_CIPHER_SPEC {
                return Ok(Some((header.content_type, fragment)));
            }
            match reader.open(&header, &fragment) {
                // A protected ChangeCipherSpec is `unexpected_message` (RFC 9846 §5).
                Ok((TLSContentType::CHANGE_CIPHER_SPEC, _)) => return Err(TLSError::unexpected()),
                Ok((content_type, plaintext)) => {
                    self.skippable = 0;
                    if plaintext.len() > self.own_limit {
                        return Err(TLSError::Protocol(TLSAlertDescription::RECORD_OVERFLOW));
                    }
                    return Ok(Some((content_type, plaintext)));
                }
                Err(TLSError::Protocol(TLSAlertDescription::BAD_RECORD_MAC)) if self.skipped(fragment.len()) => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Counts a record or message that is dropped without effect: a
    /// warning alert, a ChangeCipherSpec, a HelloRequest. More than
    /// `maximum_ignored` of them without application data between is
    /// `unexpected_message`, so that a peer cannot keep a connection busy
    /// with them.
    pub fn ignore(&mut self) -> Result<(), TLSError> {
        self.ignored += 1;
        if self.ignored > self.maximum_ignored {
            return Err(TLSError::unexpected());
        }
        Ok(())
    }

    /// Fails unless no handshake message is partly received: a message
    /// before a key change ends its record (RFC 9846 §5.1:
    /// `unexpected_message`), or, with QUIC, the data of its level (RFC 9001
    /// §4.1.3: PROTOCOL_VIOLATION).
    pub fn check_boundary(&self) -> Result<(), TLSError> {
        match self.handshake.is_empty() {
            true => Ok(()),
            false if self.quic.is_some() => Err(TLSError::Transport),
            false => Err(TLSError::unexpected()),
        }
    }

    /// Writes without protection again, as a second ClientHello after a
    /// HelloRetryRequest is, when early data was being written.
    pub fn unprotect_writing(&mut self) {
        self.writer = None;
        if let Some(quic) = &mut self.quic {
            quic.writing = super::TLSEncryptionLevel::Initial;
        }
    }

    /// The bytes to send, taken.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outgoing)
    }
}
