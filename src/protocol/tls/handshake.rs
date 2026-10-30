use alloc::vec::Vec;

use crate::bytes::{Reader, Writer};

use super::{TLSError, TLSVector};

/// The type of a handshake message: `HandshakeType` (RFC 9846 §4, RFC 5246
/// §7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TLSHandshakeType(pub u8);

impl TLSHandshakeType {
    /// TLS 1.2 only; never sent here (renegotiation is refused).
    pub const HELLO_REQUEST: TLSHandshakeType = TLSHandshakeType(0);
    pub const CLIENT_HELLO: TLSHandshakeType = TLSHandshakeType(1);
    pub const SERVER_HELLO: TLSHandshakeType = TLSHandshakeType(2);
    pub const NEW_SESSION_TICKET: TLSHandshakeType = TLSHandshakeType(4);
    pub const END_OF_EARLY_DATA: TLSHandshakeType = TLSHandshakeType(5);
    pub const ENCRYPTED_EXTENSIONS: TLSHandshakeType = TLSHandshakeType(8);
    pub const CERTIFICATE: TLSHandshakeType = TLSHandshakeType(11);
    /// TLS 1.2 only.
    pub const SERVER_KEY_EXCHANGE: TLSHandshakeType = TLSHandshakeType(12);
    pub const CERTIFICATE_REQUEST: TLSHandshakeType = TLSHandshakeType(13);
    /// TLS 1.2 only.
    pub const SERVER_HELLO_DONE: TLSHandshakeType = TLSHandshakeType(14);
    pub const CERTIFICATE_VERIFY: TLSHandshakeType = TLSHandshakeType(15);
    /// TLS 1.2 only.
    pub const CLIENT_KEY_EXCHANGE: TLSHandshakeType = TLSHandshakeType(16);
    pub const FINISHED: TLSHandshakeType = TLSHandshakeType(20);
    /// TLS 1.2 only (RFC 6066 §8).
    pub const CERTIFICATE_STATUS: TLSHandshakeType = TLSHandshakeType(22);
    pub const KEY_UPDATE: TLSHandshakeType = TLSHandshakeType(24);
    /// The synthetic message that replaces ClientHello1 in the transcript
    /// after a HelloRetryRequest (RFC 9846 §4.1); never sent.
    pub const MESSAGE_HASH: TLSHandshakeType = TLSHandshakeType(254);
}

/// A handshake message: its type and its body, without the 4-byte header
/// (RFC 9846 §4).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TLSHandshake {
    pub kind: TLSHandshakeType,
    pub body: Vec<u8>,
}

impl TLSHandshake {
    pub const HEADER_LENGTH: usize = 4;
    /// The largest body the 24-bit length can carry.
    pub const MAXIMUM_LENGTH: usize = (1 << 24) - 1;

    pub fn new(kind: TLSHandshakeType, body: Vec<u8>) -> TLSHandshake {
        TLSHandshake { kind, body }
    }

    /// A message of `kind` whose body `write` writes.
    pub fn with(
        kind: TLSHandshakeType,
        write: impl FnOnce(&mut crate::bytes::Buffer) -> Result<(), TLSError>,
    ) -> Result<TLSHandshake, TLSError> {
        let mut body = crate::bytes::Buffer::new();
        write(&mut body)?;
        Ok(TLSHandshake { kind, body: body.into_vec() })
    }

    /// The type and body length of the message at the start of `bytes`, or
    /// `None` if they do not hold its 4-byte header yet. Fails with
    /// `decode_error` for a body longer than `maximum`.
    pub fn header(bytes: &[u8], maximum: usize) -> Result<Option<(TLSHandshakeType, usize)>, TLSError> {
        let mut reader = Reader::new(bytes);
        let (Ok(kind), Ok(length)) = (reader.read_u8(), reader.read_be_sized::<u32>(3)) else { return Ok(None) };
        if length as usize > maximum {
            return Err(TLSError::decode());
        }
        Ok(Some((TLSHandshakeType(kind), length as usize)))
    }

    /// The message at the start of `bytes` and the bytes it takes, or
    /// `None` if they do not hold a whole message yet. Fails with
    /// `decode_error` for a body longer than `maximum`.
    pub fn decode(bytes: &[u8], maximum: usize) -> Result<Option<(TLSHandshake, usize)>, TLSError> {
        let Some((kind, length)) = TLSHandshake::header(bytes, maximum)? else { return Ok(None) };
        let end = TLSHandshake::HEADER_LENGTH + length;
        Ok(bytes.get(TLSHandshake::HEADER_LENGTH..end).map(|body| (TLSHandshake { kind, body: body.to_vec() }, end)))
    }

    /// Writes the message with its header, as the transcript hashes it.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        out.write_u8(self.kind.0)?;
        TLSVector::write(out, 3, TLSHandshake::MAXIMUM_LENGTH, &self.body)
    }

    /// The message with its header.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TLSError> {
        let mut bytes = crate::bytes::Buffer::new();
        self.encode(&mut bytes)?;
        Ok(bytes.into_vec())
    }
}

/// Joins the fragments of handshake records into messages (RFC 9846
/// §5.1): a message may span records, and a record may hold several
/// messages. Bodies longer than `maximum` are refused with `decode_error`,
/// so that a peer cannot make the connection buffer 16 MiB.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TLSHandshakeReassembler {
    /// The bytes received; those before `start` are taken already.
    pub pending: Vec<u8>,
    pub start: usize,
    pub maximum: usize,
}

impl TLSHandshakeReassembler {
    pub fn new(maximum: usize) -> TLSHandshakeReassembler {
        TLSHandshakeReassembler { pending: Vec::new(), start: 0, maximum }
    }

    /// Adds the fragment of a handshake record. A zero-length fragment is
    /// refused with `unexpected_message` (RFC 9846 §5.1: implementations
    /// MUST NOT send them).
    pub fn push(&mut self, fragment: &[u8]) -> Result<(), TLSError> {
        if fragment.is_empty() {
            return Err(TLSError::unexpected());
        }
        // What was taken goes once per fragment, not once per message.
        self.pending.drain(..self.start);
        self.start = 0;
        self.pending.extend_from_slice(fragment);
        // A length above the maximum fails as soon as the header is whole.
        TLSHandshake::header(&self.pending, self.maximum).map(|_| ())
    }

    /// The next whole message, if any.
    pub fn pop(&mut self) -> Result<Option<TLSHandshake>, TLSError> {
        match TLSHandshake::decode(&self.pending[self.start..], self.maximum)? {
            Some((message, length)) => {
                self.start += length;
                if self.start == self.pending.len() {
                    self.pending.clear();
                    self.start = 0;
                }
                Ok(Some(message))
            }
            None => Ok(None),
        }
    }

    /// Whether no partial message is held: what a key change requires
    /// (RFC 9846 §5.1).
    pub fn is_empty(&self) -> bool {
        self.start == self.pending.len()
    }
}
