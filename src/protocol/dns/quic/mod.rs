//! DNS: `quic` — DNS over dedicated QUIC connections (RFC 9250): the ALPN
//! "doq" on port 853, one query and its responses (one, or the messages of
//! a zone transfer) on each bidirectional stream the client opens, each
//! message after its 2-byte length and each half of the stream ended after
//! its messages (§4.2), the ID 0 (§4.2.1), no edns-tcp-keepalive
//! (§5.5.2), and the errors of §4.3.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::fmt;

use crate::protocol::quic::{QUICConnection, QUICError, QUICEvent, QUICRole, QUICStreamID};
use crate::runtime::Instant;

use super::tcp::DNSTCPFramer;
use super::{DNSError, DNSMessage, DNSOptionCode, DNSType};

/// An application error of DNS over QUIC (RFC 9250 §4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DNSQUICErrorCode(pub u64);

impl DNSQUICErrorCode {
    pub const NO_ERROR: DNSQUICErrorCode = DNSQUICErrorCode(0x0);
    pub const INTERNAL_ERROR: DNSQUICErrorCode = DNSQUICErrorCode(0x1);
    pub const PROTOCOL_ERROR: DNSQUICErrorCode = DNSQUICErrorCode(0x2);
    pub const REQUEST_CANCELLED: DNSQUICErrorCode = DNSQUICErrorCode(0x3);
    pub const EXCESSIVE_LOAD: DNSQUICErrorCode = DNSQUICErrorCode(0x4);
    pub const UNSPECIFIED_ERROR: DNSQUICErrorCode = DNSQUICErrorCode(0x5);
    /// The code of §8.4, which an implementation uses to test that unknown codes are taken as UNSPECIFIED_ERROR.
    pub const ERROR_RESERVED: DNSQUICErrorCode = DNSQUICErrorCode(0xd098ea5e);
}

/// An error of DNS over QUIC: of DNS, of QUIC, or a breach of RFC 9250,
/// after which the connection is closed with PROTOCOL_ERROR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DNSQUICError {
    DNS(DNSError),
    QUIC(QUICError),
    Protocol(&'static str),
}

impl fmt::Display for DNSQUICError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DNSQUICError::DNS(error) => write!(formatter, "{error}"),
            DNSQUICError::QUIC(error) => write!(formatter, "{error:?}"),
            DNSQUICError::Protocol(reason) => write!(formatter, "a breach of DNS over QUIC: {reason}"),
        }
    }
}

impl core::error::Error for DNSQUICError {}

impl From<DNSError> for DNSQUICError {
    fn from(error: DNSError) -> DNSQUICError {
        DNSQUICError::DNS(error)
    }
}

impl From<QUICError> for DNSQUICError {
    fn from(error: QUICError) -> DNSQUICError {
        DNSQUICError::QUIC(error)
    }
}

/// What a DNS over QUIC connection tells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DNSQUICEvent {
    /// A server's query, whole, on `stream`.
    Query { stream: QUICStreamID, message: Vec<u8> },
    /// A client's response to the query of `stream`: one, or for a zone
    /// transfer each of its messages in order, the last when the stream ends.
    Response { stream: QUICStreamID, message: DNSMessage },
    /// The peer reset `stream`, or asked to stop it, with `error`: the
    /// query is not answered (an unknown error is UNSPECIFIED_ERROR, §4.3).
    Cancelled { stream: QUICStreamID, error: DNSQUICErrorCode },
    /// An event of QUIC itself (the connection's, not a stream's).
    QUIC(QUICEvent),
}

/// A stream of a query: the messages received on it, and what is to be sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DNSQUICStream {
    pub framer: DNSTCPFramer,
    /// The messages received (a client's responses; a server's query).
    pub received: usize,
    /// For a client: its query is a zone transfer, which may have many
    /// responses (§4.2); any other has one.
    pub transfer: bool,
    /// The bytes the stream has not yet taken, and whether it ends after them.
    pub pending: Vec<u8>,
    pub finish: bool,
    /// The stream ended this way (the receiving half) and that (the sending half).
    pub received_end: bool,
    pub sent_end: bool,
}

/// The DNS of a QUIC connection, of either end (RFC 9250 §4.2): it takes
/// the connection's events, and makes and reads its streams. What a stream
/// does not take at once is kept and sent as it can take more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DNSQUICConnection {
    pub role: QUICRole,
    pub streams: BTreeMap<QUICStreamID, DNSQUICStream>,
    pub events: VecDeque<DNSQUICEvent>,
}

impl DNSQUICConnection {
    /// The ALPN of DNS over QUIC (RFC 9250 §4.1.1).
    pub const ALPN: &'static [u8] = b"doq";
    /// The port of DNS over QUIC (RFC 9250 §4.1.1).
    pub const PORT: u16 = 853;

    pub fn new(role: QUICRole) -> DNSQUICConnection {
        DNSQUICConnection { role, streams: BTreeMap::new(), events: VecDeque::new() }
    }

    /// Sends `query` on a new stream, with the ID 0 and without
    /// edns-tcp-keepalive, the stream ended after it; the stream of its response.
    pub fn send_query(&mut self, quic: &mut QUICConnection, query: &DNSMessage) -> Result<QUICStreamID, DNSQUICError> {
        if self.role != QUICRole::Client {
            return Err(DNSQUICError::DNS(DNSError::State));
        }
        let mut query = query.clone();
        query.header.id = 0;
        if let Some(edns) = &mut query.edns {
            edns.options.retain(|option| option.code != DNSOptionCode::TCP_KEEPALIVE);
        }
        let framed = DNSTCPFramer::frame(&query.encode(DNSMessage::MAXIMUM_SIZE)?)?;
        let transfer = query.question().is_some_and(|question| matches!(question.kind, DNSType::AXFR | DNSType::IXFR));
        let stream = quic.open_stream(true)?;
        self.streams
            .insert(stream, DNSQUICStream { transfer, pending: framed, finish: true, ..DNSQUICStream::default() });
        self.flush(quic, stream)?;
        Ok(stream)
    }

    /// Sends `responses`, all the server's responses to the query of
    /// `stream` (one, or the messages of a zone transfer), the stream ended after them.
    pub fn send_response(
        &mut self,
        quic: &mut QUICConnection,
        stream: QUICStreamID,
        responses: &[Vec<u8>],
    ) -> Result<(), DNSQUICError> {
        let found = self.streams.get_mut(&stream);
        let Some(state) = found.filter(|state| self.role == QUICRole::Server && state.received == 1 && !state.finish)
        else {
            return Err(DNSQUICError::DNS(DNSError::State));
        };
        for response in responses {
            state.pending.extend_from_slice(&DNSTCPFramer::frame(response)?);
        }
        state.finish = true;
        self.flush(quic, stream)
    }

    /// Gives `stream` what it can take of its pending bytes, and its end
    /// after the last; forgets the stream once both its halves have ended.
    pub fn flush(&mut self, quic: &mut QUICConnection, stream: QUICStreamID) -> Result<(), DNSQUICError> {
        let Some(state) = self.streams.get_mut(&stream) else { return Ok(()) };
        if state.finish && !state.sent_end {
            let written = quic.stream_send(stream, &state.pending, true)?;
            state.pending.drain(..written);
            state.sent_end = state.pending.is_empty();
        }
        if state.sent_end && state.received_end {
            self.streams.remove(&stream);
        }
        Ok(())
    }

    /// Takes the events of `quic` (see [`DNSQUICEvent`]); a breach of RFC
    /// 9250 closes the connection with PROTOCOL_ERROR (§4.3) and is returned.
    pub fn process(&mut self, quic: &mut QUICConnection, now: Instant) -> Result<(), DNSQUICError> {
        while let Some(event) = quic.poll_event() {
            let result = self.handle(quic, event);
            if let Err(DNSQUICError::Protocol(reason)) = result {
                let _ = quic.close(DNSQUICErrorCode::PROTOCOL_ERROR.0, reason.as_bytes(), now);
                return result;
            }
            result?;
        }
        Ok(())
    }

    pub fn handle(&mut self, quic: &mut QUICConnection, event: QUICEvent) -> Result<(), DNSQUICError> {
        match event {
            QUICEvent::StreamOpened { stream } => {
                // Only the client opens streams, bidirectional ones (§4.2).
                if self.role != QUICRole::Server || stream.initiator() != QUICRole::Client || !stream.is_bidirectional()
                {
                    return Err(DNSQUICError::Protocol("a stream not of a client's query"));
                }
                self.streams.entry(stream).or_default();
                Ok(())
            }
            QUICEvent::StreamReadable { stream } => self.read(quic, stream),
            QUICEvent::StreamWritable { stream } => self.flush(quic, stream),
            // §4.3.3: a server does not ask a client to stop sending a query.
            QUICEvent::StopSending { .. } if self.role == QUICRole::Client => {
                Err(DNSQUICError::Protocol("a STOP_SENDING to a client"))
            }
            QUICEvent::StreamReset { stream, error } | QUICEvent::StopSending { stream, error } => {
                if self.streams.remove(&stream).is_some() || self.role == QUICRole::Server {
                    let known = error <= DNSQUICErrorCode::UNSPECIFIED_ERROR.0;
                    let error = if known { DNSQUICErrorCode(error) } else { DNSQUICErrorCode::UNSPECIFIED_ERROR };
                    if self.role == QUICRole::Server {
                        let _ = quic.stream_reset(stream, DNSQUICErrorCode::REQUEST_CANCELLED.0);
                    }
                    self.events.push_back(DNSQUICEvent::Cancelled { stream, error });
                }
                Ok(())
            }
            other => {
                self.events.push_back(DNSQUICEvent::QUIC(other));
                Ok(())
            }
        }
    }

    /// Reads `stream`: each message after its length, of ID 0 and without
    /// edns-tcp-keepalive (§4.2, §4.2.1, §5.5.2). A server's stream is one
    /// query; a client's one response, or the responses of a zone transfer,
    /// ended with the stream after a whole message (§4.3).
    pub fn read(&mut self, quic: &mut QUICConnection, stream: QUICStreamID) -> Result<(), DNSQUICError> {
        let role = self.role;
        let Some(state) = self.streams.get_mut(&stream) else { return Ok(()) };
        let mut buffer = [0u8; 4096];
        loop {
            let (count, ended) = quic.stream_read(stream, &mut buffer)?;
            state.framer.receive(&buffer[..count]);
            while let Some(message) = state.framer.next_message() {
                let message = message.map_err(|_| DNSQUICError::Protocol("a message that cannot be read"))?;
                let decoded = DNSMessage::decode(&message)
                    .map_err(|_| DNSQUICError::Protocol("a message that cannot be read"))?;
                if decoded.header.id != 0 {
                    return Err(DNSQUICError::Protocol("a message of an ID other than 0"));
                }
                if decoded.edns.as_ref().is_some_and(|edns| edns.option(DNSOptionCode::TCP_KEEPALIVE).is_some()) {
                    return Err(DNSQUICError::Protocol("an edns-tcp-keepalive option"));
                }
                state.received += 1;
                if state.received > 1 && !(role == QUICRole::Client && state.transfer) {
                    return Err(DNSQUICError::Protocol("more messages on a stream than its query has"));
                }
                self.events.push_back(match role {
                    QUICRole::Server => DNSQUICEvent::Query { stream, message },
                    QUICRole::Client => DNSQUICEvent::Response { stream, message: decoded },
                });
            }
            if ended {
                if state.framer.is_partial() || state.received == 0 {
                    return Err(DNSQUICError::Protocol("a stream ended before its message"));
                }
                state.received_end = true;
                return self.flush(quic, stream);
            }
            if count == 0 {
                return Ok(());
            }
        }
    }

    pub fn poll_event(&mut self) -> Option<DNSQUICEvent> {
        self.events.pop_front()
    }
}
