use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec;
use alloc::vec::Vec;

use crate::bytes::Reader;
use crate::codec::hpack::HPACKField;
use crate::codec::qpack::{QPACKDecoded, QPACKDecoder, QPACKEncoder, QPACKError};
use crate::protocol::http::{
    HTTPConnection, HTTPContentLength, HTTPError, HTTPEvent, HTTPField, HTTPFields, HTTPMethod, HTTPPriority,
    HTTPPseudoField, HTTPRequest, HTTPReset, HTTPResponse, HTTPRole, HTTPStatus, HTTPStreamID, HTTPVersion,
};
use crate::protocol::quic::{
    QUICCloseReason, QUICConnection, QUICEvent, QUICRole, QUICStreamID, QUICStreams, QUICVarint,
};
use crate::runtime::Instant;

use super::{
    H3Config, H3Error, H3ErrorCode, H3FrameHeader, H3FrameType, H3Reading, H3Settings, H3Stream, H3StreamType,
};

/// The state of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum H3State {
    Open,
    /// GOAWAY went one way or the other: no new request, those under way finish (RFC 9114 §5.2).
    Closing,
    Closed,
}

/// A unidirectional stream of the peer (RFC 9114 §6.2): its type once
/// read, and the bytes not yet taken.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct H3Unidirectional {
    pub kind: Option<H3StreamType>,
    pub incoming: Vec<u8>,
    /// The bytes left of a control frame of an unknown type, skipped (RFC 9114 §7.2.8, §9).
    pub skip: u64,
}

/// The HTTP/3 layer of a QUIC connection (RFC 9114), without I/O and
/// without the QUIC connection itself, which its owner (a
/// [`QUICEndpoint`](crate::protocol::quic::QUICEndpoint), say) keeps: an
/// [`H3Session`] binds the two for each use. The caller has QUIC take what
/// arrives, then calls [`H3Session::process`]; it calls
/// [`H3Session::flush`] before QUIC sends. Push is off: a client sends no
/// MAX_PUSH_ID, a server never pushes.
#[derive(Clone, Debug)]
pub struct H3Connection {
    pub role: HTTPRole,
    pub config: H3Config,
    pub state: H3State,
    /// This end's settings, and the peer's once its SETTINGS arrived.
    pub local: H3Settings,
    pub peer: Option<H3Settings>,
    pub encoder: QPACKEncoder,
    pub decoder: QPACKDecoder,
    /// This end's control, QPACK encoder and decoder streams, and the bytes waiting for them.
    pub control: Option<QUICStreamID>,
    pub encoder_stream: Option<QUICStreamID>,
    pub decoder_stream: Option<QUICStreamID>,
    pub outgoing: BTreeMap<QUICStreamID, Vec<u8>>,
    /// The peer's unidirectional streams, and which are its control and QPACK streams.
    pub unidirectional: BTreeMap<QUICStreamID, H3Unidirectional>,
    pub peer_control: Option<QUICStreamID>,
    pub peer_encoder: Option<QUICStreamID>,
    pub peer_decoder: Option<QUICStreamID>,
    pub streams: BTreeMap<u64, H3Stream>,
    /// A server: the largest request stream opened. Either: the GOAWAY identifiers sent and received.
    pub highest_request: Option<u64>,
    pub goaway_sent: Option<u64>,
    pub goaway_received: Option<u64>,
    pub events: VecDeque<HTTPEvent>,
    /// The QUIC connection's events that are not HTTP/3's: Connected, NewToken, and the like.
    pub quic_events: VecDeque<QUICEvent>,
    pub now: Instant,
    pub error: Option<HTTPError>,
    /// The largest MAX_PUSH_ID a client sent, which may only grow (RFC 9114 §7.2.7).
    pub max_push_id: Option<u64>,
    /// Whether reading stopped while `maximum_events` waited: the next
    /// [`H3Session::poll_event`] goes on with it.
    pub paused: bool,
}

impl H3Connection {
    pub fn client(config: H3Config, now: Instant) -> H3Connection {
        H3Connection::new(HTTPRole::Client, config, now)
    }

    pub fn server(config: H3Config, now: Instant) -> H3Connection {
        H3Connection::new(HTTPRole::Server, config, now)
    }

    pub fn new(role: HTTPRole, config: H3Config, now: Instant) -> H3Connection {
        let local = H3Settings {
            qpack_max_table_capacity: config.qpack_decoder.maximum_table_capacity as u64,
            max_field_section_size: Some(config.qpack_decoder.maximum_field_list_size as u64),
            qpack_blocked_streams: config.qpack_decoder.blocked_streams as u64,
            enable_connect_protocol: role == HTTPRole::Server && config.enable_connect_protocol,
        };
        H3Connection {
            role,
            config,
            state: H3State::Open,
            local,
            peer: None,
            encoder: QPACKEncoder::new(config.qpack_encoder),
            decoder: QPACKDecoder::new(config.qpack_decoder),
            control: None,
            encoder_stream: None,
            decoder_stream: None,
            outgoing: BTreeMap::new(),
            unidirectional: BTreeMap::new(),
            peer_control: None,
            peer_encoder: None,
            peer_decoder: None,
            streams: BTreeMap::new(),
            highest_request: None,
            goaway_sent: None,
            goaway_received: None,
            events: VecDeque::new(),
            quic_events: VecDeque::new(),
            now,
            error: None,
            max_push_id: None,
            paused: false,
        }
    }

    /// The fields of QPACK as HTTP's, and back.
    pub fn lines_of(fields: Vec<HPACKField>) -> Vec<HTTPField> {
        fields
            .into_iter()
            .map(|field| HTTPField { name: field.name, value: field.value, sensitive: field.sensitive })
            .collect()
    }

    pub fn qpack_of(lines: Vec<HTTPField>) -> Vec<HPACKField> {
        lines
            .into_iter()
            .map(|line| HPACKField { name: line.name, value: line.value, sensitive: line.sensitive })
            .collect()
    }

    /// Queues `event`. None is dropped: reading stops once
    /// `maximum_events` wait ([`H3Session::handle_events`]).
    pub fn push_event(&mut self, event: HTTPEvent) {
        self.events.push_back(event);
    }

    /// Whether events wait up to their limit.
    pub fn is_full(&self) -> bool {
        self.events.len() >= self.config.http.maximum_events
    }

    /// Whether `stream` is a request stream this end may see: bidirectional, opened by the client (RFC 9114 §6.1).
    pub fn is_request_stream(stream: QUICStreamID) -> bool {
        stream.is_bidirectional() && stream.initiator() == QUICRole::Client
    }
}

/// An [`H3Connection`] bound to its QUIC connection, for one use: it is the
/// [`HTTPConnection`] of HTTP/3.
#[derive(Debug)]
pub struct H3Session<'a> {
    pub connection: &'a mut H3Connection,
    pub quic: &'a mut QUICConnection,
}

impl<'a> H3Session<'a> {
    pub fn new(connection: &'a mut H3Connection, quic: &'a mut QUICConnection) -> H3Session<'a> {
        H3Session { connection, quic }
    }

    /// Handles what the QUIC connection received: its events, the frames
    /// of the streams, the instructions of QPACK. `now` is QUIC's clock.
    pub fn process(&mut self, now: Instant) {
        self.connection.now = now;
        if self.connection.state == H3State::Closed {
            return;
        }
        self.start();
        let result = self.handle_events();
        self.result(result);
        self.flush();
        self.finish();
    }

    /// Opens this end's control and QPACK streams once QUIC allows (RFC
    /// 9114 §6.2.1, RFC 9204 §4.2), the control stream with SETTINGS first.
    pub fn start(&mut self) {
        if self.connection.control.is_some() {
            return;
        }
        let (Ok(control), Ok(encoder), Ok(decoder)) =
            (self.quic.open_stream(false), self.quic.open_stream(false), self.quic.open_stream(false))
        else {
            return;
        };
        let mut bytes = vec![H3StreamType::CONTROL.0 as u8];
        let mut settings = Vec::new();
        let grease = self.connection.config.grease.then_some(u64::from(control.0 as u8 % 16));
        self.connection.local.encode(grease, &mut settings);
        H3FrameHeader::write(H3FrameType::SETTINGS, &settings, &mut bytes);
        if let Some(n) = grease {
            // A frame of a reserved type, which the peer ignores (RFC 9114 §7.2.8).
            H3FrameHeader::write(H3FrameType::reserved(n), &[], &mut bytes);
        }
        self.connection.outgoing.insert(control, bytes);
        self.connection.outgoing.insert(encoder, vec![H3StreamType::ENCODER.0 as u8]);
        self.connection.outgoing.insert(decoder, vec![H3StreamType::DECODER.0 as u8]);
        self.connection.control = Some(control);
        self.connection.encoder_stream = Some(encoder);
        self.connection.decoder_stream = Some(decoder);
    }

    /// The QUIC connection's events, while the application's events are
    /// within their limit. An error of one stream resets it and the rest
    /// goes on; an error of the connection ends it.
    pub fn handle_events(&mut self) -> Result<(), H3Error> {
        self.connection.paused = false;
        loop {
            if self.connection.is_full() {
                self.connection.paused = true;
                return Ok(());
            }
            let Some(event) = self.quic.poll_event() else { break };
            match event {
                QUICEvent::StreamOpened { stream } => {
                    if stream.is_bidirectional() && !H3Connection::is_request_stream(stream) {
                        return Err(H3Error::connection(
                            H3ErrorCode::STREAM_CREATION_ERROR,
                            "a bidirectional stream of the server",
                        ));
                    }
                    let result = self.open_request(stream);
                    self.contain(result)?;
                }
                QUICEvent::StreamReadable { stream } => {
                    let result = self.read_stream(stream);
                    self.contain(result)?;
                }
                QUICEvent::StreamWritable { .. } => {}
                QUICEvent::StreamReset { stream, error } => self.stream_reset(stream, error)?,
                QUICEvent::StopSending { stream, error } => self.stop_sending(stream, error)?,
                QUICEvent::Closed { reason } => {
                    let error = match reason {
                        // An unknown code is H3_NO_ERROR (RFC 9114 §8).
                        QUICCloseReason::PeerApplication { error, .. }
                        | QUICCloseReason::LocalApplication { error, .. }
                            if H3ErrorCode::received(error) == H3ErrorCode::NO_ERROR =>
                        {
                            None
                        }
                        QUICCloseReason::PeerApplication { error, .. }
                        | QUICCloseReason::LocalApplication { error, .. } => {
                            Some(HTTPError::Protocol { code: error, reason: "the connection closed with an error" })
                        }
                        _ => Some(HTTPError::Protocol {
                            code: H3ErrorCode::INTERNAL_ERROR.0,
                            reason: "the QUIC connection ended",
                        }),
                    };
                    self.close_locally(error);
                    self.connection.quic_events.push_back(QUICEvent::Closed { reason });
                }
                QUICEvent::ZeroRTTRejected => {
                    // The streams of 0-RTT are gone, these included (RFC 9114 §3.3, RFC 9001 §4.6.2).
                    let lost: Vec<u64> = self.connection.streams.keys().copied().collect();
                    for stream in lost {
                        self.connection.streams.remove(&stream);
                        self.connection.push_event(HTTPEvent::Reset {
                            stream: HTTPStreamID(stream),
                            code: H3ErrorCode::REQUEST_REJECTED.0,
                        });
                    }
                    self.connection.control = None;
                    self.connection.encoder_stream = None;
                    self.connection.decoder_stream = None;
                    self.connection.outgoing.clear();
                    self.connection.encoder = QPACKEncoder::new(self.connection.config.qpack_encoder);
                    self.connection.quic_events.push_back(QUICEvent::ZeroRTTRejected);
                    self.start();
                }
                other => self.connection.quic_events.push_back(other),
            }
        }
        // Request streams paused while their content waited for the application.
        let paused: Vec<u64> = self.connection.streams.keys().copied().collect();
        for stream in paused {
            let result = self.read_stream(QUICStreamID(stream));
            self.contain(result)?;
        }
        Ok(())
    }

    /// The error of the connection in `result`, if any: an error of one
    /// stream resets that stream here.
    pub fn contain(&mut self, result: Result<(), H3Error>) -> Result<(), H3Error> {
        match result {
            Err(H3Error::Stream { stream, code, .. }) => {
                self.reset_stream(stream, code);
                Ok(())
            }
            other => other,
        }
    }

    /// A request stream the client opened (RFC 9114 §4.1, §6.1): QUIC
    /// opens them in order, so each is taken once, whatever order their
    /// bytes come in. Those after this end's GOAWAY are refused (§5.2).
    pub fn open_request(&mut self, stream: QUICStreamID) -> Result<(), H3Error> {
        let id = stream.0;
        if self.connection.role != HTTPRole::Server || !H3Connection::is_request_stream(stream) {
            return Ok(());
        }
        self.connection.highest_request = Some(self.connection.highest_request.map_or(id, |highest| highest.max(id)));
        if self.connection.goaway_sent.is_some_and(|first| id >= first) {
            return Err(H3Error::stream(id, H3ErrorCode::REQUEST_REJECTED, "a request after GOAWAY"));
        }
        self.connection.streams.entry(id).or_insert_with(|| H3Stream::new(id, HTTPMethod::GET));
        Ok(())
    }

    /// Ends the connection on a connection error (with QUIC's
    /// CONNECTION_CLOSE of its code), or resets a stream on a stream error.
    pub fn result(&mut self, result: Result<(), H3Error>) {
        match result {
            Ok(()) => {}
            Err(H3Error::Stream { stream, code, .. }) => self.reset_stream(stream, code),
            Err(H3Error::Connection { code, reason }) => self.fail(code, reason),
        }
    }

    /// Closes with `code` (RFC 9114 §8).
    pub fn fail(&mut self, code: H3ErrorCode, reason: &'static str) {
        if self.connection.state == H3State::Closed {
            return;
        }
        let _ = self.quic.close(code.0, reason.as_bytes(), self.connection.now);
        self.close_locally(Some(HTTPError::Protocol { code: code.0, reason }));
    }

    pub fn close_locally(&mut self, error: Option<HTTPError>) {
        if self.connection.state == H3State::Closed {
            return;
        }
        self.connection.state = H3State::Closed;
        self.connection.error = error;
        self.connection.streams.clear();
        self.connection.push_event(HTTPEvent::Closed { error });
    }

    /// Reads what `stream` has, as far as its buffers allow.
    pub fn read_stream(&mut self, stream: QUICStreamID) -> Result<(), H3Error> {
        if self.connection.state == H3State::Closed {
            return Ok(());
        }
        if stream.is_bidirectional() {
            return self.read_request_stream(stream);
        }
        if stream.initiator() == self.quic.role {
            return Ok(());
        }
        let mut buffer = [0u8; 4096];
        loop {
            let Ok((count, fin)) = self.quic.stream_read(stream, &mut buffer) else { return Ok(()) };
            if count > 0 {
                let entry = self.connection.unidirectional.entry(stream).or_default();
                entry.incoming.extend_from_slice(&buffer[..count]);
                self.take_unidirectional(stream)?;
            }
            if fin {
                // The control and QPACK streams stay open as long as the connection (RFC 9114 §6.2.1, RFC 9204 §4.2).
                if self.is_critical(stream) {
                    return Err(H3Error::connection(H3ErrorCode::CLOSED_CRITICAL_STREAM, "a critical stream closed"));
                }
                self.connection.unidirectional.remove(&stream);
                return Ok(());
            }
            if count == 0 {
                return Ok(());
            }
        }
    }

    pub fn is_critical(&self, stream: QUICStreamID) -> bool {
        [self.connection.peer_control, self.connection.peer_encoder, self.connection.peer_decoder]
            .contains(&Some(stream))
    }

    /// Takes the bytes of a unidirectional stream of the peer: its type, then its content by type (RFC 9114 §6.2).
    pub fn take_unidirectional(&mut self, stream: QUICStreamID) -> Result<(), H3Error> {
        let Some(entry) = self.connection.unidirectional.get_mut(&stream) else { return Ok(()) };
        if entry.kind.is_none() {
            let mut reader = Reader::new(&entry.incoming);
            let Ok(kind) = QUICVarint::read(&mut reader) else { return Ok(()) };
            let consumed = reader.position();
            entry.incoming.drain(..consumed);
            let kind = H3StreamType(kind);
            entry.kind = Some(kind);
            let creation = |reason| H3Error::connection(H3ErrorCode::STREAM_CREATION_ERROR, reason);
            let slot = match kind {
                H3StreamType::CONTROL => &mut self.connection.peer_control,
                H3StreamType::ENCODER => &mut self.connection.peer_encoder,
                H3StreamType::DECODER => &mut self.connection.peer_decoder,
                H3StreamType::PUSH => {
                    // A client sent no MAX_PUSH_ID; a server takes no push stream (RFC 9114 §4.6, §6.2.2).
                    return Err(match self.connection.role {
                        HTTPRole::Client => H3Error::connection(H3ErrorCode::ID_ERROR, "a push without MAX_PUSH_ID"),
                        HTTPRole::Server => creation("a push stream of a client"),
                    });
                }
                _ => {
                    // An unknown type: not read (RFC 9114 §6.2). QUIC drops
                    // what still arrives on a stream stopped (RFC 9000
                    // §3.5), so the stream is never read again and its
                    // entry can go.
                    let _ = self.quic.stream_stop(stream, H3ErrorCode::STREAM_CREATION_ERROR.0);
                    self.connection.unidirectional.remove(&stream);
                    return Ok(());
                }
            };
            if slot.is_some() {
                return Err(creation("a second control or QPACK stream"));
            }
            *slot = Some(stream);
        }
        let Some(entry) = self.connection.unidirectional.get_mut(&stream) else { return Ok(()) };
        let bytes = core::mem::take(&mut entry.incoming);
        match entry.kind {
            Some(H3StreamType::CONTROL) => {
                let entry = self.connection.unidirectional.get_mut(&stream).map(|entry| &mut entry.incoming);
                if let Some(incoming) = entry {
                    *incoming = bytes;
                }
                self.read_control(stream)
            }
            Some(H3StreamType::ENCODER) => {
                self.connection.decoder.receive_encoder_stream(&bytes).map_err(H3Session::qpack_error)?;
                // Sections that waited for these entries can go on (RFC 9204 §2.1.2).
                let blocked: Vec<u64> = self
                    .connection
                    .streams
                    .values()
                    .filter(|entry| entry.blocked.is_some())
                    .map(|entry| entry.id)
                    .collect();
                for stream in blocked {
                    let result = self.read_request_stream(QUICStreamID(stream));
                    self.contain(result)?;
                }
                Ok(())
            }
            Some(H3StreamType::DECODER) => {
                self.connection.encoder.receive_decoder_stream(&bytes).map_err(H3Session::qpack_error)
            }
            _ => Ok(()),
        }
    }

    /// The connection error of a QPACK error (RFC 9204 §6).
    pub fn qpack_error(error: QPACKError) -> H3Error {
        let code = error.code().unwrap_or(QPACKError::DECOMPRESSION_FAILED);
        H3Error::connection(H3ErrorCode(code), "QPACK failed")
    }

    /// The frames of the peer's control stream (RFC 9114 §6.2.1, §7.2):
    /// SETTINGS first, once. Frames of unknown types are skipped as they
    /// come, whatever their size (§7.2.8, §9); the others are read whole,
    /// within the limit of a field section.
    pub fn read_control(&mut self, stream: QUICStreamID) -> Result<(), H3Error> {
        loop {
            let started = self.connection.peer.is_some();
            let Some(entry) = self.connection.unidirectional.get_mut(&stream) else { return Ok(()) };
            if entry.skip > 0 {
                let take = entry.skip.min(entry.incoming.len() as u64);
                entry.incoming.drain(..take as usize);
                entry.skip -= take;
                if entry.skip > 0 {
                    return Ok(());
                }
                continue;
            }
            let Some((header, length)) = H3FrameHeader::decode(&entry.incoming) else { return Ok(()) };
            if started && header.frame_type.is_unknown() {
                entry.incoming.drain(..length);
                entry.skip = header.length;
                continue;
            }
            if header.length > self.connection.config.http.maximum_field_section_size as u64 {
                return Err(H3Error::connection(H3ErrorCode::EXCESSIVE_LOAD, "a control frame too large"));
            }
            let end = length + header.length as usize;
            if entry.incoming.len() < end {
                return Ok(());
            }
            let payload = entry.incoming[length..end].to_vec();
            entry.incoming.drain(..end);
            self.control_frame(header.frame_type, &payload)?;
        }
    }

    pub fn control_frame(&mut self, frame_type: H3FrameType, payload: &[u8]) -> Result<(), H3Error> {
        let unexpected = |reason| H3Error::connection(H3ErrorCode::FRAME_UNEXPECTED, reason);
        if self.connection.peer.is_none() {
            if frame_type != H3FrameType::SETTINGS {
                return Err(H3Error::connection(
                    H3ErrorCode::MISSING_SETTINGS,
                    "a control stream without SETTINGS first",
                ));
            }
            let settings = H3Settings::decode(payload)?;
            self.connection.encoder.set_peer_settings(
                usize::try_from(settings.qpack_max_table_capacity).unwrap_or(usize::MAX),
                usize::try_from(settings.qpack_blocked_streams).unwrap_or(usize::MAX),
            );
            self.connection.peer = Some(settings);
            return Ok(());
        }
        match frame_type {
            H3FrameType::SETTINGS => Err(unexpected("a second SETTINGS")),
            H3FrameType::DATA | H3FrameType::HEADERS | H3FrameType::PUSH_PROMISE => {
                Err(unexpected("a frame of a request stream on the control stream"))
            }
            frame_type if frame_type.is_http2() => Err(unexpected("a frame of HTTP/2")),
            H3FrameType::GOAWAY => self.receive_goaway(H3FrameHeader::integer(payload)?),
            H3FrameType::MAX_PUSH_ID => {
                if self.connection.role == HTTPRole::Client {
                    return Err(unexpected("MAX_PUSH_ID from a server"));
                }
                // This server never pushes, but the limit may not fall (RFC 9114 §7.2.7).
                let identifier = H3FrameHeader::integer(payload)?;
                if self.connection.max_push_id.is_some_and(|earlier| identifier < earlier) {
                    return Err(H3Error::connection(
                        H3ErrorCode::ID_ERROR,
                        "a MAX_PUSH_ID smaller than the one before",
                    ));
                }
                self.connection.max_push_id = Some(identifier);
                Ok(())
            }
            H3FrameType::CANCEL_PUSH => {
                H3FrameHeader::integer(payload)?;
                // No push was promised or allowed (RFC 9114 §7.2.3).
                Err(H3Error::connection(H3ErrorCode::ID_ERROR, "CANCEL_PUSH of a push that cannot exist"))
            }
            H3FrameType::PRIORITY_UPDATE_REQUEST | H3FrameType::PRIORITY_UPDATE_PUSH => {
                if self.connection.role == HTTPRole::Client {
                    return Err(unexpected("PRIORITY_UPDATE from a server"));
                }
                let mut reader = Reader::new(payload);
                let element = QUICVarint::read(&mut reader)
                    .map_err(|_| H3Error::connection(H3ErrorCode::FRAME_ERROR, "PRIORITY_UPDATE cut short"))?;
                if frame_type == H3FrameType::PRIORITY_UPDATE_PUSH
                    || !H3Connection::is_request_stream(QUICStreamID(element))
                {
                    return Err(H3Error::connection(H3ErrorCode::ID_ERROR, "PRIORITY_UPDATE of no request stream"));
                }
                let _ = HTTPPriority::parse(&payload[reader.position()..]);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// GOAWAY (RFC 9114 §5.2): from a server, the first request stream not
    /// processed; from a client, a push identifier. Never larger than before.
    pub fn receive_goaway(&mut self, identifier: u64) -> Result<(), H3Error> {
        if self.connection.goaway_received.is_some_and(|earlier| identifier > earlier) {
            return Err(H3Error::connection(H3ErrorCode::ID_ERROR, "a GOAWAY larger than the one before"));
        }
        if self.connection.role == HTTPRole::Client && !H3Connection::is_request_stream(QUICStreamID(identifier)) {
            return Err(H3Error::connection(H3ErrorCode::ID_ERROR, "a GOAWAY of no request stream"));
        }
        self.connection.goaway_received = Some(identifier);
        if self.connection.state == H3State::Open {
            self.connection.state = H3State::Closing;
        }
        if self.connection.role == HTTPRole::Client {
            let unprocessed: Vec<u64> =
                self.connection.streams.keys().copied().filter(|stream| *stream >= identifier).collect();
            // Each request the peer did not process is told apart, as rejected:
            // it may be retried (§4.1.1, §5.2). `last` alone cannot say that
            // none was processed when the identifier is 0.
            for stream in unprocessed {
                self.connection.streams.remove(&stream);
                let code = H3ErrorCode::REQUEST_REJECTED.0;
                self.connection.push_event(HTTPEvent::Reset { stream: HTTPStreamID(stream), code });
            }
            let last = identifier.saturating_sub(4);
            self.connection.push_event(HTTPEvent::GoAway { last: HTTPStreamID(last) });
        }
        self.finish();
        Ok(())
    }

    /// Reads a request stream's frames (RFC 9114 §4.1).
    pub fn read_request_stream(&mut self, stream: QUICStreamID) -> Result<(), H3Error> {
        let id = stream.0;
        // Streams are taken when they open (H3Session::open_request); one
        // not kept is over, refused or reset.
        if !self.connection.streams.contains_key(&id) {
            return Ok(());
        }
        let limit = self.connection.config.http.maximum_buffered_content;
        let mut buffer = [0u8; 4096];
        loop {
            let Some(entry) = self.connection.streams.get(&id) else { return Ok(()) };
            if entry.received_fin || entry.received.len() + entry.incoming.len() >= limit {
                break;
            }
            let Ok((count, fin)) = self.quic.stream_read(stream, &mut buffer) else { break };
            let Some(entry) = self.connection.streams.get_mut(&id) else { return Ok(()) };
            entry.incoming.extend_from_slice(&buffer[..count]);
            entry.received_fin |= fin;
            if count == 0 {
                break;
            }
        }
        self.take_frames(id)
    }

    /// The frames that arrived whole on request stream `id`.
    pub fn take_frames(&mut self, id: u64) -> Result<(), H3Error> {
        let unexpected = |reason| H3Error::connection(H3ErrorCode::FRAME_UNEXPECTED, reason);
        loop {
            let Some(entry) = self.connection.streams.get_mut(&id) else { return Ok(()) };
            if entry.discard {
                entry.incoming.clear();
                return Ok(());
            }
            if entry.blocked.is_some() {
                let section = entry.blocked.take().unwrap_or_default();
                if !self.header_section(id, section)? {
                    return Ok(());
                }
                continue;
            }
            match entry.reading {
                H3Reading::Data(left) | H3Reading::Skip(left) => {
                    let take = left.min(entry.incoming.len() as u64) as usize;
                    if take == 0 && left > 0 {
                        break;
                    }
                    let bytes: Vec<u8> = entry.incoming.drain(..take).collect();
                    let left = left - take as u64;
                    let data = matches!(entry.reading, H3Reading::Data(_));
                    entry.reading = match (left, data) {
                        (0, _) => H3Reading::Frame,
                        (left, true) => H3Reading::Data(left),
                        (left, false) => H3Reading::Skip(left),
                    };
                    if data {
                        self.content(id, &bytes)?;
                    }
                }
                H3Reading::Frame => {
                    let Some((header, length)) = H3FrameHeader::decode(&entry.incoming) else { break };
                    match header.frame_type {
                        H3FrameType::DATA => {
                            if !entry.received_head || entry.trailers {
                                return Err(unexpected("DATA out of place"));
                            }
                            entry.incoming.drain(..length);
                            entry.reading = H3Reading::Data(header.length);
                        }
                        H3FrameType::HEADERS => {
                            if header.length
                                > H3Config::maximum_frame(self.connection.config.qpack_decoder.maximum_field_list_size)
                                    as u64
                            {
                                return Err(H3Error::stream(
                                    id,
                                    H3ErrorCode::EXCESSIVE_LOAD,
                                    "a field section too large",
                                ));
                            }
                            let end = length + header.length as usize;
                            if entry.incoming.len() < end {
                                break;
                            }
                            if entry.trailers {
                                return Err(unexpected("HEADERS after trailers"));
                            }
                            let section = entry.incoming[length..end].to_vec();
                            entry.incoming.drain(..end);
                            if !self.header_section(id, section)? {
                                return Ok(());
                            }
                        }
                        H3FrameType::PUSH_PROMISE => {
                            return Err(match self.connection.role {
                                HTTPRole::Client => {
                                    H3Error::connection(H3ErrorCode::ID_ERROR, "PUSH_PROMISE without MAX_PUSH_ID")
                                }
                                HTTPRole::Server => unexpected("PUSH_PROMISE from a client"),
                            });
                        }
                        H3FrameType::SETTINGS
                        | H3FrameType::GOAWAY
                        | H3FrameType::MAX_PUSH_ID
                        | H3FrameType::CANCEL_PUSH => {
                            return Err(unexpected("a frame of the control stream on a request stream"));
                        }
                        frame_type if frame_type.is_http2() => return Err(unexpected("a frame of HTTP/2")),
                        _ => {
                            entry.incoming.drain(..length);
                            entry.reading = H3Reading::Skip(header.length);
                        }
                    }
                }
            }
        }
        self.end_of_stream(id)
    }

    /// The stream's FIN, once every frame before it was taken (RFC 9114 §4.1, §7.1).
    pub fn end_of_stream(&mut self, id: u64) -> Result<(), H3Error> {
        let Some(entry) = self.connection.streams.get_mut(&id) else { return Ok(()) };
        if !entry.received_fin || entry.ended || entry.blocked.is_some() {
            return Ok(());
        }
        if !entry.incoming.is_empty() || entry.reading != H3Reading::Frame {
            return Err(H3Error::connection(H3ErrorCode::FRAME_ERROR, "a frame cut short by the end of its stream"));
        }
        if !entry.received_head {
            return Err(H3Error::stream(id, H3ErrorCode::REQUEST_INCOMPLETE, "a stream that ended without its head"));
        }
        if !entry.no_content && entry.content_length.is_some_and(|length| length != entry.content_received) {
            return Err(H3Error::stream(
                id,
                H3ErrorCode::MESSAGE_ERROR,
                "content of another length than Content-Length",
            ));
        }
        entry.ended = true;
        self.connection.push_event(HTTPEvent::End { stream: HTTPStreamID(id) });
        self.collect(id);
        Ok(())
    }

    /// DATA's payload: the message's content (RFC 9114 §4.1.2).
    pub fn content(&mut self, id: u64, bytes: &[u8]) -> Result<(), H3Error> {
        let Some(entry) = self.connection.streams.get_mut(&id) else { return Ok(()) };
        let malformed = |reason| H3Error::stream(id, H3ErrorCode::MESSAGE_ERROR, reason);
        if entry.no_content && !bytes.is_empty() {
            return Err(malformed("content where there is none"));
        }
        entry.content_received += bytes.len() as u64;
        if entry.content_length.is_some_and(|length| entry.content_received > length) {
            return Err(malformed("content longer than Content-Length"));
        }
        let was_empty = entry.received.is_empty();
        entry.received.extend(bytes);
        if was_empty && !bytes.is_empty() {
            self.connection.push_event(HTTPEvent::Data { stream: HTTPStreamID(id) });
        }
        Ok(())
    }

    /// A HEADERS frame's field section; false if it waits for QPACK's
    /// entries (the stream is then not read further until they come).
    pub fn header_section(&mut self, id: u64, section: Vec<u8>) -> Result<bool, H3Error> {
        let (fields, too_large) = match self.connection.decoder.decode(id, &section) {
            Ok(QPACKDecoded::Blocked) => {
                if let Some(entry) = self.connection.streams.get_mut(&id) {
                    entry.blocked = Some(section);
                }
                return Ok(false);
            }
            Ok(QPACKDecoded::Fields(fields)) => (fields, false),
            Err(QPACKError::FieldListTooLarge) => (Vec::new(), true),
            Err(error) => return Err(H3Session::qpack_error(error)),
        };
        let server = self.connection.role == HTTPRole::Server;
        let malformed = |reason| H3Error::stream(id, H3ErrorCode::MESSAGE_ERROR, reason);
        let Some(entry) = self.connection.streams.get_mut(&id) else { return Ok(true) };
        let stream = HTTPStreamID(id);
        if entry.received_head {
            // Trailers (RFC 9114 §4.1).
            if too_large {
                return Err(H3Error::stream(id, H3ErrorCode::EXCESSIVE_LOAD, "trailers too large"));
            }
            let trailers = HTTPPseudoField::fields(H3Connection::lines_of(fields), false).map_err(malformed)?;
            entry.trailers = true;
            if !trailers.is_empty() {
                self.connection.push_event(HTTPEvent::Trailers { stream, fields: trailers });
            }
            return Ok(true);
        }
        if server {
            if too_large {
                // 431 (RFC 9114 §4.2.2, RFC 6585 §5), and the rest of the request is not read.
                let response = HTTPResponse::new(HTTPStatus::REQUEST_HEADER_FIELDS_TOO_LARGE);
                let section = self
                    .connection
                    .encoder
                    .encode(id, &H3Connection::qpack_of(HTTPPseudoField::response_lines(&response)));
                if let Some(entry) = self.connection.streams.get_mut(&id) {
                    H3FrameHeader::write(H3FrameType::HEADERS, &section, &mut entry.outgoing);
                    entry.fin_pending = true;
                    entry.sent_head = true;
                    entry.ended = true;
                    entry.discard = true;
                    entry.received.clear();
                    entry.incoming.clear();
                }
                let _ = self.quic.stream_stop(QUICStreamID(id), H3ErrorCode::NO_ERROR.0);
                return Ok(false);
            }
            let request =
                HTTPPseudoField::request(H3Connection::lines_of(fields), self.connection.local.enable_connect_protocol)
                    .map_err(malformed)?;
            let entry = self.connection.streams.get_mut(&id).ok_or(malformed("a stream gone"))?;
            entry.method = request.method.clone();
            entry.received_head = true;
            entry.content_length =
                request.fields.content_length().map_err(|_| malformed("an invalid Content-Length"))?;
            let end = entry.received_fin && entry.incoming.is_empty();
            if end {
                if entry.content_length.is_some_and(|length| length != 0) {
                    return Err(malformed("content shorter than Content-Length"));
                }
                entry.ended = true;
            }
            self.connection.push_event(HTTPEvent::Request { stream, request, end });
            return Ok(true);
        }
        if too_large {
            return Err(H3Error::stream(id, H3ErrorCode::EXCESSIVE_LOAD, "a response's fields too large"));
        }
        let response = HTTPPseudoField::response(H3Connection::lines_of(fields)).map_err(malformed)?;
        let status = response.status;
        // Interim responses, not 101 (RFC 9114 §4.5), then the final one.
        if status.is_informational() {
            if status == HTTPStatus::SWITCHING_PROTOCOLS {
                return Err(malformed("101 in HTTP/3"));
            }
            self.connection.push_event(HTTPEvent::Response { stream, response, end: false });
            return Ok(true);
        }
        let entry = self.connection.streams.get_mut(&id).ok_or(malformed("a stream gone"))?;
        entry.received_head = true;
        entry.no_content = entry.method == HTTPMethod::HEAD || status.has_no_content();
        entry.content_length = response.fields.content_length().map_err(|_| malformed("an invalid Content-Length"))?;
        let end = entry.received_fin && entry.incoming.is_empty();
        if end {
            // A client accepts no malformed response (RFC 9114 §4.1.2).
            if !entry.no_content && entry.content_length.is_some_and(|length| length != 0) {
                return Err(malformed("content shorter than Content-Length"));
            }
            entry.ended = true;
        }
        self.connection.push_event(HTTPEvent::Response { stream, response, end });
        Ok(true)
    }

    /// The peer reset its half of a stream: read, so that QUIC knows the
    /// reset was taken and can forget the half (RFC 9000 §3.2).
    pub fn stream_reset(&mut self, stream: QUICStreamID, error: u64) -> Result<(), H3Error> {
        let _ = self.quic.stream_read(stream, &mut []);
        if stream.is_bidirectional() {
            if let Some(entry) = self.connection.streams.remove(&stream.0) {
                self.connection.decoder.cancel_stream(stream.0);
                // The exchange is abandoned: this end's half too, unless it
                // was sent whole, so that QUIC can forget the stream.
                if !entry.sent_end {
                    let _ = self.quic.stream_reset(stream, H3ErrorCode::REQUEST_CANCELLED.0);
                }
                self.connection.push_event(HTTPEvent::Reset { stream: HTTPStreamID(stream.0), code: error });
            }
            return Ok(());
        }
        if self.is_critical(stream) {
            return Err(H3Error::connection(H3ErrorCode::CLOSED_CRITICAL_STREAM, "a critical stream reset"));
        }
        self.connection.unidirectional.remove(&stream);
        Ok(())
    }

    /// The peer asked this end to stop sending: QUIC reset the stream's sending half.
    pub fn stop_sending(&mut self, stream: QUICStreamID, error: u64) -> Result<(), H3Error> {
        if [self.connection.control, self.connection.encoder_stream, self.connection.decoder_stream]
            .contains(&Some(stream))
        {
            return Err(H3Error::connection(H3ErrorCode::CLOSED_CRITICAL_STREAM, "a critical stream stopped"));
        }
        if let Some(entry) = self.connection.streams.get_mut(&stream.0) {
            entry.outgoing.clear();
            entry.fin_pending = false;
            entry.sent_end = true;
            // A server done with the request needs no more of it (RFC 9114
            // §4.1.1); an unknown code is H3_NO_ERROR (§8).
            if H3ErrorCode::received(error) != H3ErrorCode::NO_ERROR {
                self.connection.push_event(HTTPEvent::Reset { stream: HTTPStreamID(stream.0), code: error });
            }
            self.collect(stream.0);
        }
        Ok(())
    }

    /// Resets a request stream both ways with `code`.
    pub fn reset_stream(&mut self, id: u64, code: H3ErrorCode) {
        let stream = QUICStreamID(id);
        let _ = self.quic.stream_reset(stream, code.0);
        let _ = self.quic.stream_stop(stream, code.0);
        self.connection.decoder.cancel_stream(id);
        if let Some(entry) = self.connection.streams.remove(&id)
            && (entry.received_head || self.connection.role == HTTPRole::Client)
        {
            self.connection.push_event(HTTPEvent::Reset { stream: HTTPStreamID(id), code: code.0 });
        }
    }

    /// Forgets `id` once its exchange is over and read. Once a server's
    /// response is whole, the rest of the request is not delivered: the
    /// client is asked to stop with STOP_SENDING of H3_NO_ERROR (RFC 9114
    /// §4.1.1). A CONNECT's tunnel is excepted: each way ends on its own.
    pub fn collect(&mut self, id: u64) {
        if let Some(entry) = self.connection.streams.get_mut(&id)
            && self.connection.role == HTTPRole::Server
            && entry.sent_end
            && entry.method != HTTPMethod::CONNECT
            && !entry.discard
        {
            entry.discard = true;
            entry.received.clear();
            entry.incoming.clear();
            if !entry.ended {
                entry.ended = true;
                let _ = self.quic.stream_stop(QUICStreamID(id), H3ErrorCode::NO_ERROR.0);
            }
        }
        if self.connection.streams.get(&id).is_some_and(H3Stream::is_done) {
            self.connection.streams.remove(&id);
        }
        self.finish();
    }

    /// A connection that goes away closes once its requests are over (RFC
    /// 9114 §5.2) and QUIC delivered what they sent: the request streams'
    /// sending halves are all acknowledged.
    pub fn finish(&mut self) {
        let over = self.connection.state == H3State::Closing
            && self.connection.streams.is_empty()
            && self.connection.goaway_sent.is_some();
        let delivered = self
            .quic
            .streams
            .streams
            .values()
            .filter(|stream| stream.id.is_bidirectional())
            .all(|stream| stream.send.as_ref().is_none_or(crate::protocol::quic::QUICSendStream::is_terminal));
        if over && delivered {
            let _ = self.quic.close(H3ErrorCode::NO_ERROR.0, &[], self.connection.now);
            self.close_locally(None);
        }
    }

    /// Hands QUIC what waits to be written: the control and QPACK
    /// streams' bytes first, then each request stream's.
    pub fn flush(&mut self) {
        if self.connection.state == H3State::Closed {
            return;
        }
        let instructions = self.connection.encoder.take_instructions();
        if let Some(stream) = self.connection.encoder_stream {
            self.connection.outgoing.entry(stream).or_default().extend_from_slice(&instructions);
        }
        let instructions = self.connection.decoder.take_instructions();
        if let Some(stream) = self.connection.decoder_stream {
            self.connection.outgoing.entry(stream).or_default().extend_from_slice(&instructions);
        }
        for (stream, bytes) in self.connection.outgoing.iter_mut() {
            if bytes.is_empty() {
                continue;
            }
            if let Ok(count) = self.quic.stream_send(*stream, bytes, false) {
                bytes.drain(..count);
            }
        }
        let limit = self.connection.config.http.maximum_buffered_content;
        let ids: Vec<u64> = self.connection.streams.keys().copied().collect();
        for id in ids {
            let Some(entry) = self.connection.streams.get_mut(&id) else { continue };
            if !entry.outgoing.is_empty() || entry.fin_pending {
                let fin = entry.fin_pending;
                if let Ok(count) = self.quic.stream_send(QUICStreamID(id), &entry.outgoing, fin) {
                    entry.outgoing.drain(..count);
                    if entry.outgoing.is_empty() && fin {
                        entry.fin_pending = false;
                        entry.sent_end = true;
                    }
                }
            }
            if entry.waiting && entry.outgoing.len() < limit {
                entry.waiting = false;
                self.connection.push_event(HTTPEvent::Writable { stream: HTTPStreamID(id) });
            }
            self.collect(id);
        }
    }

    /// Writes a HEADERS frame of `lines` on stream `id`.
    pub fn write_headers(&mut self, id: u64, lines: Vec<HTTPField>) -> Result<(), HTTPError> {
        let section = self.connection.encoder.encode(id, &H3Connection::qpack_of(lines));
        let entry = self.connection.streams.get_mut(&id).ok_or(HTTPError::State)?;
        H3FrameHeader::write(H3FrameType::HEADERS, &section, &mut entry.outgoing);
        Ok(())
    }

    /// Whether QUIC opened `stream`, of either end, at some time.
    pub fn was_opened(&self, stream: QUICStreamID) -> bool {
        let kind = QUICStreams::kind(stream.is_bidirectional());
        let opened = if stream.initiator() == self.quic.role {
            self.quic.streams.opened[kind]
        } else {
            self.quic.streams.peer_opened[kind]
        };
        stream.index() < opened
    }

    /// The events not of HTTP/3 that the QUIC connection had.
    pub fn poll_quic_event(&mut self) -> Option<QUICEvent> {
        self.connection.quic_events.pop_front()
    }
}

impl HTTPConnection for H3Session<'_> {
    fn version(&self) -> HTTPVersion {
        HTTPVersion::HTTP3
    }

    fn role(&self) -> HTTPRole {
        self.connection.role
    }

    /// Opens a request stream (RFC 9114 §4.1): an extended CONNECT only if the server allows it (RFC 9220 §3).
    fn send_request(&mut self, request: &HTTPRequest, end: bool) -> Result<HTTPStreamID, HTTPError> {
        if self.connection.role != HTTPRole::Client || self.connection.state != H3State::Open {
            return Err(HTTPError::State);
        }
        HTTPPseudoField::check_request(request)?;
        if request.protocol.is_some() && !self.connection.peer.is_some_and(|peer| peer.enable_connect_protocol) {
            return Err(HTTPError::Malformed("an extended CONNECT the server does not allow"));
        }
        self.start();
        let stream = self.quic.open_stream(true).map_err(|_| HTTPError::State)?;
        let mut entry = H3Stream::new(stream.0, request.method.clone());
        entry.sent = HTTPContentLength::new(request.fields.content_length()?, false);
        entry.sent.check(0, end).map_err(HTTPError::Malformed)?;
        entry.sent_head = true;
        entry.fin_pending = end;
        self.connection.streams.insert(stream.0, entry);
        self.write_headers(stream.0, HTTPPseudoField::request_lines(request))?;
        self.flush();
        Ok(HTTPStreamID(stream.0))
    }

    fn send_response(&mut self, stream: HTTPStreamID, response: &HTTPResponse, end: bool) -> Result<(), HTTPError> {
        if self.connection.role != HTTPRole::Server || self.connection.state == H3State::Closed {
            return Err(HTTPError::State);
        }
        if response.status == HTTPStatus::SWITCHING_PROTOCOLS {
            return Err(HTTPError::Malformed("101 in HTTP/3"));
        }
        HTTPPseudoField::check(&response.fields)?;
        let entry = self.connection.streams.get_mut(&stream.0).ok_or(HTTPError::State)?;
        if entry.sent_head || entry.sent_end || entry.fin_pending {
            return Err(HTTPError::State);
        }
        let informational = response.status.is_informational();
        if !informational {
            let none = entry.method == HTTPMethod::HEAD || response.status.has_no_content();
            entry.sent = HTTPContentLength::new(response.fields.content_length()?, none);
            entry.sent.check(0, end).map_err(HTTPError::Malformed)?;
            entry.sent_head = true;
            entry.fin_pending = end;
        }
        self.write_headers(stream.0, HTTPPseudoField::response_lines(response))?;
        self.flush();
        Ok(())
    }

    fn send_data(&mut self, stream: HTTPStreamID, data: &[u8], end: bool) -> Result<usize, HTTPError> {
        let limit = self.connection.config.http.maximum_buffered_content;
        let entry = self.connection.streams.get_mut(&stream.0).ok_or(HTTPError::State)?;
        if !entry.sent_head || entry.sent_end || entry.fin_pending {
            return Err(HTTPError::State);
        }
        let count = data.len().min(limit.saturating_sub(entry.outgoing.len()));
        entry.sent.check(count as u64, end && count == data.len()).map_err(HTTPError::Malformed)?;
        entry.sent.add(count as u64);
        if count > 0 {
            H3FrameHeader::write(H3FrameType::DATA, &data[..count], &mut entry.outgoing);
        }
        if end && count == data.len() {
            entry.fin_pending = true;
        }
        if count < data.len() {
            entry.waiting = true;
        }
        self.flush();
        Ok(count)
    }

    fn send_trailers(&mut self, stream: HTTPStreamID, trailers: &HTTPFields) -> Result<(), HTTPError> {
        HTTPPseudoField::check(trailers)?;
        let entry = self.connection.streams.get(&stream.0).ok_or(HTTPError::State)?;
        if !entry.sent_head || entry.sent_end || entry.fin_pending {
            return Err(HTTPError::State);
        }
        entry.sent.check(0, true).map_err(HTTPError::Malformed)?;
        self.write_headers(stream.0, trailers.fields.clone())?;
        if let Some(entry) = self.connection.streams.get_mut(&stream.0) {
            entry.fin_pending = true;
        }
        self.flush();
        Ok(())
    }

    fn read_data(&mut self, stream: HTTPStreamID, out: &mut [u8]) -> Result<usize, HTTPError> {
        let Some(entry) = self.connection.streams.get_mut(&stream.0) else { return Ok(0) };
        let count = out.len().min(entry.received.len());
        for (slot, byte) in out.iter_mut().zip(entry.received.drain(..count)) {
            *slot = byte;
        }
        // Room again: what QUIC holds for the stream is read on.
        let result = self.read_stream(QUICStreamID(stream.0));
        self.result(result);
        self.collect(stream.0);
        self.flush();
        Ok(count)
    }

    fn reset(&mut self, stream: HTTPStreamID, reason: HTTPReset) -> Result<(), HTTPError> {
        if !self.connection.streams.contains_key(&stream.0) {
            // A stream over and forgotten needs no reset; one never opened is an error.
            return if self.was_opened(QUICStreamID(stream.0)) { Ok(()) } else { Err(HTTPError::State) };
        }
        let code = match reason {
            HTTPReset::Cancel => H3ErrorCode::REQUEST_CANCELLED,
            HTTPReset::Refused => H3ErrorCode::REQUEST_REJECTED,
            HTTPReset::Internal => H3ErrorCode::INTERNAL_ERROR,
            HTTPReset::NoError => {
                // The rest of the request is not needed; the response goes on (RFC 9114 §4.1.1).
                let _ = self.quic.stream_stop(QUICStreamID(stream.0), H3ErrorCode::NO_ERROR.0);
                if let Some(entry) = self.connection.streams.get_mut(&stream.0) {
                    entry.ended = true;
                    entry.received.clear();
                }
                self.collect(stream.0);
                return Ok(());
            }
        };
        let _ = self.quic.stream_reset(QUICStreamID(stream.0), code.0);
        let _ = self.quic.stream_stop(QUICStreamID(stream.0), code.0);
        self.connection.decoder.cancel_stream(stream.0);
        self.connection.streams.remove(&stream.0);
        self.flush();
        Ok(())
    }

    fn poll_event(&mut self) -> Option<HTTPEvent> {
        let event = self.connection.events.pop_front();
        if self.connection.paused && !self.connection.is_full() {
            let now = self.connection.now;
            self.process(now);
        }
        event
    }

    /// GOAWAY (RFC 9114 §5.2): a server's of the first request it does not
    /// process, a client's of push 0; then the connection closes once its
    /// requests are over.
    fn shutdown(&mut self) {
        if self.connection.state != H3State::Open {
            return;
        }
        self.start();
        let identifier = match self.connection.role {
            HTTPRole::Server => self.connection.highest_request.map_or(0, |highest| highest + 4),
            HTTPRole::Client => 0,
        };
        let mut payload = Vec::new();
        let _ = QUICVarint::write(&mut payload, identifier);
        if let Some(control) = self.connection.control {
            H3FrameHeader::write(H3FrameType::GOAWAY, &payload, self.connection.outgoing.entry(control).or_default());
        }
        self.connection.goaway_sent = Some(identifier);
        self.connection.state = H3State::Closing;
        self.flush();
        self.finish();
    }

    fn is_closed(&self) -> bool {
        self.connection.state == H3State::Closed
    }
}
