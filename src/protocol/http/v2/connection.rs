use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::codec::hpack::{HPACKDecoder, HPACKDecoderConfig, HPACKEncoder, HPACKError, HPACKField};
use crate::protocol::http::{
    HTTPConnection, HTTPContentLength, HTTPError, HTTPEvent, HTTPField, HTTPFields, HTTPMethod, HTTPPriority,
    HTTPPseudoField, HTTPRequest, HTTPReset, HTTPResponse, HTTPRole, HTTPStatus, HTTPStreamID, HTTPVersion,
};
use crate::runtime::Instant;

use super::{H2Config, H2Error, H2ErrorCode, H2Frame, H2FrameHeader, H2FrameType, H2Settings, H2Stream, H2StreamState};

/// The state of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum H2State {
    Open,
    /// GOAWAY went one way or the other: no new stream, those under way finish (RFC 9113 §6.8).
    Closing,
    Closed,
}

/// A field block being received across HEADERS and CONTINUATION frames (RFC 9113 §4.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct H2FieldBlock {
    pub stream: u32,
    pub block: Vec<u8>,
    pub end_stream: bool,
    /// Whether its HEADERS made the stream depend on itself (RFC 9113 §5.3.1).
    pub self_dependent: bool,
}

/// An HTTP/2 connection without I/O (RFC 9113), of a client or a server,
/// over a byte stream: the caller gives it what arrives
/// ([`H2Connection::receive`]), sends what [`H2Connection::transmit`]
/// writes, closes the transport once [`H2Connection::wants_close`] after
/// sending everything, and calls [`H2Connection::expire`] at
/// [`H2Connection::poll_timeout`]. Push is off; priorities are RFC 9218's.
#[derive(Clone, Debug)]
pub struct H2Connection {
    pub role: HTTPRole,
    pub config: H2Config,
    pub state: H2State,
    /// A server: whether the client's preface arrived. Either: whether the peer's first SETTINGS did.
    pub preface_received: bool,
    pub settings_received: bool,
    pub incoming: Vec<u8>,
    /// Frames ready to send, in order: HPACK's blocks go in the order they are coded.
    pub outgoing: Vec<u8>,
    /// This end's settings as sent, and the peer's.
    pub local: H2Settings,
    pub peer: H2Settings,
    /// When this end's SETTINGS went unacknowledged since.
    pub settings_since: Option<Instant>,
    pub encoder: HPACKEncoder,
    pub decoder: HPACKDecoder,
    pub streams: BTreeMap<u32, H2Stream>,
    /// The largest stream identifier the peer opened, and the next this end opens.
    pub highest_peer: u32,
    pub next_local: u32,
    /// The connection's windows: what this end may send, and what the peer may, with what was read since crediting.
    pub send_window: i64,
    pub receive_window: i64,
    pub consumed: u32,
    pub block: Option<H2FieldBlock>,
    pub goaway_received: Option<u32>,
    pub goaway_sent: Option<u32>,
    pub events: VecDeque<HTTPEvent>,
    pub error: Option<HTTPError>,
    /// Acknowledgments owed and not yet written.
    pub pending_control: usize,
    /// The streams the peer reset since `resets_since`.
    pub resets: u32,
    pub resets_since: Instant,
    pub idle_since: Instant,
    /// Priorities of PRIORITY_UPDATE for streams not open yet (RFC 9218 §7.1).
    pub priorities: BTreeMap<u32, HTTPPriority>,
    /// The time of the latest call that gave one, for what a call without one processes.
    pub now: Instant,
}

impl H2Connection {
    /// The client's connection preface (RFC 9113 §3.4).
    pub const PREFACE: &'static [u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    pub fn client(config: H2Config, now: Instant) -> H2Connection {
        H2Connection::new(HTTPRole::Client, config, now)
    }

    pub fn server(config: H2Config, now: Instant) -> H2Connection {
        H2Connection::new(HTTPRole::Server, config, now)
    }

    /// A connection whose preface (RFC 9113 §3.4) is ready to send: the
    /// client's magic, then SETTINGS, then the connection's window.
    pub fn new(role: HTTPRole, config: H2Config, now: Instant) -> H2Connection {
        let local = H2Settings {
            header_table_size: u32::try_from(config.hpack_decoder.maximum_table_size).unwrap_or(u32::MAX),
            enable_push: role == HTTPRole::Server,
            max_concurrent_streams: Some(config.max_concurrent_streams),
            initial_window_size: config.initial_window_size.min(H2Settings::MAXIMUM_WINDOW),
            max_frame_size: config.max_frame_size.clamp(H2Settings::MINIMUM_FRAME_SIZE, H2Settings::MAXIMUM_FRAME_SIZE),
            max_header_list_size: Some(u32::try_from(config.hpack_decoder.maximum_field_list_size).unwrap_or(u32::MAX)),
            enable_connect_protocol: role == HTTPRole::Server && config.enable_connect_protocol,
            no_rfc7540_priorities: true,
        };
        // A larger table is taken at once; a smaller one once acknowledged (RFC 9113 §6.5.3).
        let initial = H2Settings::default().header_table_size as usize;
        let decoder_config = HPACKDecoderConfig {
            maximum_table_size: initial.max(local.header_table_size as usize),
            ..config.hpack_decoder
        };
        let mut outgoing = Vec::new();
        if role == HTTPRole::Client {
            outgoing.extend_from_slice(H2Connection::PREFACE);
        }
        H2Frame::Settings { ack: false, settings: local.changes() }.encode(&mut outgoing);
        let connection_window = config.connection_window.min(H2Settings::MAXIMUM_WINDOW);
        if connection_window > H2Settings::DEFAULT_WINDOW {
            let increment = connection_window - H2Settings::DEFAULT_WINDOW;
            H2Frame::WindowUpdate { stream: 0, increment }.encode(&mut outgoing);
        }
        H2Connection {
            role,
            config,
            state: H2State::Open,
            preface_received: role == HTTPRole::Client,
            settings_received: false,
            incoming: Vec::new(),
            outgoing,
            local,
            peer: H2Settings::default(),
            settings_since: Some(now),
            encoder: HPACKEncoder::new(config.hpack_encoder, initial),
            decoder: HPACKDecoder::new(decoder_config),
            streams: BTreeMap::new(),
            highest_peer: 0,
            next_local: if role == HTTPRole::Client { 1 } else { 2 },
            send_window: i64::from(H2Settings::DEFAULT_WINDOW),
            receive_window: i64::from(connection_window.max(H2Settings::DEFAULT_WINDOW)),
            consumed: 0,
            block: None,
            goaway_received: None,
            goaway_sent: None,
            events: VecDeque::new(),
            error: None,
            pending_control: 0,
            resets: 0,
            resets_since: now,
            idle_since: now,
            priorities: BTreeMap::new(),
            now,
        }
    }

    // ---- Receiving ----

    /// Takes bytes that arrived at `now`.
    pub fn receive(&mut self, bytes: &[u8], now: Instant) {
        if self.state == H2State::Closed {
            return;
        }
        self.now = now;
        self.incoming.extend_from_slice(bytes);
        match self.process(now) {
            Ok(()) => {}
            Err(H2Error::Connection { code, reason }) => self.fail(code, reason),
            // Stream errors are handled where they happen.
            Err(H2Error::Stream { stream, code, .. }) => self.reset_stream(stream, code),
        }
        if self.streams.is_empty() {
            self.idle_since = now;
        }
    }

    /// The peer closed the transport: streams under way end with an error.
    pub fn receive_close(&mut self) {
        if self.state == H2State::Closed {
            return;
        }
        let error = if self.streams.is_empty() && self.state == H2State::Closing {
            None
        } else {
            Some(HTTPError::Malformed("the connection closed with streams under way"))
        };
        self.state = H2State::Closed;
        self.streams.clear();
        self.error = error;
        self.push_event(HTTPEvent::Closed { error });
    }

    pub fn process(&mut self, now: Instant) -> Result<(), H2Error> {
        if !self.preface_received {
            let length = self.incoming.len().min(H2Connection::PREFACE.len());
            if self.incoming[..length] != H2Connection::PREFACE[..length] {
                return Err(H2Error::protocol("an invalid connection preface"));
            }
            if length < H2Connection::PREFACE.len() {
                return Ok(());
            }
            self.incoming.drain(..length);
            self.preface_received = true;
        }
        let mut offset = 0;
        let result = loop {
            // Nothing more is read while the application has events to take.
            if self.events.len() >= self.config.http.maximum_events {
                break Ok(());
            }
            let Some(header) = H2FrameHeader::decode(&self.incoming[offset..]) else { break Ok(()) };
            if header.length > self.local.max_frame_size {
                break Err(H2Error::frame_size("a frame larger than SETTINGS_MAX_FRAME_SIZE"));
            }
            let end = offset + H2FrameHeader::LENGTH + header.length as usize;
            if self.incoming.len() < end {
                break Ok(());
            }
            let payload = self.incoming[offset + H2FrameHeader::LENGTH..end].to_vec();
            offset = end;
            if let Err(error) = self.receive_frame(&header, &payload, now) {
                match error {
                    H2Error::Stream { stream, code, .. } => self.reset_stream(stream, code),
                    connection => break Err(connection),
                }
            }
            if self.state == H2State::Closed {
                break Ok(());
            }
        };
        self.incoming.drain(..offset.min(self.incoming.len()));
        result
    }

    /// One frame (RFC 9113 §4.3, §6).
    pub fn receive_frame(&mut self, header: &H2FrameHeader, payload: &[u8], now: Instant) -> Result<(), H2Error> {
        // The peer's preface ends with SETTINGS (RFC 9113 §3.4).
        if !self.settings_received {
            if header.frame_type != H2FrameType::SETTINGS || header.flags & super::H2Flags::ACK != 0 {
                return Err(H2Error::protocol("a preface without SETTINGS first"));
            }
            self.settings_received = true;
        }
        // Nothing comes between the frames of a field block (RFC 9113 §6.10).
        if let Some(block) = &self.block
            && (header.frame_type != H2FrameType::CONTINUATION || header.stream != block.stream)
        {
            return Err(H2Error::protocol("a frame inside a field block"));
        }
        match H2Frame::decode(header, payload)? {
            H2Frame::Data { stream, data, end_stream, length } => self.receive_data(stream, data, end_stream, length),
            H2Frame::Headers { stream, block, end_stream, end_headers, priority } => {
                let self_dependent = priority.is_some_and(|priority| priority.dependency == stream);
                self.start_block(
                    H2FieldBlock { stream, block: block.to_vec(), end_stream, self_dependent },
                    end_headers,
                    now,
                )
            }
            H2Frame::Continuation { stream, block, end_headers } => {
                let Some(assembly) = &mut self.block else {
                    return Err(H2Error::protocol("CONTINUATION without a field block"));
                };
                assembly.block.extend_from_slice(block);
                if assembly.block.len() > self.config.maximum_field_block {
                    return Err(H2Error::connection(H2ErrorCode::ENHANCE_YOUR_CALM, "a field block too large"));
                }
                if end_headers {
                    let assembly = self.block.take().unwrap_or(H2FieldBlock {
                        stream,
                        block: Vec::new(),
                        end_stream: false,
                        self_dependent: false,
                    });
                    self.receive_block(&assembly, now)?;
                }
                Ok(())
            }
            // RFC 7540's priorities are not used (RFC 9113 §5.3.2), but a
            // stream that depends on itself is an error (§5.3.1).
            H2Frame::Priority { stream, priority } if priority.dependency == stream => {
                Err(H2Error::stream(stream, H2ErrorCode::PROTOCOL_ERROR, "a stream that depends on itself"))
            }
            H2Frame::Priority { .. } => Ok(()),
            H2Frame::ResetStream { stream, code } => self.receive_reset(stream, code, now),
            H2Frame::Settings { ack, settings } => self.receive_settings(ack, &settings),
            H2Frame::PushPromise { .. } => Err(H2Error::protocol("PUSH_PROMISE with push off")),
            H2Frame::Ping { ack, data } => {
                if !ack {
                    self.control()?;
                    H2Frame::Ping { ack: true, data }.encode(&mut self.outgoing);
                }
                Ok(())
            }
            H2Frame::GoAway { last, code, .. } => {
                self.receive_goaway(last, code);
                Ok(())
            }
            H2Frame::WindowUpdate { stream, increment } => self.receive_window_update(stream, increment),
            H2Frame::PriorityUpdate { prioritized, value } => self.receive_priority_update(prioritized, value),
            H2Frame::Unknown { .. } => Ok(()),
        }
    }

    /// Whether `stream` is of the peer's identifiers.
    pub fn is_peer_stream(&self, stream: u32) -> bool {
        (stream % 2 == 1) == (self.role == HTTPRole::Server)
    }

    /// Whether `stream` was never opened: an idle stream (RFC 9113 §5.1).
    pub fn is_idle(&self, stream: u32) -> bool {
        if self.is_peer_stream(stream) { stream > self.highest_peer } else { stream >= self.next_local }
    }

    /// One more acknowledgment owed: within the limit (RFC 9113 §10.5).
    pub fn control(&mut self) -> Result<(), H2Error> {
        self.pending_control += 1;
        if self.pending_control > self.config.maximum_pending_control {
            return Err(H2Error::connection(H2ErrorCode::ENHANCE_YOUR_CALM, "too many frames to acknowledge"));
        }
        Ok(())
    }

    /// The first frame of a field block: whole with END_HEADERS, else
    /// kept for its CONTINUATION frames.
    pub fn start_block(&mut self, block: H2FieldBlock, end_headers: bool, now: Instant) -> Result<(), H2Error> {
        if block.block.len() > self.config.maximum_field_block {
            return Err(H2Error::connection(H2ErrorCode::ENHANCE_YOUR_CALM, "a field block too large"));
        }
        if end_headers {
            return self.receive_block(&block, now);
        }
        self.block = Some(block);
        Ok(())
    }

    /// A whole field block of HEADERS (RFC 9113 §8.1): the head of a
    /// request or response, or trailers.
    pub fn receive_block(&mut self, assembly: &H2FieldBlock, _now: Instant) -> Result<(), H2Error> {
        let (stream, end_stream) = (assembly.stream, assembly.end_stream);
        // Decoded first, whatever happens to the stream, to keep HPACK in step (RFC 9113 §4.3).
        let (fields, too_large) = match self.decoder.decode(&assembly.block) {
            Ok(fields) => (fields, false),
            Err(HPACKError::FieldListTooLarge) => (Vec::new(), true),
            Err(_) => {
                return Err(H2Error::connection(H2ErrorCode::COMPRESSION_ERROR, "a field block that does not decode"));
            }
        };
        if assembly.self_dependent {
            if self.is_peer_stream(stream) && stream > self.highest_peer {
                self.highest_peer = stream;
            }
            return Err(H2Error::stream(stream, H2ErrorCode::PROTOCOL_ERROR, "a stream that depends on itself"));
        }
        if !self.is_peer_stream(stream) || self.role == HTTPRole::Client {
            return self.receive_response_block(stream, fields, end_stream, too_large);
        }
        if let Some(existing) = self.streams.get(&stream) {
            if !existing.can_receive() {
                return Err(H2Error::stream(stream, H2ErrorCode::STREAM_CLOSED, "HEADERS after END_STREAM"));
            }
            return self.receive_trailers(stream, fields, end_stream, too_large);
        }
        if stream <= self.highest_peer {
            // A closed stream: discarded (RFC 9113 §5.1).
            return Ok(());
        }
        self.highest_peer = stream;
        if self.goaway_sent.is_some_and(|last| stream > last) {
            return Ok(());
        }
        let open = self.streams.keys().filter(|id| self.is_peer_stream(**id)).count();
        if open >= self.local.max_concurrent_streams.unwrap_or(u32::MAX) as usize {
            return Err(H2Error::stream(stream, H2ErrorCode::REFUSED_STREAM, "more streams than allowed"));
        }
        let mut entry = H2Stream::new(stream, HTTPMethod::GET, self.peer.initial_window_size, self.receive_initial());
        if let Some(priority) = self.priorities.remove(&stream) {
            entry.priority = priority;
        }
        if too_large {
            // 431, then the stream ends (RFC 6585 §5, RFC 9113 §8.2.3).
            self.streams.insert(stream, entry);
            let response = HTTPResponse::new(HTTPStatus::REQUEST_HEADER_FIELDS_TOO_LARGE);
            self.write_head(stream, &H2Connection::hpack_of(HTTPPseudoField::response_lines(&response)), true);
            if let Some(entry) = self.streams.get_mut(&stream) {
                entry.close_local();
                entry.sent_head = true;
            }
            return Err(H2Error::stream(stream, H2ErrorCode::NO_ERROR, "a field section too large"));
        }
        let request = HTTPPseudoField::request(H2Connection::lines_of(fields), self.local.enable_connect_protocol)
            .map_err(|reason| H2Error::stream(stream, H2ErrorCode::PROTOCOL_ERROR, reason))?;
        entry.method = request.method.clone();
        entry.received_head = true;
        entry.content_length = request
            .fields
            .content_length()
            .map_err(|_| H2Error::stream(stream, H2ErrorCode::PROTOCOL_ERROR, "an invalid Content-Length"))?;
        if let Some(priority) = request.fields.get(b"priority") {
            entry.priority = HTTPPriority::parse(priority);
        }
        if end_stream {
            if entry.content_length.is_some_and(|length| length != 0) {
                return Err(H2Error::stream(
                    stream,
                    H2ErrorCode::PROTOCOL_ERROR,
                    "content shorter than Content-Length",
                ));
            }
            entry.close_remote();
        }
        self.streams.insert(stream, entry);
        self.push_event(HTTPEvent::Request { stream: HTTPStreamID(u64::from(stream)), request, end: end_stream });
        Ok(())
    }

    /// A client's field block on its stream: interim and final responses, then trailers.
    pub fn receive_response_block(
        &mut self,
        stream: u32,
        fields: Vec<HPACKField>,
        end_stream: bool,
        too_large: bool,
    ) -> Result<(), H2Error> {
        let Some(entry) = self.streams.get_mut(&stream) else {
            return if self.is_idle(stream) || self.role == HTTPRole::Server {
                Err(H2Error::protocol("HEADERS on a stream never opened"))
            } else {
                Ok(())
            };
        };
        if !entry.can_receive() {
            return Err(H2Error::stream(stream, H2ErrorCode::STREAM_CLOSED, "HEADERS after END_STREAM"));
        }
        if entry.received_head {
            return self.receive_trailers(stream, fields, end_stream, too_large);
        }
        if too_large {
            return Err(H2Error::stream(stream, H2ErrorCode::CANCEL, "a response's fields too large"));
        }
        let malformed = |reason| H2Error::stream(stream, H2ErrorCode::PROTOCOL_ERROR, reason);
        let response = HTTPPseudoField::response(H2Connection::lines_of(fields)).map_err(malformed)?;
        let status = response.status;
        let id = HTTPStreamID(u64::from(stream));
        // RFC 9113 §8.1: interim responses (not 101, §8.6) without END_STREAM, then the final one.
        if status.is_informational() {
            if end_stream || status == HTTPStatus::SWITCHING_PROTOCOLS {
                return Err(malformed("an interim response that ends its stream, or 101"));
            }
            self.push_event(HTTPEvent::Response { stream: id, response, end: false });
            return Ok(());
        }
        entry.received_head = true;
        entry.no_content = entry.method == HTTPMethod::HEAD || status.has_no_content();
        entry.content_length = response.fields.content_length().map_err(|_| malformed("an invalid Content-Length"))?;
        if end_stream {
            if !entry.no_content && entry.content_length.is_some_and(|length| length != 0) {
                return Err(malformed("content shorter than Content-Length"));
            }
            entry.close_remote();
        }
        self.push_event(HTTPEvent::Response { stream: id, response, end: end_stream });
        self.collect(stream);
        Ok(())
    }

    /// Trailers: a field block that ends the stream, without pseudo-header fields (RFC 9113 §8.1).
    pub fn receive_trailers(
        &mut self,
        stream: u32,
        fields: Vec<HPACKField>,
        end_stream: bool,
        too_large: bool,
    ) -> Result<(), H2Error> {
        let malformed = |reason| H2Error::stream(stream, H2ErrorCode::PROTOCOL_ERROR, reason);
        if !end_stream {
            return Err(malformed("a second field block that does not end the stream"));
        }
        if too_large {
            return Err(H2Error::stream(stream, H2ErrorCode::CANCEL, "trailers too large"));
        }
        let trailers = HTTPPseudoField::fields(H2Connection::lines_of(fields), false).map_err(malformed)?;
        let entry = self.streams.get_mut(&stream).ok_or(malformed("trailers of no stream"))?;
        if entry.content_length.is_some_and(|length| length != entry.content_received) && !entry.no_content {
            return Err(malformed("content of another length than Content-Length"));
        }
        entry.close_remote();
        let id = HTTPStreamID(u64::from(stream));
        if !trailers.is_empty() {
            self.push_event(HTTPEvent::Trailers { stream: id, fields: trailers });
        }
        self.push_event(HTTPEvent::End { stream: id });
        self.collect(stream);
        Ok(())
    }

    /// A DATA frame (RFC 9113 §6.1, §6.9): counted against both windows,
    /// whatever its stream's state.
    pub fn receive_data(&mut self, stream: u32, data: &[u8], end_stream: bool, length: u32) -> Result<(), H2Error> {
        if i64::from(length) > self.receive_window {
            return Err(H2Error::connection(H2ErrorCode::FLOW_CONTROL_ERROR, "DATA past the connection's window"));
        }
        self.receive_window -= i64::from(length);
        let Some(entry) = self.streams.get_mut(&stream) else {
            if self.is_idle(stream) {
                return Err(H2Error::protocol("DATA on a stream never opened"));
            }
            // A closed stream: its data is credited back at once.
            self.credit_connection(length);
            return Ok(());
        };
        if !entry.can_receive() {
            self.credit_connection(length);
            return Err(H2Error::stream(stream, H2ErrorCode::STREAM_CLOSED, "DATA after END_STREAM"));
        }
        if i64::from(length) > entry.receive_window {
            self.credit_connection(length);
            return Err(H2Error::stream(stream, H2ErrorCode::FLOW_CONTROL_ERROR, "DATA past the stream's window"));
        }
        entry.receive_window -= i64::from(length);
        let received = entry.content_received + data.len() as u64;
        let invalid = if !entry.received_head {
            Some("DATA before HEADERS")
        } else if entry.no_content && !data.is_empty() {
            Some("content where there is none")
        } else if entry.content_length.is_some_and(|expected| received > expected) {
            Some("content longer than Content-Length")
        } else if end_stream && !entry.no_content && entry.content_length.is_some_and(|expected| expected != received) {
            Some("content shorter than Content-Length")
        } else {
            None
        };
        if let Some(reason) = invalid {
            // None of it is kept: the connection's window gets it all back.
            self.credit_connection(length);
            return Err(H2Error::stream(stream, H2ErrorCode::PROTOCOL_ERROR, reason));
        }
        entry.content_received = received;
        // Padding, and content dropped, are credited back at once: the application never reads them.
        let kept = if entry.discard { 0 } else { data.len() };
        let was_empty = entry.received.is_empty();
        entry.received.extend(&data[..kept]);
        let credited = length - kept as u32;
        entry.consumed += credited;
        let id = HTTPStreamID(u64::from(stream));
        if end_stream {
            entry.close_remote();
        }
        self.credit_connection(credited);
        if was_empty && kept > 0 {
            self.push_event(HTTPEvent::Data { stream: id });
        }
        if end_stream {
            self.push_event(HTTPEvent::End { stream: id });
            self.collect(stream);
        }
        Ok(())
    }

    /// Credits `length` bytes back to the peer's connection window, by
    /// WINDOW_UPDATE once half of it was used (RFC 9113 §6.9).
    pub fn credit_connection(&mut self, length: u32) {
        self.consumed = self.consumed.saturating_add(length);
        let window = self.config.connection_window.clamp(H2Settings::DEFAULT_WINDOW, H2Settings::MAXIMUM_WINDOW);
        if self.consumed >= window / 2 && self.state != H2State::Closed {
            H2Frame::WindowUpdate { stream: 0, increment: self.consumed }.encode(&mut self.outgoing);
            self.receive_window += i64::from(self.consumed);
            self.consumed = 0;
        }
    }

    /// RST_STREAM (RFC 9113 §6.4); a peer that resets too many streams
    /// too fast is closed with ENHANCE_YOUR_CALM.
    pub fn receive_reset(&mut self, stream: u32, code: H2ErrorCode, now: Instant) -> Result<(), H2Error> {
        if self.is_idle(stream) {
            return Err(H2Error::protocol("RST_STREAM on a stream never opened"));
        }
        if now.saturating_duration_since(self.resets_since) > self.config.reset_window {
            self.resets = 0;
            self.resets_since = now;
        }
        self.resets += 1;
        if self.resets > self.config.maximum_resets {
            return Err(H2Error::connection(H2ErrorCode::ENHANCE_YOUR_CALM, "too many streams reset"));
        }
        let id = HTTPStreamID(u64::from(stream));
        // A response that arrived whole stays for the application: NO_ERROR
        // only stops the request's upload (RFC 9113 §8.1).
        if let Some(entry) = self.streams.get_mut(&stream)
            && code == H2ErrorCode::NO_ERROR
            && self.role == HTTPRole::Client
            && !entry.can_receive()
        {
            entry.outgoing.clear();
            entry.end_pending = false;
            entry.trailers = None;
            entry.state = H2StreamState::Closed;
            self.push_event(HTTPEvent::Reset { stream: id, code: 0 });
            self.collect(stream);
            return Ok(());
        }
        if let Some(entry) = self.streams.remove(&stream) {
            let unread = entry.received.len() as u32;
            self.credit_connection(unread);
            self.push_event(HTTPEvent::Reset { stream: id, code: u64::from(code.0) });
        }
        Ok(())
    }

    /// SETTINGS (RFC 9113 §6.5): applied in order and acknowledged.
    pub fn receive_settings(&mut self, ack: bool, settings: &[(super::H2SettingID, u32)]) -> Result<(), H2Error> {
        if ack {
            // This end's settings hold now: a smaller table among them (RFC
            // 7541 §4.2), and a stream window below the initial one, which
            // the streams opened before had (RFC 9113 §6.9.2).
            let before = self.receive_initial();
            self.settings_since = None;
            self.decoder.set_limit(self.local.header_table_size as usize);
            let delta = i64::from(self.receive_initial()) - i64::from(before);
            for entry in self.streams.values_mut() {
                entry.receive_window += delta;
            }
            return Ok(());
        }
        for (id, value) in settings {
            let window = self.peer.initial_window_size;
            self.peer.apply(*id, *value)?;
            match *id {
                super::H2SettingID::ENABLE_PUSH if self.role == HTTPRole::Client && self.peer.enable_push => {
                    return Err(H2Error::protocol("a server that enables push"));
                }
                super::H2SettingID::HEADER_TABLE_SIZE => self.encoder.set_limit(*value as usize),
                super::H2SettingID::INITIAL_WINDOW_SIZE => {
                    // The change applies to every stream's window (RFC 9113 §6.9.2).
                    let delta = i64::from(self.peer.initial_window_size) - i64::from(window);
                    for entry in self.streams.values_mut() {
                        entry.send_window += delta;
                        if entry.send_window > i64::from(H2Settings::MAXIMUM_WINDOW) {
                            return Err(H2Error::connection(
                                H2ErrorCode::FLOW_CONTROL_ERROR,
                                "a window above 2^31 - 1",
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        self.control()?;
        H2Frame::Settings { ack: true, settings: Vec::new() }.encode(&mut self.outgoing);
        Ok(())
    }

    /// GOAWAY (RFC 9113 §6.8): this end's streams above `last` were not processed.
    pub fn receive_goaway(&mut self, last: u32, code: H2ErrorCode) {
        self.goaway_received = Some(self.goaway_received.map_or(last, |earlier| earlier.min(last)));
        if self.state == H2State::Open {
            self.state = H2State::Closing;
        }
        let unprocessed: Vec<u32> =
            self.streams.keys().copied().filter(|id| !self.is_peer_stream(*id) && *id > last).collect();
        for stream in unprocessed {
            self.streams.remove(&stream);
        }
        if code != H2ErrorCode::NO_ERROR {
            self.error = Some(HTTPError::Protocol { code: u64::from(code.0), reason: "the peer closed with an error" });
        }
        self.push_event(HTTPEvent::GoAway { last: HTTPStreamID(u64::from(last)) });
    }

    /// WINDOW_UPDATE (RFC 9113 §6.9): no window past 2^31 - 1.
    pub fn receive_window_update(&mut self, stream: u32, increment: u32) -> Result<(), H2Error> {
        let maximum = i64::from(H2Settings::MAXIMUM_WINDOW);
        if stream == 0 {
            self.send_window += i64::from(increment);
            if self.send_window > maximum {
                return Err(H2Error::connection(H2ErrorCode::FLOW_CONTROL_ERROR, "a connection window above 2^31 - 1"));
            }
            return Ok(());
        }
        if self.is_idle(stream) {
            return Err(H2Error::protocol("WINDOW_UPDATE on a stream never opened"));
        }
        if let Some(entry) = self.streams.get_mut(&stream) {
            entry.send_window += i64::from(increment);
            if entry.send_window > maximum {
                return Err(H2Error::stream(stream, H2ErrorCode::FLOW_CONTROL_ERROR, "a stream window above 2^31 - 1"));
            }
        }
        Ok(())
    }

    /// PRIORITY_UPDATE (RFC 9218 §7.1): sent by clients, for request streams.
    pub fn receive_priority_update(&mut self, prioritized: u32, value: &[u8]) -> Result<(), H2Error> {
        if self.role == HTTPRole::Client || !self.is_peer_stream(prioritized) {
            return Err(H2Error::protocol("PRIORITY_UPDATE not of a client's request stream"));
        }
        let priority = HTTPPriority::parse(value);
        if let Some(entry) = self.streams.get_mut(&prioritized) {
            entry.priority = priority;
        } else if prioritized > self.highest_peer
            && self.priorities.len() < self.local.max_concurrent_streams.unwrap_or(100) as usize
        {
            self.priorities.insert(prioritized, priority);
        }
        Ok(())
    }

    // ---- Messages and their fields ----

    /// The field lines of HPACK as HTTP's, for [`HTTPPseudoField`].
    pub fn lines_of(fields: Vec<HPACKField>) -> Vec<HTTPField> {
        fields
            .into_iter()
            .map(|field| HTTPField { name: field.name, value: field.value, sensitive: field.sensitive })
            .collect()
    }

    /// HTTP's field lines as HPACK's.
    pub fn hpack_of(lines: Vec<HTTPField>) -> Vec<HPACKField> {
        lines
            .into_iter()
            .map(|line| HPACKField { name: line.name, value: line.value, sensitive: line.sensitive })
            .collect()
    }

    /// Codes `fields` and writes HEADERS and CONTINUATION frames of the peer's frame size (RFC 9113 §4.3, §6.2, §6.10).
    pub fn write_head(&mut self, stream: u32, fields: &[HPACKField], end_stream: bool) {
        let mut block = Vec::new();
        self.encoder.encode(fields, &mut block);
        let size = self.peer.max_frame_size as usize;
        let mut chunks = block.chunks(size);
        let first = chunks.next().unwrap_or_default();
        let rest: Vec<&[u8]> = chunks.collect();
        H2Frame::Headers { stream, block: first, end_stream, end_headers: rest.is_empty(), priority: None }
            .encode(&mut self.outgoing);
        for (index, chunk) in rest.iter().enumerate() {
            H2Frame::Continuation { stream, block: chunk, end_headers: index + 1 == rest.len() }
                .encode(&mut self.outgoing);
        }
    }

    // ---- Sending ----

    /// Writes what is ready into `out` (appended): control frames and
    /// heads first, then DATA within the windows, the most urgent streams
    /// first and those of one urgency in turn (RFC 9218 §10).
    pub fn transmit(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.outgoing);
        self.pending_control = 0;
        if self.state == H2State::Closed {
            return;
        }
        for urgency in 0..=HTTPPriority::LOWEST_URGENCY {
            loop {
                let ready: Vec<u32> = self
                    .streams
                    .values()
                    .filter(|entry| {
                        entry.priority.urgency.min(HTTPPriority::LOWEST_URGENCY) == urgency && entry.has_output()
                    })
                    .map(|entry| entry.id)
                    .collect();
                let mut progress = false;
                for stream in ready {
                    progress |= self.write_data(stream);
                }
                if !progress {
                    break;
                }
            }
        }
        out.append(&mut self.outgoing);
        let limit = self.config.http.maximum_buffered_content;
        let writable: Vec<u32> = self
            .streams
            .values_mut()
            .filter(|entry| entry.blocked && entry.outgoing.len() < limit)
            .map(|entry| {
                entry.blocked = false;
                entry.id
            })
            .collect();
        for stream in writable {
            self.push_event(HTTPEvent::Writable { stream: HTTPStreamID(u64::from(stream)) });
        }
        let done: Vec<u32> = self.streams.keys().copied().collect();
        for stream in done {
            self.collect(stream);
        }
        self.finish();
    }

    /// One DATA frame of `stream`, or its end (an empty DATA or trailers);
    /// returns whether something was written.
    pub fn write_data(&mut self, stream: u32) -> bool {
        let frame_size = self.peer.max_frame_size as usize;
        let connection_window = self.send_window.max(0) as usize;
        let Some(entry) = self.streams.get_mut(&stream) else { return false };
        let length = entry.outgoing.len().min(entry.send_window.max(0) as usize).min(connection_window).min(frame_size);
        if length == 0 && !entry.outgoing.is_empty() {
            return false;
        }
        let data: Vec<u8> = entry.outgoing.drain(..length).collect();
        entry.send_window -= length as i64;
        let finished = entry.outgoing.is_empty() && entry.end_pending;
        if finished && let Some(trailers) = entry.trailers.take() {
            if !data.is_empty() {
                H2Frame::Data { stream, data: &data, end_stream: false, length: length as u32 }
                    .encode(&mut self.outgoing);
            }
            entry.end_pending = false;
            entry.close_local();
            self.send_window -= length as i64;
            let fields = H2Connection::hpack_of(trailers.fields);
            self.write_head(stream, &fields, true);
            return true;
        }
        if finished {
            entry.end_pending = false;
            entry.close_local();
        }
        self.send_window -= length as i64;
        H2Frame::Data { stream, data: &data, end_stream: finished, length: length as u32 }.encode(&mut self.outgoing);
        true
    }

    /// Forgets `stream` once it is over and read. Once a server's
    /// response is whole, the rest of the request is not delivered: the
    /// client is asked to stop with RST_STREAM of NO_ERROR (RFC 9113 §8.1).
    /// A CONNECT's tunnel is excepted: each way ends on its own.
    pub fn collect(&mut self, stream: u32) {
        let server = self.role == HTTPRole::Server;
        if let Some(entry) = self.streams.get_mut(&stream)
            && server
            && entry.sent_head
            && !entry.can_send()
            && entry.outgoing.is_empty()
            && entry.method != HTTPMethod::CONNECT
        {
            let unread = entry.received.len() as u32;
            entry.received.clear();
            entry.discard = true;
            let open = entry.can_receive();
            self.credit_connection(unread);
            if open {
                H2Frame::ResetStream { stream, code: H2ErrorCode::NO_ERROR }.encode(&mut self.outgoing);
                self.streams.remove(&stream);
            }
        }
        if self.streams.get(&stream).is_some_and(H2Stream::is_done) {
            self.streams.remove(&stream);
        }
        self.finish();
    }

    /// The window of a stream the peer opens: this end's setting once
    /// acknowledged, the initial one before if larger, since the peer may
    /// send that much before it sees the setting (RFC 9113 §6.9.2).
    pub fn receive_initial(&self) -> u32 {
        if self.settings_since.is_none() {
            self.local.initial_window_size
        } else {
            self.local.initial_window_size.max(H2Settings::DEFAULT_WINDOW)
        }
    }

    /// A connection that goes away closes once its streams are over and
    /// everything was written (RFC 9113 §6.8).
    pub fn finish(&mut self) {
        let goaway = self.goaway_sent.is_some() || self.goaway_received.is_some();
        if self.state == H2State::Closing && self.streams.is_empty() && goaway && self.outgoing.is_empty() {
            self.state = H2State::Closed;
            self.push_event(HTTPEvent::Closed { error: self.error });
        }
    }

    /// Resets `stream` with `code` (RFC 9113 §6.4): unread content is credited back.
    pub fn reset_stream(&mut self, stream: u32, code: H2ErrorCode) {
        if self.state == H2State::Closed {
            return;
        }
        H2Frame::ResetStream { stream, code }.encode(&mut self.outgoing);
        if let Some(entry) = self.streams.remove(&stream) {
            let unread = entry.received.len() as u32;
            self.credit_connection(unread);
            if entry.received_head || !self.is_peer_stream(stream) {
                self.push_event(HTTPEvent::Reset { stream: HTTPStreamID(u64::from(stream)), code: u64::from(code.0) });
            }
        }
    }

    /// Ends the connection with GOAWAY of `code` (RFC 9113 §5.4.1).
    pub fn fail(&mut self, code: H2ErrorCode, reason: &'static str) {
        if self.state == H2State::Closed {
            return;
        }
        H2Frame::GoAway { last: self.highest_peer, code, debug: reason.as_bytes() }.encode(&mut self.outgoing);
        self.goaway_sent = Some(self.highest_peer);
        self.state = H2State::Closed;
        self.streams.clear();
        let error = HTTPError::Protocol { code: u64::from(code.0), reason };
        self.error = Some(error);
        self.push_event(HTTPEvent::Closed { error: Some(error) });
    }

    /// Queues `event`. None is dropped: reading stops once
    /// `maximum_events` wait ([`H2Connection::process`]).
    pub fn push_event(&mut self, event: HTTPEvent) {
        self.events.push_back(event);
    }

    /// Whether the caller should read more from the transport: the events
    /// for the application are within their limit, and what arrived is
    /// read (a frame at most waits for its end).
    pub fn wants_receive(&self) -> bool {
        self.state != H2State::Closed
            && self.events.len() < self.config.http.maximum_events
            && self.incoming.len() <= H2FrameHeader::LENGTH + self.local.max_frame_size as usize
    }

    /// Processes what waits, once the application took events.
    pub fn resume(&mut self) {
        if self.incoming.is_empty() || self.state == H2State::Closed {
            return;
        }
        match self.process(self.now) {
            Ok(()) => {}
            Err(H2Error::Connection { code, reason }) => self.fail(code, reason),
            Err(H2Error::Stream { stream, code, .. }) => self.reset_stream(stream, code),
        }
    }

    /// Whether the caller should close the transport once it sent what
    /// [`H2Connection::transmit`] wrote.
    pub fn wants_close(&self) -> bool {
        self.state == H2State::Closed && self.outgoing.is_empty()
    }

    /// When [`H2Connection::expire`] is due: SETTINGS not acknowledged in
    /// time, or a connection idle too long.
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.state == H2State::Closed {
            return None;
        }
        let settings = self.settings_since.zip(self.config.settings_timeout).map(|(since, timeout)| since + timeout);
        let idle = self
            .streams
            .is_empty()
            .then_some(())
            .and(self.config.idle_timeout)
            .map(|timeout| self.idle_since + timeout);
        [settings, idle].into_iter().flatten().min()
    }

    /// The timers due at `now`: SETTINGS_TIMEOUT (RFC 9113 §6.5.3), or a
    /// GOAWAY of NO_ERROR for a connection idle too long (§9.1).
    pub fn expire(&mut self, now: Instant) {
        self.now = now;
        if self.poll_timeout().is_none_or(|deadline| deadline > now) {
            return;
        }
        if self.settings_since.zip(self.config.settings_timeout).is_some_and(|(since, timeout)| since + timeout <= now)
        {
            self.fail(H2ErrorCode::SETTINGS_TIMEOUT, "SETTINGS not acknowledged");
            return;
        }
        self.fail(H2ErrorCode::NO_ERROR, "idle");
        self.error = None;
        if let Some(HTTPEvent::Closed { error }) = self.events.back_mut() {
            *error = None;
        }
    }

    /// The stream of `id`, as a stream identifier of HTTP/2.
    pub fn stream_of(id: HTTPStreamID) -> Result<u32, HTTPError> {
        u32::try_from(id.0).ok().filter(|stream| *stream <= H2Settings::MAXIMUM_WINDOW).ok_or(HTTPError::State)
    }

    /// Sends PING with `data` (RFC 9113 §6.7), as keep-alive or to measure the round trip.
    pub fn ping(&mut self, data: [u8; 8]) {
        if self.state != H2State::Closed {
            H2Frame::Ping { ack: false, data }.encode(&mut self.outgoing);
        }
    }
}

impl HTTPConnection for H2Connection {
    fn version(&self) -> HTTPVersion {
        HTTPVersion::HTTP2
    }

    fn role(&self) -> HTTPRole {
        self.role
    }

    /// Opens a stream with `request` (RFC 9113 §8.3.1): within the peer's
    /// limit of streams, an extended CONNECT only if the peer allows it.
    fn send_request(&mut self, request: &HTTPRequest, end: bool) -> Result<HTTPStreamID, HTTPError> {
        if self.role != HTTPRole::Client || self.state != H2State::Open {
            return Err(HTTPError::State);
        }
        HTTPPseudoField::check_request(request)?;
        if request.protocol.is_some() && !self.peer.enable_connect_protocol {
            return Err(HTTPError::Malformed("an extended CONNECT the server does not allow"));
        }
        let open = self.streams.keys().filter(|id| !self.is_peer_stream(**id)).count();
        if open >= self.peer.max_concurrent_streams.unwrap_or(u32::MAX) as usize
            || self.next_local > H2Settings::MAXIMUM_WINDOW
        {
            return Err(HTTPError::State);
        }
        let stream = self.next_local;
        self.next_local += 2;
        let mut entry =
            H2Stream::new(stream, request.method.clone(), self.peer.initial_window_size, self.receive_initial());
        entry.sent_head = true;
        entry.sent = HTTPContentLength::new(request.fields.content_length()?, false);
        entry.sent.check(0, end).map_err(HTTPError::Malformed)?;
        if let Some(priority) = request.fields.get(b"priority") {
            entry.priority = HTTPPriority::parse(priority);
        }
        if end {
            entry.close_local();
        }
        self.streams.insert(stream, entry);
        let fields = H2Connection::hpack_of(HTTPPseudoField::request_lines(request));
        self.write_head(stream, &fields, end);
        Ok(HTTPStreamID(u64::from(stream)))
    }

    fn send_response(&mut self, stream: HTTPStreamID, response: &HTTPResponse, end: bool) -> Result<(), HTTPError> {
        let id = H2Connection::stream_of(stream)?;
        if self.role != HTTPRole::Server || self.state == H2State::Closed {
            return Err(HTTPError::State);
        }
        // No 101 in HTTP/2 (RFC 9113 §8.6).
        if response.status == HTTPStatus::SWITCHING_PROTOCOLS {
            return Err(HTTPError::Malformed("101 in HTTP/2"));
        }
        HTTPPseudoField::check(&response.fields)?;
        let entry = self.streams.get_mut(&id).ok_or(HTTPError::State)?;
        if entry.sent_head || !entry.can_send() {
            return Err(HTTPError::State);
        }
        let informational = response.status.is_informational();
        if !informational {
            let none = entry.method == HTTPMethod::HEAD || response.status.has_no_content();
            entry.sent = HTTPContentLength::new(response.fields.content_length()?, none);
            entry.sent.check(0, end).map_err(HTTPError::Malformed)?;
            entry.sent_head = true;
            if end {
                entry.close_local();
            }
        }
        let fields = H2Connection::hpack_of(HTTPPseudoField::response_lines(response));
        self.write_head(id, &fields, end && !informational);
        self.collect(id);
        Ok(())
    }

    fn send_data(&mut self, stream: HTTPStreamID, data: &[u8], end: bool) -> Result<usize, HTTPError> {
        let id = H2Connection::stream_of(stream)?;
        let limit = self.config.http.maximum_buffered_content;
        let entry = self.streams.get_mut(&id).ok_or(HTTPError::State)?;
        if !entry.sent_head || !entry.can_send() || entry.end_pending {
            return Err(HTTPError::State);
        }
        let count = data.len().min(limit.saturating_sub(entry.outgoing.len()));
        entry.sent.check(count as u64, end && count == data.len()).map_err(HTTPError::Malformed)?;
        entry.sent.add(count as u64);
        entry.outgoing.extend(&data[..count]);
        if end && count == data.len() {
            entry.end_pending = true;
        }
        if count < data.len() {
            entry.blocked = true;
        }
        Ok(count)
    }

    fn send_trailers(&mut self, stream: HTTPStreamID, trailers: &HTTPFields) -> Result<(), HTTPError> {
        let id = H2Connection::stream_of(stream)?;
        HTTPPseudoField::check(trailers)?;
        let entry = self.streams.get_mut(&id).ok_or(HTTPError::State)?;
        if !entry.sent_head || !entry.can_send() || entry.end_pending {
            return Err(HTTPError::State);
        }
        entry.sent.check(0, true).map_err(HTTPError::Malformed)?;
        entry.trailers = Some(trailers.clone());
        entry.end_pending = true;
        Ok(())
    }

    /// Reads content, giving the peer credit again once half a window was read (RFC 9113 §6.9).
    fn read_data(&mut self, stream: HTTPStreamID, out: &mut [u8]) -> Result<usize, HTTPError> {
        let id = H2Connection::stream_of(stream)?;
        let window = self.local.initial_window_size;
        let Some(entry) = self.streams.get_mut(&id) else {
            return if self.is_idle(id) { Err(HTTPError::State) } else { Ok(0) };
        };
        let count = out.len().min(entry.received.len());
        for (slot, byte) in out.iter_mut().zip(entry.received.drain(..count)) {
            *slot = byte;
        }
        entry.consumed += count as u32;
        if entry.can_receive() && entry.consumed >= window / 2 {
            let increment = entry.consumed;
            entry.receive_window += i64::from(increment);
            entry.consumed = 0;
            H2Frame::WindowUpdate { stream: id, increment }.encode(&mut self.outgoing);
        }
        self.credit_connection(count as u32);
        self.collect(id);
        Ok(count)
    }

    fn reset(&mut self, stream: HTTPStreamID, reason: HTTPReset) -> Result<(), HTTPError> {
        let id = H2Connection::stream_of(stream)?;
        if !self.streams.contains_key(&id) {
            // A stream over and forgotten needs no reset.
            return if self.is_idle(id) { Err(HTTPError::State) } else { Ok(()) };
        }
        let code = match reason {
            HTTPReset::Cancel => H2ErrorCode::CANCEL,
            HTTPReset::Refused => H2ErrorCode::REFUSED_STREAM,
            HTTPReset::Internal => H2ErrorCode::INTERNAL_ERROR,
            HTTPReset::NoError => H2ErrorCode::NO_ERROR,
        };
        // A server's NO_ERROR waits for its response to be whole (RFC 9113
        // §8.1): the request's content is dropped meanwhile.
        if code == H2ErrorCode::NO_ERROR && self.role == HTTPRole::Server {
            if let Some(entry) = self.streams.get_mut(&id) {
                let unread = entry.received.len() as u32;
                entry.received.clear();
                entry.discard = true;
                self.credit_connection(unread);
            }
            self.collect(id);
            return Ok(());
        }
        // The application knows of it: no event of its own reset.
        if let Some(entry) = self.streams.remove(&id) {
            H2Frame::ResetStream { stream: id, code }.encode(&mut self.outgoing);
            let unread = entry.received.len() as u32;
            self.credit_connection(unread);
        }
        Ok(())
    }

    fn poll_event(&mut self) -> Option<HTTPEvent> {
        let event = self.events.pop_front();
        if self.events.len() < self.config.http.maximum_events {
            self.resume();
        }
        event
    }

    /// GOAWAY of NO_ERROR (RFC 9113 §6.8): the streams under way finish,
    /// then the connection closes.
    fn shutdown(&mut self) {
        if self.state != H2State::Open {
            return;
        }
        H2Frame::GoAway { last: self.highest_peer, code: H2ErrorCode::NO_ERROR, debug: &[] }.encode(&mut self.outgoing);
        self.goaway_sent = Some(self.highest_peer);
        self.state = H2State::Closing;
        if self.streams.is_empty() {
            self.state = H2State::Closed;
            self.push_event(HTTPEvent::Closed { error: None });
        }
    }

    fn is_closed(&self) -> bool {
        self.state == H2State::Closed
    }
}
