use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use crate::crypto::random::Random;

use super::{
    WebSocketCloseCode, WebSocketConfig, WebSocketDeflate, WebSocketDeflateParameters, WebSocketFrameHeader,
    WebSocketOpcode,
};

/// Which end of a connection this is: a client masks what it sends, a
/// server must not (RFC 6455 §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WebSocketRole {
    Client,
    Server,
}

/// The state of a connection (RFC 6455 §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WebSocketState {
    Open,
    /// This end sent Close and waits for the peer's.
    Closing,
    Closed,
}

/// What a connection tells its application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebSocketEvent {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    /// The connection closed: with the peer's code and reason, or this
    /// end's on an error, or 1006 if the transport ended first (§7.1.5).
    Closed {
        code: WebSocketCloseCode,
        reason: String,
    },
}

/// A message being received in fragments (RFC 6455 §5.4).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WebSocketFragments {
    pub opcode: WebSocketOpcode,
    pub payload: Vec<u8>,
    pub compressed: bool,
    /// The bytes of a text message checked as UTF-8 so far, uncompressed ones.
    pub validated: usize,
}

/// A WebSocket connection without I/O (RFC 6455 §5 to §7), after its
/// opening handshake, over a byte stream: messages in, messages out,
/// permessage-deflate (RFC 7692) if negotiated. The caller gives it what
/// arrives ([`WebSocketConnection::receive`]), sends what
/// [`WebSocketConnection::transmit`] writes, and closes the transport once
/// [`WebSocketConnection::wants_close`].
pub struct WebSocketConnection {
    pub role: WebSocketRole,
    pub config: WebSocketConfig,
    pub state: WebSocketState,
    pub incoming: Vec<u8>,
    pub outgoing: Vec<u8>,
    /// The source of a client's masking keys (§5.3).
    pub random: Box<dyn Random + Send>,
    pub fragments: Option<WebSocketFragments>,
    pub deflate: Option<WebSocketDeflate>,
    pub events: VecDeque<WebSocketEvent>,
    pub close_received: bool,
}

impl core::fmt::Debug for WebSocketConnection {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("WebSocketConnection").field("role", &self.role).field("state", &self.state).finish()
    }
}

impl WebSocketConnection {
    /// A connection of `role`, with permessage-deflate of `deflate` if the
    /// handshake negotiated it.
    pub fn new(
        role: WebSocketRole,
        config: WebSocketConfig,
        deflate: Option<WebSocketDeflateParameters>,
        random: Box<dyn Random + Send>,
    ) -> Result<WebSocketConnection, &'static str> {
        let deflate = deflate
            .map(|parameters| WebSocketDeflate::new(parameters, role == WebSocketRole::Client, config.deflate_level))
            .transpose()?;
        Ok(WebSocketConnection {
            role,
            config,
            state: WebSocketState::Open,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            random,
            fragments: None,
            deflate,
            events: VecDeque::new(),
            close_received: false,
        })
    }

    // ---- Receiving ----

    /// Takes bytes that arrived.
    pub fn receive(&mut self, bytes: &[u8]) {
        if self.state == WebSocketState::Closed {
            return;
        }
        self.incoming.extend_from_slice(bytes);
        let mut offset = 0;
        // Nothing more is read while the application has events to take.
        while self.events.len() < self.config.maximum_events {
            match self.receive_frame(offset) {
                Ok(Some(length)) => offset += length,
                Ok(None) => break,
                Err((code, reason)) => {
                    self.fail(code, reason);
                    break;
                }
            }
            if self.state == WebSocketState::Closed {
                break;
            }
        }
        self.incoming.drain(..offset.min(self.incoming.len()));
    }

    /// The transport ended: without a Close, that is 1006 (RFC 6455 §7.1.5).
    pub fn receive_close(&mut self) {
        if self.state != WebSocketState::Closed {
            self.state = WebSocketState::Closed;
            self.push_event(WebSocketEvent::Closed { code: WebSocketCloseCode::ABNORMAL, reason: String::new() });
        }
    }

    /// One frame at `offset` of the input; its length, or `None` while it is not whole.
    pub fn receive_frame(&mut self, offset: usize) -> Result<Option<usize>, (WebSocketCloseCode, &'static str)> {
        let protocol = |reason| (WebSocketCloseCode::PROTOCOL_ERROR, reason);
        let Some((header, length)) = WebSocketFrameHeader::decode(&self.incoming[offset..]).map_err(protocol)? else {
            return Ok(None);
        };
        // A client's frames are masked, a server's are not (§5.1).
        if header.mask.is_some() != (self.role == WebSocketRole::Server) {
            return Err(protocol(if header.mask.is_some() {
                "a masked frame from the server"
            } else {
                "an unmasked frame from the client"
            }));
        }
        if !header.opcode.is_defined() {
            return Err(protocol("a reserved opcode"));
        }
        // RSV1 only on the first frame of a message under permessage-deflate (RFC 7692 §6).
        let first_data = !header.opcode.is_control() && header.opcode != WebSocketOpcode::CONTINUATION;
        if header.rsv2 || header.rsv3 || header.rsv1 && (self.deflate.is_none() || !first_data) {
            return Err(protocol("a reserved bit set"));
        }
        if header.opcode.is_control() && (!header.fin || header.length > WebSocketFrameHeader::MAXIMUM_CONTROL_LENGTH) {
            return Err(protocol("a control frame fragmented or too long"));
        }
        if header.length > self.config.maximum_message_size as u64 {
            return Err((WebSocketCloseCode::MESSAGE_TOO_BIG, "a frame larger than the limit"));
        }
        let end = offset + length + header.length as usize;
        if self.incoming.len() < end {
            return Ok(None);
        }
        let mut payload = self.incoming[offset + length..end].to_vec();
        if let Some(mask) = header.mask {
            WebSocketFrameHeader::apply_mask(mask, 0, &mut payload);
        }
        match header.opcode {
            WebSocketOpcode::CLOSE => self.receive_close_frame(&payload)?,
            WebSocketOpcode::PING => {
                // Answered with a Pong of the same data (§5.5.2), unless the
                // peer's Close arrived (this end's own Close does not stop it).
                if !self.close_received && self.state != WebSocketState::Closed {
                    self.write_frame(WebSocketOpcode::PONG, &payload, true, false);
                }
                self.push_event(WebSocketEvent::Ping(payload));
            }
            WebSocketOpcode::PONG => self.push_event(WebSocketEvent::Pong(payload)),
            opcode => self.receive_data(opcode, header.fin, header.rsv1, payload)?,
        }
        Ok(Some(end - offset))
    }

    /// A data frame (§5.4, §5.6).
    pub fn receive_data(
        &mut self,
        opcode: WebSocketOpcode,
        fin: bool,
        compressed: bool,
        payload: Vec<u8>,
    ) -> Result<(), (WebSocketCloseCode, &'static str)> {
        let protocol = |reason| (WebSocketCloseCode::PROTOCOL_ERROR, reason);
        if self.state != WebSocketState::Open {
            // After this end's Close, data is discarded (§1.4).
            return Ok(());
        }
        let mut fragments = match (opcode, self.fragments.take()) {
            (WebSocketOpcode::CONTINUATION, Some(fragments)) => fragments,
            (WebSocketOpcode::CONTINUATION, None) => return Err(protocol("a continuation of no message")),
            (_, Some(_)) => return Err(protocol("a message inside another")),
            (opcode, None) => WebSocketFragments { opcode, payload: Vec::new(), compressed, validated: 0 },
        };
        if fragments.payload.len() + payload.len() > self.config.maximum_message_size {
            return Err((WebSocketCloseCode::MESSAGE_TOO_BIG, "a message larger than the limit"));
        }
        fragments.payload.extend_from_slice(&payload);
        // Text is checked as it comes, so that invalid UTF-8 fails at once (§8.1).
        if fragments.opcode == WebSocketOpcode::TEXT && !fragments.compressed {
            match core::str::from_utf8(&fragments.payload[fragments.validated..]) {
                Ok(_) => fragments.validated = fragments.payload.len(),
                Err(error) if error.error_len().is_none() && !fin => fragments.validated += error.valid_up_to(),
                Err(_) => return Err((WebSocketCloseCode::INVALID_PAYLOAD, "text that is not UTF-8")),
            }
        }
        if !fin {
            self.fragments = Some(fragments);
            return Ok(());
        }
        let message = if fragments.compressed {
            let limit = self.config.maximum_message_size;
            let deflate = self.deflate.as_mut().ok_or(protocol("a compressed message without permessage-deflate"))?;
            deflate.decompress(&fragments.payload, limit).map_err(|reason| {
                if reason.contains("limit") {
                    (WebSocketCloseCode::MESSAGE_TOO_BIG, reason)
                } else {
                    (WebSocketCloseCode::INVALID_PAYLOAD, reason)
                }
            })?
        } else {
            fragments.payload
        };
        let event = if fragments.opcode == WebSocketOpcode::TEXT {
            WebSocketEvent::Text(
                String::from_utf8(message)
                    .map_err(|_| (WebSocketCloseCode::INVALID_PAYLOAD, "text that is not UTF-8"))?,
            )
        } else {
            WebSocketEvent::Binary(message)
        };
        self.push_event(event);
        Ok(())
    }

    /// A Close frame (§5.5.1, §7.1.5, §7.4): no code, or a valid one and a UTF-8 reason.
    pub fn receive_close_frame(&mut self, payload: &[u8]) -> Result<(), (WebSocketCloseCode, &'static str)> {
        let (code, reason) = match payload {
            [] => (WebSocketCloseCode::NO_STATUS, String::new()),
            [_] => return Err((WebSocketCloseCode::PROTOCOL_ERROR, "a Close of one byte")),
            [high, low, reason @ ..] => {
                let code = WebSocketCloseCode(u16::from_be_bytes([*high, *low]));
                if !code.is_valid() {
                    return Err((WebSocketCloseCode::PROTOCOL_ERROR, "a Close of an invalid code"));
                }
                let reason = core::str::from_utf8(reason)
                    .map_err(|_| (WebSocketCloseCode::INVALID_PAYLOAD, "a reason that is not UTF-8"))?;
                (code, String::from(reason))
            }
        };
        self.close_received = true;
        if self.state == WebSocketState::Open {
            // The echo of the code (§5.5.1): none for none.
            let mut answer = Vec::new();
            if code != WebSocketCloseCode::NO_STATUS {
                answer.extend_from_slice(&code.0.to_be_bytes());
            }
            self.write_frame(WebSocketOpcode::CLOSE, &answer, true, false);
        }
        self.state = WebSocketState::Closed;
        self.push_event(WebSocketEvent::Closed { code, reason });
        Ok(())
    }

    /// Fails the connection (§7.1.7): a Close of `code`, then the end.
    pub fn fail(&mut self, code: WebSocketCloseCode, reason: &'static str) {
        if self.state == WebSocketState::Open {
            let mut payload = code.0.to_be_bytes().to_vec();
            payload.extend_from_slice(reason.as_bytes());
            self.write_frame(WebSocketOpcode::CLOSE, &payload, true, false);
        }
        self.state = WebSocketState::Closed;
        self.push_event(WebSocketEvent::Closed { code, reason: String::from(reason) });
    }

    /// Queues `event`. None is dropped: reading stops once
    /// `maximum_events` wait ([`WebSocketConnection::receive`]).
    pub fn push_event(&mut self, event: WebSocketEvent) {
        self.events.push_back(event);
    }

    /// Whether the caller should read more from the transport: the events
    /// for the application are within their limit.
    pub fn wants_receive(&self) -> bool {
        self.state != WebSocketState::Closed && self.events.len() < self.config.maximum_events
    }

    // ---- Sending ----

    /// Appends a frame: masked with a new key by a client (§5.3).
    pub fn write_frame(&mut self, opcode: WebSocketOpcode, payload: &[u8], fin: bool, rsv1: bool) {
        let mask = match self.role {
            WebSocketRole::Client => {
                let mut key = [0u8; 4];
                // A source that fails gives the all-zero key, still a valid frame.
                let _ = self.random.fill(&mut key);
                Some(key)
            }
            WebSocketRole::Server => None,
        };
        let header =
            WebSocketFrameHeader { fin, rsv1, rsv2: false, rsv3: false, opcode, mask, length: payload.len() as u64 };
        header.encode(&mut self.outgoing);
        let start = self.outgoing.len();
        self.outgoing.extend_from_slice(payload);
        if let Some(mask) = mask {
            WebSocketFrameHeader::apply_mask(mask, 0, &mut self.outgoing[start..]);
        }
    }

    /// Sends a message, compressed under permessage-deflate, in frames of
    /// at most the configured size (§5.4, RFC 7692 §6.1).
    pub fn send_message(&mut self, opcode: WebSocketOpcode, message: &[u8]) -> Result<(), &'static str> {
        if self.state != WebSocketState::Open {
            return Err("the connection is not open");
        }
        let (payload, compressed) = match &mut self.deflate {
            Some(deflate) => (deflate.compress(message)?, true),
            None => (message.to_vec(), false),
        };
        let size = self.config.maximum_frame_size.max(1);
        let chunks: Vec<&[u8]> = if payload.is_empty() { alloc::vec![&[][..]] } else { payload.chunks(size).collect() };
        let last = chunks.len() - 1;
        for (index, chunk) in chunks.iter().enumerate() {
            let opcode = if index == 0 { opcode } else { WebSocketOpcode::CONTINUATION };
            self.write_frame(opcode, chunk, index == last, compressed && index == 0);
        }
        Ok(())
    }

    pub fn send_text(&mut self, text: &str) -> Result<(), &'static str> {
        self.send_message(WebSocketOpcode::TEXT, text.as_bytes())
    }

    pub fn send_binary(&mut self, data: &[u8]) -> Result<(), &'static str> {
        self.send_message(WebSocketOpcode::BINARY, data)
    }

    /// Sends Ping with at most 125 bytes (§5.5.2).
    pub fn send_ping(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if self.state != WebSocketState::Open || data.len() as u64 > WebSocketFrameHeader::MAXIMUM_CONTROL_LENGTH {
            return Err("a Ping not possible");
        }
        self.write_frame(WebSocketOpcode::PING, data, true, false);
        Ok(())
    }

    /// Starts the closing handshake with `code` and `reason` (§5.5.1,
    /// §7.1.2): a code valid to send, a reason of at most 123 bytes.
    pub fn close(&mut self, code: WebSocketCloseCode, reason: &str) -> Result<(), &'static str> {
        if self.state != WebSocketState::Open {
            return Err("the connection is not open");
        }
        if !code.is_valid() || reason.len() > 123 {
            return Err("a code not to send, or a reason too long");
        }
        let mut payload = code.0.to_be_bytes().to_vec();
        payload.extend_from_slice(reason.as_bytes());
        self.write_frame(WebSocketOpcode::CLOSE, &payload, true, false);
        self.state = WebSocketState::Closing;
        Ok(())
    }

    /// Writes what is ready into `out` (appended).
    pub fn transmit(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.outgoing);
    }

    /// Whether the caller should close the transport once it sent what
    /// [`WebSocketConnection::transmit`] wrote: both Close frames went
    /// (§7.1.1: a server closes first; a client may then).
    pub fn wants_close(&self) -> bool {
        self.state == WebSocketState::Closed && self.outgoing.is_empty()
    }

    pub fn poll_event(&mut self) -> Option<WebSocketEvent> {
        let event = self.events.pop_front();
        // What waited for room is read on.
        if !self.incoming.is_empty() && self.events.len() < self.config.maximum_events {
            self.receive(&[]);
        }
        event
    }
}
