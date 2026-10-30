use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::bytes::Writer;
use crate::crypto::random::Random;

use super::{
    TLSAlert, TLSAlertDescription, TLSAlertLevel, TLSCipherSuite, TLSClientConfig, TLSContentType, TLSEncryptionLevel,
    TLSError, TLSHandshake, TLSNamedGroup, TLSQUIC, TLSRecordLayer, TLSServerConfig, TLSSignatureScheme,
    TLSTrafficSecret, TLSVersion,
};

/// Which end of a connection this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLSRole {
    Client,
    Server,
}

/// What happened on a connection that the application may act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TLSEvent {
    /// The handshake completed: application data flows both ways.
    Connected,
    /// Application data can be read.
    Readable,
    /// The peer sent `close_notify`: no more data will arrive (RFC 9846 §6.1).
    PeerClosed,
    /// The client answered a certificate request after the handshake: the
    /// session holds its chain, empty if it declined (RFC 9846 §4.6.2).
    Authenticated,
}

/// What was negotiated, filled in as the handshake goes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TLSSession {
    pub version: Option<TLSVersion>,
    pub cipher_suite: Option<TLSCipherSuite>,
    pub group: Option<TLSNamedGroup>,
    /// The scheme the peer signed with.
    pub peer_signature_scheme: Option<TLSSignatureScheme>,
    /// The application protocol (ALPN), if one was negotiated.
    pub protocol: Option<Vec<u8>>,
    /// The name the client asked for (`server_name`).
    pub server_name: Option<String>,
    /// The peer's certificate chain, DER, the end-entity certificate first.
    pub peer_certificates: Vec<Vec<u8>>,
    /// The OCSP response the server stapled to its certificate, DER (RFC 6066 §8).
    pub certificate_status: Option<Vec<u8>>,
    /// Whether the handshake resumed a session (a PSK of a ticket).
    pub resumed: bool,
    /// What became of early data (0-RTT, RFC 9846 §4.2.10).
    pub early_data: TLSEarlyData,
    /// Whether the ClientHello was encrypted (ECH, RFC 9849).
    pub ech: super::TLSECHStatus,
    /// The time of the handshake: seconds since 1970, which certificates are checked at.
    pub time: i64,
    /// The peer's `quic_transport_parameters`, when QUIC carries the handshake (RFC 9001 §8.2).
    pub transport_parameters: Option<Vec<u8>>,
    /// The application's data of the session, which tickets keep (RFC 9846
    /// §4.6.1 leaves their content to each end): a server seals it in its
    /// tickets and accepts early data only when a ticket's matches the
    /// connection's, so that 0-RTT never meets settings it was not made for
    /// (RFC 9001 §4.6.3); a client keeps it with its tickets, and finds that
    /// of the ticket it offers here when the handshake starts. QUIC keeps
    /// the transport parameters that 0-RTT depends on in it (RFC 9000 §7.4.1).
    pub application: Vec<u8>,
}

/// What became of a client's early data (0-RTT, RFC 9846 §4.2.10). Early
/// data can be replayed by an attacker: only what is safe to repeat
/// belongs in it (RFC 9846 §8, Appendix E.5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TLSEarlyData {
    #[default]
    NotOffered,
    /// Offered; the server has not answered yet.
    Offered,
    Accepted,
    /// The server refused it: the client's application must send it again
    /// once connected, if it still wants to.
    Rejected,
}

/// What a handshake engine acts on.
pub struct TLSContext<'a> {
    pub layer: &'a mut TLSRecordLayer,
    pub session: &'a mut TLSSession,
    pub events: &'a mut VecDeque<TLSEvent>,
    pub random: &'a mut (dyn Random + Send),
}

/// The handshake of one version on one end: a state machine that takes
/// handshake messages and becomes its next state. Versions implement it;
/// [`TLSConnection`] drives it.
pub trait TLSHandshakeProtocol: Send {
    /// Processes `message` and returns the next state.
    fn receive(
        self: Box<Self>,
        message: TLSHandshake,
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError>;

    /// Processes a ChangeCipherSpec record of `fragment`.
    fn receive_change_cipher_spec(
        self: Box<Self>,
        fragment: &[u8],
        context: &mut TLSContext<'_>,
    ) -> Result<Box<dyn TLSHandshakeProtocol>, TLSError>;

    /// Whether application data may be sent and received.
    fn is_established(&self) -> bool;

    /// Derives `out.len()` bytes of keying material for `label` and
    /// `context` (RFC 9846 §7.5, RFC 5705); fails with [`TLSError::State`]
    /// before the handshake completes.
    fn export(&self, label: &[u8], context: Option<&[u8]>, out: &mut [u8]) -> Result<(), TLSError>;

    /// Updates the keys of sending, asking the peer to update its own if
    /// `request` (RFC 9846 §4.7.3); fails with [`TLSError::State`] where the
    /// version has no such message.
    fn update_keys(&mut self, request: bool, context: &mut TLSContext<'_>) -> Result<(), TLSError>;

    /// Called when application data was received, which ends a run of
    /// KeyUpdate messages.
    fn received_data(&mut self) {}

    /// Accounts for `length` bytes of early data the application sends
    /// before the handshake completes; fails with [`TLSError::State`] where
    /// none may be sent.
    fn send_early_data(&mut self, _length: usize) -> Result<(), TLSError> {
        Err(TLSError::State)
    }

    /// Accounts for `length` bytes of early data received before the
    /// handshake completes; fails with `unexpected_message` where none is
    /// accepted (RFC 9846 §4.2.10).
    fn receive_early_data(&mut self, _length: usize) -> Result<(), TLSError> {
        Err(TLSError::unexpected())
    }

    /// Asks the client for a certificate after the handshake (RFC 9846
    /// §4.6.2); fails with [`TLSError::State`] where the version or the
    /// client does not allow it, or a request is pending.
    fn request_certificate(&mut self, _context: &mut TLSContext<'_>) -> Result<(), TLSError> {
        Err(TLSError::State)
    }
}

/// Where a connection stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TLSConnectionState {
    Handshaking,
    Open,
    /// A fatal error was sent or received; nothing more flows.
    Failed,
}

/// A TLS connection without I/O (RFC 9846, RFC 5246): it is given the
/// bytes that arrive and the application's data, and writes the bytes to
/// send. The caller moves bytes between it and the transport:
/// [`TLSConnection::receive`] after each read, [`TLSConnection::transmit`]
/// after each call.
pub struct TLSConnection {
    pub role: TLSRole,
    pub layer: TLSRecordLayer,
    pub engine: Option<Box<dyn TLSHandshakeProtocol>>,
    pub session: TLSSession,
    pub events: VecDeque<TLSEvent>,
    /// The application data received and not yet read.
    pub data: VecDeque<u8>,
    pub random: Box<dyn Random + Send>,
    pub state: TLSConnectionState,
    pub sent_close: bool,
    pub received_close: bool,
    /// The largest application data buffered before records are refused.
    pub maximum_buffered: usize,
    /// The error that ended the connection, if any.
    pub error: Option<TLSError>,
}

impl core::fmt::Debug for TLSConnection {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TLSConnection")
            .field("role", &self.role)
            .field("state", &self.state)
            .field("session", &self.session)
            .finish()
    }
}

impl TLSConnection {
    /// A client connecting to `server_name` (a DNS name, or an address
    /// whose certificate must name it), its ClientHello written at once.
    /// `time` is the current time in seconds since 1970, for the
    /// certificates. Fails with [`TLSError::Config`] for a configuration
    /// that cannot work.
    pub fn client(
        config: Arc<TLSClientConfig>,
        server_name: Option<&str>,
        random: Box<dyn Random + Send>,
        time: i64,
    ) -> Result<TLSConnection, TLSError> {
        config.check()?;
        let connection = TLSConnection::new(TLSRole::Client, &config.config, random, time);
        connection.start_client(config, server_name)
    }

    /// A client whose handshake QUIC carries (RFC 9001 §4), sending
    /// `transport_parameters` (§8.2): handshake bytes and secrets are taken
    /// with [`TLSConnection::take_handshake`] and
    /// [`TLSConnection::take_secret`], and given with
    /// [`TLSConnection::receive_handshake`]. Fails with
    /// [`TLSError::Config`] also where [`TLSQUIC::check`] does.
    pub fn quic_client(
        config: Arc<TLSClientConfig>,
        server_name: Option<&str>,
        transport_parameters: Vec<u8>,
        random: Box<dyn Random + Send>,
        time: i64,
    ) -> Result<TLSConnection, TLSError> {
        config.check()?;
        TLSQUIC::check(&config.config)?;
        let mut connection = TLSConnection::new(TLSRole::Client, &config.config, random, time);
        connection.layer.quic = Some(TLSQUIC::new(transport_parameters));
        connection.start_client(config, server_name)
    }

    /// Writes the ClientHello and starts waiting for the server.
    pub fn start_client(
        mut self,
        config: Arc<TLSClientConfig>,
        server_name: Option<&str>,
    ) -> Result<TLSConnection, TLSError> {
        let mut context = self.context();
        let engine = super::TLSClientStart::start(config, server_name, &mut context)?;
        self.engine = Some(engine);
        Ok(self)
    }

    /// A server, which waits for a ClientHello. `time` is the current time
    /// in seconds since 1970, for the certificates of clients.
    pub fn server(
        config: Arc<TLSServerConfig>,
        random: Box<dyn Random + Send>,
        time: i64,
    ) -> Result<TLSConnection, TLSError> {
        config.check()?;
        let mut connection = TLSConnection::new(TLSRole::Server, &config.config, random, time);
        connection.engine = Some(Box::new(super::TLSServerStart::new(config)));
        Ok(connection)
    }

    /// A server whose handshake QUIC carries (RFC 9001 §4), answering with
    /// `transport_parameters` (§8.2); see [`TLSConnection::quic_client`].
    pub fn quic_server(
        config: Arc<TLSServerConfig>,
        transport_parameters: Vec<u8>,
        random: Box<dyn Random + Send>,
        time: i64,
    ) -> Result<TLSConnection, TLSError> {
        TLSQUIC::check(&config.config)?;
        let mut connection = TLSConnection::server(config, random, time)?;
        connection.layer.quic = Some(TLSQUIC::new(transport_parameters));
        Ok(connection)
    }

    pub fn new(role: TLSRole, config: &super::TLSConfig, random: Box<dyn Random + Send>, time: i64) -> TLSConnection {
        let mut connection = TLSConnection {
            role,
            // The own limit applies once the peer has acknowledged it (RFC 8449 §4).
            layer: TLSRecordLayer::new(config.maximum_handshake_message, super::TLSRecordHeader::MAXIMUM_PLAINTEXT),
            engine: None,
            session: TLSSession { time, ..TLSSession::default() },
            events: VecDeque::new(),
            data: VecDeque::new(),
            random,
            state: TLSConnectionState::Handshaking,
            sent_close: false,
            received_close: false,
            maximum_buffered: config.maximum_buffered_data,
            error: None,
        };
        connection.layer.maximum_ignored = config.maximum_ignored_records;
        connection
    }

    pub fn context(&mut self) -> TLSContext<'_> {
        TLSContext {
            layer: &mut self.layer,
            session: &mut self.session,
            events: &mut self.events,
            random: &mut *self.random,
        }
    }

    /// Takes `bytes` received from the transport and processes every whole
    /// record. On an error the alert it calls for is queued to send, the
    /// connection fails, and the error is returned (and kept in `error`).
    pub fn receive(&mut self, bytes: &[u8]) -> Result<(), TLSError> {
        if self.state == TLSConnectionState::Failed {
            return Err(self.error.unwrap_or(TLSError::State));
        }
        // QUIC has no records: its CRYPTO data goes to `receive_handshake` (RFC 9001 §4.1.3).
        if self.layer.quic.is_some() {
            return Err(TLSError::State);
        }
        // What follows close_notify is ignored (RFC 9846 §6.1).
        if self.received_close {
            return Ok(());
        }
        self.layer.incoming.extend_from_slice(bytes);
        let result = self.process();
        if let Err(error) = result {
            self.fail(error);
        }
        result
    }

    /// Processes the records received until none is whole.
    pub fn process(&mut self) -> Result<(), TLSError> {
        while !self.received_close
            && let Some((content_type, fragment)) = self.layer.read()?
        {
            match content_type {
                TLSContentType::HANDSHAKE => self.process_handshake(&fragment)?,
                TLSContentType::CHANGE_CIPHER_SPEC => {
                    // Not between the fragments of a handshake message (RFC 9846 §5.1).
                    if !self.layer.handshake.is_empty() {
                        return Err(TLSError::unexpected());
                    }
                    self.layer.ignore()?;
                    let engine = self.engine.take().ok_or(TLSError::State)?;
                    let mut context = TLSContext {
                        layer: &mut self.layer,
                        session: &mut self.session,
                        events: &mut self.events,
                        random: &mut *self.random,
                    };
                    self.engine = Some(engine.receive_change_cipher_spec(&fragment, &mut context)?);
                }
                TLSContentType::ALERT => self.receive_alert(&fragment)?,
                TLSContentType::APPLICATION_DATA => self.receive_data(&fragment)?,
                // Unknown content types are refused (RFC 9846 §5).
                _ => return Err(TLSError::unexpected()),
            }
        }
        // What follows close_notify is ignored (RFC 9846 §6.1).
        if self.received_close {
            self.layer.incoming.clear();
            self.layer.consumed = 0;
        }
        Ok(())
    }

    /// Joins `fragment` to the handshake messages received and processes
    /// every whole one.
    pub fn process_handshake(&mut self, fragment: &[u8]) -> Result<(), TLSError> {
        self.layer.handshake.push(fragment)?;
        while let Some(message) = self.layer.handshake.pop()? {
            let engine = self.engine.take().ok_or(TLSError::State)?;
            let mut context = TLSContext {
                layer: &mut self.layer,
                session: &mut self.session,
                events: &mut self.events,
                random: &mut *self.random,
            };
            let next = engine.receive(message, &mut context)?;
            if next.is_established() && self.state == TLSConnectionState::Handshaking {
                self.state = TLSConnectionState::Open;
            }
            self.engine = Some(next);
        }
        Ok(())
    }

    /// Takes handshake bytes QUIC received in CRYPTO frames at `level`, in
    /// order (RFC 9001 §4.1.3): the level must be the one TLS reads,
    /// [`TLSConnection::reading_level`], or the transport's rules are
    /// broken ([`TLSError::Transport`]); QUIC keeps data of later levels
    /// until then. On an error the connection fails; its alert is the
    /// error's (RFC 9001 §4.8), and no record is written.
    pub fn receive_handshake(&mut self, level: TLSEncryptionLevel, bytes: &[u8]) -> Result<(), TLSError> {
        if self.state == TLSConnectionState::Failed {
            return Err(self.error.unwrap_or(TLSError::State));
        }
        let reading = self.layer.quic.as_ref().ok_or(TLSError::State)?.reading;
        let result = if level == reading { self.process_handshake(bytes) } else { Err(TLSError::Transport) };
        if let Err(error) = result {
            self.fail(error);
        }
        result
    }

    /// The level QUIC must give handshake bytes at, when it carries them.
    pub fn reading_level(&self) -> Option<TLSEncryptionLevel> {
        self.layer.quic.as_ref().map(|quic| quic.reading)
    }

    /// The next handshake bytes for QUIC to send in CRYPTO frames, and their level.
    pub fn take_handshake(&mut self) -> Option<(TLSEncryptionLevel, Vec<u8>)> {
        self.layer.quic.as_mut()?.outgoing.pop_front()
    }

    /// The next secret for QUIC to install (RFC 9001 §4.1.4).
    pub fn take_secret(&mut self) -> Option<TLSTrafficSecret> {
        self.layer.quic.as_mut()?.secrets.pop_front()
    }

    /// An alert record: `close_notify` closes the peer's half, warnings of
    /// TLS 1.2 other than it are ignored, `user_canceled` too (RFC 9846
    /// §6.1), and anything else is fatal.
    pub fn receive_alert(&mut self, fragment: &[u8]) -> Result<(), TLSError> {
        if !self.layer.handshake.is_empty() {
            return Err(TLSError::unexpected());
        }
        let alert = TLSAlert::decode(fragment)?;
        match alert.description {
            TLSAlertDescription::CLOSE_NOTIFY => {
                self.received_close = true;
                self.events.push_back(TLSEvent::PeerClosed);
                Ok(())
            }
            TLSAlertDescription::USER_CANCELED => self.layer.ignore(),
            _ if alert.level == TLSAlertLevel::WARNING && self.session.version == Some(TLSVersion::TLS1_2) => {
                self.layer.ignore()
            }
            description => {
                self.state = TLSConnectionState::Failed;
                Err(TLSError::Alert(description))
            }
        }
    }

    /// Application data: refused before the handshake allows it, and
    /// interleaved with a partial handshake message (RFC 9846 §5.1).
    pub fn receive_data(&mut self, fragment: &[u8]) -> Result<(), TLSError> {
        let engine = self.engine.as_mut().ok_or(TLSError::State)?;
        if !self.layer.handshake.is_empty() {
            return Err(TLSError::unexpected());
        }
        if !engine.is_established() {
            engine.receive_early_data(fragment.len())?;
        }
        engine.received_data();
        self.layer.ignored = 0;
        if self.data.len() + fragment.len() > self.maximum_buffered {
            return Err(TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR));
        }
        if !fragment.is_empty() {
            self.data.extend(fragment);
            if !self.events.contains(&TLSEvent::Readable) {
                self.events.push_back(TLSEvent::Readable);
            }
        }
        Ok(())
    }

    /// Ends the connection on `error`: the alert it calls for is queued, if
    /// any and if `close_notify` was not sent (nothing follows it, RFC 9846 §6.1).
    pub fn fail(&mut self, error: TLSError) {
        if let Some(description) = error.alert().filter(|_| !self.sent_close) {
            let mut alert = alloc::vec::Vec::new();
            if TLSAlert::new(description).encode(&mut alert).is_ok() {
                let _ = self.layer.write(TLSContentType::ALERT, &alert);
            }
        }
        // Over QUIC, only its CONNECTION_CLOSE follows (RFC 9001 §4.8).
        if let Some(quic) = &mut self.layer.quic {
            quic.outgoing.clear();
            quic.secrets.clear();
        }
        self.state = TLSConnectionState::Failed;
        self.error = Some(error);
    }

    /// Writes the bytes to send into `out` and returns how many.
    pub fn transmit(&mut self, out: &mut impl Writer) -> Result<usize, TLSError> {
        let bytes = self.layer.take_outgoing();
        out.write(&bytes)?;
        Ok(bytes.len())
    }

    /// Whether bytes are waiting to be sent.
    pub fn wants_transmit(&self) -> bool {
        !self.layer.outgoing.is_empty()
    }

    /// Sends `data` as application data; fails with [`TLSError::State`]
    /// before the handshake completes, unless it is early data the
    /// handshake allows (see [`TLSSession::early_data`]), or after `close`.
    pub fn send(&mut self, data: &[u8]) -> Result<usize, TLSError> {
        // QUIC carries the application's data itself (RFC 9001 §4.1.3).
        if self.sent_close || self.state == TLSConnectionState::Failed || self.layer.quic.is_some() {
            return Err(TLSError::State);
        }
        let engine = self.engine.as_mut().ok_or(TLSError::State)?;
        if !engine.is_established() {
            engine.send_early_data(data.len())?;
        }
        self.layer.write(TLSContentType::APPLICATION_DATA, data)?;
        Ok(data.len())
    }

    /// Reads application data into `out` and returns how many bytes.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.data.len());
        for (slot, byte) in out.iter_mut().zip(self.data.drain(..count)) {
            *slot = byte;
        }
        count
    }

    pub fn readable(&self) -> usize {
        self.data.len()
    }

    pub fn poll_event(&mut self) -> Option<TLSEvent> {
        self.events.pop_front()
    }

    /// Sends `close_notify`: nothing more is sent (RFC 9846 §6.1). Reading
    /// goes on until the peer closes too.
    pub fn close(&mut self) -> Result<(), TLSError> {
        // QUIC closes with its own frames (RFC 9001 §4.8).
        if self.sent_close || self.state == TLSConnectionState::Failed || self.layer.quic.is_some() {
            return Err(TLSError::State);
        }
        let mut alert = alloc::vec::Vec::new();
        TLSAlert::new(TLSAlertDescription::CLOSE_NOTIFY).encode(&mut alert)?;
        self.layer.write(TLSContentType::ALERT, &alert)?;
        self.sent_close = true;
        self.layer.closed = true;
        Ok(())
    }

    /// Whether the handshake is still in progress.
    pub fn is_handshaking(&self) -> bool {
        self.state == TLSConnectionState::Handshaking
    }

    /// Updates the keys of sending, asking the peer to update its own if
    /// `request` (TLS 1.3, RFC 9846 §4.7.3).
    pub fn update_keys(&mut self, request: bool) -> Result<(), TLSError> {
        if self.state != TLSConnectionState::Open || self.sent_close {
            return Err(TLSError::State);
        }
        let mut engine = self.engine.take().ok_or(TLSError::State)?;
        let mut context = TLSContext {
            layer: &mut self.layer,
            session: &mut self.session,
            events: &mut self.events,
            random: &mut *self.random,
        };
        let result = engine.update_keys(request, &mut context);
        self.engine = Some(engine);
        result
    }

    /// Asks the client for a certificate (TLS 1.3 post-handshake
    /// authentication, RFC 9846 §4.6.2), when the client offered it and the
    /// server has a verifier of clients; [`TLSEvent::Authenticated`] tells
    /// when the answer was checked.
    pub fn request_certificate(&mut self) -> Result<(), TLSError> {
        if self.state != TLSConnectionState::Open || self.sent_close {
            return Err(TLSError::State);
        }
        let mut engine = self.engine.take().ok_or(TLSError::State)?;
        let mut context = TLSContext {
            layer: &mut self.layer,
            session: &mut self.session,
            events: &mut self.events,
            random: &mut *self.random,
        };
        let result = engine.request_certificate(&mut context);
        self.engine = Some(engine);
        result
    }

    /// Keying material for `label` and `context` (RFC 9846 §7.5, RFC 5705).
    pub fn export(&self, label: &[u8], context: Option<&[u8]>, out: &mut [u8]) -> Result<(), TLSError> {
        self.engine.as_ref().ok_or(TLSError::State)?.export(label, context, out)
    }
}
