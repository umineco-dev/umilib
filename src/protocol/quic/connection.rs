use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use crate::crypto::random::{HMACDRBG, Random};
use crate::hash::sha::v2::SHA256;
use crate::protocol::ip::IPEndpoint;
use crate::protocol::tls::{
    TLSClientConfig, TLSConnection, TLSDirection, TLSEncryptionLevel, TLSError, TLSEvent, TLSServerConfig,
};
use crate::runtime::Instant;
use crate::secret::Secret;

use super::{
    QUICACKFrame, QUICBufferedPackets, QUICCloseReason, QUICConfig, QUICConnectionID, QUICECN, QUICError,
    QUICErrorCode, QUICEvent, QUICFrame, QUICFrameType, QUICFrames, QUICHeader, QUICIssuedID, QUICKeys,
    QUICLocalConnectionIDs, QUICLongHeader, QUICNewReno, QUICOneRTT, QUICPacer, QUICPacket, QUICPacketNumber,
    QUICPacketNumberSpace, QUICPacketType, QUICPeerConnectionIDs, QUICReceiveCredit, QUICRecovery, QUICResetToken,
    QUICRole, QUICSecret, QUICSendCredit, QUICSentFrame, QUICSentPacket, QUICShortHeader, QUICSpace, QUICStreamID,
    QUICStreams, QUICTransportError, QUICTransportParameterID, QUICTransportParameters, QUICVersion,
    QUICVersionInformation, QUICVersionProfile,
};

/// Where a connection stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QUICConnectionState {
    Handshaking,
    Established,
    /// This end closed: it answers with CONNECTION_CLOSE until the deadline (RFC 9000 §10.2.1).
    Closing,
    /// The peer closed: nothing is sent until the deadline (RFC 9000 §10.2.2).
    Draining,
    Closed,
}

/// A datagram to send: its destination and ECN codepoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QUICTransmission {
    pub destination: IPEndpoint,
    pub ecn: QUICECN,
}

/// What a server knows of a client's first Initial packet when it accepts
/// the connection (RFC 9000 §7.2, §8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QUICAcceptance {
    pub version: QUICVersion,
    /// The Destination Connection ID of the client's first Initial, before any Retry.
    pub original_destination: QUICConnectionID,
    /// The Destination Connection ID of the Initial being accepted: the
    /// original one, or the Source Connection ID of this server's Retry.
    pub destination: QUICConnectionID,
    /// The client's Source Connection ID.
    pub source: QUICConnectionID,
    /// The Source Connection ID of the Retry the client answered, if any.
    pub retry_source: Option<QUICConnectionID>,
    /// Whether the client's address is validated: by a token of this server.
    pub validated: bool,
}

/// The frames waiting to be sent that are not data: each carries the
/// latest value when it goes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QUICPendingFrames {
    pub handshake_done: bool,
    pub max_data: bool,
    pub data_blocked: bool,
    pub ping: bool,
    pub new_connection_ids: Vec<u64>,
    pub retire_connection_ids: Vec<u64>,
    /// PATH_RESPONSE frames, each to the address its challenge came from (RFC 9000 §8.2.2).
    pub path_responses: VecDeque<QUICPathResponse>,
    pub new_token: Option<Vec<u8>>,
    /// Whether the path's PATH_CHALLENGE must be sent (again).
    pub challenge_due: bool,
    /// Frames of extensions, encoded (RFC 9000 §19.21).
    pub extension_frames: VecDeque<Vec<u8>>,
}

/// A PATH_RESPONSE to send (RFC 9000 §8.2.2): the challenge's data, the
/// address it came from, and the most bytes that may go there, three times
/// the datagram that carried it when the address is not validated (§8.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QUICPathResponse {
    pub data: [u8; 8],
    pub destination: IPEndpoint,
    pub limit: usize,
}

/// How a closing connection ends (RFC 9000 §10.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QUICClosing {
    /// The CONNECTION_CLOSE to send: the error, the frame type, the reason,
    /// and whether it is the application's.
    pub error: u64,
    pub frame_type: QUICFrameType,
    pub reason: Vec<u8>,
    pub application: bool,
    /// Whether it is due to be sent.
    pub due: bool,
    /// When the connection is forgotten.
    pub until: Instant,
}

/// A QUIC connection without I/O (RFC 9000, RFC 9001, RFC 9002): it takes
/// the datagrams that arrive and the application's data, and makes the
/// datagrams to send. The caller calls [`QUICConnection::receive`] for each
/// datagram, [`QUICConnection::transmit`] until it returns `None`, and
/// [`QUICConnection::expire`] at [`QUICConnection::poll_timeout`].
pub struct QUICConnection {
    pub role: QUICRole,
    pub config: Arc<QUICConfig>,
    pub version: QUICVersion,
    pub profile: &'static QUICVersionProfile,
    pub tls: TLSConnection,
    pub random: Box<dyn Random + Send>,
    pub state: QUICConnectionState,
    pub spaces: [QUICSpace; 3],
    /// The 0-RTT keys: a client's to write, a server's to read.
    pub zero_rtt: Option<QUICKeys>,
    pub one_rtt: Option<QUICOneRTT>,
    /// The 1-RTT secrets that came first, while the other direction's is missing.
    pub one_rtt_read: Option<QUICSecret>,
    pub one_rtt_write: Option<QUICSecret>,
    pub recovery: QUICRecovery,
    pub streams: QUICStreams,
    pub send_credit: QUICSendCredit,
    pub receive_credit: QUICReceiveCredit,
    pub local_ids: QUICLocalConnectionIDs,
    pub peer_ids: QUICPeerConnectionIDs,
    /// The Destination Connection ID of the client's first Initial.
    pub original_destination: QUICConnectionID,
    /// This end's Source Connection ID in its first packets.
    pub initial_source: QUICConnectionID,
    /// The peer's Source Connection ID in its first packets.
    pub peer_initial_source: Option<QUICConnectionID>,
    /// The Source Connection ID of a Retry (RFC 9000 §7.3).
    pub retry_source: Option<QUICConnectionID>,
    /// The token a client sends in its Initial packets (RFC 9000 §8.1).
    pub token: Vec<u8>,
    pub local_parameters: QUICTransportParameters,
    pub peer_parameters: Option<QUICTransportParameters>,
    pub remote: IPEndpoint,
    /// A server: whether the client's address is validated (RFC 9000 §8.1).
    /// A client: whether the server completed address validation, so that
    /// probes are not needed to unblock it (RFC 9002 §6.2.2.1).
    pub validated: bool,
    /// The bytes received and sent before validation (RFC 9000 §8.1).
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub handshake_complete: bool,
    pub handshake_confirmed: bool,
    /// Whether a packet from the server was processed, which fixes its connection ID (RFC 9000 §7.2).
    pub server_heard: bool,
    pub idle_timeout: Option<Duration>,
    pub last_activity: Instant,
    pub closing: Option<QUICClosing>,
    pub events: VecDeque<QUICEvent>,
    pub datagrams: VecDeque<Vec<u8>>,
    pub outgoing_datagrams: VecDeque<Vec<u8>>,
    pub pending: QUICPendingFrames,
    pub buffered: QUICBufferedPackets,
    pub loss_timer: Option<Instant>,
    /// The latency spin bit (RFC 9000 §17.4): whether this connection uses
    /// it, its value, and the largest packet number seen.
    pub spin_enabled: bool,
    pub spin: bool,
    pub spin_largest: Option<u64>,
    /// Packets that failed authentication (RFC 9001 §6.6), and the smallest
    /// integrity limit of the keys used so far.
    pub integrity_failures: u64,
    pub integrity_limit: u64,
    /// A buffer reused to read packets in.
    pub scratch: Vec<u8>,
    /// When pacing lets the data that waits go (RFC 9002 §7.7).
    pub paced_until: Option<Instant>,
    /// Whether a server's endpoint gave this connection its NEW_TOKEN.
    pub token_issued: bool,
    /// What a client needs to start again with another version (RFC 9368 §2.1).
    pub restart: Option<QUICRestart>,
    /// The version a client tried first, when a Version Negotiation made it
    /// use this one (RFC 9368 §4).
    pub negotiated_from: Option<QUICVersion>,
    /// The server's parameters a client's 0-RTT assumes (RFC 9000 §7.4.1).
    pub zero_rtt_parameters: Option<QUICTransportParameters>,
    /// The path to `remote` (RFC 9000 §8.2, §9): validated, or the bytes
    /// received on it and sent to it before, and the challenge sent.
    pub path_validated: bool,
    pub path_received: u64,
    pub path_sent: u64,
    pub path_challenge: Option<[u8; 8]>,
    /// Whether the datagram being read had the highest-numbered packet with
    /// a frame that is not probing, which moves the peer's address (RFC 9000 §9.3).
    pub non_probing: bool,
    /// Whether an ack-eliciting packet went since the last packet processed,
    /// which restarts the idle timer only the first time (RFC 9000 §10.1).
    pub eliciting_sent: bool,
}

/// What a client keeps to start its connection again with another version
/// after Version Negotiation (RFC 9368 §2.1): the connection that follows
/// is conceptually a new one.
#[derive(Clone)]
pub struct QUICRestart {
    pub tls: Arc<TLSClientConfig>,
    pub server_name: Option<alloc::string::String>,
    pub time: i64,
}

impl core::fmt::Debug for QUICRestart {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("QUICRestart").field("server_name", &self.server_name).finish()
    }
}

impl core::fmt::Debug for QUICConnection {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("QUICConnection")
            .field("role", &self.role)
            .field("version", &self.version)
            .field("state", &self.state)
            .finish()
    }
}

impl QUICConnection {
    /// A client connecting to `remote`, as `server_name` for TLS (RFC 9001
    /// §4.4); its first Initial is ready to send. `now` is the time of the
    /// connection's clock; `time`, seconds since 1970, of certificates.
    pub fn client(
        config: Arc<QUICConfig>,
        tls: Arc<TLSClientConfig>,
        server_name: Option<&str>,
        remote: IPEndpoint,
        random: Box<dyn Random + Send>,
        now: Instant,
        time: i64,
    ) -> Result<QUICConnection, QUICError> {
        config.check()?;
        let version = *config.versions.iter().find(|version| version.is_supported()).ok_or(QUICError::Config)?;
        QUICConnection::client_with_version(config, tls, server_name, remote, random, now, time, version, None)
    }

    /// [`QUICConnection::client`] with `version`, after a Version
    /// Negotiation away from `negotiated_from` if any (RFC 9368 §2.1).
    #[allow(clippy::too_many_arguments)]
    pub fn client_with_version(
        config: Arc<QUICConfig>,
        tls: Arc<TLSClientConfig>,
        server_name: Option<&str>,
        remote: IPEndpoint,
        mut random: Box<dyn Random + Send>,
        now: Instant,
        time: i64,
        version: QUICVersion,
        negotiated_from: Option<QUICVersion>,
    ) -> Result<QUICConnection, QUICError> {
        if !version.is_supported() {
            return Err(QUICError::Config);
        }
        // The client's first Destination Connection ID: at least 8 random bytes (RFC 9000 §7.2).
        let original = QUICConnectionID::random(config.connection_id_length.max(8), &mut *random)?;
        let source = QUICConnectionID::random(config.connection_id_length, &mut *random)?;
        let mut parameters = config.parameters();
        parameters.initial_source_connection_id = Some(source);
        // Only the chosen version: this client does not take part in
        // compatible version negotiation (RFC 9368 §2.3).
        parameters.version_information = Some(QUICVersionInformation { chosen: version, available: vec![version] });
        let encoded = QUICConnection::encode_parameters(&config, &parameters, &mut *random)?;
        let tls_random = QUICConnection::derived_random(&mut *random)?;
        let restart = QUICRestart { tls: tls.clone(), server_name: server_name.map(alloc::string::String::from), time };
        let tls = TLSConnection::quic_client(tls, server_name, encoded, tls_random, time)
            .map_err(QUICConnection::tls_error)?;
        let mut connection = QUICConnection::new(QUICRole::Client, config, version, tls, random, remote, now)?;
        connection.restart = Some(restart);
        connection.negotiated_from = negotiated_from;
        connection.original_destination = original;
        connection.initial_source = source;
        connection.peer_ids = QUICPeerConnectionIDs::new(original, None, connection.config.active_connection_id_limit);
        connection.local_parameters = parameters;
        connection.issue_initial_id(source)?;
        connection.install_initial(&original)?;
        connection.process_tls(now)?;
        // 0-RTT with the limits of the server's previous connection (RFC 9000 §7.4.1).
        if connection.tls.session.early_data == crate::protocol::tls::TLSEarlyData::Offered {
            let remembered = QUICTransportParameters::decode(&connection.tls.session.application, QUICRole::Server)?;
            connection.send_credit.raise(remembered.initial_max_data);
            connection.streams.apply(&remembered);
            connection.zero_rtt_parameters = Some(remembered);
        }
        Ok(connection)
    }

    /// A server accepting a client's connection from `remote`, as its first
    /// Initial packet described (RFC 9000 §7.2); the datagram is then given
    /// to [`QUICConnection::receive`]. Its own Source Connection ID is new.
    pub fn server(
        config: Arc<QUICConfig>,
        tls: Arc<TLSServerConfig>,
        acceptance: QUICAcceptance,
        remote: IPEndpoint,
        mut random: Box<dyn Random + Send>,
        now: Instant,
        time: i64,
    ) -> Result<QUICConnection, QUICError> {
        config.check()?;
        if !config.versions.contains(&acceptance.version) || !acceptance.version.is_supported() {
            return Err(QUICError::Config);
        }
        let source = QUICConnectionID::random(config.connection_id_length, &mut *random)?;
        let reset_token = QUICConnection::reset_token_with(&config, &source, &mut *random)?;
        let mut parameters = config.parameters();
        parameters.original_destination_connection_id = Some(acceptance.original_destination);
        parameters.initial_source_connection_id = Some(source);
        parameters.retry_source_connection_id = acceptance.retry_source;
        parameters.stateless_reset_token = (!source.is_empty()).then_some(reset_token);
        parameters.version_information =
            Some(QUICVersionInformation { chosen: acceptance.version, available: config.supported_versions() });
        // A preferred address carries the connection ID of sequence 1 (RFC 9000 §5.1.1, §9.6).
        let preferred = match config.preferred_address {
            Some(mut address) => {
                let id = QUICConnectionID::random(config.connection_id_length, &mut *random)?;
                if id == source {
                    return Err(QUICError::Random);
                }
                let reset_token = QUICConnection::reset_token_with(&config, &id, &mut *random)?;
                address.connection_id = id;
                address.reset_token = reset_token;
                parameters.preferred_address = Some(address);
                Some(QUICIssuedID { id, reset_token: Some(reset_token) })
            }
            None => None,
        };
        let encoded = QUICConnection::encode_parameters(&config, &parameters, &mut *random)?;
        let tls_random = QUICConnection::derived_random(&mut *random)?;
        let mut tls = TLSConnection::quic_server(tls, encoded, tls_random, time).map_err(QUICConnection::tls_error)?;
        // 0-RTT is accepted only with the same limits again (RFC 9000 §7.4.1, RFC 9001 §4.6.3).
        tls.session.application = QUICConnection::remembered(&config.parameters());
        let mut connection =
            QUICConnection::new(QUICRole::Server, config, acceptance.version, tls, random, remote, now)?;
        connection.original_destination = acceptance.original_destination;
        connection.initial_source = source;
        connection.peer_initial_source = Some(acceptance.source);
        connection.retry_source = acceptance.retry_source;
        connection.validated = acceptance.validated;
        connection.peer_ids =
            QUICPeerConnectionIDs::new(acceptance.source, None, connection.config.active_connection_id_limit);
        connection.local_parameters = parameters;
        connection.local_ids.issue(QUICIssuedID { id: source, reset_token: Some(reset_token) });
        if let Some(issued) = preferred {
            connection.local_ids.issue(issued);
        }
        connection.install_initial(&acceptance.destination)?;
        Ok(connection)
    }

    pub fn new(
        role: QUICRole,
        config: Arc<QUICConfig>,
        version: QUICVersion,
        tls: TLSConnection,
        mut random: Box<dyn Random + Send>,
        remote: IPEndpoint,
        now: Instant,
    ) -> Result<QUICConnection, QUICError> {
        let profile = version.profile().ok_or(QUICError::Config)?;
        let congestion: Box<dyn super::QUICCongestionControl> = match config.congestion {
            super::QUICCongestionKind::NewReno => Box::new(QUICNewReno::new(config.datagram_size)),
        };
        let pacer = config.pacing.then(|| QUICPacer::new(QUICNewReno::initial_window(config.datagram_size)));
        let recovery = QUICRecovery::new(config.initial_rtt, congestion, pacer);
        let parameters = config.parameters();
        // One connection ID in 16, at least, does without the spin bit (RFC 9000 §17.4).
        let spin_enabled = config.spin_bit && random.next_u32().map_err(|_| QUICError::Random)? % 16 != 0;
        Ok(QUICConnection {
            role,
            version,
            profile,
            tls,
            random,
            state: QUICConnectionState::Handshaking,
            spaces: Default::default(),
            zero_rtt: None,
            one_rtt: None,
            one_rtt_read: None,
            one_rtt_write: None,
            recovery,
            streams: QUICStreams::new(role, &parameters),
            send_credit: QUICSendCredit::new(0),
            receive_credit: QUICReceiveCredit::new(config.initial_max_data),
            local_ids: QUICLocalConnectionIDs::default(),
            peer_ids: QUICPeerConnectionIDs::default(),
            original_destination: QUICConnectionID::EMPTY,
            initial_source: QUICConnectionID::EMPTY,
            peer_initial_source: None,
            retry_source: None,
            token: Vec::new(),
            local_parameters: parameters,
            peer_parameters: None,
            remote,
            validated: false,
            received_bytes: 0,
            sent_bytes: 0,
            handshake_complete: false,
            handshake_confirmed: false,
            server_heard: false,
            idle_timeout: (!config.max_idle_timeout.is_zero()).then_some(config.max_idle_timeout),
            last_activity: now,
            closing: None,
            events: VecDeque::new(),
            datagrams: VecDeque::new(),
            outgoing_datagrams: VecDeque::new(),
            pending: QUICPendingFrames::default(),
            buffered: QUICBufferedPackets::default(),
            loss_timer: None,
            spin_enabled,
            spin: false,
            spin_largest: None,
            integrity_failures: 0,
            integrity_limit: u64::MAX,
            scratch: Vec::new(),
            paced_until: None,
            token_issued: false,
            restart: None,
            negotiated_from: None,
            zero_rtt_parameters: None,
            path_validated: true,
            path_received: 0,
            path_sent: 0,
            path_challenge: None,
            non_probing: false,
            eliciting_sent: false,
            config,
        })
    }

    /// The transport parameters encoded, with a reserved one when configured (RFC 9000 §18.1).
    pub fn encode_parameters(
        config: &QUICConfig,
        parameters: &QUICTransportParameters,
        random: &mut (dyn Random + Send),
    ) -> Result<Vec<u8>, QUICError> {
        let mut out = Vec::new();
        let mut value = [0u8; 4];
        let mut reserved = Vec::new();
        if config.grease_transport_parameters {
            let n = u64::from(random.next_u32().map_err(|_| QUICError::Random)? & 0xFFFF);
            random.fill(&mut value).map_err(|_| QUICError::Random)?;
            reserved.push((QUICTransportParameterID::reserved(n).ok_or(QUICError::Config)?, &value[..]));
        }
        parameters.encode(&reserved, &mut out)?;
        Ok(out)
    }

    /// What 0-RTT depends on of a server's parameters (RFC 9000 §7.4.1), as
    /// tickets keep it: its limits, without the values of a connection.
    pub fn remembered(parameters: &QUICTransportParameters) -> Vec<u8> {
        let kept = QUICTransportParameters {
            active_connection_id_limit: parameters.active_connection_id_limit,
            initial_max_data: parameters.initial_max_data,
            initial_max_stream_data_bidi_local: parameters.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: parameters.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: parameters.initial_max_stream_data_uni,
            initial_max_streams_bidi: parameters.initial_max_streams_bidi,
            initial_max_streams_uni: parameters.initial_max_streams_uni,
            max_datagram_frame_size: parameters.max_datagram_frame_size,
            ..QUICTransportParameters::default()
        };
        let mut out = Vec::new();
        // Defaults and integers within range always encode.
        let _ = kept.encode(&[], &mut out);
        out
    }

    /// The randomness of the TLS connection: a DRBG seeded from this one's.
    pub fn derived_random(random: &mut (dyn Random + Send)) -> Result<Box<dyn Random + Send>, QUICError> {
        let mut seed = Secret::new([0u8; 48]);
        random.fill(seed.expose_mut()).map_err(|_| QUICError::Random)?;
        let (entropy, nonce) = seed.expose().split_at(32);
        let drbg = HMACDRBG::<SHA256>::new(entropy, nonce, b"umilib quic tls").map_err(|_| QUICError::Random)?;
        Ok(Box::new(drbg))
    }

    /// The stateless reset token of `id`: from the configured key, or random.
    pub fn reset_token_with(
        config: &QUICConfig,
        id: &QUICConnectionID,
        random: &mut (dyn Random + Send),
    ) -> Result<[u8; 16], QUICError> {
        match &config.reset_key {
            Some(key) => Ok(QUICResetToken::of(key, id)),
            None => {
                let mut token = [0u8; 16];
                random.fill(&mut token).map_err(|_| QUICError::Random)?;
                Ok(token)
            }
        }
    }

    /// The connection error of a TLS failure (RFC 9001 §4.8).
    pub fn tls_error(error: TLSError) -> QUICError {
        match error {
            TLSError::Protocol(alert) => QUICError::transport(QUICErrorCode::crypto(alert.0), "TLS alert"),
            TLSError::Transport => QUICError::transport(QUICErrorCode::PROTOCOL_VIOLATION, "TLS over QUIC"),
            TLSError::Config => QUICError::Config,
            TLSError::Alert(_) | TLSError::State | TLSError::Write(_) => {
                QUICError::transport(QUICErrorCode::INTERNAL_ERROR, "TLS failed")
            }
        }
    }

    /// Issues `source`, sequence 0, with its stateless reset token.
    pub fn issue_initial_id(&mut self, source: QUICConnectionID) -> Result<(), QUICError> {
        let reset_token = QUICConnection::reset_token_with(&self.config, &source, &mut *self.random)?;
        self.local_ids.issue(QUICIssuedID { id: source, reset_token: Some(reset_token) });
        Ok(())
    }

    /// The Initial keys of `destination` (RFC 9001 §5.2).
    pub fn install_initial(&mut self, destination: &QUICConnectionID) -> Result<(), QUICError> {
        let client = QUICSecret::initial(self.profile, destination, QUICRole::Client)?;
        let server = QUICSecret::initial(self.profile, destination, QUICRole::Server)?;
        let (read, write) = match self.role {
            QUICRole::Client => (server, client),
            QUICRole::Server => (client, server),
        };
        let space = &mut self.spaces[QUICPacketNumberSpace::Initial.index()];
        space.read = Some(QUICKeys::new(self.profile, &read)?);
        space.write = Some(QUICKeys::new(self.profile, &write)?);
        Ok(())
    }

    /// The space of a TLS encryption level; early data shares the application's.
    pub const fn space_of(level: TLSEncryptionLevel) -> QUICPacketNumberSpace {
        match level {
            TLSEncryptionLevel::Initial => QUICPacketNumberSpace::Initial,
            TLSEncryptionLevel::Handshake => QUICPacketNumberSpace::Handshake,
            TLSEncryptionLevel::EarlyData | TLSEncryptionLevel::Application => QUICPacketNumberSpace::ApplicationData,
        }
    }

    pub const fn level_of(space: QUICPacketNumberSpace) -> TLSEncryptionLevel {
        match space {
            QUICPacketNumberSpace::Initial => TLSEncryptionLevel::Initial,
            QUICPacketNumberSpace::Handshake => TLSEncryptionLevel::Handshake,
            QUICPacketNumberSpace::ApplicationData => TLSEncryptionLevel::Application,
        }
    }

    // ---- TLS ----

    /// Moves what TLS produced: its secrets become keys, its handshake
    /// bytes CRYPTO data, its events the connection's; the peer's transport
    /// parameters are applied once known (RFC 9001 §4.1).
    pub fn process_tls(&mut self, now: Instant) -> Result<(), QUICError> {
        while let Some(secret) = self.tls.take_secret() {
            let quic = QUICSecret { hash: secret.hash, aead: secret.aead, secret: secret.secret };
            match (secret.level, secret.direction) {
                (TLSEncryptionLevel::Handshake, direction) => {
                    let keys = QUICKeys::new(self.profile, &quic)?;
                    let space = &mut self.spaces[QUICPacketNumberSpace::Handshake.index()];
                    match direction {
                        TLSDirection::Reading => space.read = Some(keys),
                        TLSDirection::Writing => space.write = Some(keys),
                    }
                }
                (TLSEncryptionLevel::EarlyData, _) => self.zero_rtt = Some(QUICKeys::new(self.profile, &quic)?),
                (TLSEncryptionLevel::Application, TLSDirection::Reading) => self.one_rtt_read = Some(quic),
                (TLSEncryptionLevel::Application, TLSDirection::Writing) => self.one_rtt_write = Some(quic),
                (TLSEncryptionLevel::Initial, _) => return Err(QUICError::Config),
            }
            if self.one_rtt.is_none() && self.one_rtt_read.is_some() && self.one_rtt_write.is_some() {
                let (Some(read), Some(write)) = (self.one_rtt_read.take(), self.one_rtt_write.take()) else {
                    return Err(QUICError::State);
                };
                self.one_rtt = Some(QUICOneRTT::new(self.profile, read, write)?);
            }
        }
        while let Some((level, bytes)) = self.tls.take_handshake() {
            self.spaces[QUICConnection::space_of(level).index()].crypto_send.write(&bytes)?;
        }
        if self.peer_parameters.is_none()
            && let Some(bytes) = self.tls.session.transport_parameters.clone()
        {
            self.apply_parameters(&bytes, now)?;
        }
        while let Some(event) = self.tls.poll_event() {
            if event == TLSEvent::Connected {
                self.complete_handshake(now)?;
            }
        }
        Ok(())
    }

    /// The peer's transport parameters (RFC 9000 §7.3, §7.4, §18.2; RFC 9368 §4).
    pub fn apply_parameters(&mut self, bytes: &[u8], now: Instant) -> Result<(), QUICError> {
        let parameters = QUICTransportParameters::decode(bytes, self.role.peer())?;
        let invalid = QUICError::parameter;
        // The connection IDs of the handshake, authenticated (RFC 9000 §7.3).
        if parameters.initial_source_connection_id.is_none()
            || parameters.initial_source_connection_id != self.peer_initial_source
        {
            return Err(invalid("initial_source_connection_id does not match"));
        }
        if self.role == QUICRole::Client {
            if parameters.original_destination_connection_id != Some(self.original_destination) {
                return Err(invalid("original_destination_connection_id does not match"));
            }
            if parameters.retry_source_connection_id != self.retry_source {
                return Err(invalid("retry_source_connection_id does not match"));
            }
            if parameters.preferred_address.is_some()
                && self.peer_ids.current().is_some_and(|current| current.id.is_empty())
            {
                return Err(invalid("a preferred address with a zero-length connection ID"));
            }
        }
        self.check_version_information(&parameters)?;
        if let Some(remembered) = self.zero_rtt_parameters.take() {
            match self.tls.session.early_data {
                crate::protocol::tls::TLSEarlyData::Accepted => {
                    QUICConnection::check_remembered(&remembered, &parameters)?
                }
                _ => self.reject_zero_rtt(),
            }
        }
        self.send_credit.raise(parameters.initial_max_data);
        self.streams.apply(&parameters);
        self.recovery.max_ack_delay = Duration::from_millis(parameters.max_ack_delay);
        if let Some(token) = parameters.stateless_reset_token
            && let Some(first) = self.peer_ids.ids.get_mut(&0)
        {
            first.reset_token = Some(token);
        }
        // The connection ID of a preferred address is the server's of sequence 1 (RFC 9000 §5.1.1).
        if let Some(address) = &parameters.preferred_address {
            let issued = QUICIssuedID { id: address.connection_id, reset_token: Some(address.reset_token) };
            self.peer_ids.insert(1, 0, issued).map_err(|_| invalid("the connection ID of preferred_address"))?;
        }
        // The idle timeout is the smaller of both that are set (RFC 9000 §10.1).
        let peer_idle = Duration::from_millis(parameters.max_idle_timeout);
        self.idle_timeout = match (self.idle_timeout, peer_idle.is_zero()) {
            (Some(own), false) => Some(own.min(peer_idle)),
            (None, false) => Some(peer_idle),
            (own, true) => own,
        };
        if self.role == QUICRole::Client {
            // What 0-RTT of a later connection may assume (RFC 9000 §7.4.1).
            self.tls.session.application = QUICConnection::remembered(&parameters);
        }
        self.peer_parameters = Some(parameters);
        self.issue_connection_ids()?;
        self.set_loss_timer(now);
        Ok(())
    }

    /// A server that accepted 0-RTT keeps at least the limits it had (RFC
    /// 9000 §7.4.1, RFC 9221 §3): PROTOCOL_VIOLATION otherwise.
    pub fn check_remembered(
        remembered: &QUICTransportParameters,
        parameters: &QUICTransportParameters,
    ) -> Result<(), QUICError> {
        let pairs = [
            (remembered.initial_max_data, parameters.initial_max_data),
            (remembered.initial_max_stream_data_bidi_local, parameters.initial_max_stream_data_bidi_local),
            (remembered.initial_max_stream_data_bidi_remote, parameters.initial_max_stream_data_bidi_remote),
            (remembered.initial_max_stream_data_uni, parameters.initial_max_stream_data_uni),
            (remembered.initial_max_streams_bidi, parameters.initial_max_streams_bidi),
            (remembered.initial_max_streams_uni, parameters.initial_max_streams_uni),
            (remembered.active_connection_id_limit, parameters.active_connection_id_limit),
            (remembered.max_datagram_frame_size, parameters.max_datagram_frame_size),
        ];
        if pairs.iter().any(|(before, now)| now < before) {
            return Err(QUICError::transport(QUICErrorCode::PROTOCOL_VIOLATION, "limits below those of 0-RTT"));
        }
        Ok(())
    }

    /// The server refused 0-RTT (RFC 9001 §4.6.2): the streams and data of
    /// 0-RTT are gone, and the application must send again what it still wants.
    pub fn reject_zero_rtt(&mut self) {
        self.zero_rtt = None;
        self.streams = QUICStreams::new(self.role, &self.local_parameters);
        self.send_credit = QUICSendCredit::new(0);
        let space = QUICPacketNumberSpace::ApplicationData.index();
        let sent = core::mem::take(&mut self.recovery.spaces[space].sent);
        for packet in sent.values().filter(|packet| packet.in_flight) {
            self.recovery.bytes_in_flight = self.recovery.bytes_in_flight.saturating_sub(packet.size as u64);
        }
        self.recovery.spaces[space].last_ack_eliciting = None;
        self.outgoing_datagrams.clear();
        self.push_event(QUICEvent::ZeroRTTRejected);
    }

    /// Version Information (RFC 9368 §4): a server's must name the
    /// version in use, chosen from the client's; a client's chosen must be
    /// the version of its packets.
    pub fn check_version_information(&self, parameters: &QUICTransportParameters) -> Result<(), QUICError> {
        let error = QUICError::transport(QUICErrorCode::VERSION_NEGOTIATION_ERROR, "version information");
        // A client that followed a Version Negotiation needs the server's,
        // which must lead to the same choice (RFC 9368 §4).
        let Some(information) = &parameters.version_information else {
            return if self.negotiated_from.is_some() { Err(error) } else { Ok(()) };
        };
        if self.role == QUICRole::Client && self.negotiated_from.is_some() {
            let mut offered = information.available.clone();
            offered.push(self.version);
            let choice = self.config.supported_versions().into_iter().find(|version| offered.contains(version));
            if information.available.is_empty() || choice != Some(self.version) {
                return Err(error);
            }
        }
        match self.role {
            QUICRole::Server if information.chosen != self.version => Err(error),
            QUICRole::Client
                if information.chosen != self.version
                    || !self.config.supported_versions().contains(&information.chosen) =>
            {
                Err(error)
            }
            _ => Ok(()),
        }
    }

    /// The handshake completed (RFC 9001 §4.1.1): a server confirms it at
    /// once and sends HANDSHAKE_DONE (§4.1.2).
    pub fn complete_handshake(&mut self, now: Instant) -> Result<(), QUICError> {
        if self.peer_parameters.is_none() {
            return Err(QUICError::parameter("no transport parameters"));
        }
        self.handshake_complete = true;
        self.state = QUICConnectionState::Established;
        self.events.push_back(QUICEvent::Connected);
        if self.role == QUICRole::Server {
            self.pending.handshake_done = true;
            self.confirm_handshake(now);
        }
        Ok(())
    }

    /// The handshake is confirmed: the Handshake keys go (RFC 9001 §4.9.2).
    pub fn confirm_handshake(&mut self, now: Instant) {
        if self.handshake_confirmed {
            return;
        }
        self.handshake_confirmed = true;
        self.validated = true;
        self.discard_space(QUICPacketNumberSpace::Handshake);
        // A client sends no more 0-RTT packets once it has 1-RTT keys (RFC 9001 §4.9.3).
        self.zero_rtt = None;
        self.events.push_back(QUICEvent::HandshakeConfirmed);
        self.set_loss_timer(now);
    }

    /// Discards the keys of `space` and its recovery state (RFC 9001 §4.9, RFC 9002 §6.4).
    pub fn discard_space(&mut self, space: QUICPacketNumberSpace) {
        if self.spaces[space.index()].discarded {
            return;
        }
        self.spaces[space.index()].discard();
        self.recovery.discard(space);
    }

    /// Issues connection IDs up to the peer's limit (RFC 9000 §5.1.1).
    pub fn issue_connection_ids(&mut self) -> Result<(), QUICError> {
        if self.config.connection_id_length == 0 {
            return Ok(());
        }
        let limit = self.peer_parameters.as_ref().map_or(2, |parameters| parameters.active_connection_id_limit);
        // Eight at most: enough to migrate, few enough to keep.
        while (self.local_ids.ids.len() as u64) < limit.min(8) {
            let id = QUICConnectionID::random(self.config.connection_id_length, &mut *self.random)?;
            if self.local_ids.contains(&id) {
                continue;
            }
            let reset_token = QUICConnection::reset_token_with(&self.config, &id, &mut *self.random)?;
            let sequence = self.local_ids.issue(QUICIssuedID { id, reset_token: Some(reset_token) });
            self.pending.new_connection_ids.push(sequence);
        }
        Ok(())
    }

    // ---- Receiving ----

    /// Takes a datagram from `remote` with its ECN codepoint, received at
    /// `now` (RFC 9000 §12.2): its packets are read in order. Errors close
    /// the connection; they are reported by [`QUICEvent::Closed`].
    pub fn receive(&mut self, datagram: &[u8], remote: IPEndpoint, ecn: QUICECN, now: Instant) {
        match self.state {
            QUICConnectionState::Closed | QUICConnectionState::Draining => return,
            QUICConnectionState::Closing => {
                // A closing end answers what arrives with its CONNECTION_CLOSE (RFC 9000 §10.2.1).
                if let Some(closing) = &mut self.closing {
                    closing.due = true;
                }
                return;
            }
            _ => {}
        }
        // No migration during the handshake, nor by a server (RFC 9000 §9, §9.6).
        let new_path = remote != self.remote;
        if new_path && (!self.handshake_confirmed || self.role == QUICRole::Client) {
            return;
        }
        if !self.validated {
            self.received_bytes += datagram.len() as u64;
        }
        if !self.path_validated && !new_path {
            self.path_received += datagram.len() as u64;
        }
        let responses = self.pending.path_responses.len();
        self.non_probing = false;
        let mut offset = 0;
        let mut first_destination = None;
        let mut processed = false;
        while offset < datagram.len() {
            let rest = &datagram[offset..];
            let Ok(packet) = QUICPacket::decode(rest, self.config.connection_id_length) else { break };
            let length = packet.length(rest);
            match self.receive_packet(packet, &rest[..length], &mut first_destination, ecn, now) {
                Ok(true) => processed = true,
                Ok(false) => {}
                Err(error) => {
                    self.fail(error, now);
                    return;
                }
            }
            offset += length;
            // A peer that closed sent nothing more to read (RFC 9000 §10.2.2).
            if matches!(self.state, QUICConnectionState::Draining | QUICConnectionState::Closed) {
                break;
            }
        }
        // The answers to this datagram's challenges go where it came from,
        // within three times its size there (RFC 9000 §8.2.1, §8.2.2, §9.1).
        for response in self.pending.path_responses.iter_mut().skip(responses) {
            response.destination = remote;
            response.limit = datagram.len().saturating_mul(QUICConfig::AMPLIFICATION_FACTOR as usize);
        }
        if processed && new_path && self.non_probing {
            self.migrate(remote, datagram.len(), now);
        }
        if processed {
            self.restart_idle(now);
        } else if self.is_stateless_reset(datagram) {
            self.closing = None;
            self.state = QUICConnectionState::Draining;
            self.close_deadline(now);
            self.events.push_back(QUICEvent::Closed { reason: QUICCloseReason::StatelessReset });
            return;
        }
        if let Err(error) = self.process_tls(now).and_then(|()| self.retry_buffered(now)) {
            self.fail(error, now);
        }
        self.set_loss_timer(now);
    }

    /// A packet of the peer was processed: the idle timer starts again (RFC 9000 §10.1).
    pub fn restart_idle(&mut self, now: Instant) {
        self.last_activity = now;
        self.eliciting_sent = false;
    }

    /// Whether `datagram`, which nothing could read, ends with a stateless
    /// reset token of the peer (RFC 9000 §10.3.1).
    pub fn is_stateless_reset(&self, datagram: &[u8]) -> bool {
        datagram.len() >= 21
            && datagram[0] & 0x80 == 0
            && datagram[datagram.len() - 16..].try_into().is_ok_and(|token| self.peer_ids.is_reset_token(token))
    }

    /// Reads the packets buffered while their keys were missing.
    pub fn retry_buffered(&mut self, now: Instant) -> Result<(), QUICError> {
        if self.buffered.packets.is_empty() {
            return Ok(());
        }
        let packets = core::mem::take(&mut self.buffered.packets);
        for (bytes, ecn) in packets {
            if let Ok(packet) = QUICPacket::decode(&bytes, self.config.connection_id_length) {
                let mut first = None;
                if self.receive_packet(packet, &bytes, &mut first, ecn, now)? {
                    self.restart_idle(now);
                }
            }
        }
        self.process_tls(now)
    }

    /// One packet of a datagram; `Ok(true)` if it was processed, `Ok(false)`
    /// if it was dropped, an error if it breaks the protocol.
    pub fn receive_packet(
        &mut self,
        packet: QUICPacket<'_>,
        bytes: &[u8],
        first_destination: &mut Option<QUICConnectionID>,
        ecn: QUICECN,
        now: Instant,
    ) -> Result<bool, QUICError> {
        let protected = match packet {
            QUICPacket::Protected(protected) => protected,
            QUICPacket::VersionNegotiation(negotiation) => {
                // It echoes the connection IDs of the client's packet (RFC 9000 §17.2.1).
                if negotiation.destination == self.initial_source.as_slice()
                    && negotiation.source == self.original_destination.as_slice()
                {
                    self.receive_version_negotiation(negotiation.versions().collect(), now);
                }
                return Ok(false);
            }
            QUICPacket::Retry(retry) => {
                // Without the QUIC bit only if this end allows it (RFC 9000 §17.2, RFC 9287 §3).
                if bytes[0] & 0x40 == 0 && !self.local_parameters.grease_quic_bit {
                    return Ok(false);
                }
                return self.receive_retry(retry.source, retry.token.to_vec(), bytes, retry.version, now);
            }
            QUICPacket::Unsupported(_) => return Ok(false),
        };
        let destination = protected.header.destination();
        // The packets of a datagram go to one connection ID (RFC 9000 §12.2).
        if first_destination.is_some_and(|first| first != destination) {
            return Ok(false);
        }
        *first_destination = Some(destination);
        if !self.accepts_destination(&protected.header) {
            return Ok(false);
        }
        // Without the QUIC bit only if this end allows it (RFC 9000 §17.2, RFC 9287).
        if !protected.fixed && !self.local_parameters.grease_quic_bit {
            return Ok(false);
        }
        let packet_type = protected.header.packet_type();
        if let QUICHeader::Long(long) = &protected.header {
            if long.version != self.version {
                return Ok(false);
            }
            // The peer's Source Connection ID stays that of its first packet (RFC 9000 §7.2).
            if self.peer_initial_source.is_some_and(|source| source != long.source) {
                return Ok(false);
            }
            // A client drops a server's Initial with a token (RFC 9000 §17.2.2).
            if self.role == QUICRole::Client && packet_type == QUICPacketType::Initial && !long.token.is_empty() {
                return Ok(false);
            }
            if packet_type == QUICPacketType::ZeroRTT && self.role == QUICRole::Client {
                return Ok(false);
            }
        }
        let Some(space) = packet_type.space() else { return Ok(false) };
        if self.spaces[space.index()].discarded {
            return Ok(false);
        }
        // Keys not yet there: the packet waits for them, up to a limit (RFC 9001 §4.1.4, §5.7).
        if !self.has_read_keys(packet_type) {
            let later = match packet_type {
                QUICPacketType::Handshake => true,
                QUICPacketType::ZeroRTT => self.role == QUICRole::Server && !self.handshake_complete,
                QUICPacketType::OneRTT => !self.handshake_complete,
                _ => false,
            };
            if later && self.buffered.packets.len() < self.config.maximum_buffered_packets {
                self.buffered.packets.push((bytes.to_vec(), ecn));
            }
            return Ok(false);
        }
        let mut scratch = core::mem::take(&mut self.scratch);
        scratch.clear();
        scratch.extend_from_slice(bytes);
        let result = self.unprotect(packet_type, space, protected.number_offset, &mut scratch, now);
        let (number, header_length, payload_length) = match result {
            Ok(Some(found)) => found,
            Ok(None) => {
                self.scratch = scratch;
                return Ok(false);
            }
            Err(error) => {
                self.scratch = scratch;
                return Err(error);
            }
        };
        // The reserved bits are zero once protection is removed (RFC 9000 §17.2, §17.3.1).
        let reserved = if scratch[0] & 0x80 != 0 { scratch[0] & 0x0C } else { scratch[0] & 0x18 };
        if reserved != 0 {
            self.scratch = scratch;
            return Err(QUICError::transport(QUICErrorCode::PROTOCOL_VIOLATION, "reserved bits set"));
        }
        if self.spaces[space.index()].received.is_duplicate(number) {
            self.scratch = scratch;
            return Ok(false);
        }
        if let QUICHeader::Long(long) = &protected.header {
            self.learn_peer(long, packet_type)?;
        }
        let payload = scratch[header_length..header_length + payload_length].to_vec();
        self.scratch = scratch;
        let largest = self.spaces[space.index()].received.largest.map(|(largest, _)| largest);
        let (ack_eliciting, non_probing) = self.receive_frames(packet_type, space, &payload, &destination, now)?;
        // Only the highest-numbered packet that is not probing moves the peer (RFC 9000 §9.3).
        if packet_type == QUICPacketType::OneRTT && non_probing && largest.is_none_or(|largest| number > largest) {
            self.non_probing = true;
        }
        let max_ack_delay = self.config.max_ack_delay;
        let limit = self.config.maximum_received_ranges;
        let received = &mut self.spaces[space.index()];
        received.received.receive(space, number, ack_eliciting, ecn, max_ack_delay, limit, now);
        received.unacknowledged = true;
        if packet_type == QUICPacketType::OneRTT {
            self.update_spin(number, bytes[0]);
        }
        // A server's address validation and the end of Initial packets (RFC 9001 §4.9.1, RFC 9000 §8.1).
        if packet_type == QUICPacketType::Handshake && self.role == QUICRole::Server {
            self.validated = true;
            self.discard_space(QUICPacketNumberSpace::Initial);
        }
        Ok(true)
    }

    /// Whether a packet of `header` is for this connection: to one of its IDs,
    /// or a client's first packets to the ID it chose (RFC 9000 §5.2).
    pub fn accepts_destination(&self, header: &QUICHeader<'_>) -> bool {
        let destination = header.destination();
        if self.local_ids.contains(&destination) {
            return true;
        }
        let early = matches!(header.packet_type(), QUICPacketType::Initial | QUICPacketType::ZeroRTT);
        self.role == QUICRole::Server
            && early
            && (destination == self.original_destination || self.retry_source.is_some_and(|retry| retry == destination))
            || (self.role == QUICRole::Client && destination.is_empty() && self.config.connection_id_length == 0)
    }

    /// Whether keys to read packets of `packet_type` are there: 1-RTT ones
    /// only once the handshake completed (RFC 9001 §5.7).
    pub fn has_read_keys(&self, packet_type: QUICPacketType) -> bool {
        match packet_type {
            QUICPacketType::Initial => self.spaces[0].read.is_some(),
            QUICPacketType::Handshake => self.spaces[1].read.is_some(),
            QUICPacketType::ZeroRTT => self.zero_rtt.is_some() && self.role == QUICRole::Server,
            QUICPacketType::OneRTT => self.one_rtt.is_some() && self.handshake_complete,
            QUICPacketType::Retry => false,
        }
    }

    /// Removes the packet's protection in place (RFC 9001 §5): its number,
    /// the length of its header and of its plaintext payload; `None` if it
    /// does not authenticate, which drops it. 1-RTT packets pick their key
    /// by the key phase, and one of the next phase updates the keys (§6).
    pub fn unprotect(
        &mut self,
        packet_type: QUICPacketType,
        space: QUICPacketNumberSpace,
        number_offset: usize,
        packet: &mut [u8],
        now: Instant,
    ) -> Result<Option<(u64, usize, usize)>, QUICError> {
        let largest = self.spaces[space.index()].received.largest.map(|(largest, _)| largest);
        let header_keys = match packet_type {
            QUICPacketType::Initial => self.spaces[0].read.as_ref().map(|keys| &keys.header),
            QUICPacketType::Handshake => self.spaces[1].read.as_ref().map(|keys| &keys.header),
            QUICPacketType::ZeroRTT => self.zero_rtt.as_ref().map(|keys| &keys.header),
            QUICPacketType::OneRTT => self.one_rtt.as_ref().map(|keys| &keys.read_header),
            QUICPacketType::Retry => None,
        };
        let Some(header_keys) = header_keys else { return Ok(None) };
        let Ok((length, truncated)) = header_keys.remove(packet, number_offset) else { return Ok(None) };
        let number = QUICPacketNumber::decode(truncated, length, largest);
        let header = number_offset + length;
        let opened = match packet_type {
            QUICPacketType::OneRTT => self.open_one_rtt(number, header, packet, now)?,
            _ => {
                let key = match packet_type {
                    QUICPacketType::Initial => self.spaces[0].read.as_ref().map(|keys| &keys.packet),
                    QUICPacketType::Handshake => self.spaces[1].read.as_ref().map(|keys| &keys.packet),
                    _ => self.zero_rtt.as_ref().map(|keys| &keys.packet),
                };
                key.and_then(|key| key.open(number, header, packet).ok())
            }
        };
        match opened {
            Some(payload) => Ok(Some((number, header, payload))),
            None => {
                // Across all keys, within the smallest limit of those used (RFC 9001 §6.6).
                self.integrity_failures += 1;
                let keys = [&self.spaces[0].read, &self.spaces[1].read, &self.zero_rtt];
                let limits = keys.into_iter().flatten().map(|keys| keys.packet.integrity_limit());
                let limit = limits.chain(self.one_rtt.as_ref().map(|keys| keys.read.integrity_limit())).min();
                self.integrity_limit = self.integrity_limit.min(limit.unwrap_or(u64::MAX));
                if self.integrity_failures > self.integrity_limit {
                    return Err(QUICError::transport(QUICErrorCode::AEAD_LIMIT_REACHED, "too many forgeries"));
                }
                Ok(None)
            }
        }
    }

    /// Opens a 1-RTT packet with the key of its phase (RFC 9001 §6.2–§6.5).
    pub fn open_one_rtt(
        &mut self,
        number: u64,
        header: usize,
        packet: &mut [u8],
        now: Instant,
    ) -> Result<Option<usize>, QUICError> {
        let profile = self.profile;
        let pto = self.recovery.base_probe_timeout(QUICPacketNumberSpace::ApplicationData);
        let Some(keys) = &mut self.one_rtt else { return Ok(None) };
        let phase = packet[0] & 0x04 != 0;
        if let Some((_, discard_at)) = &keys.previous_read
            && *discard_at <= now
        {
            keys.previous_read = None;
        }
        if phase == keys.phase {
            let opened = keys.read.open(number, header, packet).ok();
            if opened.is_some() {
                keys.first_received = Some(keys.first_received.map_or(number, |first| first.min(number)));
            }
            return Ok(opened);
        }
        // A packet of the previous phase: below the first of this one, or any
        // while none of this one came, as after this end's update (RFC 9001 §6.5).
        if let Some((previous, _)) = &keys.previous_read
            && keys.first_received.is_none_or(|first| number < first)
        {
            return Ok(previous.open(number, header, packet).ok());
        }
        // The peer updated: the next key, then this end's update (RFC 9001 §6.2).
        match keys.next_read.open(number, header, packet) {
            Ok(opened) => {
                keys.update(profile, now + pto * 3)?;
                keys.first_received = Some(number);
                Ok(Some(opened))
            }
            // The old key after newer ones protected lower numbers (RFC 9001 §6.4).
            Err(_)
                if keys
                    .previous_read
                    .as_ref()
                    .is_some_and(|(previous, _)| previous.open(number, header, packet).is_ok()) =>
            {
                Err(QUICError::transport(QUICErrorCode::KEY_UPDATE_ERROR, "old keys after new ones"))
            }
            Err(_) => Ok(None),
        }
    }

    /// The peer moved to `remote` (RFC 9000 §9.3): the new path is validated
    /// with a challenge, limited to three times what came from it until then,
    /// with a new connection ID if there is one (§9.5); the congestion
    /// controller and RTT start over unless only the port changed (§9.4).
    pub fn migrate(&mut self, remote: IPEndpoint, received: usize, now: Instant) {
        let address_changed = remote.address != self.remote.address;
        self.remote = remote;
        self.peer_ids.rotate();
        let retiring = core::mem::take(&mut self.peer_ids.retiring);
        self.pending.retire_connection_ids.extend(retiring);
        self.spin = false;
        self.spin_largest = None;
        let mut challenge = [0u8; 8];
        if self.random.fill(&mut challenge).is_err() {
            return;
        }
        self.path_challenge = Some(challenge);
        self.pending.challenge_due = true;
        self.path_validated = false;
        self.path_received = received as u64;
        self.path_sent = 0;
        if address_changed {
            let congestion: Box<dyn super::QUICCongestionControl> = match self.config.congestion {
                super::QUICCongestionKind::NewReno => Box::new(QUICNewReno::new(self.config.datagram_size)),
            };
            self.recovery.congestion = congestion;
            self.recovery.rtt = super::QUICRTT::new(self.config.initial_rtt);
        }
        self.set_loss_timer(now);
    }

    /// A client moves to a new local address (RFC 9000 §9.2): with a new
    /// connection ID for the peer to see, and a challenge of the path. The
    /// caller sends from the new address afterwards. Fails with
    /// [`QUICError::State`] before confirmation, when the server disabled
    /// it, or without a connection ID to spare.
    pub fn migrate_local(&mut self, now: Instant) -> Result<(), QUICError> {
        let disabled = self.peer_parameters.as_ref().is_some_and(|parameters| parameters.disable_active_migration);
        if self.role != QUICRole::Client || !self.handshake_confirmed || disabled || !self.peer_ids.rotate() {
            return Err(QUICError::State);
        }
        let retiring = core::mem::take(&mut self.peer_ids.retiring);
        self.pending.retire_connection_ids.extend(retiring);
        self.spin = false;
        self.spin_largest = None;
        let mut challenge = [0u8; 8];
        self.random.fill(&mut challenge).map_err(|_| QUICError::Random)?;
        self.path_challenge = Some(challenge);
        self.pending.challenge_due = true;
        self.set_loss_timer(now);
        Ok(())
    }

    /// The peer's connection IDs from its long headers (RFC 9000 §7.2):
    /// a client takes the server's first Source Connection ID.
    pub fn learn_peer(&mut self, header: &QUICLongHeader<'_>, packet_type: QUICPacketType) -> Result<(), QUICError> {
        if self.role != QUICRole::Client || self.server_heard {
            return Ok(());
        }
        if matches!(packet_type, QUICPacketType::Initial | QUICPacketType::Handshake) {
            self.server_heard = true;
            self.peer_initial_source = Some(header.source);
            self.peer_ids = QUICPeerConnectionIDs::new(header.source, None, self.config.active_connection_id_limit);
        }
        Ok(())
    }

    /// The latency spin bit (RFC 9000 §17.4): a server reflects it, a
    /// client inverts it, on each packet that raises the largest number.
    pub fn update_spin(&mut self, number: u64, first: u8) {
        if !self.spin_enabled || self.spin_largest.is_some_and(|largest| number <= largest) {
            return;
        }
        self.spin_largest = Some(number);
        let received = first & 0x20 != 0;
        self.spin = match self.role {
            QUICRole::Server => received,
            QUICRole::Client => !received,
        };
    }

    /// A Version Negotiation packet (RFC 9000 §6.2, RFC 9368 §4): only a
    /// client before any packet of the server; ignored if it lists the
    /// version in use, else the connection fails if none is acceptable.
    pub fn receive_version_negotiation(&mut self, versions: Vec<QUICVersion>, now: Instant) {
        // Once, before anything else of the server, and never one that lists
        // the version tried: that one is forged (RFC 9368 §4).
        if self.role != QUICRole::Client
            || self.server_heard
            || self.retry_source.is_some()
            || self.negotiated_from.is_some()
            || versions.contains(&self.version)
        {
            return;
        }
        let choice = self.config.supported_versions().into_iter().find(|version| versions.contains(version));
        let restarted = match (choice, self.restart.clone()) {
            (Some(version), Some(restart)) => QUICConnection::derived_random(&mut *self.random).and_then(|random| {
                QUICConnection::client_with_version(
                    self.config.clone(),
                    restart.tls,
                    restart.server_name.as_deref(),
                    self.remote,
                    random,
                    now,
                    restart.time,
                    version,
                    Some(self.version),
                )
            }),
            _ => Err(QUICError::Config),
        };
        match restarted {
            Ok(connection) => *self = connection,
            Err(_) => {
                self.state = QUICConnectionState::Closed;
                self.events.push_back(QUICEvent::Closed { reason: QUICCloseReason::VersionNegotiation });
            }
        }
    }

    /// A Retry packet (RFC 9000 §17.2.5, RFC 9001 §5.8): a client accepts
    /// one, authenticated, before any other packet of the server, and starts
    /// again with its token and the server's new connection ID.
    pub fn receive_retry(
        &mut self,
        source: QUICConnectionID,
        token: Vec<u8>,
        bytes: &[u8],
        version: QUICVersion,
        now: Instant,
    ) -> Result<bool, QUICError> {
        if self.role != QUICRole::Client
            || self.server_heard
            || self.retry_source.is_some()
            || version != self.version
            || token.is_empty()
            || source == self.original_destination
            || !super::QUICRetryIntegrity::verify(self.profile, &self.original_destination, bytes)
        {
            return Ok(false);
        }
        // The server's Initial still names its own Source Connection ID, which
        // the client then sends to and its parameters authenticate (RFC 9000 §7.2, §7.3).
        self.retry_source = Some(source);
        self.token = token;
        self.peer_ids = QUICPeerConnectionIDs::new(source, None, self.config.active_connection_id_limit);
        // New Initial keys; the CRYPTO data and 0-RTT go again (RFC 9000 §17.2.5.3).
        self.install_initial(&source)?;
        let lost: Vec<QUICSentPacket> = core::mem::take(&mut self.recovery.spaces[0].sent).into_values().collect();
        for packet in lost.iter().filter(|packet| packet.in_flight) {
            self.recovery.bytes_in_flight = self.recovery.bytes_in_flight.saturating_sub(packet.size as u64);
        }
        self.recovery.spaces[0] = Default::default();
        self.recovery.pto_count = 0;
        for packet in lost {
            self.lose_frames(QUICPacketNumberSpace::Initial, &packet.frames);
        }
        let lost: Vec<QUICSentPacket> = core::mem::take(&mut self.recovery.spaces[2].sent).into_values().collect();
        for packet in &lost {
            if packet.in_flight {
                self.recovery.bytes_in_flight = self.recovery.bytes_in_flight.saturating_sub(packet.size as u64);
            }
        }
        for packet in lost {
            self.lose_frames(QUICPacketNumberSpace::ApplicationData, &packet.frames);
        }
        self.set_loss_timer(now);
        Ok(true)
    }

    /// The frames of a packet's payload (RFC 9000 §12.4): at least one,
    /// each allowed in the packet's type. Returns whether one elicits an ACK,
    /// and whether one is not probing (§9.1).
    pub fn receive_frames(
        &mut self,
        packet_type: QUICPacketType,
        space: QUICPacketNumberSpace,
        payload: &[u8],
        destination: &QUICConnectionID,
        now: Instant,
    ) -> Result<(bool, bool), QUICError> {
        if payload.is_empty() {
            return Err(QUICError::transport(QUICErrorCode::PROTOCOL_VIOLATION, "a packet without frames"));
        }
        let mut ack_eliciting = false;
        let mut non_probing = false;
        let mut frames = QUICFrames::new(payload);
        loop {
            let start = frames.reader.position();
            let Some(frame) = frames.next() else { break };
            let frame = frame?;
            let size = frames.reader.position() - start;
            let frame_type = frame.frame_type();
            if !frame_type.permits(packet_type) {
                return Err(QUICError::violation(frame_type, "a frame not allowed in its packet type"));
            }
            ack_eliciting |= frame_type.is_ack_eliciting();
            non_probing |= !frame_type.is_probing();
            self.receive_frame(frame, size, space, destination, now).map_err(|error| error.in_frame(frame_type))?;
            if matches!(self.state, QUICConnectionState::Draining | QUICConnectionState::Closed) {
                break;
            }
        }
        Ok((ack_eliciting, non_probing))
    }

    /// One frame, of `size` bytes on the wire.
    pub fn receive_frame(
        &mut self,
        frame: QUICFrame<'_>,
        size: usize,
        space: QUICPacketNumberSpace,
        destination: &QUICConnectionID,
        now: Instant,
    ) -> Result<(), QUICError> {
        let violation = |reason| QUICError::transport(QUICErrorCode::PROTOCOL_VIOLATION, reason);
        match frame {
            QUICFrame::Padding { .. } | QUICFrame::Ping => {}
            QUICFrame::ACK(ack) => self.receive_ack(space, &ack, now)?,
            QUICFrame::Crypto { offset, data } => self.receive_crypto(space, offset, data)?,
            QUICFrame::NewToken { token } => {
                if self.role == QUICRole::Server {
                    return Err(violation("NEW_TOKEN from a client"));
                }
                // The latest token is the one to keep (RFC 9000 §8.1.3).
                self.events.retain(|event| !matches!(event, QUICEvent::NewToken { .. }));
                self.push_event(QUICEvent::NewToken { token: token.to_vec() });
            }
            QUICFrame::Stream { stream, offset, data, fin } => self.receive_stream(stream, offset, data, fin)?,
            QUICFrame::ResetStream { stream, error, final_size } => {
                let frame_type = QUICFrameType::RESET_STREAM;
                let Some(found) = self.streams.frame(stream, frame_type, true, &mut self.events)? else {
                    return Ok(());
                };
                let Some(receive) = &mut found.receive else { return Ok(()) };
                let Some(new) = receive.receive_reset(error, final_size)? else { return Ok(()) };
                self.receive_credit.receive(new)?;
                // What was never read counts as read for the connection's credit (RFC 9000 §4.5).
                let unread = final_size - receive.buffer.read;
                receive.buffer.read = final_size;
                self.receive_credit.consume(unread);
                // A stream this end stopped reading ends here; otherwise the application learns of it.
                let stopped = receive.stop.is_some();
                if stopped {
                    receive.state = super::QUICReceiveState::ResetRead;
                }
                if self.receive_credit.update().is_some() {
                    self.pending.max_data = true;
                }
                if stopped {
                    self.streams.collect();
                } else {
                    self.push_event(QUICEvent::StreamReset { stream, error });
                }
            }
            QUICFrame::StopSending { stream, error } => {
                let frame_type = QUICFrameType::STOP_SENDING;
                let Some(found) = self.streams.frame(stream, frame_type, false, &mut self.events)? else {
                    return Ok(());
                };
                if let Some(send) = &mut found.send
                    && send.reset.is_none()
                    && !send.is_terminal()
                {
                    // An endpoint that receives STOP_SENDING resets the stream (RFC 9000 §3.5).
                    send.reset(error);
                    self.streams.schedule(stream);
                    self.push_event(QUICEvent::StopSending { stream, error });
                }
            }
            QUICFrame::MaxData { maximum } => {
                self.send_credit.raise(maximum);
            }
            QUICFrame::MaxStreamData { stream, maximum } => {
                let frame_type = QUICFrameType::MAX_STREAM_DATA;
                let Some(found) = self.streams.frame(stream, frame_type, false, &mut self.events)? else {
                    return Ok(());
                };
                if let Some(send) = &mut found.send
                    && send.credit.raise(maximum)
                {
                    self.streams.schedule(stream);
                    self.push_event(QUICEvent::StreamWritable { stream });
                }
            }
            QUICFrame::MaxStreams { bidirectional, maximum } => {
                self.streams.raise_limit(bidirectional, maximum, &mut self.events);
            }
            QUICFrame::DataBlocked { .. } | QUICFrame::StreamsBlocked { .. } => {}
            QUICFrame::StreamDataBlocked { stream, .. } => {
                let frame_type = QUICFrameType::STREAM_DATA_BLOCKED;
                self.streams.frame(stream, frame_type, true, &mut self.events)?;
            }
            QUICFrame::NewConnectionID { sequence, retire_prior_to, id, reset_token } => {
                if self.peer_ids.current().is_some_and(|current| current.id.is_empty()) {
                    return Err(violation("NEW_CONNECTION_ID to an end that uses zero-length IDs"));
                }
                let before = self.peer_ids.retiring.len();
                self.peer_ids.insert(sequence, retire_prior_to, QUICIssuedID { id, reset_token: Some(reset_token) })?;
                let retiring: Vec<u64> = self.peer_ids.retiring.drain(before..).collect();
                self.pending.retire_connection_ids.extend(retiring);
            }
            QUICFrame::RetireConnectionID { sequence } => {
                if self.config.connection_id_length == 0 {
                    return Err(violation("RETIRE_CONNECTION_ID to an end that uses zero-length IDs"));
                }
                if self.local_ids.retire(sequence, destination)?.is_some() {
                    self.issue_connection_ids()?;
                }
            }
            QUICFrame::PathChallenge { data } => {
                if self.pending.path_responses.len() < 4 {
                    let response = QUICPathResponse { data, destination: self.remote, limit: usize::MAX };
                    self.pending.path_responses.push_back(response);
                }
            }
            QUICFrame::PathResponse { data } => {
                // The path is validated by the answer to its challenge (RFC 9000 §8.2.3).
                if self.path_challenge == Some(data) {
                    self.path_challenge = None;
                    self.path_validated = true;
                }
            }
            QUICFrame::ConnectionClose { error, reason, .. } => {
                self.drain(QUICCloseReason::Peer { error, reason: reason.to_vec() }, now);
            }
            QUICFrame::ApplicationClose { error, reason } => {
                self.drain(QUICCloseReason::PeerApplication { error, reason: reason.to_vec() }, now);
            }
            QUICFrame::HandshakeDone => {
                if self.role == QUICRole::Server {
                    return Err(violation("HANDSHAKE_DONE from a client"));
                }
                self.confirm_handshake(now);
            }
            QUICFrame::Datagram { data } => {
                // The limit counts the frame's type, length and data (RFC 9221 §3).
                let maximum = self.local_parameters.max_datagram_frame_size;
                if maximum == 0 || size as u64 > maximum {
                    return Err(violation("a DATAGRAM frame not accepted"));
                }
                if self.datagrams.len() < self.config.maximum_datagrams {
                    self.datagrams.push_back(data.to_vec());
                    self.push_event(QUICEvent::Datagram);
                }
            }
        }
        Ok(())
    }

    /// An ACK frame (RFC 9000 §13.2, RFC 9002 §5, §6): what it acknowledges
    /// is released, what it shows lost goes again.
    pub fn receive_ack(
        &mut self,
        space: QUICPacketNumberSpace,
        ack: &QUICACKFrame<'_>,
        now: Instant,
    ) -> Result<(), QUICError> {
        if ack.largest >= self.spaces[space.index()].next_number {
            return Err(QUICError::transport(QUICErrorCode::PROTOCOL_VIOLATION, "an ACK of a packet never sent"));
        }
        let exponent = self.peer_parameters.as_ref().map_or(3, |parameters| parameters.ack_delay_exponent);
        let delay = Duration::from_micros(ack.delay.checked_shl(exponent as u32).unwrap_or(u64::MAX));
        let limited = self.streams.ready.is_empty();
        let result =
            self.recovery.acknowledge(space, ack.ranges(), delay, ack.ecn, self.handshake_confirmed, limited, now);
        if result.acknowledged.is_empty() {
            return Ok(());
        }
        // A client knows the server validated its address once it acknowledges a Handshake packet (RFC 9002 §6.2.2.1).
        if space == QUICPacketNumberSpace::Handshake && self.role == QUICRole::Client {
            self.validated = true;
        }
        // Unless a client is unsure the server validated its address (RFC 9002 Appendix A.7).
        if self.peer_validated() {
            self.recovery.pto_count = 0;
        }
        for packet in &result.acknowledged {
            self.acknowledge_frames(space, packet);
        }
        for packet in &result.lost {
            self.lose_frames(space, &packet.frames);
        }
        Ok(())
    }

    /// The frames of an acknowledged packet.
    pub fn acknowledge_frames(&mut self, space: QUICPacketNumberSpace, packet: &QUICSentPacket) {
        if space == QUICPacketNumberSpace::ApplicationData
            && let Some(keys) = &mut self.one_rtt
            && keys.first_sent.is_some_and(|first| packet.number >= first)
        {
            keys.acknowledged = true;
        }
        for frame in &packet.frames {
            match frame {
                QUICSentFrame::ACK { largest } => self.spaces[space.index()].received.stop_acknowledging(*largest),
                QUICSentFrame::Crypto { offset, length } => {
                    self.spaces[space.index()].crypto_send.acknowledge(*offset, *length, false)
                }
                QUICSentFrame::Stream { stream, offset, length, fin } => {
                    if let Some(found) = self.streams.streams.get_mut(stream)
                        && let Some(send) = &mut found.send
                    {
                        send.buffer.acknowledge(*offset, *length, *fin);
                        if send.buffer.is_acknowledged() && send.state != super::QUICSendState::ResetSent {
                            send.state = super::QUICSendState::DataReceived;
                        }
                        self.push_event(QUICEvent::StreamWritable { stream: *stream });
                    }
                }
                QUICSentFrame::ResetStream { stream } => {
                    if let Some(found) = self.streams.streams.get_mut(stream)
                        && let Some(send) = &mut found.send
                    {
                        send.state = super::QUICSendState::ResetReceived;
                    }
                }
                QUICSentFrame::RetireConnectionID { sequence } => self.peer_ids.retired(*sequence),
                _ => {}
            }
        }
        self.streams.collect();
    }

    /// The frames of a lost packet: what must reach the peer goes again,
    /// with its latest value (RFC 9000 §13.3).
    pub fn lose_frames(&mut self, space: QUICPacketNumberSpace, frames: &[QUICSentFrame]) {
        for frame in frames {
            match frame {
                QUICSentFrame::Crypto { offset, length } => {
                    self.spaces[space.index()].crypto_send.lose(*offset, *length, false)
                }
                QUICSentFrame::Stream { stream, offset, length, fin } => {
                    if let Some(found) = self.streams.streams.get_mut(stream)
                        && let Some(send) = &mut found.send
                        && send.reset.is_none()
                    {
                        send.buffer.lose(*offset, *length, *fin);
                        self.streams.schedule(*stream);
                    }
                }
                QUICSentFrame::ResetStream { stream } => {
                    if let Some(found) = self.streams.streams.get_mut(stream)
                        && let Some(send) = &mut found.send
                        && send.state == super::QUICSendState::ResetSent
                    {
                        send.reset_pending = true;
                        self.streams.schedule(*stream);
                    }
                }
                QUICSentFrame::StopSending { stream } => {
                    if let Some(found) = self.streams.streams.get_mut(stream)
                        && let Some(receive) = &mut found.receive
                        && receive.reset.is_none()
                        && !receive.is_terminal()
                    {
                        receive.stop_pending = true;
                        self.streams.schedule(*stream);
                    }
                }
                QUICSentFrame::MaxData => self.pending.max_data = true,
                QUICSentFrame::MaxStreamData { stream } => {
                    if let Some(found) = self.streams.streams.get_mut(stream)
                        && let Some(receive) = &mut found.receive
                        && receive.buffer.final_size.is_none()
                    {
                        receive.limit_pending = true;
                        self.streams.schedule(*stream);
                    }
                }
                QUICSentFrame::MaxStreams { bidirectional } => {
                    self.streams.limit_pending[QUICStreams::kind(*bidirectional)] = true
                }
                // Blocked signals go again only while still blocked, with the limit then (RFC 9000 §13.3).
                QUICSentFrame::DataBlocked => {
                    if self.send_credit.available() == 0 {
                        self.pending.data_blocked = true;
                    }
                }
                QUICSentFrame::StreamDataBlocked { stream } => {
                    if let Some(found) = self.streams.streams.get_mut(stream)
                        && let Some(send) = &mut found.send
                        && send.reset.is_none()
                        && send.credit.available() == 0
                    {
                        send.blocked_pending = true;
                        self.streams.schedule(*stream);
                    }
                }
                QUICSentFrame::StreamsBlocked { bidirectional } => {
                    let kind = QUICStreams::kind(*bidirectional);
                    if self.streams.opened[kind] >= self.streams.peer_limit[kind] {
                        self.streams.blocked_pending[kind] = true;
                    }
                }
                QUICSentFrame::NewConnectionID { sequence, .. } => {
                    if self.local_ids.ids.contains_key(sequence) {
                        self.pending.new_connection_ids.push(*sequence);
                    }
                }
                QUICSentFrame::RetireConnectionID { sequence } => self.pending.retire_connection_ids.push(*sequence),
                QUICSentFrame::NewToken { token } => self.pending.new_token = Some(token.clone()),
                QUICSentFrame::HandshakeDone => self.pending.handshake_done = true,
                QUICSentFrame::PathChallenge { data } => {
                    if self.path_challenge == Some(*data) {
                        self.pending.challenge_due = true;
                    }
                }
                QUICSentFrame::ACK { .. }
                | QUICSentFrame::PathResponse { .. }
                | QUICSentFrame::Ping
                | QUICSentFrame::Datagram
                | QUICSentFrame::Extension => {}
            }
        }
    }

    /// CRYPTO data of `space` (RFC 9000 §7.5, RFC 9001 §4.1.3): joined in
    /// order and given to TLS at the level it reads.
    pub fn receive_crypto(&mut self, space: QUICPacketNumberSpace, offset: u64, data: &[u8]) -> Result<(), QUICError> {
        let level = QUICConnection::level_of(space);
        let reading = self.tls.reading_level().unwrap_or(TLSEncryptionLevel::Initial);
        let crypto = &mut self.spaces[space.index()].crypto_receive;
        let end = offset + data.len() as u64;
        // A level TLS left must not get data past what it had (RFC 9001 §4.1.3).
        if level < reading && end > crypto.highest {
            return Err(QUICError::transport(QUICErrorCode::PROTOCOL_VIOLATION, "CRYPTO data past a level left"));
        }
        if end > crypto.read + self.config.maximum_crypto_buffer as u64 {
            return Err(QUICError::transport(QUICErrorCode::CRYPTO_BUFFER_EXCEEDED, "too much CRYPTO data"));
        }
        crypto.insert(offset, data, false)?;
        self.feed_tls()
    }

    /// Gives TLS the CRYPTO data of the level it reads, as long as there is some.
    pub fn feed_tls(&mut self) -> Result<(), QUICError> {
        loop {
            let Some(level) = self.tls.reading_level() else { return Ok(()) };
            let space = QUICConnection::space_of(level);
            let bytes = self.spaces[space.index()].crypto_receive.read_all();
            if bytes.is_empty() {
                return Ok(());
            }
            self.tls.receive_handshake(level, &bytes).map_err(QUICConnection::tls_error)?;
            // The level may have moved: data already received at the next one goes on.
            if self.tls.reading_level() == Some(level) {
                return Ok(());
            }
        }
    }

    /// STREAM data (RFC 9000 §2.2, §4).
    pub fn receive_stream(
        &mut self,
        stream: QUICStreamID,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(), QUICError> {
        let Some(found) = self.streams.frame(stream, QUICFrameType::STREAM, true, &mut self.events)? else {
            return Ok(());
        };
        let Some(receive) = &mut found.receive else { return Ok(()) };
        let new = receive.receive(offset, data, fin)?;
        self.receive_credit.receive(new)?;
        // What arrives for a reader that stopped is dropped, and counts as read (RFC 9000 §3.5).
        if receive.stop.is_some() {
            let taken = receive.absorb();
            self.receive_credit.consume(taken);
            if self.receive_credit.update().is_some() {
                self.pending.max_data = true;
            }
            self.streams.collect();
            return Ok(());
        }
        if receive.buffer.readable() > 0 || receive.state == super::QUICReceiveState::DataReceived {
            self.push_event(QUICEvent::StreamReadable { stream });
        }
        Ok(())
    }

    /// Queues `event`, once, within the configured limit.
    pub fn push_event(&mut self, event: QUICEvent) {
        if self.events.len() < self.config.maximum_events && !self.events.contains(&event) {
            self.events.push_back(event);
        }
    }

    // ---- Closing ----

    /// Closes on `error` (RFC 9000 §10.2): a transport error goes in a
    /// CONNECTION_CLOSE, configuration failures end the connection silently.
    pub fn fail(&mut self, error: QUICError, now: Instant) {
        let QUICError::Transport(QUICTransportError { code, frame_type, reason }) = error else {
            self.state = QUICConnectionState::Closed;
            self.events.push_back(QUICEvent::Closed {
                reason: QUICCloseReason::Local { error: QUICErrorCode::INTERNAL_ERROR, reason: Vec::new() },
            });
            return;
        };
        self.start_closing(code.0, frame_type, reason.as_bytes().to_vec(), false, now);
    }

    /// Closes the connection with the application's `error` and `reason` (RFC 9000 §10.2).
    pub fn close(&mut self, error: u64, reason: &[u8], now: Instant) -> Result<(), QUICError> {
        if matches!(
            self.state,
            QUICConnectionState::Closing | QUICConnectionState::Draining | QUICConnectionState::Closed
        ) {
            return Err(QUICError::State);
        }
        self.start_closing(error, QUICFrameType::PADDING, reason.to_vec(), true, now);
        Ok(())
    }

    pub fn start_closing(
        &mut self,
        error: u64,
        frame_type: QUICFrameType,
        reason: Vec<u8>,
        application: bool,
        now: Instant,
    ) {
        let event = if application {
            QUICCloseReason::LocalApplication { error, reason: reason.clone() }
        } else {
            QUICCloseReason::Local { error: QUICErrorCode(error), reason: reason.clone() }
        };
        let until = now + self.recovery.base_probe_timeout(QUICPacketNumberSpace::ApplicationData) * 3;
        self.closing = Some(QUICClosing { error, frame_type, reason, application, due: true, until });
        self.state = QUICConnectionState::Closing;
        self.events.push_back(QUICEvent::Closed { reason: event });
    }

    /// The peer closed: nothing more is sent (RFC 9000 §10.2.2).
    pub fn drain(&mut self, reason: QUICCloseReason, now: Instant) {
        self.closing = None;
        self.state = QUICConnectionState::Draining;
        self.close_deadline(now);
        self.events.push_back(QUICEvent::Closed { reason });
    }

    /// Forgets the connection three probe timeouts from `now` (RFC 9000 §10.2).
    pub fn close_deadline(&mut self, now: Instant) {
        let until = now + self.recovery.base_probe_timeout(QUICPacketNumberSpace::ApplicationData) * 3;
        self.closing = Some(QUICClosing {
            error: 0,
            frame_type: QUICFrameType::PADDING,
            reason: Vec::new(),
            application: false,
            due: false,
            until,
        });
    }

    // ---- Timers ----

    /// When [`QUICConnection::expire`] is next due.
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.state == QUICConnectionState::Closed {
            return None;
        }
        if let Some(closing) = &self.closing
            && matches!(self.state, QUICConnectionState::Closing | QUICConnectionState::Draining)
        {
            return Some(closing.until);
        }
        // Acknowledgments and pacing wait for nothing while nothing can be sent.
        let sending = self.send_limit() >= QUICConnection::MINIMUM_SEND;
        let ack = QUICPacketNumberSpace::ALL
            .into_iter()
            .filter(|space| sending && self.can_acknowledge(*space))
            .filter_map(|space| self.spaces[space.index()].received.due)
            .min();
        let paced = self.paced_until.filter(|_| sending);
        [self.loss_timer, ack, self.idle_deadline(), paced].into_iter().flatten().min()
    }

    /// Whether ACK frames of `space` can be sent now: with its keys, and in
    /// 1-RTT packets for the application space, as 0-RTT ones carry none (RFC 9000 §12.4).
    pub fn can_acknowledge(&self, space: QUICPacketNumberSpace) -> bool {
        !self.spaces[space.index()].discarded
            && self.can_write(space)
            && (space != QUICPacketNumberSpace::ApplicationData || self.one_rtt_writable())
    }

    /// When the idle timeout ends the connection: at least three probe
    /// timeouts after the last activity (RFC 9000 §10.1).
    pub fn idle_deadline(&self) -> Option<Instant> {
        let timeout = self.idle_timeout?;
        let floor = self.recovery.base_probe_timeout(QUICPacketNumberSpace::ApplicationData) * 3;
        Some(self.last_activity + timeout.max(floor))
    }

    /// Handles the timers due at `now`.
    pub fn expire(&mut self, now: Instant) {
        if matches!(self.state, QUICConnectionState::Closing | QUICConnectionState::Draining) {
            if self.closing.as_ref().is_some_and(|closing| closing.until <= now) {
                self.state = QUICConnectionState::Closed;
            }
            return;
        }
        if self.state == QUICConnectionState::Closed {
            return;
        }
        if self.idle_deadline().is_some_and(|deadline| deadline <= now) {
            // The idle timeout closes silently (RFC 9000 §10.1).
            self.state = QUICConnectionState::Closed;
            self.events.push_back(QUICEvent::Closed { reason: QUICCloseReason::IdleTimeout });
            return;
        }
        if self.loss_timer.is_some_and(|timer| timer <= now) {
            self.loss_timeout(now);
        }
    }

    /// Whether the server cannot send more before the client's address is
    /// validated (RFC 9000 §8.1).
    pub fn amplification_limited(&self) -> bool {
        self.role == QUICRole::Server
            && !self.validated
            && self.sent_bytes >= self.received_bytes * QUICConfig::AMPLIFICATION_FACTOR
    }

    /// Whether the peer completed address validation (RFC 9002 Appendix A.6).
    pub fn peer_validated(&self) -> bool {
        self.role == QUICRole::Server || self.validated || self.handshake_confirmed
    }

    /// Sets the loss detection timer (RFC 9002 Appendix A.8).
    pub fn set_loss_timer(&mut self, now: Instant) {
        if let Some((time, _)) = self.recovery.loss_time() {
            self.loss_timer = Some(time);
            return;
        }
        if self.amplification_limited() {
            self.loss_timer = None;
            return;
        }
        let in_flight = self.recovery.spaces.iter().any(|space| space.ack_eliciting_in_flight());
        if !in_flight && self.peer_validated() {
            self.loss_timer = None;
            return;
        }
        if !in_flight {
            // A client unblocks a server stuck at its amplification limit (RFC 9002 §6.2.2.1).
            let duration = self.recovery.probe_timeout(QUICPacketNumberSpace::Initial);
            self.loss_timer = Some(now + duration);
            return;
        }
        let confirmed = self.handshake_confirmed;
        let spaces = &self.spaces;
        self.loss_timer = self
            .recovery
            .probe_time(|space| {
                !spaces[space.index()].discarded && (space != QUICPacketNumberSpace::ApplicationData || confirmed)
            })
            .map(|(time, _)| time);
    }

    /// The loss detection timer fired (RFC 9002 Appendix A.9): packets lost
    /// by time go again, or probes are owed.
    pub fn loss_timeout(&mut self, now: Instant) {
        if let Some((_, space)) = self.recovery.loss_time() {
            let lost = self.recovery.detect_lost(space, now);
            self.recovery.lost(&lost, &[], now);
            for packet in &lost {
                self.lose_frames(space, &packet.frames);
            }
            self.set_loss_timer(now);
            return;
        }
        let in_flight = self.recovery.spaces.iter().any(|space| space.ack_eliciting_in_flight());
        let space = if !in_flight {
            // The anti-deadlock probe: Handshake if its keys are there, else Initial.
            if self.spaces[1].write.is_some() {
                QUICPacketNumberSpace::Handshake
            } else {
                QUICPacketNumberSpace::Initial
            }
        } else {
            let confirmed = self.handshake_confirmed;
            let spaces = &self.spaces;
            let found = self.recovery.probe_time(|space| {
                !spaces[space.index()].discarded && (space != QUICPacketNumberSpace::ApplicationData || confirmed)
            });
            match found {
                Some((_, space)) => space,
                None => QUICPacketNumberSpace::ApplicationData,
            }
        };
        self.spaces[space.index()].probes = 2;
        // The probes carry the CRYPTO data still unacknowledged (RFC 9002 §6.2.4).
        let frames: Vec<QUICSentFrame> = self.recovery.spaces[space.index()]
            .sent
            .values()
            .flat_map(|packet| packet.frames.iter().filter(|frame| matches!(frame, QUICSentFrame::Crypto { .. })))
            .cloned()
            .collect();
        self.lose_frames(space, &frames);
        self.recovery.pto_count += 1;
        self.set_loss_timer(now);
    }

    // ---- Sending ----

    /// Writes the next datagram to send into `out` (cleared first) and
    /// returns where it goes, or `None` if there is nothing to send now.
    pub fn transmit(&mut self, now: Instant, out: &mut Vec<u8>) -> Option<QUICTransmission> {
        out.clear();
        self.paced_until = None;
        if matches!(self.state, QUICConnectionState::Closed | QUICConnectionState::Draining) {
            return None;
        }
        // An answer to a challenge from another address goes there alone,
        // within what that address allows (RFC 9000 §8.2.1, §9.1).
        if self.state != QUICConnectionState::Closing
            && let Some(response) = self.pending.path_responses.front().copied()
            && response.destination != self.remote
            && self.one_rtt_writable()
        {
            self.pending.path_responses.pop_front();
            let limit = self.datagram_limit().min(response.limit);
            let mut payload = Vec::new();
            if limit >= QUICConnection::MINIMUM_SEND
                && (QUICFrame::PathResponse { data: response.data }).encode(&mut payload).is_ok()
            {
                let frames = vec![QUICSentFrame::PathResponse { data: response.data }];
                let pad = Some(QUICConfig::MINIMUM_DATAGRAM_SIZE.min(limit));
                let space = QUICPacketNumberSpace::ApplicationData;
                let _ = self.seal_packet(space, payload, frames, true, limit, pad, now, out);
            }
            if !out.is_empty() {
                return Some(QUICTransmission { destination: response.destination, ecn: QUICECN::NotECT });
            }
        }
        let limit = self.send_limit();
        if limit < QUICConnection::MINIMUM_SEND {
            return None;
        }
        if self.state == QUICConnectionState::Closing {
            self.build_close(limit, now, out);
        } else {
            self.build_datagram(limit, now, out);
        }
        if out.is_empty() {
            return None;
        }
        if !self.validated {
            self.sent_bytes += out.len() as u64;
        }
        if !self.path_validated {
            self.path_sent += out.len() as u64;
        }
        self.set_loss_timer(now);
        Some(QUICTransmission { destination: self.remote, ecn: QUICECN::NotECT })
    }

    /// The smallest datagram worth writing: a short header and a frame.
    pub const MINIMUM_SEND: usize = 32;

    /// The largest datagram this end may send: its own size, within the peer's max_udp_payload_size.
    pub fn datagram_limit(&self) -> usize {
        let limit = self.config.datagram_size;
        match &self.peer_parameters {
            Some(parameters) => limit.min(usize::try_from(parameters.max_udp_payload_size).unwrap_or(usize::MAX)),
            None => limit,
        }
    }

    /// The largest datagram that may go to the peer's address now: three
    /// times what came from an address not validated, less what went there
    /// (RFC 9000 §8.1, §8.2, §9.3).
    pub fn send_limit(&self) -> usize {
        let mut limit = self.datagram_limit();
        let budget = |received: u64, sent: u64| {
            usize::try_from((received.saturating_mul(QUICConfig::AMPLIFICATION_FACTOR)).saturating_sub(sent))
                .unwrap_or(usize::MAX)
        };
        if self.role == QUICRole::Server && !self.validated {
            limit = limit.min(budget(self.received_bytes, self.sent_bytes));
        }
        if !self.path_validated {
            limit = limit.min(budget(self.path_received, self.path_sent));
        }
        limit
    }

    /// The datagram of a closing connection: its CONNECTION_CLOSE in the
    /// spaces the peer can read (RFC 9000 §10.2.3).
    pub fn build_close(&mut self, limit: usize, now: Instant, out: &mut Vec<u8>) {
        let Some(closing) = self.closing.clone().filter(|closing| closing.due) else { return };
        if let Some(closing) = &mut self.closing {
            closing.due = false;
        }
        let reason_room = limit.saturating_sub(100) / 2;
        let reason = &closing.reason[..closing.reason.len().min(reason_room)];
        for space in QUICPacketNumberSpace::ALL {
            if !self.can_write(space) {
                continue;
            }
            // The application's error is hidden in Initial and Handshake packets (RFC 9000 §10.2.3).
            let frame = match (closing.application, space) {
                (true, QUICPacketNumberSpace::ApplicationData) => {
                    QUICFrame::ApplicationClose { error: closing.error, reason }
                }
                (true, _) => QUICFrame::ConnectionClose {
                    error: QUICErrorCode::APPLICATION_ERROR,
                    frame_type: QUICFrameType::PADDING,
                    reason: &[],
                },
                (false, _) => QUICFrame::ConnectionClose {
                    error: QUICErrorCode(closing.error),
                    frame_type: closing.frame_type,
                    reason,
                },
            };
            let mut payload = Vec::new();
            if frame.encode(&mut payload).is_err() {
                continue;
            }
            let room = limit.saturating_sub(out.len());
            let _ = self.seal_packet(space, payload, Vec::new(), false, room, None, now, out);
        }
    }

    /// Whether packets of `space` can be written now.
    pub fn can_write(&self, space: QUICPacketNumberSpace) -> bool {
        match space {
            QUICPacketNumberSpace::Initial => self.spaces[0].write.is_some(),
            QUICPacketNumberSpace::Handshake => self.spaces[1].write.is_some(),
            QUICPacketNumberSpace::ApplicationData => {
                (self.one_rtt.is_some() && (self.handshake_complete || self.role == QUICRole::Server))
                    || (self.zero_rtt.is_some() && self.role == QUICRole::Client)
            }
        }
    }

    /// Fills a datagram with a packet of each space that has something to
    /// send, padded to 1200 bytes when it carries an ack-eliciting Initial
    /// (RFC 9000 §14.1).
    pub fn build_datagram(&mut self, limit: usize, now: Instant, out: &mut Vec<u8>) {
        let congestion = self.recovery.congestion_credit();
        // Pacing lets a datagram go once its bytes are earned (RFC 9002 §7.7);
        // a full congestion window waits for acknowledgments instead.
        let window = self.recovery.congestion.window();
        let rtt = self.recovery.rtt.smoothed;
        let waiting = congestion > 0 && QUICPacketNumberSpace::ALL.into_iter().any(|space| self.has_frames(space));
        self.paced_until = match &mut self.recovery.pacer {
            Some(pacer) => {
                pacer.refill(window, rtt, now);
                let size = limit.min(congestion as usize);
                pacer.next(size, window, rtt).filter(|time| *time > now && waiting)
            }
            None => None,
        };
        let paced = self.paced_until.is_none();
        let probing = self.spaces.iter().any(|space| space.probes > 0);
        let mut payloads: Vec<(QUICPacketNumberSpace, Vec<u8>, Vec<QUICSentFrame>, bool)> = Vec::new();
        let mut used = 0;
        for space in QUICPacketNumberSpace::ALL {
            if !self.can_write(space) || self.spaces[space.index()].discarded {
                continue;
            }
            let overhead = self.header_overhead(space) + super::QUICPacketKey::TAG_LENGTH;
            let room = limit.saturating_sub(used + overhead);
            if room < 8 {
                break;
            }
            // Data stays within the congestion window, unless it probes (RFC 9002 §7).
            let mut data_room = match (probing, paced) {
                (true, _) => room,
                (false, true) => {
                    room.min(usize::try_from(congestion).unwrap_or(usize::MAX).saturating_sub(used + overhead))
                }
                (false, false) => 0,
            };
            // A server's ack-eliciting Initial needs a datagram of 1200 bytes (RFC 9000 §14.1).
            if space == QUICPacketNumberSpace::Initial
                && self.role == QUICRole::Server
                && limit < QUICConfig::MINIMUM_DATAGRAM_SIZE
            {
                data_room = 0;
            }
            let (payload, frames, ack_eliciting) = self.collect_frames(space, room, data_room, now);
            if payload.is_empty() {
                continue;
            }
            used += overhead + payload.len();
            payloads.push((space, payload, frames, ack_eliciting));
        }
        let Some(last) = payloads.len().checked_sub(1) else { return };
        // Datagrams with an ack-eliciting Initial, and those that probe a
        // path, are expanded to 1200 bytes (RFC 9000 §8.2.1, §14.1).
        let pad_initial = payloads.iter().any(|(space, _, frames, eliciting)| {
            (*space == QUICPacketNumberSpace::Initial && (*eliciting || self.role == QUICRole::Client))
                || frames.iter().any(|frame| {
                    matches!(frame, QUICSentFrame::PathChallenge { .. } | QUICSentFrame::PathResponse { .. })
                })
        });
        for (index, (space, payload, frames, ack_eliciting)) in payloads.into_iter().enumerate() {
            let pad_to = (index == last && pad_initial).then_some(QUICConfig::MINIMUM_DATAGRAM_SIZE.min(limit));
            let room = limit.saturating_sub(out.len());
            let _ = self.seal_packet(space, payload, frames, ack_eliciting, room, pad_to, now, out);
            // A client drops its Initial keys once it sends a Handshake packet (RFC 9001 §4.9.1).
            if space == QUICPacketNumberSpace::Handshake && self.role == QUICRole::Client {
                self.discard_space(QUICPacketNumberSpace::Initial);
            }
        }
        let _ = now;
    }

    /// The bytes of a packet header of `space`, with a 4-byte packet number.
    pub fn header_overhead(&self, space: QUICPacketNumberSpace) -> usize {
        let destination = self.peer_ids.current().map_or(0, |current| current.id.len());
        match space {
            QUICPacketNumberSpace::ApplicationData if self.one_rtt.is_some() && self.handshake_complete => {
                1 + destination + 4
            }
            QUICPacketNumberSpace::ApplicationData if self.one_rtt.is_some() && self.role == QUICRole::Server => {
                1 + destination + 4
            }
            _ => {
                let token = if space == QUICPacketNumberSpace::Initial {
                    super::QUICVarint::length(self.token.len() as u64).unwrap_or(8) + self.token.len()
                } else {
                    0
                };
                7 + destination + self.initial_source.len() + token + 4 + 4
            }
        }
    }

    /// The frames of the next packet of `space`, within `room` bytes:
    /// acknowledgments, then, within `data_room` bytes of payload (what the
    /// congestion window and pacing allow), CRYPTO data, the frames that are
    /// not data, streams and datagrams, and a PING when a probe is owed.
    pub fn collect_frames(
        &mut self,
        space: QUICPacketNumberSpace,
        room: usize,
        data_room: usize,
        now: Instant,
    ) -> (Vec<u8>, Vec<QUICSentFrame>, bool) {
        let send_data = data_room > 0;
        let mut payload = Vec::with_capacity(room.min(1500));
        let mut frames = Vec::new();
        let mut ack_eliciting = false;
        let zero_rtt = space == QUICPacketNumberSpace::ApplicationData && !self.one_rtt_writable();
        // An ACK when one is due, or along with anything else (RFC 9000 §13.2.1).
        let wants_ack = self.spaces[space.index()].received.wants_ack(now);
        let owed = self.spaces[space.index()].unacknowledged;
        let others = send_data && self.has_frames(space);
        if !zero_rtt && (wants_ack || (owed && others)) {
            // The exponent this end advertised, in every space (RFC 9000 §19.3).
            let exponent = self.config.ack_delay_exponent;
            let received = &self.spaces[space.index()].received;
            if let Some((ranges, delay)) = received.ack(exponent, self.config.maximum_ack_ranges, now) {
                let ecn = received.ecn_seen.then_some(received.ecn);
                let mut bytes = Vec::new();
                if QUICACKFrame::encode_ranges(&ranges, delay, ecn, &mut bytes).is_ok() && bytes.len() <= room {
                    payload.extend_from_slice(&bytes);
                    frames.push(QUICSentFrame::ACK { largest: *ranges[0].end() });
                    let space_state = &mut self.spaces[space.index()];
                    space_state.received.acknowledged();
                    space_state.unacknowledged = false;
                }
            }
        }
        if !send_data {
            return (payload, frames, false);
        }
        let room = room.min(data_room);
        let push = |payload: &mut Vec<u8>, frame: &QUICFrame<'_>, limit: usize| -> bool {
            if payload.len() + frame.encoded_length() > limit {
                return false;
            }
            frame.encode(payload).is_ok()
        };
        // CRYPTO data, never in 0-RTT.
        if !zero_rtt {
            loop {
                let available = room.saturating_sub(payload.len() + 16);
                if available < 8 {
                    break;
                }
                let crypto = &mut self.spaces[space.index()].crypto_send;
                let Some((offset, data, _)) = crypto.next(available, u64::MAX) else { break };
                let frame = QUICFrame::Crypto { offset, data: &data };
                if !push(&mut payload, &frame, room) {
                    crypto.lose(offset, data.len(), false);
                    break;
                }
                frames.push(QUICSentFrame::Crypto { offset, length: data.len() });
                ack_eliciting = true;
            }
        }
        if space == QUICPacketNumberSpace::ApplicationData {
            ack_eliciting |= self.collect_application(&mut payload, &mut frames, room, zero_rtt);
        }
        let space_state = &mut self.spaces[space.index()];
        if space_state.probes > 0 {
            space_state.probes -= 1;
            if !ack_eliciting && payload.len() < room {
                payload.push(0x01);
                frames.push(QUICSentFrame::Ping);
                ack_eliciting = true;
            }
        } else if self.pending.ping
            && space == QUICPacketNumberSpace::ApplicationData
            && !ack_eliciting
            && payload.len() < room
        {
            self.pending.ping = false;
            payload.push(0x01);
            frames.push(QUICSentFrame::Ping);
            ack_eliciting = true;
        }
        (payload, frames, ack_eliciting)
    }

    /// Whether 1-RTT packets can be written now.
    pub fn one_rtt_writable(&self) -> bool {
        self.one_rtt.is_some() && (self.handshake_complete || self.role == QUICRole::Server)
    }

    /// Whether `space` has frames to send besides acknowledgments.
    pub fn has_frames(&self, space: QUICPacketNumberSpace) -> bool {
        let state = &self.spaces[space.index()];
        if state.probes > 0 || state.crypto_send.has_data(u64::MAX) {
            return true;
        }
        if space != QUICPacketNumberSpace::ApplicationData {
            return false;
        }
        let pending = &self.pending;
        pending.handshake_done
            || pending.max_data
            || pending.data_blocked
            || pending.ping
            || !pending.new_connection_ids.is_empty()
            || !pending.retire_connection_ids.is_empty()
            || !pending.path_responses.is_empty()
            || pending.challenge_due
            || !pending.extension_frames.is_empty()
            || pending.new_token.is_some()
            || self.streams.limit_pending.iter().any(|pending| *pending)
            || self.streams.blocked_pending.iter().any(|pending| *pending)
            || !self.streams.ready.is_empty()
            || !self.outgoing_datagrams.is_empty()
    }

    /// The frames of the application space: those that are not data, then
    /// stream data in turn, then datagrams. Returns whether one elicits an ACK.
    pub fn collect_application(
        &mut self,
        payload: &mut Vec<u8>,
        frames: &mut Vec<QUICSentFrame>,
        room: usize,
        zero_rtt: bool,
    ) -> bool {
        let packet_type = if zero_rtt { QUICPacketType::ZeroRTT } else { QUICPacketType::OneRTT };
        let mut eliciting = false;
        let push =
            |payload: &mut Vec<u8>, frames: &mut Vec<QUICSentFrame>, frame: QUICFrame<'_>, sent: QUICSentFrame| {
                if !frame.frame_type().permits(packet_type) || payload.len() + frame.encoded_length() > room {
                    return false;
                }
                if frame.encode(payload).is_err() {
                    return false;
                }
                frames.push(sent);
                true
            };
        if self.pending.handshake_done
            && !zero_rtt
            && push(payload, frames, QUICFrame::HandshakeDone, QUICSentFrame::HandshakeDone)
        {
            self.pending.handshake_done = false;
            eliciting = true;
        }
        // Answers on this path; those to another go in datagrams of their own.
        while let Some(QUICPathResponse { data, destination, .. }) = self.pending.path_responses.front().copied() {
            if destination != self.remote
                || !push(payload, frames, QUICFrame::PathResponse { data }, QUICSentFrame::PathResponse { data })
            {
                break;
            }
            self.pending.path_responses.pop_front();
            eliciting = true;
        }
        if let Some(data) = self.path_challenge
            && self.pending.challenge_due
            && push(payload, frames, QUICFrame::PathChallenge { data }, QUICSentFrame::PathChallenge { data })
        {
            self.pending.challenge_due = false;
            eliciting = true;
        }
        if self.pending.max_data
            && push(payload, frames, QUICFrame::MaxData { maximum: self.receive_credit.limit }, QUICSentFrame::MaxData)
        {
            self.pending.max_data = false;
            eliciting = true;
        }
        if self.pending.data_blocked
            && push(
                payload,
                frames,
                QUICFrame::DataBlocked { maximum: self.send_credit.limit },
                QUICSentFrame::DataBlocked,
            )
        {
            self.pending.data_blocked = false;
            eliciting = true;
        }
        for bidirectional in [true, false] {
            let kind = QUICStreams::kind(bidirectional);
            if self.streams.limit_pending[kind] {
                let frame = QUICFrame::MaxStreams { bidirectional, maximum: self.streams.limit[kind] };
                if push(payload, frames, frame, QUICSentFrame::MaxStreams { bidirectional }) {
                    self.streams.limit_pending[kind] = false;
                    eliciting = true;
                }
            }
            if self.streams.blocked_pending[kind] {
                let frame = QUICFrame::StreamsBlocked { bidirectional, maximum: self.streams.peer_limit[kind] };
                if push(payload, frames, frame, QUICSentFrame::StreamsBlocked { bidirectional }) {
                    self.streams.blocked_pending[kind] = false;
                    eliciting = true;
                }
            }
        }
        while let Some(sequence) = self.pending.new_connection_ids.first().copied() {
            let Some(issued) = self.local_ids.ids.get(&sequence).copied() else {
                self.pending.new_connection_ids.remove(0);
                continue;
            };
            let frame = QUICFrame::NewConnectionID {
                sequence,
                retire_prior_to: 0,
                id: issued.id,
                reset_token: issued.reset_token.unwrap_or([0; 16]),
            };
            if !push(payload, frames, frame, QUICSentFrame::NewConnectionID { sequence, id: issued.id }) {
                break;
            }
            self.pending.new_connection_ids.remove(0);
            eliciting = true;
        }
        while let Some(sequence) = self.pending.retire_connection_ids.first().copied() {
            let frame = QUICFrame::RetireConnectionID { sequence };
            if !push(payload, frames, frame, QUICSentFrame::RetireConnectionID { sequence }) {
                break;
            }
            self.pending.retire_connection_ids.remove(0);
            eliciting = true;
        }
        if let Some(token) = self.pending.new_token.clone()
            && push(
                payload,
                frames,
                QUICFrame::NewToken { token: &token },
                QUICSentFrame::NewToken { token: token.clone() },
            )
        {
            self.pending.new_token = None;
            eliciting = true;
        }
        while let Some(frame) = self.pending.extension_frames.front() {
            if zero_rtt || payload.len() + frame.len() > room {
                break;
            }
            payload.extend_from_slice(frame);
            frames.push(QUICSentFrame::Extension);
            self.pending.extension_frames.pop_front();
            eliciting = true;
        }
        eliciting |= self.collect_streams(payload, frames, room, packet_type);
        while let Some(datagram) = self.outgoing_datagrams.front() {
            let frame = QUICFrame::Datagram { data: datagram };
            if payload.len() + frame.encoded_length() > room {
                break;
            }
            if frame.encode(payload).is_ok() {
                frames.push(QUICSentFrame::Datagram);
                eliciting = true;
            }
            self.outgoing_datagrams.pop_front();
        }
        eliciting
    }

    /// Stream frames, a stream at a time in turn: resets, STOP_SENDING,
    /// MAX_STREAM_DATA, then data within the stream's and the
    /// connection's credit (RFC 9000 §4.1).
    pub fn collect_streams(
        &mut self,
        payload: &mut Vec<u8>,
        frames: &mut Vec<QUICSentFrame>,
        room: usize,
        packet_type: QUICPacketType,
    ) -> bool {
        let mut eliciting = false;
        let mut turns = self.streams.ready.len();
        while turns > 0 && payload.len() + 8 < room {
            turns -= 1;
            let Some(id) = self.streams.ready.pop_front() else { break };
            let Some(stream) = self.streams.streams.get_mut(&id) else { continue };
            let mut again = false;
            if let Some(receive) = &mut stream.receive {
                if receive.stop_pending
                    && let Some(error) = receive.stop
                {
                    let frame = QUICFrame::StopSending { stream: id, error };
                    if payload.len() + frame.encoded_length() <= room && frame.encode(payload).is_ok() {
                        frames.push(QUICSentFrame::StopSending { stream: id });
                        receive.stop_pending = false;
                        eliciting = true;
                    } else {
                        again = true;
                    }
                }
                if receive.limit_pending {
                    let frame = QUICFrame::MaxStreamData { stream: id, maximum: receive.credit.limit };
                    if payload.len() + frame.encoded_length() <= room && frame.encode(payload).is_ok() {
                        frames.push(QUICSentFrame::MaxStreamData { stream: id });
                        receive.limit_pending = false;
                        eliciting = true;
                    } else {
                        again = true;
                    }
                }
            }
            if let Some(send) = &mut stream.send {
                if send.reset_pending
                    && let Some(error) = send.reset
                {
                    let frame = QUICFrame::ResetStream { stream: id, error, final_size: send.final_size() };
                    if frame.frame_type().permits(packet_type)
                        && payload.len() + frame.encoded_length() <= room
                        && frame.encode(payload).is_ok()
                    {
                        frames.push(QUICSentFrame::ResetStream { stream: id });
                        send.reset_pending = false;
                        eliciting = true;
                    } else {
                        again = true;
                    }
                } else if send.reset.is_none() {
                    // New data counts against the connection's credit too.
                    let new_limit = send.buffer.sent + self.send_credit.available().min(send.credit.available());
                    let limit = new_limit.min(send.credit.limit);
                    let header = 1 + 8 + 8 + 4;
                    let available = room.saturating_sub(payload.len() + header);
                    if available > 0
                        && send.buffer.has_data(limit)
                        && let Some((offset, data, fin)) = send.buffer.next(available, limit)
                    {
                        let end = offset + data.len() as u64;
                        if end > send.credit.used {
                            let new = end - send.credit.used;
                            send.credit.used = end;
                            self.send_credit.used += new;
                        }
                        let frame = QUICFrame::Stream { stream: id, offset, data: &data, fin };
                        if frame.encode(payload).is_ok() {
                            frames.push(QUICSentFrame::Stream { stream: id, offset, length: data.len(), fin });
                            eliciting = true;
                            if fin && send.state != super::QUICSendState::ResetSent {
                                send.state = super::QUICSendState::DataSent;
                            } else if send.state == super::QUICSendState::Ready {
                                send.state = super::QUICSendState::Send;
                            }
                        }
                    }
                    // Blocked by flow control: STREAM_DATA_BLOCKED and DATA_BLOCKED (RFC 9000 §4.1).
                    if send.buffer.written() > send.buffer.sent {
                        if send.credit.is_blocked() {
                            send.blocked_pending = true;
                        }
                        if self.send_credit.is_blocked() {
                            self.pending.data_blocked = true;
                            self.send_credit.blocked_at = Some(self.send_credit.limit);
                        }
                    }
                    if send.blocked_pending {
                        let frame = QUICFrame::StreamDataBlocked { stream: id, maximum: send.credit.limit };
                        if payload.len() + frame.encoded_length() <= room && frame.encode(payload).is_ok() {
                            frames.push(QUICSentFrame::StreamDataBlocked { stream: id });
                            send.blocked_pending = false;
                            send.credit.blocked_at = Some(send.credit.limit);
                            eliciting = true;
                        }
                    }
                    again |=
                        send.buffer.has_data(send.credit.limit.min(send.buffer.sent + self.send_credit.available()));
                }
            }
            if again {
                self.streams.ready.push_back(id);
            }
        }
        eliciting
    }

    /// Protects a packet of `space` with `payload` and appends it to `out`,
    /// padded so that `out` reaches `pad_to` bytes, and records it for
    /// recovery. Fails silently (writes nothing) without keys or room.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_packet(
        &mut self,
        space: QUICPacketNumberSpace,
        mut payload: Vec<u8>,
        frames: Vec<QUICSentFrame>,
        ack_eliciting: bool,
        room: usize,
        pad_to: Option<usize>,
        now: Instant,
        out: &mut Vec<u8>,
    ) -> Result<(), QUICError> {
        let number = self.spaces[space.index()].next_number;
        let largest = self.recovery.spaces[space.index()].largest_acknowledged;
        let length = QUICPacketNumber::length(number, largest).unwrap_or(4);
        let zero_rtt = space == QUICPacketNumberSpace::ApplicationData && !self.one_rtt_writable();
        let destination = self.peer_ids.current().map(|current| current.id).unwrap_or_default();
        let fixed = !(self.peer_parameters.as_ref().is_some_and(|parameters| parameters.grease_quic_bit)
            && self.random.next_u32().is_ok_and(|value| value & 1 == 0));
        let header = match space {
            QUICPacketNumberSpace::ApplicationData if !zero_rtt => QUICHeader::Short(QUICShortHeader {
                destination,
                spin: self.spin_enabled && self.spin,
                key_phase: self.one_rtt.as_ref().is_some_and(|keys| keys.phase),
            }),
            _ => QUICHeader::Long(QUICLongHeader {
                packet_type: match space {
                    QUICPacketNumberSpace::Initial => QUICPacketType::Initial,
                    QUICPacketNumberSpace::Handshake => QUICPacketType::Handshake,
                    QUICPacketNumberSpace::ApplicationData => QUICPacketType::ZeroRTT,
                },
                version: self.version,
                destination,
                source: self.initial_source,
                token: if space == QUICPacketNumberSpace::Initial { &self.token } else { &[] },
            }),
        };
        // The sample of header protection needs 4 bytes of packet number and payload (RFC 9001 §5.4.2).
        let minimum = 4usize.saturating_sub(length);
        let mut padded = payload.len() < minimum;
        if padded {
            payload.resize(minimum, 0);
        }
        let start = out.len();
        let mut packet = Vec::with_capacity(room.min(1500));
        let tag = super::QUICPacketKey::TAG_LENGTH;
        let mut offset = header.encode(fixed, number, length, payload.len() + tag, &mut packet)?;
        if let Some(target) = pad_to {
            let total = start + packet.len() + payload.len() + tag;
            if total < target {
                payload.resize(payload.len() + target - total, 0);
                padded = true;
                packet.clear();
                offset = header.encode(fixed, number, length, payload.len() + tag, &mut packet)?;
                // A longer Length field: take the extra bytes from the padding.
                let total = start + packet.len() + payload.len() + tag;
                if total > target {
                    payload.truncate(payload.len() - (total - target).min(payload.len().saturating_sub(minimum)));
                    packet.clear();
                    offset = header.encode(fixed, number, length, payload.len() + tag, &mut packet)?;
                }
            }
        }
        if packet.len() + payload.len() + tag > room {
            return Err(QUICError::Config);
        }
        let header_length = packet.len();
        packet.extend_from_slice(&payload);
        let profile = self.profile;
        let (key, header_key) = match space {
            QUICPacketNumberSpace::Initial => {
                let keys = self.spaces[0].write.as_ref().ok_or(QUICError::State)?;
                (&keys.packet, &keys.header)
            }
            QUICPacketNumberSpace::Handshake => {
                let keys = self.spaces[1].write.as_ref().ok_or(QUICError::State)?;
                (&keys.packet, &keys.header)
            }
            QUICPacketNumberSpace::ApplicationData if zero_rtt => {
                let keys = self.zero_rtt.as_ref().ok_or(QUICError::State)?;
                (&keys.packet, &keys.header)
            }
            QUICPacketNumberSpace::ApplicationData => {
                let keys = self.one_rtt.as_ref().ok_or(QUICError::State)?;
                (&keys.write, &keys.write_header)
            }
        };
        key.seal(number, header_length, &mut packet)?;
        header_key.apply(&mut packet, offset, length)?;
        let _ = profile;
        if space == QUICPacketNumberSpace::ApplicationData
            && !zero_rtt
            && let Some(keys) = &mut self.one_rtt
        {
            keys.written += 1;
            if keys.first_sent.is_none() {
                keys.first_sent = Some(number);
            }
        }
        self.check_confidentiality(now);
        out.extend_from_slice(&packet);
        self.spaces[space.index()].next_number += 1;
        // The first ack-eliciting packet since the peer's last restarts the idle timer (RFC 9000 §10.1).
        if ack_eliciting && !self.eliciting_sent {
            self.eliciting_sent = true;
            self.last_activity = now;
        }
        let in_flight = ack_eliciting || padded;
        let sent = QUICSentPacket { number, time: now, size: packet.len(), ack_eliciting, in_flight, frames };
        self.recovery.sent(space, sent);
        Ok(())
    }
}

impl QUICConnection {
    // ---- The application's interface ----

    /// Opens a stream; fails with [`QUICError::State`] at the peer's limit.
    pub fn open_stream(&mut self, bidirectional: bool) -> Result<QUICStreamID, QUICError> {
        if !matches!(self.state, QUICConnectionState::Handshaking | QUICConnectionState::Established) {
            return Err(QUICError::State);
        }
        self.streams.open(bidirectional)
    }

    /// Writes `data` to a stream, as much as its buffer takes; returns how
    /// much. With `fin`, after all of `data`, the stream ends.
    pub fn stream_send(&mut self, stream: QUICStreamID, data: &[u8], fin: bool) -> Result<usize, QUICError> {
        let maximum = self.config.maximum_send_buffer;
        let found = self.streams.streams.get_mut(&stream).ok_or(QUICError::State)?;
        let send = found.send.as_mut().ok_or(QUICError::State)?;
        if send.reset.is_some() || send.buffer.fin {
            return Err(QUICError::State);
        }
        let count = data.len().min(maximum.saturating_sub(send.buffer.buffered()));
        send.buffer.write(&data[..count])?;
        if fin && count == data.len() {
            send.buffer.finish();
        }
        self.streams.schedule(stream);
        Ok(count)
    }

    /// Reads from a stream into `out`: how many bytes, and whether the
    /// stream ended. Reading gives the peer credit again (RFC 9000 §4.2).
    pub fn stream_read(&mut self, stream: QUICStreamID, out: &mut [u8]) -> Result<(usize, bool), QUICError> {
        let found = self.streams.streams.get_mut(&stream).ok_or(QUICError::State)?;
        let receive = found.receive.as_mut().ok_or(QUICError::State)?;
        if let Some(error) = receive.reset {
            receive.state = super::QUICReceiveState::ResetRead;
            let _ = error;
            self.streams.collect();
            return Ok((0, true));
        }
        let count = receive.buffer.read(out);
        receive.credit.consume(count as u64);
        let update = receive.buffer.final_size.is_none() && receive.credit.update().is_some();
        if update {
            receive.limit_pending = true;
        }
        let finished = receive.buffer.is_finished();
        if finished {
            receive.state = super::QUICReceiveState::DataRead;
        }
        if update {
            self.streams.schedule(stream);
        }
        self.receive_credit.consume(count as u64);
        if self.receive_credit.update().is_some() {
            self.pending.max_data = true;
        }
        self.streams.collect();
        Ok((count, finished))
    }

    /// Resets the sending half of a stream with the application's `error` (RFC 9000 §19.4).
    pub fn stream_reset(&mut self, stream: QUICStreamID, error: u64) -> Result<(), QUICError> {
        let found = self.streams.streams.get_mut(&stream).ok_or(QUICError::State)?;
        found.send.as_mut().ok_or(QUICError::State)?.reset(error);
        self.streams.schedule(stream);
        Ok(())
    }

    /// Asks the peer to stop sending on a stream (RFC 9000 §19.5).
    pub fn stream_stop(&mut self, stream: QUICStreamID, error: u64) -> Result<(), QUICError> {
        let found = self.streams.streams.get_mut(&stream).ok_or(QUICError::State)?;
        let receive = found.receive.as_mut().ok_or(QUICError::State)?;
        if receive.stop.is_some() || receive.reset.is_some() || receive.is_terminal() {
            return Ok(());
        }
        receive.stop = Some(error);
        // Once the final size is known, the peer sends nothing new: it need not be told.
        receive.stop_pending = receive.buffer.final_size.is_none();
        let taken = receive.absorb();
        let pending = receive.stop_pending;
        self.receive_credit.consume(taken);
        if self.receive_credit.update().is_some() {
            self.pending.max_data = true;
        }
        if pending {
            self.streams.schedule(stream);
        }
        self.streams.collect();
        Ok(())
    }

    /// Queues a DATAGRAM frame (RFC 9221 §5): only if the peer accepts
    /// one of that size and it fits in a packet; it is never sent again if lost.
    pub fn send_datagram(&mut self, data: &[u8]) -> Result<(), QUICError> {
        let maximum = self.peer_parameters.as_ref().map_or(0, |parameters| parameters.max_datagram_frame_size);
        let size = (QUICFrame::Datagram { data }).encoded_length();
        if maximum == 0 || size as u64 > maximum || size > self.frame_room() {
            return Err(QUICError::State);
        }
        if self.outgoing_datagrams.len() >= self.config.maximum_datagrams {
            return Err(QUICError::State);
        }
        self.outgoing_datagrams.push_back(data.to_vec());
        Ok(())
    }

    /// Queues `frame`, a frame of an extension the peer negotiated, encoded
    /// (RFC 9000 §19.21): it goes in a 1-RTT packet, elicits an ACK, counts
    /// for congestion control, and is not sent again if lost. Fails with
    /// [`QUICError::State`] once closing, or for a frame empty or too large
    /// for a packet.
    pub fn send_extension_frame(&mut self, frame: Vec<u8>) -> Result<(), QUICError> {
        if frame.is_empty()
            || frame.len() > self.frame_room()
            || !matches!(self.state, QUICConnectionState::Handshaking | QUICConnectionState::Established)
        {
            return Err(QUICError::State);
        }
        self.pending.extension_frames.push_back(frame);
        Ok(())
    }

    /// The bytes of frames that a 1-RTT packet in a datagram of
    /// [`QUICConnection::datagram_limit`] holds, whatever the length of the
    /// peer's connection ID: the datagram less the longest short header and the tag.
    pub fn frame_room(&self) -> usize {
        let header = 1 + QUICConnectionID::MAXIMUM_LENGTH + 4;
        self.datagram_limit().saturating_sub(header + super::QUICPacketKey::TAG_LENGTH)
    }

    /// The next DATAGRAM frame received.
    pub fn read_datagram(&mut self) -> Option<Vec<u8>> {
        self.datagrams.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<QUICEvent> {
        self.events.pop_front()
    }

    /// Updates the 1-RTT keys (RFC 9001 §6.1): only once the handshake is
    /// confirmed and a packet sent in the current phase was acknowledged.
    pub fn update_keys(&mut self, now: Instant) -> Result<(), QUICError> {
        let pto = self.recovery.base_probe_timeout(QUICPacketNumberSpace::ApplicationData);
        let profile = self.profile;
        let keys = self.one_rtt.as_mut().filter(|_| self.handshake_confirmed).ok_or(QUICError::State)?;
        if !keys.acknowledged {
            return Err(QUICError::State);
        }
        keys.update(profile, now + pto * 3)
    }

    /// The packets protected under one key stay below the AEAD's limit (RFC
    /// 9001 §6.6): the keys update at nine tenths of it, and the connection
    /// closes with AEAD_LIMIT_REACHED if they cannot before the limit.
    pub fn check_confidentiality(&mut self, now: Instant) {
        let Some(keys) = &self.one_rtt else { return };
        let limit = keys.write.confidentiality_limit();
        let written = keys.written;
        if written >= limit / 10 * 9 && self.update_keys_permitted() {
            let _ = self.update_keys(now);
        } else if written >= limit {
            self.fail(QUICError::transport(QUICErrorCode::AEAD_LIMIT_REACHED, "the key's packets ran out"), now);
        }
    }

    /// Whether [`QUICConnection::update_keys`] may update the keys now.
    pub fn update_keys_permitted(&self) -> bool {
        self.handshake_confirmed && self.one_rtt.as_ref().is_some_and(|keys| keys.acknowledged)
    }

    /// Asks for an ACK, as keep-alive (RFC 9000 §10.1.2).
    pub fn ping(&mut self) {
        self.pending.ping = true;
    }

    /// Whether the connection is gone.
    pub fn is_closed(&self) -> bool {
        self.state == QUICConnectionState::Closed
    }
}

impl QUICConnection {
    /// The datagrams [`QUICConnection::transmit`] writes, all of them, for loops that move everything.
    pub fn transmit_all(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut datagrams = vec![];
        let mut out = Vec::new();
        while self.transmit(now, &mut out).is_some() {
            datagrams.push(core::mem::take(&mut out));
            if datagrams.len() > 64 {
                break;
            }
        }
        datagrams
    }
}
