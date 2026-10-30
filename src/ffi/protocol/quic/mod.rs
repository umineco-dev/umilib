//! The C ABI of [`crate::protocol::quic`].
//!
//! A configuration and an endpoint are handles; the connections of an
//! endpoint are named by the numbers it gives them. The limits, a session's
//! state and an event are structures; versions cross as their numbers,
//! times as nanoseconds of the caller's monotonic clock (`now`) and seconds
//! since 1970 (`time`, for certificates and tokens). An endpoint and each
//! connection draw their randomness from HMAC-DRBGs (SP 800-90A) seeded by
//! the caller with at least 48 bytes from the operating system.

#[cfg(umilib_feature = "protocol-quic-v1")]
pub mod v1;
#[cfg(umilib_feature = "protocol-quic-v2")]
pub mod v2;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::time::Duration;

use crate::crypto::random::HMACDRBG;
use crate::ffi::protocol::ip::FFIIPEndpoint;
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::hash::sha::v2::SHA256;
use crate::protocol::quic::{
    QUICCloseReason, QUICConfig, QUICConnection, QUICConnectionState, QUICECN, QUICEndpoint, QUICEndpointConfig,
    QUICError, QUICEvent, QUICStreamID, QUICVersion,
};
use crate::protocol::tls::{TLSClientConfig, TLSServerConfig};
use crate::runtime::Instant;

/// The statuses of this module, one per variant of [`QUICError`] that is not
/// another module's.
pub struct QUICStatus;

impl QUICStatus {
    pub const INVALID_PACKET: Status =
        Status::new(c"protocol.quic", c"InvalidPacket", c"not a valid QUIC packet: it is discarded");
    pub const TRANSPORT: Status =
        Status::new(c"protocol.quic", c"Transport", c"what the QUIC peer sent breaks the protocol");
    pub const STATE: Status = Status::new(c"protocol.quic", c"State", c"the QUIC connection's state does not allow it");
    pub const CONFIG: Status = Status::new(c"protocol.quic", c"Config", c"the QUIC configuration cannot work");
    pub const RANDOM: Status = Status::new(c"protocol.quic", c"Random", c"the source of randomness failed");
    pub const UNKNOWN_CONNECTION: Status =
        Status::new(c"protocol.quic", c"UnknownConnection", c"the endpoint has no connection of that number");
    /// The fewest bytes of seed a source of randomness takes.
    pub const SEED_LENGTH: usize = 48;

    /// A DRBG seeded with the `length` bytes at `seed`, at least 48.
    ///
    /// # Safety
    /// As [`Pointer::slice`].
    pub unsafe fn random(seed: *const u8, length: usize) -> Result<Box<HMACDRBG<SHA256>>, &'static Status> {
        // SAFETY: the caller's promise.
        let seed = unsafe { Pointer::slice(seed, length) }?;
        if seed.len() < QUICStatus::SEED_LENGTH {
            return Err(&Status::INVALID_ARGUMENT);
        }
        let (entropy, nonce) = seed.split_at(32);
        let random = HMACDRBG::new(entropy, nonce, b"umilib protocol quic").map_err(|_| &Status::INVALID_ARGUMENT)?;
        Ok(Box::new(random))
    }

    /// The connection `handle` of `endpoint`.
    pub fn connection(endpoint: &mut QUICEndpoint, handle: u64) -> Result<&mut QUICConnection, &'static Status> {
        endpoint.connection(handle).ok_or(&QUICStatus::UNKNOWN_CONNECTION)
    }
}

impl ToStatus for QUICError {
    fn to_status(&self) -> &'static Status {
        match self {
            QUICError::InvalidPacket => &QUICStatus::INVALID_PACKET,
            QUICError::Transport(_) => &QUICStatus::TRANSPORT,
            QUICError::State => &QUICStatus::STATE,
            QUICError::Config => &QUICStatus::CONFIG,
            QUICError::Random => &QUICStatus::RANDOM,
            QUICError::Write(error) => error.to_status(),
        }
    }
}

/// The limits and flags of a [`QUICConfig`]: durations in milliseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIQUICLimits {
    pub connection_id_length: usize,
    pub max_idle_timeout: u64,
    pub max_udp_payload_size: u64,
    pub datagram_size: usize,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: u64,
    pub active_connection_id_limit: u64,
    pub initial_rtt: u64,
    pub max_datagram_frame_size: u64,
    pub disable_active_migration: bool,
    pub pacing: bool,
    pub grease_quic_bit: bool,
    pub spin_bit: bool,
    pub grease_transport_parameters: bool,
    pub maximum_crypto_buffer: usize,
    pub maximum_send_buffer: usize,
    pub maximum_datagrams: usize,
}

impl FFIQUICLimits {
    pub fn of(config: &QUICConfig) -> FFIQUICLimits {
        FFIQUICLimits {
            connection_id_length: config.connection_id_length,
            max_idle_timeout: config.max_idle_timeout.as_millis() as u64,
            max_udp_payload_size: config.max_udp_payload_size,
            datagram_size: config.datagram_size,
            initial_max_data: config.initial_max_data,
            initial_max_stream_data_bidi_local: config.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: config.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: config.initial_max_stream_data_uni,
            initial_max_streams_bidi: config.initial_max_streams_bidi,
            initial_max_streams_uni: config.initial_max_streams_uni,
            ack_delay_exponent: config.ack_delay_exponent,
            max_ack_delay: config.max_ack_delay.as_millis() as u64,
            active_connection_id_limit: config.active_connection_id_limit,
            initial_rtt: config.initial_rtt.as_millis() as u64,
            max_datagram_frame_size: config.max_datagram_frame_size,
            disable_active_migration: config.disable_active_migration,
            pacing: config.pacing,
            grease_quic_bit: config.grease_quic_bit,
            spin_bit: config.spin_bit,
            grease_transport_parameters: config.grease_transport_parameters,
            maximum_crypto_buffer: config.maximum_crypto_buffer,
            maximum_send_buffer: config.maximum_send_buffer,
            maximum_datagrams: config.maximum_datagrams,
        }
    }

    pub fn apply(&self, config: &mut QUICConfig) {
        config.connection_id_length = self.connection_id_length;
        config.max_idle_timeout = Duration::from_millis(self.max_idle_timeout);
        config.max_udp_payload_size = self.max_udp_payload_size;
        config.datagram_size = self.datagram_size;
        config.initial_max_data = self.initial_max_data;
        config.initial_max_stream_data_bidi_local = self.initial_max_stream_data_bidi_local;
        config.initial_max_stream_data_bidi_remote = self.initial_max_stream_data_bidi_remote;
        config.initial_max_stream_data_uni = self.initial_max_stream_data_uni;
        config.initial_max_streams_bidi = self.initial_max_streams_bidi;
        config.initial_max_streams_uni = self.initial_max_streams_uni;
        config.ack_delay_exponent = self.ack_delay_exponent;
        config.max_ack_delay = Duration::from_millis(self.max_ack_delay);
        config.active_connection_id_limit = self.active_connection_id_limit;
        config.initial_rtt = Duration::from_millis(self.initial_rtt);
        config.max_datagram_frame_size = self.max_datagram_frame_size;
        config.disable_active_migration = self.disable_active_migration;
        config.pacing = self.pacing;
        config.grease_quic_bit = self.grease_quic_bit;
        config.spin_bit = self.spin_bit;
        config.grease_transport_parameters = self.grease_transport_parameters;
        config.maximum_crypto_buffer = self.maximum_crypto_buffer;
        config.maximum_send_buffer = self.maximum_send_buffer;
        config.maximum_datagrams = self.maximum_datagrams;
    }
}

/// Where a connection stands: its state as the number of its variant
/// (0 handshaking, 1 established, 2 closing, 3 draining, 4 closed), the
/// version, and the handshake's progress.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIQUICSession {
    pub state: u8,
    pub version: u32,
    pub handshake_complete: bool,
    pub handshake_confirmed: bool,
    pub zero_rtt_rejected: bool,
}

impl FFIQUICSession {
    pub fn of(connection: &QUICConnection) -> FFIQUICSession {
        FFIQUICSession {
            state: match connection.state {
                QUICConnectionState::Handshaking => 0,
                QUICConnectionState::Established => 1,
                QUICConnectionState::Closing => 2,
                QUICConnectionState::Draining => 3,
                QUICConnectionState::Closed => 4,
            },
            version: connection.version.0,
            handshake_complete: connection.handshake_complete,
            handshake_confirmed: connection.handshake_confirmed,
            zero_rtt_rejected: connection.tls.session.early_data == crate::protocol::tls::TLSEarlyData::Rejected,
        }
    }
}

/// A [`QUICEvent`]: `kind` the number of its variant (0 Connected, 1
/// HandshakeConfirmed, 2 StreamOpened, 3 StreamReadable, 4 StreamWritable,
/// 5 StreamReset, 6 StopSending, 7 StreamsAvailable, 8 Datagram, 9
/// NewToken, 10 ZeroRTTRejected, 11 Closed), with its stream, error and
/// kind of stream; a Closed event's `reason` is the number of its
/// [`QUICCloseReason`] (0 Local, 1 LocalApplication, 2 Peer, 3
/// PeerApplication, 4 IdleTimeout, 5 StatelessReset, 6 VersionNegotiation).
/// The token or the reason phrase goes in a buffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIQUICEvent {
    pub kind: u8,
    pub stream: u64,
    pub error: u64,
    pub bidirectional: bool,
    pub reason: u8,
}

impl FFIQUICEvent {
    /// The structure of `event` and its bytes.
    pub fn of(event: QUICEvent) -> (FFIQUICEvent, alloc::vec::Vec<u8>) {
        let mut out = FFIQUICEvent::default();
        let mut bytes = alloc::vec::Vec::new();
        match event {
            QUICEvent::Connected => out.kind = 0,
            QUICEvent::HandshakeConfirmed => out.kind = 1,
            QUICEvent::StreamOpened { stream } => (out.kind, out.stream) = (2, stream.0),
            QUICEvent::StreamReadable { stream } => (out.kind, out.stream) = (3, stream.0),
            QUICEvent::StreamWritable { stream } => (out.kind, out.stream) = (4, stream.0),
            QUICEvent::StreamReset { stream, error } => (out.kind, out.stream, out.error) = (5, stream.0, error),
            QUICEvent::StopSending { stream, error } => (out.kind, out.stream, out.error) = (6, stream.0, error),
            QUICEvent::StreamsAvailable { bidirectional } => (out.kind, out.bidirectional) = (7, bidirectional),
            QUICEvent::Datagram => out.kind = 8,
            QUICEvent::NewToken { token } => (out.kind, bytes) = (9, token),
            QUICEvent::ZeroRTTRejected => out.kind = 10,
            QUICEvent::Closed { reason } => {
                out.kind = 11;
                (out.reason, out.error, bytes) = match reason {
                    QUICCloseReason::Local { error, reason } => (0, error.0, reason),
                    QUICCloseReason::LocalApplication { error, reason } => (1, error, reason),
                    QUICCloseReason::Peer { error, reason } => (2, error.0, reason),
                    QUICCloseReason::PeerApplication { error, reason } => (3, error, reason),
                    QUICCloseReason::IdleTimeout => (4, 0, alloc::vec::Vec::new()),
                    QUICCloseReason::StatelessReset => (5, 0, alloc::vec::Vec::new()),
                    QUICCloseReason::VersionNegotiation => (6, 0, alloc::vec::Vec::new()),
                };
            }
        }
        (out, bytes)
    }
}

impl Value for FFIQUICLimits {
    const TYPE: Type = Type::Named("umilib_protocol_quic_QUICLimits");
}

impl Value for FFIQUICSession {
    const TYPE: Type = Type::Named("umilib_protocol_quic_QUICSession");
}

impl Value for FFIQUICEvent {
    const TYPE: Type = Type::Named("umilib_protocol_quic_QUICEvent");
}

impl Value for QUICConfig {
    const TYPE: Type = Type::Named("umilib_protocol_quic_QUICConfig");
}

impl Value for QUICEndpoint {
    const TYPE: Type = Type::Named("umilib_protocol_quic_QUICEndpoint");
}

crate::ffi_functions! {
    /// Writes the default configuration (every version compiled in, version 1 first) into `out`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_config_new(out: *mut *mut QUICConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, QUICConfig::default()) })
    }

    /// Releases a configuration. Does nothing if `config` is null.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_config_free(config: *mut QUICConfig) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(config) }
    }

    /// Sets the versions, most preferred first, to the `count` numbers at `versions`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_config_set_versions(config: *mut QUICConfig, versions: *const u32, count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable numbers.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.versions = unsafe { Pointer::slice_of(versions, count) }?.iter().copied().map(QUICVersion).collect();
            Ok(())
        })())
    }

    /// Writes the limits and flags of the configuration into `out`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_config_limits(config: *const QUICConfig, out: *mut FFIQUICLimits) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            unsafe { Pointer::write(out, FFIQUICLimits::of(config)) }
        })())
    }

    /// Sets the limits and flags of the configuration; fails with Config, changing nothing, if they cannot work.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_config_set_limits(config: *mut QUICConfig, limits: *const FFIQUICLimits) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and structure.
            let config = unsafe { Pointer::reference_mut(config) }?;
            let mut changed = config.clone();
            unsafe { Pointer::reference(limits) }?.apply(&mut changed);
            changed.check().map_err(|error| error.to_status())?;
            *config = changed;
            Ok(())
        })())
    }

    /// Sets the key of stateless reset tokens to the 32 bytes at `key`, or none if `key` is null.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_config_set_reset_key(config: *mut QUICConfig, key: *const u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and 32 readable bytes or null.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.reset_key = match key.is_null() {
                true => None,
                false => Some(unsafe { Pointer::slice(key, 32) }?.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?),
            };
            Ok(())
        })())
    }

    /// Writes an endpoint of the connection configuration `config` into `out`: one that accepts
    /// connections with the TLS configuration `tls`, or only connects if `tls` is null; with the 32
    /// bytes at `token_key` (none if null) it validates addresses, with a Retry first if `retry`.
    /// Its randomness is seeded by the `seed_length` bytes at `seed` (at least 48).
    pub unsafe extern "C" fn umilib_protocol_quic_quic_endpoint_new(config: *const QUICConfig, tls: *const TLSServerConfig, token_key: *const u8, retry: bool, seed: *const u8, seed_length: usize, out: *mut *mut QUICEndpoint) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles or null, readable bytes and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            let tls = match tls.is_null() {
                true => None,
                false => Some(Arc::new(unsafe { Pointer::reference(tls) }?.clone())),
            };
            let token_key = match token_key.is_null() {
                true => None,
                false => Some(unsafe { Pointer::slice(token_key, 32) }?.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?),
            };
            let random = unsafe { QUICStatus::random(seed, seed_length) }?;
            Pointer::check_range(out, 1)?;
            let mut endpoint_config = QUICEndpointConfig::new(Arc::new(config.clone()), tls);
            endpoint_config.token_key = token_key;
            endpoint_config.retry = retry;
            let endpoint = QUICEndpoint::new(endpoint_config, random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, endpoint) }
        })())
    }

    /// Releases an endpoint and its connections. Does nothing if `endpoint` is null.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_endpoint_free(endpoint: *mut QUICEndpoint) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(endpoint) }
    }

    /// Opens a connection to `remote` as the server `server_name` (none for 0 bytes) with the TLS
    /// configuration `tls`, and the NEW_TOKEN token of `token_length` bytes at `token` (none for 0),
    /// at `now` (nanoseconds) and `time` (seconds since 1970); its randomness is seeded by the
    /// `seed_length` bytes at `seed` (at least 48). Writes its number into `out`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_endpoint_connect(endpoint: *mut QUICEndpoint, tls: *const TLSClientConfig, server_name: *const u8, length: usize, remote: *const FFIIPEndpoint, token: *const u8, token_length: usize, seed: *const u8, seed_length: usize, now: u64, time: i64, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[
                    Pointer::range(server_name, length),
                    Pointer::range(remote, 1),
                    Pointer::range(token, token_length),
                    Pointer::range(seed, seed_length),
                ],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes valid handles, readable bytes and structures, and a writable pointer.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let tls = unsafe { Pointer::reference(tls) }?;
            let server_name = unsafe { Pointer::optional_text(server_name, length) }?.filter(|name| !name.is_empty());
            let remote = unsafe { Pointer::reference(remote) }?.endpoint()?;
            let token = unsafe { Pointer::slice(token, token_length) }?;
            let random = unsafe { QUICStatus::random(seed, seed_length) }?;
            Pointer::check_range(out, 1)?;
            let token = (!token.is_empty()).then(|| token.to_vec());
            let handle = endpoint
                .connect(Arc::new(tls.clone()), server_name, remote, token, random, Instant::from_nanos(now), time)
                .map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, handle) }
        })())
    }

    /// Takes the datagram of `length` bytes at `datagram` from `remote` with the ECN codepoint `ecn`
    /// (0 Not-ECT, 1 ECT(1), 2 ECT(0), 3 CE); writes whether a connection took it into `out_found`
    /// and its number into `out`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_endpoint_receive(endpoint: *mut QUICEndpoint, datagram: *const u8, length: usize, remote: *const FFIIPEndpoint, ecn: u8, now: u64, time: i64, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(datagram, length), Pointer::range(remote, 1)],
                &[Pointer::range(out_found, 1), Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes a valid handle, readable bytes and structure, and writable pointers.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let datagram = unsafe { Pointer::slice(datagram, length) }?;
            let remote = unsafe { Pointer::reference(remote) }?.endpoint()?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let ecn = match ecn {
                0 => QUICECN::NotECT,
                1 => QUICECN::ECT1,
                2 => QUICECN::ECT0,
                3 => QUICECN::CE,
                _ => return Err(&Status::INVALID_ARGUMENT),
            };
            let handle = endpoint.receive(datagram, remote, ecn, Instant::from_nanos(now), time);
            unsafe { Pointer::write(out_found, handle.is_some()) }?;
            unsafe { Pointer::write(out, handle.unwrap_or(0)) }
        })())
    }

    /// Writes the next datagram to send into `out` and its destination into `out_destination`, and
    /// whether there was one into `out_found`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_endpoint_transmit(endpoint: *mut QUICEndpoint, now: u64, out_found: *mut bool, out_destination: *mut FFIIPEndpoint, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out_destination, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_destination, 1)?;
            Pointer::check_range(out, 1)?;
            let mut datagram = alloc::vec::Vec::new();
            let transmission = endpoint.transmit(Instant::from_nanos(now), &mut datagram);
            unsafe { Pointer::write(out_found, transmission.is_some()) }?;
            if let Some(transmission) = transmission {
                unsafe { Pointer::write(out_destination, FFIIPEndpoint::of(&transmission.destination)) }?;
            }
            unsafe { Pointer::write(out, Buffer::from_vec(datagram)) }
        })())
    }

    /// Writes whether a timer is set into `out_found` and when it fires (nanoseconds) into `out`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_endpoint_poll_timeout(endpoint: *const QUICEndpoint, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let endpoint = unsafe { Pointer::reference(endpoint) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let timeout = endpoint.poll_timeout();
            unsafe { Pointer::write(out_found, timeout.is_some()) }?;
            unsafe { Pointer::write(out, timeout.map_or(0, Instant::as_nanos)) }
        })())
    }

    /// Fires the timers due at `now`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_endpoint_expire(endpoint: *mut QUICEndpoint, now: u64, time: i64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            endpoint.expire(Instant::from_nanos(now), time);
            Ok(())
        })())
    }

    /// Writes whether a connection was accepted into `out_found` and its number into `out`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_endpoint_accept(endpoint: *mut QUICEndpoint, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let handle = endpoint.accept();
            unsafe { Pointer::write(out_found, handle.is_some()) }?;
            unsafe { Pointer::write(out, handle.unwrap_or(0)) }
        })())
    }

    /// Writes where the connection `connection` stands into `out`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_session(endpoint: *mut QUICEndpoint, connection: u64, out: *mut FFIQUICSession) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let connection = QUICStatus::connection(endpoint, connection)?;
            unsafe { Pointer::write(out, FFIQUICSession::of(connection)) }
        })())
    }

    /// Writes the application protocol the connection negotiated (empty before) into `out`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_protocol(endpoint: *mut QUICEndpoint, connection: u64, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let connection = QUICStatus::connection(endpoint, connection)?;
            let protocol = connection.tls.session.protocol.clone().unwrap_or_default();
            unsafe { Pointer::write(out, Buffer::from_vec(protocol)) }
        })())
    }

    /// Writes whether an event is pending into `out_found`, the event into `out`, and its token or
    /// reason phrase into `out_bytes`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_poll_event(endpoint: *mut QUICEndpoint, connection: u64, out_found: *mut bool, out: *mut FFIQUICEvent, out_bytes: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_bytes, 1)?;
            let event = QUICStatus::connection(endpoint, connection)?.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let (structure, bytes) = event.map(FFIQUICEvent::of).unwrap_or_default();
            unsafe { Pointer::write(out, structure) }?;
            unsafe { Pointer::write(out_bytes, Buffer::from_vec(bytes)) }
        })())
    }

    /// Opens a stream, bidirectional if `bidirectional`, and writes its ID into `out`; fails with
    /// State at the peer's limit.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_open_stream(endpoint: *mut QUICEndpoint, connection: u64, bidirectional: bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            Pointer::check_range(out, 1)?;
            let stream = QUICStatus::connection(endpoint, connection)?.open_stream(bidirectional).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, stream.0) }
        })())
    }

    /// Writes the `length` bytes at `data` to the stream, as many as it takes (into `out`), and its
    /// end after them if `fin`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_stream_send(endpoint: *mut QUICEndpoint, connection: u64, stream: u64, data: *const u8, length: usize, fin: bool, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            let connection = QUICStatus::connection(endpoint, connection)?;
            let count = connection.stream_send(QUICStreamID(stream), data, fin).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, count) }
        })())
    }

    /// Reads up to `capacity` bytes of the stream into `out`; writes how many into `out_count` and
    /// whether the stream ended into `out_fin`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_stream_read(endpoint: *mut QUICEndpoint, connection: u64, stream: u64, out: *mut u8, capacity: usize, out_count: *mut usize, out_fin: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[Pointer::range(out, capacity), Pointer::range(out_count, 1), Pointer::range(out_fin, 1)],
            )?;
            // SAFETY: the caller passes a valid handle and writable memory.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let out = unsafe { Pointer::slice_mut(out, capacity) }?;
            Pointer::check_range(out_count, 1)?;
            Pointer::check_range(out_fin, 1)?;
            let connection = QUICStatus::connection(endpoint, connection)?;
            let (count, fin) = connection.stream_read(QUICStreamID(stream), out).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_count, count) }?;
            unsafe { Pointer::write(out_fin, fin) }
        })())
    }

    /// Resets the sending half of the stream with the application's `error`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_stream_reset(endpoint: *mut QUICEndpoint, connection: u64, stream: u64, error: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            QUICStatus::connection(endpoint, connection)?.stream_reset(QUICStreamID(stream), error).map_err(|error| error.to_status())
        })())
    }

    /// Asks the peer to stop sending on the stream, with the application's `error`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_stream_stop(endpoint: *mut QUICEndpoint, connection: u64, stream: u64, error: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            QUICStatus::connection(endpoint, connection)?.stream_stop(QUICStreamID(stream), error).map_err(|error| error.to_status())
        })())
    }

    /// Queues the DATAGRAM frame of the `length` bytes at `data`; fails with State if the peer does not accept it.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_send_datagram(endpoint: *mut QUICEndpoint, connection: u64, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            QUICStatus::connection(endpoint, connection)?.send_datagram(data).map_err(|error| error.to_status())
        })())
    }

    /// Writes whether a DATAGRAM frame was received into `out_found` and its data into `out`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_read_datagram(endpoint: *mut QUICEndpoint, connection: u64, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let datagram = QUICStatus::connection(endpoint, connection)?.read_datagram();
            unsafe { Pointer::write(out_found, datagram.is_some()) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(datagram.unwrap_or_default())) }
        })())
    }

    /// Closes the connection with the application's `error` and the reason of `length` bytes at `reason`.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_close(endpoint: *mut QUICEndpoint, connection: u64, error: u64, reason: *const u8, length: usize, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            let reason = unsafe { Pointer::slice(reason, length) }?;
            let connection = QUICStatus::connection(endpoint, connection)?;
            connection.close(error, reason, Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Updates the 1-RTT keys; fails with State before the handshake is confirmed or while an update is unacknowledged.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_update_keys(endpoint: *mut QUICEndpoint, connection: u64, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            QUICStatus::connection(endpoint, connection)?.update_keys(Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }

    /// Asks the peer for an acknowledgment, as keep-alive.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_ping(endpoint: *mut QUICEndpoint, connection: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            QUICStatus::connection(endpoint, connection)?.ping();
            Ok(())
        })())
    }

    /// Moves a client's connection to a new local address (the caller's next datagrams come from it);
    /// fails with State before confirmation, when the server disabled it, or without a connection ID to spare.
    pub unsafe extern "C" fn umilib_protocol_quic_quic_connection_migrate(endpoint: *mut QUICEndpoint, connection: u64, now: u64) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let endpoint = unsafe { Pointer::reference_mut(endpoint) }?;
            QUICStatus::connection(endpoint, connection)?.migrate_local(Instant::from_nanos(now)).map_err(|error| error.to_status())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "quic",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_quic_QUICLimits",
            documentation: " The limits and flags of a QUIC configuration; durations in milliseconds.",
            fields: &[
                Parameter { name: "connection_id_length", value: <usize as Value>::TYPE },
                Parameter { name: "max_idle_timeout", value: <u64 as Value>::TYPE },
                Parameter { name: "max_udp_payload_size", value: <u64 as Value>::TYPE },
                Parameter { name: "datagram_size", value: <usize as Value>::TYPE },
                Parameter { name: "initial_max_data", value: <u64 as Value>::TYPE },
                Parameter { name: "initial_max_stream_data_bidi_local", value: <u64 as Value>::TYPE },
                Parameter { name: "initial_max_stream_data_bidi_remote", value: <u64 as Value>::TYPE },
                Parameter { name: "initial_max_stream_data_uni", value: <u64 as Value>::TYPE },
                Parameter { name: "initial_max_streams_bidi", value: <u64 as Value>::TYPE },
                Parameter { name: "initial_max_streams_uni", value: <u64 as Value>::TYPE },
                Parameter { name: "ack_delay_exponent", value: <u64 as Value>::TYPE },
                Parameter { name: "max_ack_delay", value: <u64 as Value>::TYPE },
                Parameter { name: "active_connection_id_limit", value: <u64 as Value>::TYPE },
                Parameter { name: "initial_rtt", value: <u64 as Value>::TYPE },
                Parameter { name: "max_datagram_frame_size", value: <u64 as Value>::TYPE },
                Parameter { name: "disable_active_migration", value: <bool as Value>::TYPE },
                Parameter { name: "pacing", value: <bool as Value>::TYPE },
                Parameter { name: "grease_quic_bit", value: <bool as Value>::TYPE },
                Parameter { name: "spin_bit", value: <bool as Value>::TYPE },
                Parameter { name: "grease_transport_parameters", value: <bool as Value>::TYPE },
                Parameter { name: "maximum_crypto_buffer", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_send_buffer", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_datagrams", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_quic_QUICSession",
            documentation: " Where a QUIC connection stands.",
            fields: &[
                Parameter { name: "state", value: <u8 as Value>::TYPE },
                Parameter { name: "version", value: <u32 as Value>::TYPE },
                Parameter { name: "handshake_complete", value: <bool as Value>::TYPE },
                Parameter { name: "handshake_confirmed", value: <bool as Value>::TYPE },
                Parameter { name: "zero_rtt_rejected", value: <bool as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_quic_QUICEvent",
            documentation: " An event of a QUIC connection.",
            fields: &[
                Parameter { name: "kind", value: <u8 as Value>::TYPE },
                Parameter { name: "stream", value: <u64 as Value>::TYPE },
                Parameter { name: "error", value: <u64 as Value>::TYPE },
                Parameter { name: "bidirectional", value: <bool as Value>::TYPE },
                Parameter { name: "reason", value: <u8 as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_quic_QUICConfig",
            documentation: " The configuration of QUIC connections.",
        },
        Definition::Opaque {
            name: "umilib_protocol_quic_QUICEndpoint",
            documentation: " A QUIC endpoint without I/O and its connections.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[
        #[cfg(umilib_feature = "protocol-quic-v1")]
        v1::MODULE,
        #[cfg(umilib_feature = "protocol-quic-v2")]
        v2::MODULE,
    ],
};
