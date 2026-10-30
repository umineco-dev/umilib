use alloc::vec::Vec;
use core::time::Duration;

use super::{QUICConnectionID, QUICError, QUICPreferredAddress, QUICTransportParameters, QUICVersion};

/// Which congestion controller a connection uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum QUICCongestionKind {
    /// NewReno as RFC 9002 §7 defines it.
    #[default]
    NewReno = 0,
}

/// The configuration of QUIC connections, the same for clients and servers;
/// every limit and timeout can be changed. The transport parameters a
/// connection sends are made from it (RFC 9000 §18.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QUICConfig {
    /// The versions, most preferred first: a client starts with the first,
    /// a server accepts these and lists them in Version Negotiation. Those
    /// this crate implements by default, version 1 first (RFC 9369 §4).
    pub versions: Vec<QUICVersion>,
    /// The length of the connection IDs this end issues: 0 to 20, 8 by
    /// default. A zero length gives up migration and routing by ID.
    pub connection_id_length: usize,
    /// The idle timeout advertised: 30 s by default; zero for none (RFC 9000 §10.1).
    pub max_idle_timeout: Duration,
    /// The largest UDP payload this end accepts (max_udp_payload_size).
    pub max_udp_payload_size: u64,
    /// The size of the datagrams this end sends: 1200 by default, the
    /// smallest every path carries (RFC 9000 §14).
    pub datagram_size: usize,
    /// The flow control windows given to the peer (RFC 9000 §4): the
    /// connection's, and a stream's by who opened it.
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    /// The streams the peer may open (RFC 9000 §4.6), raised as they close.
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    /// The most an acknowledgment is delayed: 25 ms by default (RFC 9000 §13.2.1).
    pub max_ack_delay: Duration,
    /// The connection IDs of the peer this end keeps: 4 by default.
    pub active_connection_id_limit: u64,
    pub disable_active_migration: bool,
    /// A server's preferred address (RFC 9000 §9.6), its connection ID and
    /// token filled by the connection; it needs connection IDs that are not
    /// empty. The application receives on it too; clients of this crate
    /// keep to the address they connected to.
    pub preferred_address: Option<QUICPreferredAddress>,
    /// The round-trip time assumed before a sample: 333 ms by default (RFC 9002 §6.2.2).
    pub initial_rtt: Duration,
    pub congestion: QUICCongestionKind,
    /// Whether datagrams are paced (RFC 9002 §7.7): on by default.
    pub pacing: bool,
    /// The largest DATAGRAM frame accepted (RFC 9221 §3): 0, the default,
    /// accepts none.
    pub max_datagram_frame_size: u64,
    /// Whether packets without the QUIC bit are accepted and, when the peer
    /// accepts them too, sent (RFC 9287): on by default.
    pub grease_quic_bit: bool,
    /// Whether the latency spin bit is used (RFC 9000 §17.4); it is still
    /// off for one connection ID in 16, as the RFC requires. On by default.
    pub spin_bit: bool,
    /// Whether reserved transport parameters are sent, to exercise the
    /// peer's rule of ignoring unknown ones (RFC 9000 §18.1): on by default.
    pub grease_transport_parameters: bool,
    /// The key of stateless reset tokens (RFC 9000 §10.3.2), shared by the
    /// servers of a deployment; random tokens without one.
    pub reset_key: Option<[u8; 32]>,
    /// The most ranges an ACK frame carries, and kept of received packet numbers.
    pub maximum_ack_ranges: usize,
    pub maximum_received_ranges: usize,
    /// The most CRYPTO data held out of order at one level (RFC 9000 §7.5:
    /// at least 4096): 64 KiB by default.
    pub maximum_crypto_buffer: usize,
    /// The most datagrams kept that cannot be read yet because their keys
    /// are not there (RFC 9001 §4.1.4).
    pub maximum_buffered_packets: usize,
    /// The most DATAGRAM frames received and not yet read.
    pub maximum_datagrams: usize,
    /// The most events queued.
    pub maximum_events: usize,
    /// The most bytes a stream holds for sending, written and not acknowledged.
    pub maximum_send_buffer: usize,
}

impl Default for QUICConfig {
    fn default() -> QUICConfig {
        QUICConfig {
            versions: [QUICVersion::V1, QUICVersion::V2].into_iter().filter(|version| version.is_supported()).collect(),
            connection_id_length: 8,
            max_idle_timeout: Duration::from_secs(30),
            max_udp_payload_size: QUICTransportParameters::DEFAULT_MAX_UDP_PAYLOAD_SIZE,
            datagram_size: QUICConfig::MINIMUM_DATAGRAM_SIZE,
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 1 << 18,
            initial_max_stream_data_bidi_remote: 1 << 18,
            initial_max_stream_data_uni: 1 << 18,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: QUICTransportParameters::DEFAULT_ACK_DELAY_EXPONENT,
            max_ack_delay: Duration::from_millis(QUICTransportParameters::DEFAULT_MAX_ACK_DELAY),
            active_connection_id_limit: 4,
            disable_active_migration: false,
            preferred_address: None,
            initial_rtt: Duration::from_millis(333),
            congestion: QUICCongestionKind::NewReno,
            pacing: true,
            max_datagram_frame_size: 0,
            grease_quic_bit: true,
            spin_bit: true,
            grease_transport_parameters: true,
            reset_key: None,
            maximum_ack_ranges: 32,
            maximum_received_ranges: 256,
            maximum_crypto_buffer: 1 << 16,
            maximum_buffered_packets: 8,
            maximum_datagrams: 64,
            maximum_events: 1024,
            maximum_send_buffer: 1 << 20,
        }
    }
}

impl QUICConfig {
    /// The smallest datagram every path carries, and that a client's first
    /// Initial must fill (RFC 9000 §14.1).
    pub const MINIMUM_DATAGRAM_SIZE: usize = 1200;
    /// How much a server sends to an address it has not validated, for each
    /// byte it received from it (RFC 9000 §8.1).
    pub const AMPLIFICATION_FACTOR: u64 = 3;

    /// Fails with [`QUICError::Config`] if the configuration cannot work: no
    /// version this crate implements, a connection ID above 20 bytes, a
    /// preferred address with empty connection IDs (RFC 9000 §18.2), a
    /// datagram size below 1200 or above the UDP payload size, values the
    /// transport parameters cannot carry (RFC 9000 §18.2), or a CRYPTO
    /// buffer below 4096 bytes (RFC 9000 §7.5).
    pub fn check(&self) -> Result<(), QUICError> {
        let working = self.versions.iter().any(|version| version.is_supported())
            && self.connection_id_length <= QUICConnectionID::MAXIMUM_LENGTH
            && (self.preferred_address.is_none() || self.connection_id_length > 0)
            && self.datagram_size as u64 <= self.max_udp_payload_size
            && self.max_datagram_frame_size <= super::QUICVarint::MAXIMUM
            && [
                self.initial_max_data,
                self.initial_max_stream_data_bidi_local,
                self.initial_max_stream_data_bidi_remote,
                self.initial_max_stream_data_uni,
            ]
            .iter()
            .all(|value| *value <= super::QUICVarint::MAXIMUM)
            && self.datagram_size >= QUICConfig::MINIMUM_DATAGRAM_SIZE
            && self.max_udp_payload_size >= QUICTransportParameters::MINIMUM_MAX_UDP_PAYLOAD_SIZE
            && self.ack_delay_exponent <= QUICTransportParameters::MAXIMUM_ACK_DELAY_EXPONENT
            && self.max_ack_delay.as_millis() <= u128::from(QUICTransportParameters::MAXIMUM_MAX_ACK_DELAY)
            && self.active_connection_id_limit >= 2
            && self.initial_max_streams_bidi <= super::QUICStreamID::MAXIMUM_COUNT
            && self.initial_max_streams_uni <= super::QUICStreamID::MAXIMUM_COUNT
            && self.maximum_crypto_buffer >= 4096
            && self.maximum_ack_ranges >= 1
            && self.maximum_received_ranges >= self.maximum_ack_ranges
            && !self.initial_rtt.is_zero();
        if working { Ok(()) } else { Err(QUICError::Config) }
    }

    /// The transport parameters of these limits, without the values of a
    /// connection (its connection IDs and tokens).
    pub fn parameters(&self) -> QUICTransportParameters {
        QUICTransportParameters {
            max_idle_timeout: self.max_idle_timeout.as_millis().min(u128::from(super::QUICVarint::MAXIMUM)) as u64,
            max_udp_payload_size: self.max_udp_payload_size,
            initial_max_data: self.initial_max_data,
            initial_max_stream_data_bidi_local: self.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: self.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: self.initial_max_stream_data_uni,
            initial_max_streams_bidi: self.initial_max_streams_bidi,
            initial_max_streams_uni: self.initial_max_streams_uni,
            ack_delay_exponent: self.ack_delay_exponent,
            max_ack_delay: self.max_ack_delay.as_millis() as u64,
            disable_active_migration: self.disable_active_migration,
            active_connection_id_limit: self.active_connection_id_limit,
            max_datagram_frame_size: self.max_datagram_frame_size,
            grease_quic_bit: self.grease_quic_bit,
            ..QUICTransportParameters::default()
        }
    }

    /// The versions as Version Negotiation lists them.
    pub fn supported_versions(&self) -> Vec<QUICVersion> {
        self.versions.iter().copied().filter(|version| version.is_supported()).collect()
    }
}
