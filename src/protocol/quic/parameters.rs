use alloc::vec::Vec;

use crate::bytes::{Reader, Writer};
use crate::protocol::ip::{IPv4Address, IPv6Address};

use super::{QUICConnectionID, QUICError, QUICRole, QUICStreamID, QUICVarint, QUICVersion};

/// The identifier of a transport parameter (RFC 9000 §18.2, §22.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct QUICTransportParameterID(pub u64);

impl QUICTransportParameterID {
    pub const ORIGINAL_DESTINATION_CONNECTION_ID: QUICTransportParameterID = QUICTransportParameterID(0x00);
    pub const MAX_IDLE_TIMEOUT: QUICTransportParameterID = QUICTransportParameterID(0x01);
    pub const STATELESS_RESET_TOKEN: QUICTransportParameterID = QUICTransportParameterID(0x02);
    pub const MAX_UDP_PAYLOAD_SIZE: QUICTransportParameterID = QUICTransportParameterID(0x03);
    pub const INITIAL_MAX_DATA: QUICTransportParameterID = QUICTransportParameterID(0x04);
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: QUICTransportParameterID = QUICTransportParameterID(0x05);
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: QUICTransportParameterID = QUICTransportParameterID(0x06);
    pub const INITIAL_MAX_STREAM_DATA_UNI: QUICTransportParameterID = QUICTransportParameterID(0x07);
    pub const INITIAL_MAX_STREAMS_BIDI: QUICTransportParameterID = QUICTransportParameterID(0x08);
    pub const INITIAL_MAX_STREAMS_UNI: QUICTransportParameterID = QUICTransportParameterID(0x09);
    pub const ACK_DELAY_EXPONENT: QUICTransportParameterID = QUICTransportParameterID(0x0A);
    pub const MAX_ACK_DELAY: QUICTransportParameterID = QUICTransportParameterID(0x0B);
    pub const DISABLE_ACTIVE_MIGRATION: QUICTransportParameterID = QUICTransportParameterID(0x0C);
    pub const PREFERRED_ADDRESS: QUICTransportParameterID = QUICTransportParameterID(0x0D);
    pub const ACTIVE_CONNECTION_ID_LIMIT: QUICTransportParameterID = QUICTransportParameterID(0x0E);
    pub const INITIAL_SOURCE_CONNECTION_ID: QUICTransportParameterID = QUICTransportParameterID(0x0F);
    pub const RETRY_SOURCE_CONNECTION_ID: QUICTransportParameterID = QUICTransportParameterID(0x10);
    /// RFC 9368 §3.
    pub const VERSION_INFORMATION: QUICTransportParameterID = QUICTransportParameterID(0x11);
    /// RFC 9221 §3.
    pub const MAX_DATAGRAM_FRAME_SIZE: QUICTransportParameterID = QUICTransportParameterID(0x20);
    /// RFC 9287 §3.
    pub const GREASE_QUIC_BIT: QUICTransportParameterID = QUICTransportParameterID(0x2AB2);

    /// The `n`th reserved identifier, 31 × n + 27, which carries no meaning
    /// and exercises the rule that unknown parameters are ignored (RFC 9000
    /// §18.1); `None` past the largest varint.
    pub const fn reserved(n: u64) -> Option<QUICTransportParameterID> {
        match n.checked_mul(31) {
            Some(value) if value <= QUICVarint::MAXIMUM - 27 => Some(QUICTransportParameterID(value + 27)),
            _ => None,
        }
    }

    pub const fn is_reserved(self) -> bool {
        self.0 % 31 == 27
    }
}

/// The server's preferred address (RFC 9000 §9.6, §18.2): an address of
/// each family, the unspecified one for a family it does not offer, and the
/// connection ID of sequence number 1 with its stateless reset token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QUICPreferredAddress {
    pub ipv4: IPv4Address,
    pub ipv4_port: u16,
    pub ipv6: IPv6Address,
    pub ipv6_port: u16,
    pub connection_id: QUICConnectionID,
    pub reset_token: [u8; 16],
}

/// The Version Information of compatible version negotiation (RFC 9368 §3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct QUICVersionInformation {
    pub chosen: QUICVersion,
    /// A client's versions its first flight is compatible with, most
    /// preferred first; a server's fully deployed versions, in no order.
    pub available: Vec<QUICVersion>,
}

/// The transport parameters of one end (RFC 9000 §7.4, §18.2), with those
/// of RFC 9221, RFC 9287 and RFC 9368. A parameter that is absent has its
/// default value here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct QUICTransportParameters {
    /// The server's copy of the Destination Connection ID of the client's
    /// first Initial packet (RFC 9000 §7.3).
    pub original_destination_connection_id: Option<QUICConnectionID>,
    /// Milliseconds; 0 for no idle timeout (RFC 9000 §10.1).
    pub max_idle_timeout: u64,
    /// The server's stateless reset token for the connection ID of the
    /// handshake (RFC 9000 §10.3).
    pub stateless_reset_token: Option<[u8; 16]>,
    /// At least 1200; 65527 by default.
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    /// At most 2^60 (RFC 9000 §4.6).
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    /// At most 20; 3 by default.
    pub ack_delay_exponent: u64,
    /// Milliseconds, below 2^14; 25 by default.
    pub max_ack_delay: u64,
    pub disable_active_migration: bool,
    pub preferred_address: Option<QUICPreferredAddress>,
    /// At least 2; 2 by default.
    pub active_connection_id_limit: u64,
    pub initial_source_connection_id: Option<QUICConnectionID>,
    pub retry_source_connection_id: Option<QUICConnectionID>,
    pub version_information: Option<QUICVersionInformation>,
    /// The largest DATAGRAM frame accepted; 0, the default, accepts none (RFC 9221 §3).
    pub max_datagram_frame_size: u64,
    /// Whether packets without the QUIC bit are accepted (RFC 9287 §3).
    pub grease_quic_bit: bool,
}

impl Default for QUICTransportParameters {
    fn default() -> QUICTransportParameters {
        QUICTransportParameters {
            original_destination_connection_id: None,
            max_idle_timeout: 0,
            stateless_reset_token: None,
            max_udp_payload_size: QUICTransportParameters::DEFAULT_MAX_UDP_PAYLOAD_SIZE,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: QUICTransportParameters::DEFAULT_ACK_DELAY_EXPONENT,
            max_ack_delay: QUICTransportParameters::DEFAULT_MAX_ACK_DELAY,
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: QUICTransportParameters::DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            version_information: None,
            max_datagram_frame_size: 0,
            grease_quic_bit: false,
        }
    }
}

impl QUICTransportParameters {
    pub const DEFAULT_MAX_UDP_PAYLOAD_SIZE: u64 = 65_527;
    pub const MINIMUM_MAX_UDP_PAYLOAD_SIZE: u64 = 1200;
    pub const DEFAULT_ACK_DELAY_EXPONENT: u64 = 3;
    pub const MAXIMUM_ACK_DELAY_EXPONENT: u64 = 20;
    pub const DEFAULT_MAX_ACK_DELAY: u64 = 25;
    /// max_ack_delay must stay below 2^14 milliseconds.
    pub const MAXIMUM_MAX_ACK_DELAY: u64 = (1 << 14) - 1;
    pub const DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

    /// Writes the parameters that differ from their defaults, then
    /// `reserved`: parameters of reserved identifiers that the peer must
    /// ignore (RFC 9000 §18.1), to keep that rule exercised. Fails with
    /// [`QUICError::Config`] for values that [`QUICTransportParameters::decode`] refuses.
    pub fn encode(
        &self,
        reserved: &[(QUICTransportParameterID, &[u8])],
        out: &mut impl Writer,
    ) -> Result<(), QUICError> {
        let valid = self.max_udp_payload_size >= QUICTransportParameters::MINIMUM_MAX_UDP_PAYLOAD_SIZE
            && self.ack_delay_exponent <= QUICTransportParameters::MAXIMUM_ACK_DELAY_EXPONENT
            && self.max_ack_delay <= QUICTransportParameters::MAXIMUM_MAX_ACK_DELAY
            && self.active_connection_id_limit >= 2
            && self.initial_max_streams_bidi <= QUICStreamID::MAXIMUM_COUNT
            && self.initial_max_streams_uni <= QUICStreamID::MAXIMUM_COUNT
            && self.preferred_address.is_none_or(|address| !address.connection_id.is_empty())
            && self.version_information.as_ref().is_none_or(|information| {
                information.chosen != QUICVersion::NEGOTIATION
                    && !information.available.contains(&QUICVersion::NEGOTIATION)
            });
        if !valid {
            return Err(QUICError::Config);
        }
        let defaults = QUICTransportParameters::default();
        if let Some(cid) = &self.original_destination_connection_id {
            QUICTransportParameters::write_opaque(
                out,
                QUICTransportParameterID::ORIGINAL_DESTINATION_CONNECTION_ID,
                cid.as_slice(),
            )?;
        }
        let integers = [
            (QUICTransportParameterID::MAX_IDLE_TIMEOUT, self.max_idle_timeout, defaults.max_idle_timeout),
            (QUICTransportParameterID::MAX_UDP_PAYLOAD_SIZE, self.max_udp_payload_size, defaults.max_udp_payload_size),
            (QUICTransportParameterID::INITIAL_MAX_DATA, self.initial_max_data, 0),
            (QUICTransportParameterID::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, self.initial_max_stream_data_bidi_local, 0),
            (
                QUICTransportParameterID::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                self.initial_max_stream_data_bidi_remote,
                0,
            ),
            (QUICTransportParameterID::INITIAL_MAX_STREAM_DATA_UNI, self.initial_max_stream_data_uni, 0),
            (QUICTransportParameterID::INITIAL_MAX_STREAMS_BIDI, self.initial_max_streams_bidi, 0),
            (QUICTransportParameterID::INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni, 0),
            (QUICTransportParameterID::ACK_DELAY_EXPONENT, self.ack_delay_exponent, defaults.ack_delay_exponent),
            (QUICTransportParameterID::MAX_ACK_DELAY, self.max_ack_delay, defaults.max_ack_delay),
            (
                QUICTransportParameterID::ACTIVE_CONNECTION_ID_LIMIT,
                self.active_connection_id_limit,
                defaults.active_connection_id_limit,
            ),
            (QUICTransportParameterID::MAX_DATAGRAM_FRAME_SIZE, self.max_datagram_frame_size, 0),
        ];
        if let Some(token) = &self.stateless_reset_token {
            QUICTransportParameters::write_opaque(out, QUICTransportParameterID::STATELESS_RESET_TOKEN, token)?;
        }
        for (parameter, value, default) in integers {
            if value != default {
                QUICTransportParameters::write_integer(out, parameter, value)?;
            }
        }
        if self.disable_active_migration {
            QUICTransportParameters::write_opaque(out, QUICTransportParameterID::DISABLE_ACTIVE_MIGRATION, &[])?;
        }
        if let Some(address) = &self.preferred_address {
            let mut value = Vec::with_capacity(41 + address.connection_id.len());
            value.extend_from_slice(&address.ipv4.0);
            value.extend_from_slice(&address.ipv4_port.to_be_bytes());
            value.extend_from_slice(&address.ipv6.0);
            value.extend_from_slice(&address.ipv6_port.to_be_bytes());
            value.push(address.connection_id.len() as u8);
            value.extend_from_slice(address.connection_id.as_slice());
            value.extend_from_slice(&address.reset_token);
            QUICTransportParameters::write_opaque(out, QUICTransportParameterID::PREFERRED_ADDRESS, &value)?;
        }
        if let Some(cid) = &self.initial_source_connection_id {
            QUICTransportParameters::write_opaque(
                out,
                QUICTransportParameterID::INITIAL_SOURCE_CONNECTION_ID,
                cid.as_slice(),
            )?;
        }
        if let Some(cid) = &self.retry_source_connection_id {
            QUICTransportParameters::write_opaque(
                out,
                QUICTransportParameterID::RETRY_SOURCE_CONNECTION_ID,
                cid.as_slice(),
            )?;
        }
        if let Some(information) = &self.version_information {
            let mut value = Vec::with_capacity(4 * (1 + information.available.len()));
            value.extend_from_slice(&information.chosen.0.to_be_bytes());
            for version in &information.available {
                value.extend_from_slice(&version.0.to_be_bytes());
            }
            QUICTransportParameters::write_opaque(out, QUICTransportParameterID::VERSION_INFORMATION, &value)?;
        }
        if self.grease_quic_bit {
            QUICTransportParameters::write_opaque(out, QUICTransportParameterID::GREASE_QUIC_BIT, &[])?;
        }
        for (parameter, value) in reserved {
            if !parameter.is_reserved() {
                return Err(QUICError::Config);
            }
            QUICTransportParameters::write_opaque(out, *parameter, value)?;
        }
        Ok(())
    }

    /// Writes a parameter of `value`.
    pub fn write_opaque(
        out: &mut impl Writer,
        parameter: QUICTransportParameterID,
        value: &[u8],
    ) -> Result<(), QUICError> {
        QUICVarint::write_all(out, &[parameter.0, value.len() as u64])?;
        out.write(value)?;
        Ok(())
    }

    /// Writes a parameter of an integer value.
    pub fn write_integer(
        out: &mut impl Writer,
        parameter: QUICTransportParameterID,
        value: u64,
    ) -> Result<(), QUICError> {
        let length = QUICVarint::length(value).ok_or(QUICError::Config)?;
        QUICVarint::write_all(out, &[parameter.0, length as u64, value])?;
        Ok(())
    }

    /// The parameters `sender` sent. Fails with TRANSPORT_PARAMETER_ERROR
    /// (RFC 9000 §7.4, §18.2, RFC 9221 §3, RFC 9287 §3, RFC 9368 §4) for a
    /// parameter cut short or repeated, a value out of range, an integer
    /// whose length is not that of its encoding, a connection ID above 20
    /// bytes, a server-only parameter from a client, or a preferred address
    /// with an empty connection ID. Unknown parameters are ignored.
    pub fn decode(bytes: &[u8], sender: QUICRole) -> Result<QUICTransportParameters, QUICError> {
        let mut parameters = QUICTransportParameters::default();
        let mut reader = Reader::new(bytes);
        let mut seen: Vec<u64> = Vec::new();
        while !reader.is_empty() {
            let cut = || QUICError::parameter("transport parameter cut short");
            let parameter = QUICTransportParameterID(QUICVarint::read(&mut reader).map_err(|_| cut())?);
            let length = QUICVarint::read(&mut reader).map_err(|_| cut())?;
            let length = usize::try_from(length).map_err(|_| cut())?;
            let value = reader.read_slice(length).map_err(|_| cut())?;
            seen.push(parameter.0);
            let server_only = matches!(parameter.0, 0x00 | 0x02 | 0x0D | 0x10);
            if server_only && sender == QUICRole::Client {
                return Err(QUICError::parameter("server-only transport parameter from a client"));
            }
            match parameter {
                QUICTransportParameterID::ORIGINAL_DESTINATION_CONNECTION_ID => {
                    parameters.original_destination_connection_id = Some(QUICTransportParameters::connection_id(value)?)
                }
                QUICTransportParameterID::MAX_IDLE_TIMEOUT => {
                    parameters.max_idle_timeout = QUICTransportParameters::integer(value)?
                }
                QUICTransportParameterID::STATELESS_RESET_TOKEN => {
                    let token = value.try_into().map_err(|_| QUICError::parameter("stateless_reset_token"))?;
                    parameters.stateless_reset_token = Some(token);
                }
                QUICTransportParameterID::MAX_UDP_PAYLOAD_SIZE => {
                    parameters.max_udp_payload_size = QUICTransportParameters::integer(value)?;
                    if parameters.max_udp_payload_size < QUICTransportParameters::MINIMUM_MAX_UDP_PAYLOAD_SIZE {
                        return Err(QUICError::parameter("max_udp_payload_size below 1200"));
                    }
                }
                QUICTransportParameterID::INITIAL_MAX_DATA => {
                    parameters.initial_max_data = QUICTransportParameters::integer(value)?
                }
                QUICTransportParameterID::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    parameters.initial_max_stream_data_bidi_local = QUICTransportParameters::integer(value)?
                }
                QUICTransportParameterID::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    parameters.initial_max_stream_data_bidi_remote = QUICTransportParameters::integer(value)?
                }
                QUICTransportParameterID::INITIAL_MAX_STREAM_DATA_UNI => {
                    parameters.initial_max_stream_data_uni = QUICTransportParameters::integer(value)?
                }
                QUICTransportParameterID::INITIAL_MAX_STREAMS_BIDI => {
                    parameters.initial_max_streams_bidi = QUICTransportParameters::stream_count(value)?
                }
                QUICTransportParameterID::INITIAL_MAX_STREAMS_UNI => {
                    parameters.initial_max_streams_uni = QUICTransportParameters::stream_count(value)?
                }
                QUICTransportParameterID::ACK_DELAY_EXPONENT => {
                    parameters.ack_delay_exponent = QUICTransportParameters::integer(value)?;
                    if parameters.ack_delay_exponent > QUICTransportParameters::MAXIMUM_ACK_DELAY_EXPONENT {
                        return Err(QUICError::parameter("ack_delay_exponent above 20"));
                    }
                }
                QUICTransportParameterID::MAX_ACK_DELAY => {
                    parameters.max_ack_delay = QUICTransportParameters::integer(value)?;
                    if parameters.max_ack_delay > QUICTransportParameters::MAXIMUM_MAX_ACK_DELAY {
                        return Err(QUICError::parameter("max_ack_delay of 2^14 or more"));
                    }
                }
                QUICTransportParameterID::DISABLE_ACTIVE_MIGRATION => {
                    QUICTransportParameters::empty(value)?;
                    parameters.disable_active_migration = true;
                }
                QUICTransportParameterID::PREFERRED_ADDRESS => {
                    parameters.preferred_address = Some(QUICTransportParameters::preferred_address(value)?)
                }
                QUICTransportParameterID::ACTIVE_CONNECTION_ID_LIMIT => {
                    parameters.active_connection_id_limit = QUICTransportParameters::integer(value)?;
                    if parameters.active_connection_id_limit < 2 {
                        return Err(QUICError::parameter("active_connection_id_limit below 2"));
                    }
                }
                QUICTransportParameterID::INITIAL_SOURCE_CONNECTION_ID => {
                    parameters.initial_source_connection_id = Some(QUICTransportParameters::connection_id(value)?)
                }
                QUICTransportParameterID::RETRY_SOURCE_CONNECTION_ID => {
                    parameters.retry_source_connection_id = Some(QUICTransportParameters::connection_id(value)?)
                }
                QUICTransportParameterID::VERSION_INFORMATION => {
                    parameters.version_information = Some(QUICTransportParameters::version_information(value, sender)?)
                }
                QUICTransportParameterID::MAX_DATAGRAM_FRAME_SIZE => {
                    parameters.max_datagram_frame_size = QUICTransportParameters::integer(value)?
                }
                QUICTransportParameterID::GREASE_QUIC_BIT => {
                    QUICTransportParameters::empty(value)?;
                    parameters.grease_quic_bit = true;
                }
                _ => {}
            }
        }
        // Sorted, so that thousands of parameters cost no more than reading them.
        seen.sort_unstable();
        if seen.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(QUICError::parameter("transport parameter repeated"));
        }
        Ok(parameters)
    }

    /// An integer value: one varint that is the whole value.
    pub fn integer(value: &[u8]) -> Result<u64, QUICError> {
        let mut reader = Reader::new(value);
        let integer = QUICVarint::read(&mut reader).map_err(|_| QUICError::parameter("integer cut short"))?;
        if !reader.is_empty() {
            return Err(QUICError::parameter("integer shorter than its length"));
        }
        Ok(integer)
    }

    /// A count of streams: at most 2^60 (RFC 9000 §4.6).
    pub fn stream_count(value: &[u8]) -> Result<u64, QUICError> {
        let count = QUICTransportParameters::integer(value)?;
        if count > QUICStreamID::MAXIMUM_COUNT {
            return Err(QUICError::parameter("more than 2^60 streams"));
        }
        Ok(count)
    }

    pub fn connection_id(value: &[u8]) -> Result<QUICConnectionID, QUICError> {
        QUICConnectionID::new(value).ok_or(QUICError::parameter("connection ID above 20 bytes"))
    }

    pub fn empty(value: &[u8]) -> Result<(), QUICError> {
        if value.is_empty() { Ok(()) } else { Err(QUICError::parameter("value of a flag not empty")) }
    }

    /// A preferred address: its connection ID must not be empty (RFC 9000 §18.2).
    pub fn preferred_address(value: &[u8]) -> Result<QUICPreferredAddress, QUICError> {
        let mut reader = Reader::new(value);
        let cut = |_| QUICError::parameter("preferred_address cut short");
        let ipv4 = IPv4Address(reader.read_array().map_err(cut)?);
        let ipv4_port = reader.read_be().map_err(cut)?;
        let ipv6 = IPv6Address(reader.read_array().map_err(cut)?);
        let ipv6_port = reader.read_be().map_err(cut)?;
        let length = reader.read_u8().map_err(cut)? as usize;
        let connection_id = QUICTransportParameters::connection_id(reader.read_slice(length).map_err(cut)?)?;
        let reset_token = reader.read_array().map_err(cut)?;
        if connection_id.is_empty() || !reader.is_empty() {
            return Err(QUICError::parameter("preferred_address malformed"));
        }
        Ok(QUICPreferredAddress { ipv4, ipv4_port, ipv6, ipv6_port, connection_id, reset_token })
    }

    /// Version Information (RFC 9368 §4): a multiple of 4 bytes, at least
    /// the Chosen Version; no version zero; a client's Available Versions
    /// include its Chosen Version.
    pub fn version_information(value: &[u8], sender: QUICRole) -> Result<QUICVersionInformation, QUICError> {
        let (versions, rest) = value.as_chunks::<4>();
        let malformed = QUICError::parameter("version_information malformed");
        let [chosen, available @ ..] = versions else { return Err(malformed) };
        if !rest.is_empty() {
            return Err(malformed);
        }
        let chosen = QUICVersion(u32::from_be_bytes(*chosen));
        let available: Vec<QUICVersion> =
            available.iter().map(|bytes| QUICVersion(u32::from_be_bytes(*bytes))).collect();
        let zero = chosen == QUICVersion::NEGOTIATION || available.contains(&QUICVersion::NEGOTIATION);
        if zero || (sender == QUICRole::Client && !available.contains(&chosen)) {
            return Err(malformed);
        }
        Ok(QUICVersionInformation { chosen, available })
    }
}
