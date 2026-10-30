//! QUIC without I/O: version 1 (RFC 9000, RFC 9001, RFC 9002) and version 2
//! (RFC 9369), with Version Negotiation (RFC 8999, RFC 9368), DATAGRAM
//! frames (RFC 9221) and the greasing of the QUIC bit (RFC 9287).
//!
//! This root module holds the transport, which the versions share: the
//! variable-length integers ([`QUICVarint`]), the invariant headers
//! ([`QUICInvariantHeader`]), packets ([`QUICPacket`]), frames
//! ([`QUICFrame`]) and transport parameters ([`QUICTransportParameters`]).
//! What differs between versions is a [`QUICVersionProfile`], which the
//! modules `v1` (feature `protocol-quic-v1`) and `v2` (`protocol-quic-v2`)
//! define.

mod config;
mod connection;
mod connection_id;
mod connection_ids;
mod endpoint;
mod error;
mod event;
mod flow;
mod frame;
mod packet;
mod parameters;
mod protection;
mod range_set;
mod received;
mod recovery;
mod role;
mod rule;
mod sent;
mod space;
mod stream;
mod stream_buffer;
mod stream_id;
mod token;
mod varint;
mod version;

#[cfg(umilib_feature = "protocol-quic-v1")]
pub mod v1;
#[cfg(umilib_feature = "protocol-quic-v2")]
pub mod v2;

pub use config::{QUICConfig, QUICCongestionKind};
pub use connection::{
    QUICAcceptance, QUICClosing, QUICConnection, QUICConnectionState, QUICPathResponse, QUICPendingFrames, QUICRestart,
    QUICTransmission,
};
pub use connection_id::QUICConnectionID;
pub use connection_ids::{QUICIssuedID, QUICLocalConnectionIDs, QUICPeerConnectionIDs, QUICResetToken};
pub use endpoint::{QUICEndpoint, QUICEndpointConfig};
pub use error::{QUICError, QUICErrorCode, QUICTransportError};
pub use event::{QUICCloseReason, QUICEvent};
pub use flow::{QUICReceiveCredit, QUICSendCredit};
pub use frame::{QUICACKFrame, QUICACKRanges, QUICECNCounts, QUICFrame, QUICFrameReader, QUICFrameType, QUICFrames};
pub use packet::{
    QUICHeader, QUICInvariantHeader, QUICLongHeader, QUICPacket, QUICPacketNumber, QUICPacketNumberSpace,
    QUICPacketType, QUICProtectedPacket, QUICRetry, QUICShortHeader, QUICVersionNegotiation,
};
pub use parameters::{QUICPreferredAddress, QUICTransportParameterID, QUICTransportParameters, QUICVersionInformation};
pub use protection::{QUICHeaderProtection, QUICPacketKey, QUICRetryIntegrity, QUICSecret};
pub use range_set::QUICRangeSet;
pub use received::{QUICECN, QUICReceivedPackets};
pub use recovery::{
    QUICAcknowledgment, QUICCongestionControl, QUICNewReno, QUICPacer, QUICRTT, QUICRecovery, QUICSpaceRecovery,
};
pub use role::QUICRole;
pub use rule::QUICRule;
pub use sent::{QUICSentFrame, QUICSentPacket};
pub use space::{QUICBufferedPackets, QUICKeys, QUICOneRTT, QUICSpace};
pub use stream::{
    QUICReceiveState, QUICReceiveStream, QUICSendState, QUICSendStream, QUICStream, QUICStreamWindows, QUICStreams,
};
pub use stream_buffer::{QUICReceiveBuffer, QUICSendBuffer};
pub use stream_id::QUICStreamID;
pub use token::{QUICToken, QUICTokenKey, QUICTokenKind};
pub use varint::QUICVarint;
pub use version::{QUICVersion, QUICVersionProfile};
