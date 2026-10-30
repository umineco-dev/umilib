use alloc::vec::Vec;

use super::{QUICErrorCode, QUICStreamID};

/// Why a connection ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QUICCloseReason {
    /// This end closed it, with this error of the transport.
    Local { error: QUICErrorCode, reason: Vec<u8> },
    /// This end's application closed it with its error.
    LocalApplication { error: u64, reason: Vec<u8> },
    /// The peer closed it with a transport error (RFC 9000 §19.19).
    Peer { error: QUICErrorCode, reason: Vec<u8> },
    /// The peer's application closed it.
    PeerApplication { error: u64, reason: Vec<u8> },
    /// Nothing arrived for the idle timeout (RFC 9000 §10.1).
    IdleTimeout,
    /// The peer lost the connection's state (RFC 9000 §10.3).
    StatelessReset,
    /// The server answered with versions none of which this client accepts (RFC 9000 §6.2).
    VersionNegotiation,
}

/// What happened on a connection that the application may act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QUICEvent {
    /// The handshake completed (RFC 9001 §4.1.1): streams flow both ways.
    Connected,
    /// The handshake is confirmed (RFC 9001 §4.1.2).
    HandshakeConfirmed,
    /// The peer opened a stream.
    StreamOpened { stream: QUICStreamID },
    /// A stream has data, or its end, to read.
    StreamReadable { stream: QUICStreamID },
    /// A stream can take more data to send.
    StreamWritable { stream: QUICStreamID },
    /// The peer reset its half of a stream (RFC 9000 §19.4).
    StreamReset { stream: QUICStreamID, error: u64 },
    /// The peer asked this end to stop sending on a stream (RFC 9000 §19.5).
    StopSending { stream: QUICStreamID, error: u64 },
    /// More streams of a kind may be opened.
    StreamsAvailable { bidirectional: bool },
    /// A DATAGRAM frame arrived (RFC 9221).
    Datagram,
    /// The server gave a token for later connections (RFC 9000 §8.1.3).
    NewToken { token: Vec<u8> },
    /// 0-RTT was refused: the streams opened before are gone, and their
    /// data must be sent again if still wanted (RFC 9001 §4.6.2).
    ZeroRTTRejected,
    /// The connection ended.
    Closed { reason: QUICCloseReason },
}
