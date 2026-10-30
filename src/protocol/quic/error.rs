use core::fmt;

use crate::bytes::BytesError;

use super::QUICFrameType;

/// A transport error code of QUIC (RFC 9000 §20.1), carried by
/// CONNECTION_CLOSE frames of type 0x1c.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct QUICErrorCode(pub u64);

impl QUICErrorCode {
    pub const NO_ERROR: QUICErrorCode = QUICErrorCode(0x00);
    pub const INTERNAL_ERROR: QUICErrorCode = QUICErrorCode(0x01);
    pub const CONNECTION_REFUSED: QUICErrorCode = QUICErrorCode(0x02);
    pub const FLOW_CONTROL_ERROR: QUICErrorCode = QUICErrorCode(0x03);
    pub const STREAM_LIMIT_ERROR: QUICErrorCode = QUICErrorCode(0x04);
    pub const STREAM_STATE_ERROR: QUICErrorCode = QUICErrorCode(0x05);
    pub const FINAL_SIZE_ERROR: QUICErrorCode = QUICErrorCode(0x06);
    pub const FRAME_ENCODING_ERROR: QUICErrorCode = QUICErrorCode(0x07);
    pub const TRANSPORT_PARAMETER_ERROR: QUICErrorCode = QUICErrorCode(0x08);
    pub const CONNECTION_ID_LIMIT_ERROR: QUICErrorCode = QUICErrorCode(0x09);
    pub const PROTOCOL_VIOLATION: QUICErrorCode = QUICErrorCode(0x0A);
    pub const INVALID_TOKEN: QUICErrorCode = QUICErrorCode(0x0B);
    pub const APPLICATION_ERROR: QUICErrorCode = QUICErrorCode(0x0C);
    pub const CRYPTO_BUFFER_EXCEEDED: QUICErrorCode = QUICErrorCode(0x0D);
    pub const KEY_UPDATE_ERROR: QUICErrorCode = QUICErrorCode(0x0E);
    pub const AEAD_LIMIT_REACHED: QUICErrorCode = QUICErrorCode(0x0F);
    pub const NO_VIABLE_PATH: QUICErrorCode = QUICErrorCode(0x10);
    /// RFC 9368 §10.2.
    pub const VERSION_NEGOTIATION_ERROR: QUICErrorCode = QUICErrorCode(0x11);
    /// The first code of CRYPTO_ERROR: 0x0100 plus a TLS alert (RFC 9001 §4.8).
    pub const CRYPTO_ERROR: QUICErrorCode = QUICErrorCode(0x0100);

    /// The CRYPTO_ERROR of the TLS alert `description` (RFC 9001 §4.8).
    pub const fn crypto(description: u8) -> QUICErrorCode {
        QUICErrorCode(QUICErrorCode::CRYPTO_ERROR.0 + description as u64)
    }

    /// The TLS alert of a CRYPTO_ERROR, or `None` for another code.
    pub const fn alert(self) -> Option<u8> {
        if self.0 >= 0x0100 && self.0 <= 0x01FF { Some((self.0 - 0x0100) as u8) } else { None }
    }
}

/// A connection error (RFC 9000 §11.1): the code, the type of the frame
/// that caused it (PADDING's 0 when none or unknown, RFC 9000 §19.19), and
/// a reason phrase for the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QUICTransportError {
    pub code: QUICErrorCode,
    pub frame_type: QUICFrameType,
    pub reason: &'static str,
}

impl QUICTransportError {
    pub const fn new(code: QUICErrorCode, reason: &'static str) -> QUICTransportError {
        QUICTransportError { code, frame_type: QUICFrameType::PADDING, reason }
    }

    /// This error, caused by a frame of `frame_type`.
    pub const fn in_frame(self, frame_type: QUICFrameType) -> QUICTransportError {
        QUICTransportError { frame_type, ..self }
    }
}

/// Why a QUIC operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QUICError {
    /// Not a packet of a version this end can read, or one that fails a rule
    /// whose answer is to discard it (RFC 9000 §5.2, §12.2, §17.2).
    InvalidPacket,
    /// What the peer sent breaks the protocol: the connection closes with this error.
    Transport(QUICTransportError),
    /// An operation that the connection's state does not allow.
    State,
    /// A configuration that cannot work.
    Config,
    /// The source of randomness failed.
    Random,
    /// A writer that cannot take the encoded bytes.
    Write(BytesError),
}

impl QUICError {
    /// The connection error `code` with `reason`.
    pub const fn transport(code: QUICErrorCode, reason: &'static str) -> QUICError {
        QUICError::Transport(QUICTransportError::new(code, reason))
    }

    /// A malformed frame of `frame_type` (RFC 9000 §12.4).
    pub const fn frame_encoding(frame_type: QUICFrameType, reason: &'static str) -> QUICError {
        QUICError::Transport(QUICTransportError::new(QUICErrorCode::FRAME_ENCODING_ERROR, reason).in_frame(frame_type))
    }

    /// A rule of the protocol broken by a frame of `frame_type`.
    pub const fn violation(frame_type: QUICFrameType, reason: &'static str) -> QUICError {
        QUICError::Transport(QUICTransportError::new(QUICErrorCode::PROTOCOL_VIOLATION, reason).in_frame(frame_type))
    }

    /// This error, caused by a frame of `frame_type`.
    pub const fn in_frame(self, frame_type: QUICFrameType) -> QUICError {
        match self {
            QUICError::Transport(error) => QUICError::Transport(error.in_frame(frame_type)),
            other => other,
        }
    }

    /// A malformed or forbidden transport parameter (RFC 9000 §7.4, §18).
    pub const fn parameter(reason: &'static str) -> QUICError {
        QUICError::transport(QUICErrorCode::TRANSPORT_PARAMETER_ERROR, reason)
    }
}

impl fmt::Display for QUICError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QUICError::InvalidPacket => formatter.write_str("not a valid QUIC packet"),
            QUICError::Transport(error) => {
                write!(formatter, "QUIC transport error {:#x}: {}", error.code.0, error.reason)
            }
            QUICError::State => formatter.write_str("the QUIC connection's state does not allow it"),
            QUICError::Config => formatter.write_str("the QUIC configuration cannot work"),
            QUICError::Random => formatter.write_str("the source of randomness failed"),
            QUICError::Write(error) => write!(formatter, "the QUIC data cannot be written: {error}"),
        }
    }
}

impl core::error::Error for QUICError {}

impl From<BytesError> for QUICError {
    fn from(error: BytesError) -> QUICError {
        QUICError::Write(error)
    }
}
