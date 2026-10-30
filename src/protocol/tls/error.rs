use crate::bytes::BytesError;

use super::TLSAlertDescription;

/// Why a TLS operation failed. A failure caused by what the peer sent
/// carries the alert to send it (RFC 9846 §6.2), so that the connection can
/// always answer with the right alert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TLSError {
    /// What the peer sent breaks the protocol; the alert says how.
    Protocol(TLSAlertDescription),
    /// The peer sent this fatal alert, or closed with `close_notify`.
    Alert(TLSAlertDescription),
    /// An operation that the connection's state does not allow.
    State,
    /// A configuration that cannot work.
    Config,
    /// A writer that cannot take the encoded bytes.
    Write(BytesError),
    /// What the peer sent breaks a rule of the transport that carries the
    /// handshake rather than of TLS: QUIC's PROTOCOL_VIOLATION (RFC 9001
    /// §4.1.3, §4.4, §4.6.1, §8.4). No alert is sent.
    Transport,
}

impl TLSError {
    /// A malformed message: `decode_error` (RFC 9846 §6.2).
    pub const fn decode() -> TLSError {
        TLSError::Protocol(TLSAlertDescription::DECODE_ERROR)
    }

    /// A field with a value that is not allowed: `illegal_parameter`.
    pub const fn illegal() -> TLSError {
        TLSError::Protocol(TLSAlertDescription::ILLEGAL_PARAMETER)
    }

    /// A message that is not expected now: `unexpected_message`.
    pub const fn unexpected() -> TLSError {
        TLSError::Protocol(TLSAlertDescription::UNEXPECTED_MESSAGE)
    }

    /// The alert to send for this failure, if any: the protocol's, or
    /// `internal_error` for a local failure while the connection is open.
    pub fn alert(&self) -> Option<TLSAlertDescription> {
        match self {
            TLSError::Protocol(description) => Some(*description),
            TLSError::Alert(_) | TLSError::State | TLSError::Config | TLSError::Transport => None,
            TLSError::Write(_) => Some(TLSAlertDescription::INTERNAL_ERROR),
        }
    }
}

impl core::fmt::Display for TLSError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TLSError::Protocol(description) => write!(formatter, "TLS protocol error (alert {})", description.0),
            TLSError::Alert(description) => write!(formatter, "the TLS peer sent alert {}", description.0),
            TLSError::State => formatter.write_str("the TLS connection's state does not allow it"),
            TLSError::Config => formatter.write_str("the TLS configuration cannot work"),
            TLSError::Write(error) => write!(formatter, "the TLS data cannot be written: {error}"),
            TLSError::Transport => formatter.write_str("the TLS handshake breaks a rule of its transport"),
        }
    }
}

impl core::error::Error for TLSError {}

impl From<BytesError> for TLSError {
    fn from(error: BytesError) -> TLSError {
        TLSError::Write(error)
    }
}
