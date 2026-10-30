use crate::bytes::{Reader, Writer};

use super::TLSError;

/// The level of an alert (RFC 9846 §6). In TLS 1.3 the level carries no
/// meaning but is still sent: `close_notify` and `user_canceled` as
/// warnings, the others as fatal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TLSAlertLevel(pub u8);

impl TLSAlertLevel {
    pub const WARNING: TLSAlertLevel = TLSAlertLevel(1);
    pub const FATAL: TLSAlertLevel = TLSAlertLevel(2);
}

/// The description of an alert (RFC 9846 §6, Appendix B.2, and the IANA
/// "TLS Alerts" registry). Unknown values are kept as they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TLSAlertDescription(pub u8);

impl TLSAlertDescription {
    pub const CLOSE_NOTIFY: TLSAlertDescription = TLSAlertDescription(0);
    pub const UNEXPECTED_MESSAGE: TLSAlertDescription = TLSAlertDescription(10);
    pub const BAD_RECORD_MAC: TLSAlertDescription = TLSAlertDescription(20);
    pub const RECORD_OVERFLOW: TLSAlertDescription = TLSAlertDescription(22);
    pub const HANDSHAKE_FAILURE: TLSAlertDescription = TLSAlertDescription(40);
    pub const BAD_CERTIFICATE: TLSAlertDescription = TLSAlertDescription(42);
    pub const UNSUPPORTED_CERTIFICATE: TLSAlertDescription = TLSAlertDescription(43);
    pub const CERTIFICATE_REVOKED: TLSAlertDescription = TLSAlertDescription(44);
    pub const CERTIFICATE_EXPIRED: TLSAlertDescription = TLSAlertDescription(45);
    pub const CERTIFICATE_UNKNOWN: TLSAlertDescription = TLSAlertDescription(46);
    pub const ILLEGAL_PARAMETER: TLSAlertDescription = TLSAlertDescription(47);
    pub const UNKNOWN_CA: TLSAlertDescription = TLSAlertDescription(48);
    pub const ACCESS_DENIED: TLSAlertDescription = TLSAlertDescription(49);
    pub const DECODE_ERROR: TLSAlertDescription = TLSAlertDescription(50);
    pub const DECRYPT_ERROR: TLSAlertDescription = TLSAlertDescription(51);
    pub const PROTOCOL_VERSION: TLSAlertDescription = TLSAlertDescription(70);
    pub const INSUFFICIENT_SECURITY: TLSAlertDescription = TLSAlertDescription(71);
    pub const INTERNAL_ERROR: TLSAlertDescription = TLSAlertDescription(80);
    pub const INAPPROPRIATE_FALLBACK: TLSAlertDescription = TLSAlertDescription(86);
    pub const USER_CANCELED: TLSAlertDescription = TLSAlertDescription(90);
    /// TLS 1.2 only (RFC 5246 §7.2.2); reserved in TLS 1.3.
    pub const NO_RENEGOTIATION: TLSAlertDescription = TLSAlertDescription(100);
    pub const MISSING_EXTENSION: TLSAlertDescription = TLSAlertDescription(109);
    pub const UNSUPPORTED_EXTENSION: TLSAlertDescription = TLSAlertDescription(110);
    pub const UNRECOGNIZED_NAME: TLSAlertDescription = TLSAlertDescription(112);
    pub const BAD_CERTIFICATE_STATUS_RESPONSE: TLSAlertDescription = TLSAlertDescription(113);
    pub const UNKNOWN_PSK_IDENTITY: TLSAlertDescription = TLSAlertDescription(115);
    pub const CERTIFICATE_REQUIRED: TLSAlertDescription = TLSAlertDescription(116);
    pub const GENERAL_ERROR: TLSAlertDescription = TLSAlertDescription(117);
    pub const NO_APPLICATION_PROTOCOL: TLSAlertDescription = TLSAlertDescription(120);
    /// The ECH configuration the server could not use (RFC 9849 §11.2).
    pub const ECH_REQUIRED: TLSAlertDescription = TLSAlertDescription(121);

    /// The level an alert of this description is sent at: warning for
    /// `close_notify` and `user_canceled`, fatal otherwise (RFC 9846 §6).
    pub fn level(self) -> TLSAlertLevel {
        match self {
            TLSAlertDescription::CLOSE_NOTIFY | TLSAlertDescription::USER_CANCELED => TLSAlertLevel::WARNING,
            _ => TLSAlertLevel::FATAL,
        }
    }
}

/// An alert message (RFC 9846 §6): its level and description.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TLSAlert {
    pub level: TLSAlertLevel,
    pub description: TLSAlertDescription,
}

impl TLSAlert {
    pub const LENGTH: usize = 2;

    /// The alert of `description` at the level it is sent at.
    pub fn new(description: TLSAlertDescription) -> TLSAlert {
        TLSAlert { level: description.level(), description }
    }

    /// The alert in `bytes`, which must be exactly two bytes.
    pub fn decode(bytes: &[u8]) -> Result<TLSAlert, TLSError> {
        let mut reader = Reader::new(bytes);
        let level = TLSAlertLevel(reader.read_u8().map_err(|_| TLSError::decode())?);
        let description = TLSAlertDescription(reader.read_u8().map_err(|_| TLSError::decode())?);
        if !reader.is_empty() {
            return Err(TLSError::decode());
        }
        Ok(TLSAlert { level, description })
    }

    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TLSError> {
        out.write(&[self.level.0, self.description.0])?;
        Ok(())
    }
}
