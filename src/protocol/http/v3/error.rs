use crate::protocol::http::HTTPError;

/// An error code of HTTP/3 (RFC 9114 §8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct H3ErrorCode(pub u64);

impl H3ErrorCode {
    pub const NO_ERROR: H3ErrorCode = H3ErrorCode(0x100);
    pub const GENERAL_PROTOCOL_ERROR: H3ErrorCode = H3ErrorCode(0x101);
    pub const INTERNAL_ERROR: H3ErrorCode = H3ErrorCode(0x102);
    pub const STREAM_CREATION_ERROR: H3ErrorCode = H3ErrorCode(0x103);
    pub const CLOSED_CRITICAL_STREAM: H3ErrorCode = H3ErrorCode(0x104);
    pub const FRAME_UNEXPECTED: H3ErrorCode = H3ErrorCode(0x105);
    pub const FRAME_ERROR: H3ErrorCode = H3ErrorCode(0x106);
    pub const EXCESSIVE_LOAD: H3ErrorCode = H3ErrorCode(0x107);
    pub const ID_ERROR: H3ErrorCode = H3ErrorCode(0x108);
    pub const SETTINGS_ERROR: H3ErrorCode = H3ErrorCode(0x109);
    pub const MISSING_SETTINGS: H3ErrorCode = H3ErrorCode(0x10A);
    pub const REQUEST_REJECTED: H3ErrorCode = H3ErrorCode(0x10B);
    pub const REQUEST_CANCELLED: H3ErrorCode = H3ErrorCode(0x10C);
    pub const REQUEST_INCOMPLETE: H3ErrorCode = H3ErrorCode(0x10D);
    pub const MESSAGE_ERROR: H3ErrorCode = H3ErrorCode(0x10E);
    pub const CONNECT_ERROR: H3ErrorCode = H3ErrorCode(0x10F);
    pub const VERSION_FALLBACK: H3ErrorCode = H3ErrorCode(0x110);

    /// Whether the code is one RFC 9114 §8.1 or RFC 9204 §6 defines; any
    /// other means H3_NO_ERROR to its receiver (RFC 9114 §8, §9).
    pub const fn is_known(self) -> bool {
        matches!(self.0, 0x100..=0x110 | 0x200..=0x202)
    }

    /// The code as its receiver takes it: an unknown one is H3_NO_ERROR (RFC 9114 §8).
    pub const fn received(code: u64) -> H3ErrorCode {
        let code = H3ErrorCode(code);
        if code.is_known() { code } else { H3ErrorCode::NO_ERROR }
    }

    /// The reserved code 0x1f × `n` + 0x21, which means nothing (RFC 9114 §8.1).
    pub const fn reserved(n: u64) -> H3ErrorCode {
        H3ErrorCode(0x1F * n + 0x21)
    }
}

/// An error HTTP/3 detects: of the connection, which closes with its code,
/// or of one stream, which is reset with it (RFC 9114 §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum H3Error {
    Connection { code: H3ErrorCode, reason: &'static str },
    Stream { stream: u64, code: H3ErrorCode, reason: &'static str },
}

impl H3Error {
    pub const fn connection(code: H3ErrorCode, reason: &'static str) -> H3Error {
        H3Error::Connection { code, reason }
    }

    pub const fn stream(stream: u64, code: H3ErrorCode, reason: &'static str) -> H3Error {
        H3Error::Stream { stream, code, reason }
    }

    pub const fn to_http(self) -> HTTPError {
        match self {
            H3Error::Connection { code, reason } | H3Error::Stream { code, reason, .. } => {
                HTTPError::Protocol { code: code.0, reason }
            }
        }
    }
}
