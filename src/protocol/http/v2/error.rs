use crate::protocol::http::HTTPError;

/// An error code of HTTP/2 (RFC 9113 §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct H2ErrorCode(pub u32);

impl H2ErrorCode {
    pub const NO_ERROR: H2ErrorCode = H2ErrorCode(0x0);
    pub const PROTOCOL_ERROR: H2ErrorCode = H2ErrorCode(0x1);
    pub const INTERNAL_ERROR: H2ErrorCode = H2ErrorCode(0x2);
    pub const FLOW_CONTROL_ERROR: H2ErrorCode = H2ErrorCode(0x3);
    pub const SETTINGS_TIMEOUT: H2ErrorCode = H2ErrorCode(0x4);
    pub const STREAM_CLOSED: H2ErrorCode = H2ErrorCode(0x5);
    pub const FRAME_SIZE_ERROR: H2ErrorCode = H2ErrorCode(0x6);
    pub const REFUSED_STREAM: H2ErrorCode = H2ErrorCode(0x7);
    pub const CANCEL: H2ErrorCode = H2ErrorCode(0x8);
    pub const COMPRESSION_ERROR: H2ErrorCode = H2ErrorCode(0x9);
    pub const CONNECT_ERROR: H2ErrorCode = H2ErrorCode(0xA);
    pub const ENHANCE_YOUR_CALM: H2ErrorCode = H2ErrorCode(0xB);
    pub const INADEQUATE_SECURITY: H2ErrorCode = H2ErrorCode(0xC);
    pub const HTTP_1_1_REQUIRED: H2ErrorCode = H2ErrorCode(0xD);
}

/// An error that HTTP/2 detects (RFC 9113 §5.4): of the whole connection,
/// answered with GOAWAY, or of one stream, answered with RST_STREAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum H2Error {
    Connection { code: H2ErrorCode, reason: &'static str },
    Stream { stream: u32, code: H2ErrorCode, reason: &'static str },
}

impl H2Error {
    pub const fn connection(code: H2ErrorCode, reason: &'static str) -> H2Error {
        H2Error::Connection { code, reason }
    }

    pub const fn stream(stream: u32, code: H2ErrorCode, reason: &'static str) -> H2Error {
        H2Error::Stream { stream, code, reason }
    }

    /// A PROTOCOL_ERROR of the connection.
    pub const fn protocol(reason: &'static str) -> H2Error {
        H2Error::Connection { code: H2ErrorCode::PROTOCOL_ERROR, reason }
    }

    /// A FRAME_SIZE_ERROR of the connection.
    pub const fn frame_size(reason: &'static str) -> H2Error {
        H2Error::Connection { code: H2ErrorCode::FRAME_SIZE_ERROR, reason }
    }

    /// The error as the application sees it.
    pub const fn to_http(self) -> HTTPError {
        match self {
            H2Error::Connection { code, reason } | H2Error::Stream { code, reason, .. } => {
                HTTPError::Protocol { code: code.0 as u64, reason }
            }
        }
    }
}
