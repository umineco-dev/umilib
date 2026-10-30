use core::fmt;

/// The type of a message (RFC 7252 §3, §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoAPType {
    Confirmable,
    NonConfirmable,
    Acknowledgement,
    Reset,
}

impl CoAPType {
    pub fn from_bits(bits: u8) -> CoAPType {
        match bits & 3 {
            0 => CoAPType::Confirmable,
            1 => CoAPType::NonConfirmable,
            2 => CoAPType::Acknowledgement,
            _ => CoAPType::Reset,
        }
    }

    pub fn bits(&self) -> u8 {
        match self {
            CoAPType::Confirmable => 0,
            CoAPType::NonConfirmable => 1,
            CoAPType::Acknowledgement => 2,
            CoAPType::Reset => 3,
        }
    }
}

/// The code of a message (RFC 7252 §3, §12.1): a class of 3 bits and a
/// detail of 5, written c.dd.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoAPCode(pub u8);

impl CoAPCode {
    pub const EMPTY: CoAPCode = CoAPCode::new(0, 0);
    pub const GET: CoAPCode = CoAPCode::new(0, 1);
    pub const POST: CoAPCode = CoAPCode::new(0, 2);
    pub const PUT: CoAPCode = CoAPCode::new(0, 3);
    pub const DELETE: CoAPCode = CoAPCode::new(0, 4);
    /// RFC 8132 §2.
    pub const FETCH: CoAPCode = CoAPCode::new(0, 5);
    pub const PATCH: CoAPCode = CoAPCode::new(0, 6);
    pub const IPATCH: CoAPCode = CoAPCode::new(0, 7);
    pub const CREATED: CoAPCode = CoAPCode::new(2, 1);
    pub const DELETED: CoAPCode = CoAPCode::new(2, 2);
    pub const VALID: CoAPCode = CoAPCode::new(2, 3);
    pub const CHANGED: CoAPCode = CoAPCode::new(2, 4);
    pub const CONTENT: CoAPCode = CoAPCode::new(2, 5);
    /// RFC 7959 §2.9.1.
    pub const CONTINUE: CoAPCode = CoAPCode::new(2, 31);
    pub const BAD_REQUEST: CoAPCode = CoAPCode::new(4, 0);
    pub const UNAUTHORIZED: CoAPCode = CoAPCode::new(4, 1);
    pub const BAD_OPTION: CoAPCode = CoAPCode::new(4, 2);
    pub const FORBIDDEN: CoAPCode = CoAPCode::new(4, 3);
    pub const NOT_FOUND: CoAPCode = CoAPCode::new(4, 4);
    pub const METHOD_NOT_ALLOWED: CoAPCode = CoAPCode::new(4, 5);
    pub const NOT_ACCEPTABLE: CoAPCode = CoAPCode::new(4, 6);
    /// RFC 7959 §2.9.2.
    pub const REQUEST_ENTITY_INCOMPLETE: CoAPCode = CoAPCode::new(4, 8);
    /// RFC 8132 §2.2.
    pub const CONFLICT: CoAPCode = CoAPCode::new(4, 9);
    pub const PRECONDITION_FAILED: CoAPCode = CoAPCode::new(4, 12);
    pub const REQUEST_ENTITY_TOO_LARGE: CoAPCode = CoAPCode::new(4, 13);
    pub const UNSUPPORTED_CONTENT_FORMAT: CoAPCode = CoAPCode::new(4, 15);
    /// RFC 8132 §2.2.
    pub const UNPROCESSABLE_ENTITY: CoAPCode = CoAPCode::new(4, 22);
    pub const INTERNAL_SERVER_ERROR: CoAPCode = CoAPCode::new(5, 0);
    pub const NOT_IMPLEMENTED: CoAPCode = CoAPCode::new(5, 1);
    pub const BAD_GATEWAY: CoAPCode = CoAPCode::new(5, 2);
    pub const SERVICE_UNAVAILABLE: CoAPCode = CoAPCode::new(5, 3);
    pub const GATEWAY_TIMEOUT: CoAPCode = CoAPCode::new(5, 4);
    pub const PROXYING_NOT_SUPPORTED: CoAPCode = CoAPCode::new(5, 5);

    pub const fn new(class: u8, detail: u8) -> CoAPCode {
        CoAPCode((class & 7) << 5 | (detail & 31))
    }

    pub fn class(&self) -> u8 {
        self.0 >> 5
    }

    pub fn detail(&self) -> u8 {
        self.0 & 31
    }

    pub fn is_empty(&self) -> bool {
        *self == CoAPCode::EMPTY
    }

    /// A request: of class 0 but not empty (§12.1.1).
    pub fn is_request(&self) -> bool {
        self.class() == 0 && !self.is_empty()
    }

    /// A response: of class 2, 4 or 5 (§12.1.2).
    pub fn is_response(&self) -> bool {
        matches!(self.class(), 2 | 4 | 5)
    }
}

impl fmt::Display for CoAPCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{:02}", self.class(), self.detail())
    }
}

/// A Content-Format (RFC 7252 §12.3, IANA's registry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoAPContentFormat(pub u16);

impl CoAPContentFormat {
    pub const TEXT_PLAIN: CoAPContentFormat = CoAPContentFormat(0);
    pub const LINK_FORMAT: CoAPContentFormat = CoAPContentFormat(40);
    pub const XML: CoAPContentFormat = CoAPContentFormat(41);
    pub const OCTET_STREAM: CoAPContentFormat = CoAPContentFormat(42);
    pub const EXI: CoAPContentFormat = CoAPContentFormat(47);
    pub const JSON: CoAPContentFormat = CoAPContentFormat(50);
    pub const CBOR: CoAPContentFormat = CoAPContentFormat(60);
}
