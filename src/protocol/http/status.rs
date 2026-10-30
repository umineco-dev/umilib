use alloc::vec::Vec;

/// A status code (RFC 9110 §15): three digits, 100 to 599.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HTTPStatus(pub u16);

impl HTTPStatus {
    pub const CONTINUE: HTTPStatus = HTTPStatus(100);
    pub const SWITCHING_PROTOCOLS: HTTPStatus = HTTPStatus(101);
    pub const EARLY_HINTS: HTTPStatus = HTTPStatus(103);
    pub const OK: HTTPStatus = HTTPStatus(200);
    pub const CREATED: HTTPStatus = HTTPStatus(201);
    pub const ACCEPTED: HTTPStatus = HTTPStatus(202);
    pub const NON_AUTHORITATIVE_INFORMATION: HTTPStatus = HTTPStatus(203);
    pub const NO_CONTENT: HTTPStatus = HTTPStatus(204);
    pub const RESET_CONTENT: HTTPStatus = HTTPStatus(205);
    pub const PARTIAL_CONTENT: HTTPStatus = HTTPStatus(206);
    pub const MULTIPLE_CHOICES: HTTPStatus = HTTPStatus(300);
    pub const MOVED_PERMANENTLY: HTTPStatus = HTTPStatus(301);
    pub const FOUND: HTTPStatus = HTTPStatus(302);
    pub const SEE_OTHER: HTTPStatus = HTTPStatus(303);
    pub const NOT_MODIFIED: HTTPStatus = HTTPStatus(304);
    pub const TEMPORARY_REDIRECT: HTTPStatus = HTTPStatus(307);
    pub const PERMANENT_REDIRECT: HTTPStatus = HTTPStatus(308);
    pub const BAD_REQUEST: HTTPStatus = HTTPStatus(400);
    pub const UNAUTHORIZED: HTTPStatus = HTTPStatus(401);
    pub const FORBIDDEN: HTTPStatus = HTTPStatus(403);
    pub const NOT_FOUND: HTTPStatus = HTTPStatus(404);
    pub const METHOD_NOT_ALLOWED: HTTPStatus = HTTPStatus(405);
    pub const NOT_ACCEPTABLE: HTTPStatus = HTTPStatus(406);
    pub const REQUEST_TIMEOUT: HTTPStatus = HTTPStatus(408);
    pub const CONFLICT: HTTPStatus = HTTPStatus(409);
    pub const GONE: HTTPStatus = HTTPStatus(410);
    pub const LENGTH_REQUIRED: HTTPStatus = HTTPStatus(411);
    pub const PRECONDITION_FAILED: HTTPStatus = HTTPStatus(412);
    pub const CONTENT_TOO_LARGE: HTTPStatus = HTTPStatus(413);
    pub const URI_TOO_LONG: HTTPStatus = HTTPStatus(414);
    pub const UNSUPPORTED_MEDIA_TYPE: HTTPStatus = HTTPStatus(415);
    pub const RANGE_NOT_SATISFIABLE: HTTPStatus = HTTPStatus(416);
    pub const EXPECTATION_FAILED: HTTPStatus = HTTPStatus(417);
    pub const MISDIRECTED_REQUEST: HTTPStatus = HTTPStatus(421);
    pub const UNPROCESSABLE_CONTENT: HTTPStatus = HTTPStatus(422);
    pub const TOO_EARLY: HTTPStatus = HTTPStatus(425);
    pub const UPGRADE_REQUIRED: HTTPStatus = HTTPStatus(426);
    pub const PRECONDITION_REQUIRED: HTTPStatus = HTTPStatus(428);
    pub const TOO_MANY_REQUESTS: HTTPStatus = HTTPStatus(429);
    pub const REQUEST_HEADER_FIELDS_TOO_LARGE: HTTPStatus = HTTPStatus(431);
    pub const INTERNAL_SERVER_ERROR: HTTPStatus = HTTPStatus(500);
    pub const NOT_IMPLEMENTED: HTTPStatus = HTTPStatus(501);
    pub const BAD_GATEWAY: HTTPStatus = HTTPStatus(502);
    pub const SERVICE_UNAVAILABLE: HTTPStatus = HTTPStatus(503);
    pub const GATEWAY_TIMEOUT: HTTPStatus = HTTPStatus(504);
    pub const HTTP_VERSION_NOT_SUPPORTED: HTTPStatus = HTTPStatus(505);

    /// The status of three digits `bytes`, 100 to 599 (RFC 9110 §15).
    pub fn parse(bytes: &[u8]) -> Option<HTTPStatus> {
        let [a, b, c] = bytes else { return None };
        if !(a.is_ascii_digit() && b.is_ascii_digit() && c.is_ascii_digit()) {
            return None;
        }
        let code = u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0');
        HTTPStatus::new(code)
    }

    /// The status `code`, if it is 100 to 599.
    pub const fn new(code: u16) -> Option<HTTPStatus> {
        if code >= 100 && code <= 599 { Some(HTTPStatus(code)) } else { None }
    }

    /// Appends the three digits.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[
            b'0' + (self.0 / 100 % 10) as u8,
            b'0' + (self.0 / 10 % 10) as u8,
            b'0' + (self.0 % 10) as u8,
        ]);
    }

    /// 1xx: a response that another follows (RFC 9110 §15.2).
    pub const fn is_informational(&self) -> bool {
        self.0 / 100 == 1
    }

    pub const fn is_successful(&self) -> bool {
        self.0 / 100 == 2
    }

    pub const fn is_redirection(&self) -> bool {
        self.0 / 100 == 3
    }

    pub const fn is_client_error(&self) -> bool {
        self.0 / 100 == 4
    }

    pub const fn is_server_error(&self) -> bool {
        self.0 / 100 == 5
    }

    /// Whether a response of this status has no content, whatever its
    /// framing says: 1xx, 204 and 304 (RFC 9110 §6.4.1).
    pub const fn has_no_content(&self) -> bool {
        self.is_informational() || self.0 == 204 || self.0 == 304
    }

    /// The reason phrase of the RFC for the code, or of its class (RFC 9110 §15).
    pub fn reason(&self) -> &'static str {
        match self.0 {
            100 => "Continue",
            101 => "Switching Protocols",
            103 => "Early Hints",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            203 => "Non-Authoritative Information",
            204 => "No Content",
            205 => "Reset Content",
            206 => "Partial Content",
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            305 => "Use Proxy",
            306 => "(Unused)",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Content Too Large",
            414 => "URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Range Not Satisfiable",
            417 => "Expectation Failed",
            418 => "(Unused)",
            421 => "Misdirected Request",
            422 => "Unprocessable Content",
            425 => "Too Early",
            426 => "Upgrade Required",
            428 => "Precondition Required",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            505 => "HTTP Version Not Supported",
            _ => match self.0 / 100 {
                1 => "Informational",
                2 => "Success",
                3 => "Redirection",
                4 => "Client Error",
                _ => "Server Error",
            },
        }
    }
}
