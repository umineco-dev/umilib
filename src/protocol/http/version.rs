use alloc::vec::Vec;

/// A version of HTTP (RFC 9110 §2.5): its major and minor numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HTTPVersion {
    pub major: u8,
    pub minor: u8,
}

impl HTTPVersion {
    pub const HTTP1_0: HTTPVersion = HTTPVersion { major: 1, minor: 0 };
    pub const HTTP1_1: HTTPVersion = HTTPVersion { major: 1, minor: 1 };
    pub const HTTP2: HTTPVersion = HTTPVersion { major: 2, minor: 0 };
    pub const HTTP3: HTTPVersion = HTTPVersion { major: 3, minor: 0 };

    /// The version of the HTTP-version of an HTTP/1.x message: "HTTP/",
    /// a digit, ".", a digit, case-sensitive (RFC 9112 §2.3).
    pub fn parse(bytes: &[u8]) -> Option<HTTPVersion> {
        match bytes {
            [b'H', b'T', b'T', b'P', b'/', major, b'.', minor] if major.is_ascii_digit() && minor.is_ascii_digit() => {
                Some(HTTPVersion { major: major - b'0', minor: minor - b'0' })
            }
            _ => None,
        }
    }

    /// Appends "HTTP/" and the numbers; for single digits only, as HTTP/1.x has.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"HTTP/");
        out.push(b'0' + self.major % 10);
        out.push(b'.');
        out.push(b'0' + self.minor % 10);
    }

    /// The ALPN protocol of the version over TLS (RFC 9113 §3.2, RFC 9114
    /// §3.1, RFC 7301 §6): `None` for one without its own.
    pub fn protocol(&self) -> Option<&'static [u8]> {
        match *self {
            HTTPVersion::HTTP1_1 => Some(b"http/1.1"),
            HTTPVersion::HTTP2 => Some(b"h2"),
            HTTPVersion::HTTP3 => Some(b"h3"),
            _ => None,
        }
    }

    /// The version of an ALPN protocol, if it is one of HTTP's.
    pub fn from_protocol(protocol: &[u8]) -> Option<HTTPVersion> {
        match protocol {
            b"http/1.1" => Some(HTTPVersion::HTTP1_1),
            b"h2" => Some(HTTPVersion::HTTP2),
            b"h3" => Some(HTTPVersion::HTTP3),
            _ => None,
        }
    }
}
