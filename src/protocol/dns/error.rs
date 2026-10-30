use core::fmt;

/// An error of DNS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DNSError {
    /// Bytes that are not a DNS message, record or name (RFC 1035 §4).
    Malformed(&'static str),
    /// Text that is not a name, a record or a zone file (RFC 1035 §5).
    Syntax(&'static str),
    /// A message or a name larger than its limit.
    TooLarge(&'static str),
    /// What the call asks for is not possible now.
    State,
    /// A configuration that cannot work.
    Config,
    /// A response that cannot be trusted: DNSSEC failed, or it does not
    /// answer the question it should (RFC 4035 §5, RFC 5452). `code` is the
    /// extended error that tells why ([`super::DNSExtendedError`], RFC 8914).
    Bogus { code: u16, reason: &'static str },
    /// No server answered in time.
    Timeout,
}

impl fmt::Display for DNSError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DNSError::Malformed(reason) => write!(formatter, "a malformed DNS message: {reason}"),
            DNSError::Syntax(reason) => write!(formatter, "invalid DNS text: {reason}"),
            DNSError::TooLarge(reason) => write!(formatter, "too large: {reason}"),
            DNSError::State => formatter.write_str("not possible in this state"),
            DNSError::Config => formatter.write_str("a DNS configuration that cannot work"),
            DNSError::Bogus { reason, .. } => write!(formatter, "a bogus response: {reason}"),
            DNSError::Timeout => formatter.write_str("no DNS server answered in time"),
        }
    }
}

impl core::error::Error for DNSError {}
