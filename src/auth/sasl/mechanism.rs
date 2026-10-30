/// The SASL mechanisms this module implements, by their names in the IANA
/// registry. A protocol negotiates them by name (RFC 4422 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SASLMechanism {
    /// RFC 4616.
    PLAIN,
    /// RFC 4422 appendix A.
    EXTERNAL,
    /// RFC 4505.
    ANONYMOUS,
    /// RFC 5802.
    SCRAMSHA1,
    SCRAMSHA1PLUS,
    /// RFC 7677.
    SCRAMSHA256,
    SCRAMSHA256PLUS,
    /// RFC 7628.
    OAUTHBEARER,
}

impl SASLMechanism {
    pub const ALL: [SASLMechanism; 8] = [
        SASLMechanism::PLAIN,
        SASLMechanism::EXTERNAL,
        SASLMechanism::ANONYMOUS,
        SASLMechanism::SCRAMSHA1,
        SASLMechanism::SCRAMSHA1PLUS,
        SASLMechanism::SCRAMSHA256,
        SASLMechanism::SCRAMSHA256PLUS,
        SASLMechanism::OAUTHBEARER,
    ];
    /// The longest mechanism name (RFC 4422 §3.1).
    pub const MAXIMUM_NAME_LENGTH: usize = 20;

    /// The registered name.
    pub const fn name(self) -> &'static str {
        match self {
            SASLMechanism::PLAIN => "PLAIN",
            SASLMechanism::EXTERNAL => "EXTERNAL",
            SASLMechanism::ANONYMOUS => "ANONYMOUS",
            SASLMechanism::SCRAMSHA1 => "SCRAM-SHA-1",
            SASLMechanism::SCRAMSHA1PLUS => "SCRAM-SHA-1-PLUS",
            SASLMechanism::SCRAMSHA256 => "SCRAM-SHA-256",
            SASLMechanism::SCRAMSHA256PLUS => "SCRAM-SHA-256-PLUS",
            SASLMechanism::OAUTHBEARER => "OAUTHBEARER",
        }
    }

    /// The mechanism of the name `name`, compared exactly (names are upper
    /// case, RFC 4422 §3.1); `None` for one this module does not implement.
    pub fn from_name(name: &str) -> Option<SASLMechanism> {
        SASLMechanism::ALL.into_iter().find(|mechanism| mechanism.name() == name)
    }

    /// Whether `name` has the syntax of a mechanism name (RFC 4422 §3.1):
    /// 1 to 20 upper-case letters, digits, hyphens and underscores.
    pub fn is_name(name: &str) -> bool {
        (1..=SASLMechanism::MAXIMUM_NAME_LENGTH).contains(&name.len())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_')
    }

    /// Whether the mechanism binds the authentication to the channel (the
    /// `-PLUS` variants of SCRAM, RFC 5802 §4).
    pub const fn is_plus(self) -> bool {
        matches!(self, SASLMechanism::SCRAMSHA1PLUS | SASLMechanism::SCRAMSHA256PLUS)
    }
}
